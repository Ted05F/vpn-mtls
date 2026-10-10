// Package session — учёт активных VPN-сессий.
//
// Manager держит живые сессии в памяти (лимит на пользователя, принудительный
// разрыв при отзыве), а RedisStore зеркалирует их в Redis: метаданные с TTL,
// множество активных пользователей и накопительные счётчики трафика.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	sessionPrefix    = "vpn:session:"
	activeClientsKey = "vpn:active_clients"
	trafficPrefix    = "vpn:traffic:"
)

// Session — метаданные одной VPN-сессии (одного TLS-соединения).
type Session struct {
	ID           string    `json:"id"`
	User         string    `json:"user"`
	CertSerial   string    `json:"cert_serial"`
	RemoteAddr   string    `json:"remote_addr"`
	Client       string    `json:"client"`
	ConnectedAt  time.Time `json:"connected_at"`
	LastActivity time.Time `json:"last_activity"`
	BytesUp      int64     `json:"bytes_up"`
	BytesDown    int64     `json:"bytes_down"`
}

// RedisStore сохраняет сессии в Redis.
type RedisStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewRedisStore создаёт хранилище; ttl — срок жизни записи без обновлений.
func NewRedisStore(rdb *redis.Client, ttl time.Duration) *RedisStore {
	return &RedisStore{rdb: rdb, ttl: ttl}
}

// Save сохраняет (или обновляет) сессию атомарным pipeline.
func (s *RedisStore) Save(ctx context.Context, sess *Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, sessionPrefix+sess.ID, data, s.ttl)
		p.SAdd(ctx, activeClientsKey, sess.User)
		return nil
	})
	return err
}

// Delete удаляет сессию; пользователь убирается из активных, если сессий у него не осталось.
func (s *RedisStore) Delete(ctx context.Context, sess *Session, userHasMore bool) error {
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Del(ctx, sessionPrefix+sess.ID)
		if !userHasMore {
			p.SRem(ctx, activeClientsKey, sess.User)
		}
		return nil
	})
	return err
}

// AddTraffic увеличивает накопительные счётчики трафика пользователя.
func (s *RedisStore) AddTraffic(ctx context.Context, user string, up, down int64) error {
	if up == 0 && down == 0 {
		return nil
	}
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HIncrBy(ctx, trafficPrefix+user, "up", up)
		p.HIncrBy(ctx, trafficPrefix+user, "down", down)
		return nil
	})
	return err
}

// Traffic возвращает накопленный трафик пользователя.
func (s *RedisStore) Traffic(ctx context.Context, user string) (up, down int64, err error) {
	m, err := s.rdb.HGetAll(ctx, trafficPrefix+user).Result()
	if err != nil {
		return 0, 0, err
	}
	fmt.Sscan(m["up"], &up)
	fmt.Sscan(m["down"], &down)
	return up, down, nil
}

// Reset очищает следы прошлого запуска: после рестарта сервера живых сессий нет.
func (s *RedisStore) Reset(ctx context.Context) error {
	iter := s.rdb.Scan(ctx, 0, sessionPrefix+"*", 200).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return err
	}
	keys = append(keys, activeClientsKey)
	return s.rdb.Del(ctx, keys...).Err()
}

// ── Manager ─────────────────────────────────────────────────────────────────

// ErrTooManySessions — превышен лимит одновременных сессий пользователя.
var ErrTooManySessions = errors.New("too many concurrent sessions")

// Counters — источник счётчиков трафика живой сессии.
type Counters interface {
	Up() int64
	Down() int64
	Client() string // название клиента из cmdSettings, например "sing-box/1.14.2"
}

// Live — живая сессия.
type Live struct {
	Session
	cancel   context.CancelFunc
	counters Counters
	flushed  [2]int64 // сколько трафика уже учтено в Redis
}

// Manager управляет живыми сессиями.
type Manager struct {
	store      *RedisStore
	maxPerUser int
	log        *logrus.Entry

	mu     sync.Mutex
	live   map[string]*Live
	byUser map[string]int
}

// NewManager создаёт менеджер. maxPerUser <= 0 — без ограничения.
func NewManager(store *RedisStore, maxPerUser int, log *logrus.Entry) *Manager {
	return &Manager{store: store, maxPerUser: maxPerUser, log: log,
		live: map[string]*Live{}, byUser: map[string]int{}}
}

// Open регистрирует новую сессию. cancel вызывается при принудительном разрыве.
func (m *Manager) Open(ctx context.Context, user, serial, remote string, c Counters, cancel context.CancelFunc) (*Live, error) {
	m.mu.Lock()
	if m.maxPerUser > 0 && m.byUser[user] >= m.maxPerUser {
		m.mu.Unlock()
		return nil, ErrTooManySessions
	}
	now := time.Now().UTC()
	l := &Live{
		Session: Session{ID: uuid.NewString(), User: user, CertSerial: serial, RemoteAddr: remote,
			ConnectedAt: now, LastActivity: now},
		cancel:   cancel,
		counters: c,
	}
	m.live[l.ID] = l
	m.byUser[user]++
	m.mu.Unlock()

	if err := m.store.Save(ctx, &l.Session); err != nil {
		m.log.WithError(err).Warn("redis: save session")
	}
	return l, nil
}

// Close снимает сессию с учёта и сбрасывает остаток трафика в Redis.
func (m *Manager) Close(ctx context.Context, l *Live) {
	m.mu.Lock()
	if _, ok := m.live[l.ID]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.live, l.ID)
	m.byUser[l.User]--
	more := m.byUser[l.User] > 0
	if !more {
		delete(m.byUser, l.User)
	}
	up, down := m.takeDeltaLocked(l)
	m.mu.Unlock()

	if err := m.store.AddTraffic(ctx, l.User, up, down); err != nil {
		m.log.WithError(err).Warn("redis: add traffic")
	}
	if err := m.store.Delete(ctx, &l.Session, more); err != nil {
		m.log.WithError(err).Warn("redis: delete session")
	}
}

func (m *Manager) takeDeltaLocked(l *Live) (up, down int64) {
	u, d := l.counters.Up(), l.counters.Down()
	up, down = u-l.flushed[0], d-l.flushed[1]
	l.flushed = [2]int64{u, d}
	l.BytesUp, l.BytesDown = u, d
	l.Client = l.counters.Client()
	if up > 0 || down > 0 {
		l.LastActivity = time.Now().UTC()
	}
	return up, down
}

// KillUser разрывает все сессии пользователя. Возвращает их количество.
func (m *Manager) KillUser(user string) int {
	return m.kill(func(l *Live) bool { return l.User == user })
}

// KillSerial разрывает сессии, установленные с данным сертификатом.
func (m *Manager) KillSerial(serialKey string, keyOf func(string) string) int {
	return m.kill(func(l *Live) bool { return keyOf(l.CertSerial) == serialKey })
}

func (m *Manager) kill(match func(*Live) bool) int {
	m.mu.Lock()
	var victims []*Live
	for _, l := range m.live {
		if match(l) {
			victims = append(victims, l)
		}
	}
	m.mu.Unlock()
	for _, l := range victims {
		l.cancel()
	}
	return len(victims)
}

// Snapshot возвращает копии живых сессий с актуальными счётчиками.
func (m *Manager) Snapshot() []Session {
	m.mu.Lock()
	out := make([]Session, 0, len(m.live))
	for _, l := range m.live {
		s := l.Session
		s.BytesUp, s.BytesDown = l.counters.Up(), l.counters.Down()
		s.Client = l.counters.Client()
		out = append(out, s)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectedAt.Before(out[j].ConnectedAt) })
	return out
}

// RunFlusher периодически переносит счётчики трафика и last_activity в Redis.
func (m *Manager) RunFlusher(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		type item struct {
			sess     Session
			up, down int64
		}
		m.mu.Lock()
		items := make([]item, 0, len(m.live))
		for _, l := range m.live {
			up, down := m.takeDeltaLocked(l)
			items = append(items, item{l.Session, up, down})
		}
		m.mu.Unlock()
		for _, it := range items {
			if err := m.store.AddTraffic(ctx, it.sess.User, it.up, it.down); err != nil {
				m.log.WithError(err).Warn("redis: add traffic")
				continue
			}
			if err := m.store.Save(ctx, &it.sess); err != nil {
				m.log.WithError(err).Warn("redis: save session")
			}
		}
	}
}
