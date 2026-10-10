// Package users — реестр пользователей VPN. Записи хранятся в Vault KV v2
// (secret/vpn/users/<имя>) и кэшируются в памяти сервера.
//
// Пользователь аутентифицируется двумя независимыми факторами, которые
// должны указывать на одно и то же имя:
//  1. клиентский X.509-сертификат (CN = <имя>.vpn.internal), выпущенный Vault PKI;
//  2. пароль протокола AnyTLS (sha256 передаётся внутри TLS).
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/vpn-mtls/internal/pki"
)

const kvPrefix = "vpn/users/"

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ErrNotFound — пользователь не существует.
var ErrNotFound = errors.New("user not found")

// User — запись о пользователе.
type User struct {
	Name           string     `json:"name"`
	Password       string     `json:"password"`
	SubTokenSHA256 string     `json:"sub_token_sha256"`
	Serials        []string   `json:"serials"` // все выпущенные сертификаты — для отзыва
	CreatedAt      time.Time  `json:"created_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// Active — пользователь не отозван.
func (u *User) Active() bool { return u.RevokedAt == nil }

// Registry — потокобезопасный кэш пользователей поверх Vault KV.
type Registry struct {
	v *pki.Vault

	mu     sync.RWMutex
	byName map[string]*User
	byPass map[[32]byte]string
}

// NewRegistry создаёт реестр; данные загружаются вызовом Load.
func NewRegistry(v *pki.Vault) *Registry {
	return &Registry{v: v, byName: map[string]*User{}, byPass: map[[32]byte]string{}}
}

// Load перечитывает всех пользователей из Vault.
func (r *Registry) Load(ctx context.Context) error {
	keys, err := r.v.KVList(ctx, strings.TrimSuffix(kvPrefix, "/"))
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	byName := make(map[string]*User, len(keys))
	for _, k := range keys {
		var u User
		ok, err := r.v.KVGet(ctx, kvPrefix+k, &u)
		if err != nil {
			return fmt.Errorf("read user %s: %w", k, err)
		}
		if ok {
			byName[u.Name] = &u
		}
	}
	r.mu.Lock()
	r.byName = byName
	r.reindexLocked()
	r.mu.Unlock()
	return nil
}

func (r *Registry) reindexLocked() {
	r.byPass = make(map[[32]byte]string, len(r.byName))
	for _, u := range r.byName {
		if u.Active() {
			r.byPass[sha256.Sum256([]byte(u.Password))] = u.Name
		}
	}
}

// Get возвращает копию записи пользователя.
func (r *Registry) Get(name string) (User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.byName[name]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// List возвращает всех пользователей, отсортированных по имени.
func (r *Registry) List() []User {
	r.mu.RLock()
	out := make([]User, 0, len(r.byName))
	for _, u := range r.byName {
		out = append(out, *u)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupPassword сопоставляет sha256(password) из AnyTLS активному пользователю.
func (r *Registry) LookupPassword(hash [32]byte) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.byPass[hash]
	return name, ok
}

// LookupSubToken находит активного пользователя по токену подписки.
func (r *Registry) LookupSubToken(token string) (User, bool) {
	sum := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(sum[:])
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.byName {
		if u.Active() && subtle.ConstantTimeCompare([]byte(u.SubTokenSHA256), []byte(want)) == 1 {
			return *u, true
		}
	}
	return User{}, false
}

// NameFromCN извлекает имя пользователя из CN сертификата.
func NameFromCN(cn string) (string, bool) {
	name, ok := strings.CutSuffix(cn, "."+pki.ClientDomain)
	return name, ok && nameRe.MatchString(name)
}

// Create заводит пользователя и возвращает его вместе с токеном подписки
// (токен хранится только в виде хеша и показывается один раз).
func (r *Registry) Create(ctx context.Context, name string) (User, string, error) {
	if !nameRe.MatchString(name) {
		return User{}, "", fmt.Errorf("invalid user name %q: use a-z, 0-9, '-' (max 32)", name)
	}
	r.mu.RLock()
	_, exists := r.byName[name]
	r.mu.RUnlock()
	if exists {
		return User{}, "", fmt.Errorf("user %q already exists", name)
	}
	token := randomString(24)
	sum := sha256.Sum256([]byte(token))
	u := &User{
		Name:           name,
		Password:       randomString(24),
		SubTokenSHA256: hex.EncodeToString(sum[:]),
		CreatedAt:      time.Now().UTC(),
	}
	if err := r.save(ctx, u); err != nil {
		return User{}, "", err
	}
	return *u, token, nil
}

// RotateSubToken выдаёт пользователю новый токен подписки (старый перестаёт работать).
func (r *Registry) RotateSubToken(ctx context.Context, name string) (string, error) {
	token := randomString(24)
	sum := sha256.Sum256([]byte(token))
	err := r.update(ctx, name, func(u *User) error {
		if !u.Active() {
			return fmt.Errorf("user %q is revoked", name)
		}
		u.SubTokenSHA256 = hex.EncodeToString(sum[:])
		return nil
	})
	return token, err
}

// AddSerial запоминает серийный номер выпущенного пользователю сертификата.
func (r *Registry) AddSerial(ctx context.Context, name, serial string) error {
	return r.update(ctx, name, func(u *User) error {
		u.Serials = append(u.Serials, serial)
		// Храним только последние сертификаты: старые к этому моменту истекли.
		if len(u.Serials) > 50 {
			u.Serials = u.Serials[len(u.Serials)-50:]
		}
		return nil
	})
}

// Revoke помечает пользователя отозванным и возвращает его серийные номера.
func (r *Registry) Revoke(ctx context.Context, name string) ([]string, error) {
	var serials []string
	err := r.update(ctx, name, func(u *User) error {
		now := time.Now().UTC()
		u.RevokedAt = &now
		serials = append(serials, u.Serials...)
		return nil
	})
	return serials, err
}

func (r *Registry) update(ctx context.Context, name string, fn func(*User) error) error {
	r.mu.RLock()
	cur, ok := r.byName[name]
	r.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	u := *cur
	u.Serials = append([]string(nil), cur.Serials...)
	if err := fn(&u); err != nil {
		return err
	}
	return r.save(ctx, &u)
}

func (r *Registry) save(ctx context.Context, u *User) error {
	if err := r.v.KVPut(ctx, kvPrefix+u.Name, u); err != nil {
		return fmt.Errorf("save user %s: %w", u.Name, err)
	}
	r.mu.Lock()
	r.byName[u.Name] = u
	r.reindexLocked()
	r.mu.Unlock()
	return nil
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
