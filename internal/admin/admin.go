// Package admin — управление пользователями (локальный HTTP API для vpnctl)
// и выдача клиентских профилей по ссылке-подписке.
//
// Подписка: https://<домен>/sub/<токен>. Karing периодически обновляет её,
// и при каждом обновлении (не чаще раза в ReissueAfter) Vault выпускает
// новый краткоживущий клиентский сертификат. Так сертификаты живут недолго,
// а пользователю не нужно ничего перевыпускать вручную.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yourorg/vpn-mtls/internal/pki"
	"github.com/yourorg/vpn-mtls/internal/profile"
	"github.com/yourorg/vpn-mtls/internal/session"
	"github.com/yourorg/vpn-mtls/internal/users"
)

// Settings — параметры генерации профилей.
type Settings struct {
	Server        string // адрес, к которому подключаются клиенты
	ServerPort    int
	ServerName    string // SNI
	ServerCAPEM   string // CA сертификата сервера (только для TLS_MODE=vault)
	PublicBaseURL string // https://домен — для ссылок-подписок
	CertTTL       string // срок жизни клиентских сертификатов, например "168h"
	ReissueAfter  time.Duration
	UpdateHours   int // рекомендуемый интервал обновления подписки
}

// Service реализует операции администратора.
type Service struct {
	Vault    *pki.Vault
	Trust    *pki.Trust
	Users    *users.Registry
	Sessions *session.Manager
	Store    *session.RedisStore
	Settings Settings
	Log      *logrus.Entry

	mu    sync.Mutex
	cache map[string]cachedProfile
}

type cachedProfile struct {
	body     []byte
	issuedAt time.Time
	notAfter time.Time
}

// Profile возвращает профиль пользователя, при необходимости выпуская новый сертификат.
func (s *Service) Profile(ctx context.Context, name string, forceNew bool) ([]byte, time.Time, error) {
	u, ok := s.Users.Get(name)
	if !ok {
		return nil, time.Time{}, users.ErrNotFound
	}
	if !u.Active() {
		return nil, time.Time{}, fmt.Errorf("user %q is revoked", name)
	}

	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]cachedProfile{}
	}
	c, ok := s.cache[name]
	s.mu.Unlock()
	if ok && !forceNew && time.Since(c.issuedAt) < s.Settings.ReissueAfter {
		return c.body, c.notAfter, nil
	}

	b, err := s.Vault.IssueClient(ctx, name, s.Settings.CertTTL)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := s.Users.AddSerial(ctx, name, b.Serial); err != nil {
		return nil, time.Time{}, err
	}
	// Клиент предъявляет leaf + промежуточный CA; корневой серверу уже известен.
	chain := b.CertPEM
	for _, c := range b.ChainPEM {
		if certs := pki.ParseCertsPEM(c); len(certs) == 1 && certs[0].CheckSignatureFrom(certs[0]) == nil {
			continue
		}
		chain += "\n" + c
	}
	body, err := profile.Build(profile.Params{
		User:        name,
		Server:      s.Settings.Server,
		ServerPort:  s.Settings.ServerPort,
		ServerName:  s.Settings.ServerName,
		Password:    u.Password,
		CertPEM:     chain,
		KeyPEM:      b.KeyPEM,
		ServerCAPEM: s.Settings.ServerCAPEM,
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	s.mu.Lock()
	s.cache[name] = cachedProfile{body: body, issuedAt: time.Now(), notAfter: b.NotAfter}
	s.mu.Unlock()
	s.Log.WithFields(logrus.Fields{"user": name, "serial": b.Serial, "not_after": b.NotAfter}).Info("client certificate issued")
	return body, b.NotAfter, nil
}

// Revoke отзывает пользователя: все его сертификаты в Vault (попадут в CRL),
// локальный список отзыва и разрыв активных сессий — немедленно.
func (s *Service) Revoke(ctx context.Context, name string) (int, error) {
	serials, err := s.Users.Revoke(ctx, name)
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, sn := range serials {
		s.Trust.MarkRevoked(sn)
		if err := s.Vault.Revoke(ctx, sn); err != nil {
			errs = append(errs, fmt.Errorf("revoke %s: %w", sn, err))
		}
	}
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
	killed := s.Sessions.KillUser(name)
	s.Log.WithFields(logrus.Fields{"user": name, "certs": len(serials), "sessions_killed": killed}).Warn("user revoked")
	return killed, errors.Join(errs...)
}

func (s *Service) subURL(token string) string {
	return strings.TrimRight(s.Settings.PublicBaseURL, "/") + "/sub/" + token
}

// ── Подписка (публичная часть, внутри сайта-заглушки) ───────────────────────

// SubscriptionHandler обслуживает /sub/<токен>; всё остальное (и неверные
// токены) уходит в next — сайт-заглушку, поэтому перебор токенов
// неотличим от запросов к несуществующим страницам.
func (s *Service) SubscriptionHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.URL.Path, "/sub/")
		if !ok || token == "" || r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		u, ok := s.Users.LookupSubToken(token)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		body, notAfter, err := s.Profile(r.Context(), u.Name, false)
		if err != nil {
			s.Log.WithError(err).WithField("user", u.Name).Error("subscription: build profile")
			http.Error(w, "temporary error", http.StatusServiceUnavailable)
			return
		}
		up, down, _ := s.Store.Traffic(r.Context(), u.Name)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vpn-mtls-%s.json"`, u.Name))
		w.Header().Set("Profile-Title", "vpn-mtls "+u.Name)
		w.Header().Set("Profile-Update-Interval", fmt.Sprint(s.Settings.UpdateHours))
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=0; expire=%d", up, down, notAfter.Unix()))
		_, _ = w.Write(body)
		s.Log.WithFields(logrus.Fields{"user": u.Name, "remote": r.RemoteAddr}).Info("subscription fetched")
	})
}

// ── Локальный API администратора ────────────────────────────────────────────

// APIHandler — JSON API для утилиты vpnctl. Слушает только localhost.
func (s *Service) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions": len(s.Sessions.Snapshot())})
	})

	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Name      string     `json:"name"`
			Active    bool       `json:"active"`
			CreatedAt time.Time  `json:"created_at"`
			RevokedAt *time.Time `json:"revoked_at,omitempty"`
			Certs     int        `json:"certs_issued"`
			Up        int64      `json:"bytes_up"`
			Down      int64      `json:"bytes_down"`
		}
		var out []row
		for _, u := range s.Users.List() {
			up, down, _ := s.Store.Traffic(r.Context(), u.Name)
			out = append(out, row{u.Name, u.Active(), u.CreatedAt, u.RevokedAt, len(u.Serials), up, down})
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		u, token, err := s.Users.Create(r.Context(), req.Name)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"name": u.Name, "subscription_url": s.subURL(token)})
	})

	mux.HandleFunc("POST /api/users/{name}/revoke", func(w http.ResponseWriter, r *http.Request) {
		killed, err := s.Revoke(r.Context(), r.PathValue("name"))
		if errors.Is(err, users.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		resp := map[string]any{"revoked": r.PathValue("name"), "sessions_killed": killed}
		if err != nil {
			resp["warning"] = err.Error()
		}
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("POST /api/users/{name}/rotate-subscription", func(w http.ResponseWriter, r *http.Request) {
		token, err := s.Users.RotateSubToken(r.Context(), r.PathValue("name"))
		if err != nil {
			writeErr(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"subscription_url": s.subURL(token)})
	})

	mux.HandleFunc("GET /api/users/{name}/profile", func(w http.ResponseWriter, r *http.Request) {
		body, _, err := s.Profile(r.Context(), r.PathValue("name"), r.URL.Query().Has("new"))
		if err != nil {
			writeErr(w, statusFor(err), err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Sessions.Snapshot())
	})

	mux.HandleFunc("POST /api/users/{name}/kick", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"sessions_killed": s.Sessions.KillUser(r.PathValue("name"))})
	})
	return mux
}

func statusFor(err error) int {
	if errors.Is(err, users.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
