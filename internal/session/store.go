// Package session хранит метаданные VPN-сессий в Redis (TTL, множество активных клиентов, refresh-токены).
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

const (
	sessionPrefix      = "vpn:session:"
	refreshTokenPrefix = "vpn:refresh:"
	activeClientsKey   = "vpn:active_clients"
)

// Session holds runtime metadata for a connected VPN client.
type Session struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	ClientIP     string    `json:"client_ip"`
	CertSerial   string    `json:"cert_serial"`
	ConnectedAt  time.Time `json:"connected_at"`
	LastActivity time.Time `json:"last_activity"`
	BytesIn      int64     `json:"bytes_in"`
	BytesOut     int64     `json:"bytes_out"`
}

// RefreshToken allows re-authentication without re-issuing certificates.
type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// New creates a new session with a fresh UUID.
func New(clientID, clientIP, certSerial string) *Session {
	return &Session{
		ID:           uuid.NewString(),
		ClientID:     clientID,
		ClientIP:     clientIP,
		CertSerial:   certSerial,
		ConnectedAt:  time.Now().UTC(),
		LastActivity: time.Now().UTC(),
	}
}

// RedisStore persists sessions in Redis with configurable TTL.
type RedisStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewRedisStore constructs a RedisStore.
func NewRedisStore(rdb *redis.Client, ttl time.Duration) *RedisStore {
	return &RedisStore{rdb: rdb, ttl: ttl}
}

// Save serialises and stores a session.
func (s *RedisStore) Save(ctx context.Context, sess *Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	key := sessionPrefix + sess.ID
	pipe := s.rdb.Pipeline()
	pipe.Set(ctx, key, data, s.ttl)
	pipe.SAdd(ctx, activeClientsKey, sess.ClientID)
	_, err = pipe.Exec(ctx)
	return err
}

// Get retrieves a session by ID.
func (s *RedisStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	data, err := s.rdb.Get(ctx, sessionPrefix+sessionID).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &sess, nil
}

// UpdateActivity refreshes the last-activity timestamp and byte counters.
func (s *RedisStore) UpdateActivity(ctx context.Context, sessionID string, bytesIn, bytesOut int64) error {
	sess, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	sess.LastActivity = time.Now().UTC()
	sess.BytesIn += bytesIn
	sess.BytesOut += bytesOut
	return s.Save(ctx, sess)
}

// Delete removes a session and cleans up the active-clients set.
func (s *RedisStore) Delete(ctx context.Context, sessionID string) error {
	sess, err := s.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	pipe := s.rdb.Pipeline()
	pipe.Del(ctx, sessionPrefix+sessionID)
	pipe.SRem(ctx, activeClientsKey, sess.ClientID)
	_, err = pipe.Exec(ctx)
	return err
}

// ActiveClients returns the set of currently connected client IDs.
func (s *RedisStore) ActiveClients(ctx context.Context) ([]string, error) {
	return s.rdb.SMembers(ctx, activeClientsKey).Result()
}

// IssueRefreshToken creates and stores a refresh token for a client.
func (s *RedisStore) IssueRefreshToken(ctx context.Context, clientID string, ttl time.Duration) (*RefreshToken, error) {
	rt := &RefreshToken{
		Token:     uuid.NewString(),
		ClientID:  clientID,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	data, err := json.Marshal(rt)
	if err != nil {
		return nil, err
	}
	key := refreshTokenPrefix + rt.Token
	if err := s.rdb.Set(ctx, key, data, ttl).Err(); err != nil {
		return nil, err
	}
	return rt, nil
}

// ValidateRefreshToken checks a token and returns the associated client ID.
func (s *RedisStore) ValidateRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	data, err := s.rdb.Get(ctx, refreshTokenPrefix+token).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("refresh token not found or expired")
	}
	if err != nil {
		return nil, err
	}
	var rt RefreshToken
	if err := json.Unmarshal(data, &rt); err != nil {
		return nil, err
	}
	if rt.Revoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}
	if time.Now().UTC().After(rt.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}
	return &rt, nil
}

// RevokeRefreshToken marks a token as revoked (does not delete from Redis
// so the revocation is preserved for the remaining TTL).
func (s *RedisStore) RevokeRefreshToken(ctx context.Context, token string) error {
	rt, err := s.ValidateRefreshToken(ctx, token)
	if err != nil {
		return err
	}
	rt.Revoked = true
	data, _ := json.Marshal(rt)
	remaining := time.Until(rt.ExpiresAt)
	return s.rdb.Set(ctx, refreshTokenPrefix+token, data, remaining).Err()
}
