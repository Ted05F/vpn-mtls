// cmd/server/main.go — VPN Server entry point
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/yourorg/vpn-mtls/internal/session"
	"github.com/yourorg/vpn-mtls/internal/tls_utils"
	"github.com/yourorg/vpn-mtls/internal/tunnel"
	"github.com/yourorg/vpn-mtls/internal/vault_client"
	"github.com/yourorg/vpn-mtls/pkg/cert"
)

var log = logrus.WithField("component", "server")

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	level, _ := logrus.ParseLevel(envOrDefault("LOG_LEVEL", "info"))
	logrus.SetLevel(level)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── 1. Vault client ──────────────────────────────────────────────────
	vaultCfg := &vault_client.Config{
		Address: envOrDefault("VAULT_ADDR", "http://127.0.0.1:8200"),
		Token:   mustEnv("VAULT_TOKEN"),
	}
	vc, err := vault_client.New(vaultCfg)
	if err != nil {
		logrus.WithError(err).Fatal("vault init failed")
	}

	// ── 2. Load PKI material from Vault ──────────────────────────────────
	pkiBundle, err := cert.FetchServerBundle(ctx, vc)
	if err != nil {
		logrus.WithError(err).Fatal("fetch server cert bundle")
	}

	// ── 3. Build mTLS config ─────────────────────────────────────────────
	tlsCfg, err := tls_utils.ServerTLSConfig(pkiBundle)
	if err != nil {
		logrus.WithError(err).Fatal("build TLS config")
	}

	// ── 4. Redis session store ───────────────────────────────────────────
	rdb := redis.NewClient(&redis.Options{
		Addr:     envOrDefault("REDIS_ADDR", "127.0.0.1:6379"),
		Password: envOrDefault("REDIS_PASSWORD", ""),
		DB:       0,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		logrus.WithError(err).Fatal("redis ping failed")
	}
	store := session.NewRedisStore(rdb, 24*time.Hour)

	// ── 5. TUN interface ─────────────────────────────────────────────────
	tun, err := tunnel.NewServer(
		envOrDefault("TUN_SUBNET", "10.8.0.0/24"),
		envOrDefault("TUN_GW", "10.8.0.1"),
	)
	if err != nil {
		logrus.WithError(err).Fatal("create TUN interface")
	}
	defer tun.Close()

	// ── 6. mTLS listener ─────────────────────────────────────────────────
	listenAddr := envOrDefault("LISTEN_ADDR", "0.0.0.0:8443")
	ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		logrus.WithError(err).Fatalf("listen on %s", listenAddr)
	}
	defer ln.Close()

	logrus.WithField("addr", listenAddr).Info("VPN server listening")

	// ── 7. Accept loop ───────────────────────────────────────────────────
	srv := &Server{
		listener: ln,
		store:    store,
		tun:      tun,
		vault:    vc,
	}

	go srv.acceptLoop(ctx)

	// ── 8. HTTP health endpoint ───────────────────────────────────────────
	go startHealthServer(":8080")

	<-ctx.Done()
	logrus.Info("shutdown signal received")
}

// Server holds all runtime dependencies.
type Server struct {
	listener net.Listener
	store    *session.RedisStore
	tun      *tunnel.TunServer
	vault    *vault_client.Client
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.WithError(err).Warn("accept error")
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()

	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		log.Warn("non-TLS connection rejected")
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		log.WithError(err).Warn("TLS handshake failed")
		return
	}

	// Verify client certificate
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Warn("no client certificate presented")
		return
	}
	clientCert := state.PeerCertificates[0]
	clientID := clientCert.Subject.CommonName

	log.WithFields(logrus.Fields{
		"client_id": clientID,
		"cipher":    tls.CipherSuiteName(state.CipherSuite),
	}).Info("client connected")

	// Выдаём адрес из пула; один CN может переиспользовать тот же IP.
	clientIP, err := s.tun.AssignIP(clientID)
	if err != nil {
		log.WithError(err).Error("IP assignment failed")
		return
	}
	defer s.tun.ReleaseIP(clientID)

	// Первый фрейм по TLS — JSON ClientTunnelConfig, чтобы клиент настроил TUN до обмена пакетами.
	_, vpnNet, err := net.ParseCIDR(s.tun.SubnetCIDR())
	if err != nil {
		log.WithError(err).Error("invalid VPN subnet")
		return
	}
	ones, bits := vpnNet.Mask.Size()
	if bits != 32 {
		log.Error("only IPv4 VPN subnets are supported")
		return
	}
	addrCIDR := fmt.Sprintf("%s/%d", clientIP.String(), ones)
	wireCfg := tunnel.ClientTunnelConfig{
		AddressCIDR: addrCIDR,
		RouteCIDR:   s.tun.SubnetCIDR(),
	}
	payload, err := json.Marshal(wireCfg)
	if err != nil {
		log.WithError(err).Error("marshal tunnel config")
		return
	}
	if err := tunnel.WriteFramed(tlsConn, payload); err != nil {
		log.WithError(err).Error("send tunnel config")
		return
	}

	// Create session
	sess := session.New(clientID, clientIP.String(), clientCert.SerialNumber.String())
	if err := s.store.Save(ctx, sess); err != nil {
		log.WithError(err).Error("session save failed")
		return
	}
	defer s.store.Delete(ctx, sess.ID)

	log.WithFields(logrus.Fields{
		"client_id":  clientID,
		"client_ip":  clientIP,
		"session_id": sess.ID,
	}).Info("session established")

	// Bidirectional tunnel
	s.tun.Bridge(ctx, tlsConn, clientIP)
}

func startHealthServer(addr string) {
	http := &simpleHTTP{}
	logrus.WithField("addr", addr).Info("health server started")
	if err := http.ListenAndServe(addr); err != nil {
		logrus.WithError(err).Error("health server error")
	}
}

// simpleHTTP is a minimal HTTP server for /health checks.
type simpleHTTP struct{}

func (h *simpleHTTP) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}(conn)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		logrus.Fatalf("required env var %s is not set", key)
	}
	return v
}
