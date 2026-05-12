// cmd/client/main.go — VPN Client entry point
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yourorg/vpn-mtls/internal/tls_utils"
	"github.com/yourorg/vpn-mtls/internal/tunnel"
	"github.com/yourorg/vpn-mtls/internal/vault_client"
	"github.com/yourorg/vpn-mtls/pkg/cert"
)

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	level, _ := logrus.ParseLevel(envOrDefault("LOG_LEVEL", "info"))
	logrus.SetLevel(level)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── 1. Vault — get client certificate ────────────────────────────────
	vaultCfg := &vault_client.Config{
		Address: envOrDefault("VAULT_ADDR", "http://127.0.0.1:8200"),
		Token:   mustEnv("VAULT_TOKEN"),
	}
	vc, err := vault_client.New(vaultCfg)
	if err != nil {
		logrus.WithError(err).Fatal("vault init failed")
	}

	clientName := envOrDefault("CLIENT_NAME", "vpn-client")
	pkiBundle, err := cert.FetchClientBundle(ctx, vc, clientName)
	if err != nil {
		logrus.WithError(err).Fatal("fetch client cert bundle")
	}

	// ── 2. Build mTLS config ─────────────────────────────────────────────
	tlsCfg, err := tls_utils.ClientTLSConfig(pkiBundle)
	if err != nil {
		logrus.WithError(err).Fatal("build TLS config")
	}

	// ── 3. Create TUN interface ───────────────────────────────────────────
	tun, err := tunnel.NewClient("tun0")
	if err != nil {
		logrus.WithError(err).Fatal("create TUN interface")
	}
	defer tun.Close()

	// ── 4. Connect with exponential backoff ───────────────────────────────
	serverAddr := envOrDefault("SERVER_ADDR", "127.0.0.1:8443")
	client := &VPNClient{
		serverAddr: serverAddr,
		tlsCfg:     tlsCfg,
		tun:        tun,
	}

	client.RunWithReconnect(ctx)
}

// VPNClient encapsulates connection state and reconnect logic.
type VPNClient struct {
	serverAddr string
	tlsCfg     *tls.Config
	tun        *tunnel.TunClient
}

// RunWithReconnect dials the server and restarts on disconnect.
func (c *VPNClient) RunWithReconnect(ctx context.Context) {
	backoff := time.Second
	maxBackoff := 30 * time.Second
	attempts := 0

	for {
		select {
		case <-ctx.Done():
			logrus.Info("client shutting down")
			return
		default:
		}

		attempts++
		logrus.WithFields(logrus.Fields{
			"server":  c.serverAddr,
			"attempt": attempts,
		}).Info("connecting to VPN server")

		if err := c.connect(ctx); err != nil {
			logrus.WithError(err).WithField("backoff", backoff).
				Warn("connection failed, will retry")

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff with cap
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			// Successful session — reset backoff
			logrus.Info("session ended cleanly")
			backoff = time.Second
			attempts = 0
		}
	}
}

// connect dials the server, performs mTLS handshake, and bridges the TUN.
func (c *VPNClient) connect(ctx context.Context) error {
	dialer := &tls.Dialer{Config: c.tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", c.serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	logrus.WithFields(logrus.Fields{
		"server":  c.serverAddr,
		"version": tls.VersionName(state.Version),
		"cipher":  tls.CipherSuiteName(state.CipherSuite),
	}).Info("TLS session established")

	// Синхронизация с сервером: получаем назначенный адрес и маршрут к VPN-подсети.
	buf := make([]byte, 65536)
	raw, err := tunnel.ReadFramed(tlsConn, buf)
	if err != nil {
		return fmt.Errorf("read tunnel config from server: %w", err)
	}
	var wireCfg tunnel.ClientTunnelConfig
	if err := json.Unmarshal(raw, &wireCfg); err != nil {
		return fmt.Errorf("parse tunnel config: %w", err)
	}
	if err := c.tun.Configure(wireCfg.AddressCIDR, wireCfg.RouteCIDR); err != nil {
		return fmt.Errorf("configure TUN: %w", err)
	}
	logrus.WithFields(logrus.Fields{
		"address": wireCfg.AddressCIDR,
		"route":   wireCfg.RouteCIDR,
	}).Info("TUN configured from server")

	// Дальше только IP-пакеты в length-prefixed фреймах.
	return c.tun.Bridge(ctx, tlsConn)
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
