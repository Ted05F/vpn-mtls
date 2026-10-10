// Package gateway — TLS-шлюз на порту 443.
//
// Каждое входящее соединение проходит обычное TLS-рукопожатие с публичным
// сертификатом сервера. Дальше:
//
//   - клиент предъявил валидный клиентский сертификат (TLS 1.3, цепочка до
//     нашего CA, не отозван, пользователь активен) → AnyTLS-сессия (VPN);
//   - иначе (браузер, сканер, цензор, неверный сертификат) → обычный
//     HTTPS-сайт-заглушка. Сервер неотличим от веб-сайта и не выдаёт себя
//     TLS-алертом при активном зондировании.
//
// Клиентский сертификат запрашивается в режиме RequestClientCert без списка
// допустимых CA (certificate_authorities), поэтому сообщение CertificateRequest
// не раскрывает имя нашего CA, а в TLS 1.3 оно к тому же зашифровано.
package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yourorg/vpn-mtls/internal/anytls"
	"github.com/yourorg/vpn-mtls/internal/pki"
	"github.com/yourorg/vpn-mtls/internal/proxy"
	"github.com/yourorg/vpn-mtls/internal/session"
	"github.com/yourorg/vpn-mtls/internal/users"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/http2"
)

// Gateway — TLS-шлюз.
type Gateway struct {
	// GetCertificate — источник сертификата сервера (Let's Encrypt или Vault).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// MTLSServerNames — если не пусто, клиентский сертификат запрашивается
	// только при этих SNI (остальным — чистый сайт без CertificateRequest).
	MTLSServerNames []string

	Trust    *pki.Trust
	Users    *users.Registry
	Sessions *session.Manager
	Padding  *anytls.PaddingScheme
	Proxy    *proxy.Handler
	Decoy    http.Handler
	Log      *logrus.Entry

	HandshakeTimeout   time.Duration
	AuthTimeout        time.Duration
	SessionIdleTimeout time.Duration

	once     sync.Once
	base     *tls.Config
	vpnCfg   *tls.Config
	plainCfg *tls.Config
}

func (g *Gateway) init() {
	g.once.Do(func() {
		if g.HandshakeTimeout <= 0 {
			g.HandshakeTimeout = 10 * time.Second
		}
		if g.AuthTimeout <= 0 {
			g.AuthTimeout = 10 * time.Second
		}
		if g.SessionIdleTimeout <= 0 {
			g.SessionIdleTimeout = 10 * time.Minute
		}
		common := &tls.Config{
			GetCertificate: g.GetCertificate,
			// Как у обычного веб-сервера: TLS 1.2+, h2 и http/1.1.
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
		}
		g.plainCfg = common.Clone()
		g.plainCfg.ClientAuth = tls.NoClientCert

		g.vpnCfg = common.Clone()
		// Сертификат запрашивается, но не проверяется в рукопожатии:
		// проверка — после него, чтобы при неудаче отдать заглушку, а не alert.
		// Владение закрытым ключом (CertificateVerify) crypto/tls проверяет всегда.
		g.vpnCfg.ClientAuth = tls.RequestClientCert

		g.base = &tls.Config{GetConfigForClient: g.configForClient}
	})
}

func (g *Gateway) configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	// Клиентский сертификат имеет смысл запрашивать только в TLS 1.3:
	// в TLS 1.2 CertificateRequest и сертификат клиента передаются открыто.
	if !slices.Contains(hello.SupportedVersions, tls.VersionTLS13) {
		return g.plainCfg, nil
	}
	if len(g.MTLSServerNames) > 0 && !slices.Contains(g.MTLSServerNames, strings.ToLower(hello.ServerName)) {
		return g.plainCfg, nil
	}
	return g.vpnCfg, nil
}

// Serve принимает соединения до закрытия listener или отмены ctx.
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	g.init()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go g.handle(ctx, c)
	}
}

func (g *Gateway) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	remote := raw.RemoteAddr().String()
	log := g.Log.WithField("remote", remote)

	tc := tls.Server(raw, g.base)
	_ = raw.SetDeadline(time.Now().Add(g.HandshakeTimeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		log.WithError(err).Debug("TLS handshake failed")
		return
	}
	_ = raw.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	if st.NegotiatedProtocol == acme.ALPNProto {
		return // проверка TLS-ALPN-01 от Let's Encrypt — рукопожатия достаточно
	}

	if len(st.PeerCertificates) > 0 {
		user, leaf, err := g.authorize(st)
		if err == nil {
			g.serveVPN(ctx, tc, user, leaf, log)
			return
		}
		log.WithError(err).Info("client certificate rejected, serving decoy")
	}
	g.serveDecoy(tc, st.NegotiatedProtocol)
}

// authorize — первый фактор: X.509-сертификат клиента.
func (g *Gateway) authorize(st tls.ConnectionState) (string, *x509.Certificate, error) {
	if st.Version != tls.VersionTLS13 {
		return "", nil, errors.New("VPN requires TLS 1.3")
	}
	leaf, err := g.Trust.VerifyClient(st.PeerCertificates)
	if err != nil {
		return "", nil, err
	}
	name, ok := users.NameFromCN(leaf.Subject.CommonName)
	if !ok {
		return "", nil, fmt.Errorf("unexpected certificate CN %q", leaf.Subject.CommonName)
	}
	u, ok := g.Users.Get(name)
	if !ok {
		return "", nil, fmt.Errorf("unknown user %q", name)
	}
	if !u.Active() {
		return "", nil, fmt.Errorf("user %q is revoked", name)
	}
	return name, leaf, nil
}

func (g *Gateway) serveVPN(ctx context.Context, tc *tls.Conn, user string, leaf *x509.Certificate, log *logrus.Entry) {
	log = log.WithField("user", user)

	// Второй фактор: пароль AnyTLS должен принадлежать тому же пользователю.
	br := bufio.NewReaderSize(tc, 64*1024)
	_ = tc.SetReadDeadline(time.Now().Add(g.AuthTimeout))
	hash, err := anytls.ReadAuth(br)
	if err != nil {
		log.WithError(err).Info("anytls auth: read failed")
		return
	}
	if name, ok := g.Users.LookupPassword(hash); !ok || name != user {
		log.Warn("anytls auth: password does not match certificate owner")
		return
	}
	_ = tc.SetReadDeadline(time.Time{})

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sess := anytls.NewSession(sctx, tc, br, anytls.SessionConfig{
		Padding:     g.Padding,
		Handler:     g.Proxy.HandleStream,
		IdleTimeout: g.SessionIdleTimeout,
		Log:         log,
	})
	live, err := g.Sessions.Open(ctx, user, pki.SerialKeyOf(leaf.SerialNumber), tc.RemoteAddr().String(), counters{sess}, cancel)
	if err != nil {
		log.WithError(err).Warn("session rejected")
		return
	}
	defer g.Sessions.Close(context.WithoutCancel(ctx), live)

	start := time.Now()
	log.WithField("session", live.ID).Info("VPN session started")
	err = sess.Serve()
	log.WithFields(logrus.Fields{
		"session":  live.ID,
		"client":   sess.ClientName(),
		"duration": time.Since(start).Round(time.Second).String(),
		"up":       sess.BytesUp.Load(),
		"down":     sess.BytesDown.Load(),
	}).WithError(err).Info("VPN session ended")
}

type counters struct{ s *anytls.Session }

func (c counters) Up() int64      { return c.s.BytesUp.Load() }
func (c counters) Down() int64    { return c.s.BytesDown.Load() }
func (c counters) Client() string { return c.s.ClientName() }

// serveDecoy отдаёт HTTP(S)-заглушку поверх уже установленного TLS-соединения.
func (g *Gateway) serveDecoy(tc *tls.Conn, alpn string) {
	if alpn == "h2" {
		(&http2.Server{IdleTimeout: 2 * time.Minute}).ServeConn(tc, &http2.ServeConnOpts{
			Handler:    g.Decoy,
			BaseConfig: &http.Server{ReadHeaderTimeout: 10 * time.Second},
		})
		return
	}
	srv := &http.Server{
		Handler:           g.Decoy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	_ = srv.Serve(newOneConnListener(tc))
}

// oneConnListener отдаёт http.Server ровно одно соединение и завершается после его закрытия.
type oneConnListener struct {
	conn      net.Conn
	once      sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{closed: make(chan struct{})}
	l.conn = &notifyCloseConn{Conn: c, onClose: func() { l.Close() }}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyCloseConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *notifyCloseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}
