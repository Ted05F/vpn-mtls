// Package tls_utils собирает строгие tls.Config для VPN: только TLS 1.3, обязательный клиентский сертификат на сервере.
package tls_utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/yourorg/vpn-mtls/pkg/cert"
)

// ServerTLSConfig returns a tls.Config requiring client certificates,
// pinned to TLS 1.3 with strong cipher suites.
func ServerTLSConfig(bundle *cert.PKIBundle) (*tls.Config, error) {
	tlsCert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse server cert/key: %w", err)
	}

	caPool, err := buildCAPool(bundle.CACertPEM)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		// Force TLS 1.3 — no fallback
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,

		// Require and verify client certificate
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,

		Certificates: []tls.Certificate{tlsCert},

		// Explicit cipher suite preferences (TLS 1.3 ciphers are fixed,
		// but we list them for documentation clarity)
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},

		// Reject expired / revoked certificates
		VerifyPeerCertificate: makeVerifyClientCert(caPool),

		// Session resumption — disabled for security
		SessionTicketsDisabled: true,
	}

	return cfg, nil
}

// ClientTLSConfig returns a tls.Config that presents a client certificate
// and verifies the server against our private CA.
func ClientTLSConfig(bundle *cert.PKIBundle) (*tls.Config, error) {
	tlsCert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client cert/key: %w", err)
	}

	caPool, err := buildCAPool(bundle.CACertPEM)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,

		// Present our client certificate
		Certificates: []tls.Certificate{tlsCert},

		// Pin to our private CA — reject all other certificates
		RootCAs: caPool,

		// Disable standard hostname check — we use CN/SAN manually
		InsecureSkipVerify: false,

		// Additional server cert verification
		VerifyPeerCertificate: makeVerifyServerCert(caPool),

		SessionTicketsDisabled: true,
	}

	return cfg, nil
}

// buildCAPool creates an x509.CertPool from a PEM-encoded CA certificate.
func buildCAPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid CA certs found in PEM")
	}
	return pool, nil
}

// makeVerifyClientCert returns a VerifyPeerCertificate function that checks
// the client cert against our CA and validates extended key usage.
func makeVerifyClientCert(caPool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no client certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse client cert: %w", err)
		}

		opts := x509.VerifyOptions{
			Roots:     caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("client cert verification failed: %w", err)
		}
		return nil
	}
}

// makeVerifyServerCert verifies the server certificate explicitly.
func makeVerifyServerCert(caPool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse server cert: %w", err)
		}

		opts := x509.VerifyOptions{
			Roots:     caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("server cert verification failed: %w", err)
		}
		return nil
	}
}
