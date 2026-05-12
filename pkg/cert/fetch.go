// Package cert получает короткоживущие сертификаты из Vault PKI и собирает материал для mTLS.
package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yourorg/vpn-mtls/internal/vault_client"
)

// PKIBundle — всё PEM-данные, нужное crypto/tls: своя пара ключей и доверенный CA для проверки пира.
type PKIBundle struct {
	CertPEM   []byte // конечный сертификат (и при необходимости цепочка)
	KeyPEM    []byte // приватный ключ (держим только в памяти процесса)
	CACertPEM []byte // CA, которым подписаны сертификаты пиров
}

const (
	serverRole = "vpn-server" // имя роли в Vault PKI для узла-сервера
	clientRole = "vpn-client" // имя роли для клиентов VPN
)

// defaultCertTTL — leaf не может жить дольше NotAfter корневого CA в Vault; 8760h ломает выпуск при «коротком» lab-CA.
const defaultCertTTL = "720h"

// issueTTL возвращает TTL для pki/issue: VPN_CERT_TTL или безопасный дефолт (30 суток).
func issueTTL() string {
	if v := strings.TrimSpace(os.Getenv("VPN_CERT_TTL")); v != "" {
		return v
	}
	return defaultCertTTL
}

// clampTTLToCA сокращает запрошенный TTL, если он выходит за NotAfter подписанта в Vault (устраняет 400 при коротком lab-CA).
func clampTTLToCA(caPEM []byte, requestedTTL string) (string, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return requestedTTL, nil
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return requestedTTL, nil
	}
	req, err := time.ParseDuration(strings.ToLower(strings.TrimSpace(requestedTTL)))
	if err != nil {
		return "", fmt.Errorf("parse certificate TTL %q: %w", requestedTTL, err)
	}
	const margin = 48 * time.Hour
	maxLeaf := time.Until(caCert.NotAfter) - margin
	if maxLeaf <= 0 {
		return "", fmt.Errorf("CA expires at %v — renew PKI or use a longer-lived root", caCert.NotAfter.UTC())
	}
	if req <= maxLeaf {
		return requestedTTL, nil
	}
	h := int(maxLeaf / time.Hour)
	if h < 1 {
		h = 1
	}
	return fmt.Sprintf("%dh", h), nil
}

// FetchServerBundle запрашивает у Vault сертификат для VPN-сервера (CN фиксирован под внутренний DNS).
func FetchServerBundle(ctx context.Context, vc *vault_client.Client) (*PKIBundle, error) {
	caBytes, err := vc.GetCA(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch CA cert: %w", err)
	}
	ttl, err := clampTTLToCA(caBytes, issueTTL())
	if err != nil {
		return nil, err
	}
	bundle, err := vc.IssueCertificate(ctx, serverRole, "vpn-server.internal", ttl)
	if err != nil {
		return nil, fmt.Errorf("issue server certificate: %w", err)
	}
	return buildBundle(caBytes, bundle)
}

// FetchClientBundle выпускает клиентский сертификат; CN строится из CLIENT_NAME для идентификации в сессии.
func FetchClientBundle(ctx context.Context, vc *vault_client.Client, clientName string) (*PKIBundle, error) {
	caBytes, err := vc.GetCA(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch CA cert: %w", err)
	}
	ttl, err := clampTTLToCA(caBytes, issueTTL())
	if err != nil {
		return nil, err
	}
	cn := fmt.Sprintf("%s.vpn.internal", clientName)
	bundle, err := vc.IssueCertificate(ctx, clientRole, cn, ttl)
	if err != nil {
		return nil, fmt.Errorf("issue client certificate for %s: %w", clientName, err)
	}
	return buildBundle(caBytes, bundle)
}

// buildBundle подмешивает цепочку из ответа Vault к leaf-сертификату (CA уже прочитан).
func buildBundle(caBytes []byte, vb *vault_client.CertBundle) (*PKIBundle, error) {
	// Если Vault вернул промежуточные сертификаты — включаем их в PEM вместе с leaf для корректной верификации.
	certPEM := vb.CertificatePEM
	if len(vb.CAChainPEM) > 0 {
		certPEM = vb.CertificatePEM + "\n" + strings.Join(vb.CAChainPEM, "\n")
	}

	return &PKIBundle{
		CertPEM:   []byte(certPEM),
		KeyPEM:    []byte(vb.PrivateKeyPEM),
		CACertPEM: caBytes,
	}, nil
}
