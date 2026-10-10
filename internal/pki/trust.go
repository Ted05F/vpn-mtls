package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Trust проверяет клиентские сертификаты: цепочка до корневого CA,
// EKU clientAuth, срок действия, отсутствие в списке отзыва.
//
// Проверка выполняется уже после TLS-рукопожатия (сервер запрашивает
// сертификат в режиме RequestClientCert). Так клиент с невалидным
// сертификатом получает сайт-заглушку, а не TLS alert, по которому
// сервер можно было бы опознать при активном зондировании.
type Trust struct {
	mu            sync.RWMutex
	roots         *x509.CertPool
	intermediates *x509.CertPool
	issuers       []*x509.Certificate // промежуточные CA — ими подписан CRL
	revoked       map[string]time.Time
	crlNext       time.Time
}

// NewTrustFromPEM строит хранилище доверия из цепочки [промежуточный, ..., корневой].
// Самоподписанные сертификаты считаются корневыми, остальные — промежуточными.
func NewTrustFromPEM(chain []string) (*Trust, error) {
	t := &Trust{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
		revoked:       map[string]time.Time{},
	}
	var nRoots int
	for _, c := range ParseCertsPEM(strings.Join(chain, "\n")) {
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			t.roots.AddCert(c)
			nRoots++
		} else {
			t.intermediates.AddCert(c)
			t.issuers = append(t.issuers, c)
		}
	}
	if nRoots == 0 {
		return nil, errors.New("CA chain has no self-signed root certificate")
	}
	return t, nil
}

// ParseCertsPEM разбирает все блоки CERTIFICATE из PEM-текста.
func ParseCertsPEM(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// VerifyClient проверяет цепочку, предъявленную клиентом в TLS (leaf первым).
func (t *Trust) VerifyClient(peer []*x509.Certificate) (*x509.Certificate, error) {
	if len(peer) == 0 {
		return nil, errors.New("no client certificate")
	}
	leaf := peer[0]
	t.mu.RLock()
	defer t.mu.RUnlock()

	inter := t.intermediates.Clone()
	for _, c := range peer[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         t.roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, fmt.Errorf("chain verification: %w", err)
	}
	if at, ok := t.revoked[SerialKeyOf(leaf.SerialNumber)]; ok {
		return nil, fmt.Errorf("certificate %s revoked at %s", SerialKeyOf(leaf.SerialNumber), at.UTC().Format(time.RFC3339))
	}
	return leaf, nil
}

// MarkRevoked немедленно добавляет серийный номер в локальный список отзыва,
// не дожидаясь очередной загрузки CRL.
func (t *Trust) MarkRevoked(serial string) {
	t.mu.Lock()
	t.revoked[SerialKey(serial)] = time.Now()
	t.mu.Unlock()
}

// UpdateCRL разбирает CRL (DER или PEM), проверяет подпись промежуточного CA
// и заменяет список отозванных серийных номеров. Возвращает их количество.
func (t *Trust) UpdateCRL(raw []byte) (int, error) {
	if b, _ := pem.Decode(raw); b != nil {
		raw = b.Bytes
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return 0, fmt.Errorf("parse CRL: %w", err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var sigOK bool
	for _, iss := range t.issuers {
		if crl.CheckSignatureFrom(iss) == nil {
			sigOK = true
			break
		}
	}
	if !sigOK {
		return 0, errors.New("CRL signature does not match any intermediate CA")
	}
	revoked := make(map[string]time.Time, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		revoked[SerialKeyOf(e.SerialNumber)] = e.RevocationTime
	}
	// Отзывы, сделанные локально и ещё не попавшие в CRL, не теряем.
	for k, v := range t.revoked {
		if _, ok := revoked[k]; !ok && time.Since(v) < 10*time.Minute {
			revoked[k] = v
		}
	}
	t.revoked = revoked
	t.crlNext = crl.NextUpdate
	return len(crl.RevokedCertificateEntries), nil
}

// RunCRLRefresher периодически загружает CRL из Vault.
func (t *Trust) RunCRLRefresher(ctx context.Context, v *Vault, every time.Duration, onErr func(error), onOK func(int)) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		raw, err := v.CRL(ctx)
		if err == nil {
			var n int
			if n, err = t.UpdateCRL(raw); err == nil && onOK != nil {
				onOK(n)
			}
		}
		if err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
