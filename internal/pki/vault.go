// Package pki — работа с HashiCorp Vault (выпуск и отзыв сертификатов, CRL,
// KV-хранилище) и проверка клиентских сертификатов на стороне VPN-сервера.
package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

const (
	pkiMount   = "pki"
	kvMount    = "secret"
	clientRole = "vpn-client"
	serverRole = "vpn-server"

	// ClientDomain — суффикс CN клиентских сертификатов: <имя>.vpn.internal.
	ClientDomain = "vpn.internal"
)

// Vault — тонкая обёртка над Vault API для нужд VPN-сервера.
type Vault struct {
	api *vault.Client
}

// NewVault подключается к Vault. Токен берётся из token, либо из файла tokenFile
// (его создаёт init-контейнер с политикой vpn-server, не root).
func NewVault(addr, token, tokenFile string) (*Vault, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = addr
	cfg.Timeout = 15 * time.Second
	api, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	if token == "" && tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read vault token file: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return nil, fmt.Errorf("vault token is not set (VAULT_TOKEN or VAULT_TOKEN_FILE)")
	}
	api.SetToken(token)
	return &Vault{api: api}, nil
}

// Bundle — выпущенный сертификат с ключом и цепочкой.
type Bundle struct {
	CertPEM  string
	KeyPEM   string
	ChainPEM []string // промежуточный CA (+ корневой, если Vault его вернул)
	Serial   string   // в формате Vault: "1a:2b:..."
	NotAfter time.Time
}

// IssueClient выпускает клиентский сертификат (EKU clientAuth) для пользователя.
func (v *Vault) IssueClient(ctx context.Context, user, ttl string) (*Bundle, error) {
	return v.issue(ctx, clientRole, map[string]any{
		"common_name": user + "." + ClientDomain,
		"ttl":         ttl,
	})
}

// IssueServer выпускает серверный сертификат (EKU serverAuth) — используется
// в режиме TLS_MODE=vault (лабораторный стенд без публичного домена).
func (v *Vault) IssueServer(ctx context.Context, cn string, dnsSANs, ipSANs []string, ttl string) (*Bundle, error) {
	return v.issue(ctx, serverRole, map[string]any{
		"common_name": cn,
		"alt_names":   strings.Join(dnsSANs, ","),
		"ip_sans":     strings.Join(ipSANs, ","),
		"ttl":         ttl,
	})
}

func (v *Vault) issue(ctx context.Context, role string, req map[string]any) (*Bundle, error) {
	sec, err := v.api.Logical().WriteWithContext(ctx, pkiMount+"/issue/"+role, req)
	if err != nil {
		return nil, fmt.Errorf("vault issue (%s): %w", role, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("vault issue (%s): empty response", role)
	}
	b := &Bundle{}
	b.CertPEM, _ = sec.Data["certificate"].(string)
	b.KeyPEM, _ = sec.Data["private_key"].(string)
	b.Serial, _ = sec.Data["serial_number"].(string)
	if exp, ok := sec.Data["expiration"].(json.Number); ok {
		if n, err := exp.Int64(); err == nil {
			b.NotAfter = time.Unix(n, 0)
		}
	}
	if chain, ok := sec.Data["ca_chain"].([]any); ok {
		for _, c := range chain {
			if s, ok := c.(string); ok {
				b.ChainPEM = append(b.ChainPEM, s)
			}
		}
	}
	if b.CertPEM == "" || b.KeyPEM == "" {
		return nil, fmt.Errorf("vault issue (%s): missing certificate or key", role)
	}
	return b, nil
}

// IssuerChain возвращает цепочку издателя по умолчанию: [промежуточный CA, ..., корневой CA].
func (v *Vault) IssuerChain(ctx context.Context) ([]string, error) {
	sec, err := v.api.Logical().ReadWithContext(ctx, pkiMount+"/issuer/default/json")
	if err != nil {
		return nil, fmt.Errorf("vault read issuer: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("vault read issuer: empty response")
	}
	var chain []string
	if arr, ok := sec.Data["ca_chain"].([]any); ok {
		for _, c := range arr {
			if s, ok := c.(string); ok {
				chain = append(chain, s)
			}
		}
	}
	if len(chain) == 0 {
		if s, ok := sec.Data["certificate"].(string); ok {
			chain = []string{s}
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("vault issuer has no certificate")
	}
	return chain, nil
}

// CRL возвращает текущий список отзыва (DER).
func (v *Vault) CRL(ctx context.Context) ([]byte, error) {
	resp, err := v.api.Logical().ReadRawWithContext(ctx, pkiMount+"/crl")
	if err != nil {
		return nil, fmt.Errorf("vault read CRL: %w", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Revoke немедленно отзывает сертификат по серийному номеру.
func (v *Vault) Revoke(ctx context.Context, serial string) error {
	_, err := v.api.Logical().WriteWithContext(ctx, pkiMount+"/revoke", map[string]any{
		"serial_number": serial,
	})
	if err != nil && strings.Contains(err.Error(), "already revoked") {
		return nil
	}
	return err
}

// ── KV v2 ───────────────────────────────────────────────────────────────────
// Записи хранятся как JSON-строка в поле "json", чтобы не терять типы.

// KVGet читает JSON-запись из secret/data/<path> в out. Возвращает false, если записи нет.
func (v *Vault) KVGet(ctx context.Context, path string, out any) (bool, error) {
	sec, err := v.api.Logical().ReadWithContext(ctx, kvMount+"/data/"+path)
	if err != nil {
		return false, err
	}
	if sec == nil || sec.Data == nil {
		return false, nil
	}
	data, _ := sec.Data["data"].(map[string]any)
	raw, _ := data["json"].(string)
	if raw == "" {
		return false, nil
	}
	return true, json.Unmarshal([]byte(raw), out)
}

// KVPut сохраняет значение как JSON в secret/data/<path>.
func (v *Vault) KVPut(ctx context.Context, path string, val any) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return err
	}
	_, err = v.api.Logical().WriteWithContext(ctx, kvMount+"/data/"+path, map[string]any{
		"data": map[string]any{"json": string(raw)},
	})
	return err
}

// KVList перечисляет ключи в secret/metadata/<path>.
func (v *Vault) KVList(ctx context.Context, path string) ([]string, error) {
	sec, err := v.api.Logical().ListWithContext(ctx, kvMount+"/metadata/"+path)
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, nil
	}
	var keys []string
	if arr, ok := sec.Data["keys"].([]any); ok {
		for _, k := range arr {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
		}
	}
	return keys, nil
}

// ── Серийные номера ─────────────────────────────────────────────────────────

// SerialKey приводит серийный номер к каноническому виду (hex без ведущих нулей),
// одинаковому для формата Vault ("0a:1b:...") и *big.Int из x509.
func SerialKey(s string) string {
	n, ok := new(big.Int).SetString(strings.ReplaceAll(s, ":", ""), 16)
	if !ok {
		return strings.ToLower(s)
	}
	return n.Text(16)
}

// SerialKeyOf — то же для *big.Int.
func SerialKeyOf(n *big.Int) string { return n.Text(16) }
