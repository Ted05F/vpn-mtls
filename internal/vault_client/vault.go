// Package vault_client — минимальная обёртка над Vault API: выпуск сертификатов PKI и чтение CA.
package vault_client

import (
	"context"
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

// Config holds the connection parameters for Vault.
type Config struct {
	Address   string
	Token     string
	Namespace string // Enterprise only; leave empty for OSS
}

// Client wraps the Vault API client.
type Client struct {
	api *vault.Client
	cfg *Config
}

// New creates an authenticated Vault client.
func New(cfg *Config) (*Client, error) {
	vcfg := vault.DefaultConfig()
	vcfg.Address = cfg.Address

	api, err := vault.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("vault client init: %w", err)
	}
	api.SetToken(cfg.Token)
	if cfg.Namespace != "" {
		api.SetNamespace(cfg.Namespace)
	}
	return &Client{api: api, cfg: cfg}, nil
}

// IssueCertificate requests a new certificate from Vault PKI engine.
//
// role       — the Vault PKI role name (e.g. "vpn-server", "vpn-client")
// commonName — the CN for the certificate
// ttl        — validity period (e.g. "24h", "8760h")
func (c *Client) IssueCertificate(ctx context.Context, role, commonName, ttl string) (*CertBundle, error) {
	path := fmt.Sprintf("pki/issue/%s", role)
	// Поля должны совпадать с разрешениями роли в Vault (DNS SAN / TTL и т.д.).
	secret, err := c.api.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
		"alt_names":   commonName,
		"ip_sans":     "127.0.0.1", // для локальных проверок; в проде задать реальные IP или убрать через политику роли
	})
	if err != nil {
		return nil, fmt.Errorf("vault issue cert (%s): %w", role, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault returned empty certificate data")
	}
	return parseCertBundle(secret.Data)
}

// GetCA fetches the root CA certificate from the PKI engine.
func (c *Client) GetCA(ctx context.Context) ([]byte, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, "pki/cert/ca")
	if err != nil {
		return nil, fmt.Errorf("vault read CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault returned empty CA data")
	}
	raw, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected CA certificate format")
	}
	return []byte(raw), nil
}

// WriteSecret stores a KV secret.
func (c *Client) WriteSecret(ctx context.Context, path string, data map[string]interface{}) error {
	_, err := c.api.Logical().WriteWithContext(ctx, path, data)
	return err
}

// ReadSecret fetches a KV secret.
func (c *Client) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found at %s", path)
	}
	return secret.Data, nil
}

// RevokeCertificate revokes a certificate by serial number.
func (c *Client) RevokeCertificate(ctx context.Context, serialNumber string) error {
	_, err := c.api.Logical().WriteWithContext(ctx, "pki/revoke", map[string]interface{}{
		"serial_number": serialNumber,
	})
	return err
}

// CertBundle holds the PEM-encoded PKI material returned by Vault.
type CertBundle struct {
	CertificatePEM   string
	PrivateKeyPEM    string
	IssuingCACertPEM string
	CAChainPEM       []string
	SerialNumber     string
	Expiration       int64
}

func parseCertBundle(data map[string]interface{}) (*CertBundle, error) {
	bundle := &CertBundle{}

	if v, ok := data["certificate"].(string); ok {
		bundle.CertificatePEM = v
	} else {
		return nil, fmt.Errorf("missing certificate in vault response")
	}
	if v, ok := data["private_key"].(string); ok {
		bundle.PrivateKeyPEM = v
	} else {
		return nil, fmt.Errorf("missing private_key in vault response")
	}
	if v, ok := data["issuing_ca"].(string); ok {
		bundle.IssuingCACertPEM = v
	}
	if v, ok := data["serial_number"].(string); ok {
		bundle.SerialNumber = v
	}
	if v, ok := data["expiration"].(float64); ok {
		bundle.Expiration = int64(v)
	}
	if chain, ok := data["ca_chain"].([]interface{}); ok {
		for _, c := range chain {
			if s, ok := c.(string); ok {
				bundle.CAChainPEM = append(bundle.CAChainPEM, s)
			}
		}
	}
	return bundle, nil
}
