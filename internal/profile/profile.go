// Package profile генерирует клиентский профиль в формате sing-box
// (импортируется в Karing и в sing-box CLI начиная с версии 1.13 —
// в ней появились поля client_certificate / client_key для mTLS).
package profile

import (
	"encoding/json"
	"strings"
)

// Params — всё, что нужно для профиля конкретного пользователя.
type Params struct {
	User        string
	Server      string // адрес сервера (домен или IP)
	ServerPort  int
	ServerName  string // SNI; пусто — совпадает с Server
	Password    string // пароль AnyTLS
	CertPEM     string // клиентский сертификат + промежуточный CA
	KeyPEM      string
	ServerCAPEM string // доверенный CA для сертификата сервера; пусто — системные корни (Let's Encrypt)
	Fingerprint string // uTLS fingerprint, по умолчанию chrome
	DNS         string // DoH-резолвер внутри туннеля, по умолчанию 1.1.1.1
}

// Build возвращает полный конфиг sing-box: TUN-интерфейс, весь трафик через
// AnyTLS-over-mTLS, частные сети — напрямую, DNS — через туннель (DoH).
func Build(p Params) ([]byte, error) {
	if p.ServerName == "" {
		p.ServerName = p.Server
	}
	if p.Fingerprint == "" {
		p.Fingerprint = "chrome"
	}
	if p.DNS == "" {
		p.DNS = "1.1.1.1"
	}

	tlsOpts := obj{
		"enabled":            true,
		"server_name":        p.ServerName,
		"min_version":        "1.3",
		"alpn":               []string{"h2", "http/1.1"},
		"utls":               obj{"enabled": true, "fingerprint": p.Fingerprint},
		"client_certificate": pemLines(p.CertPEM),
		"client_key":         pemLines(p.KeyPEM),
	}
	if p.ServerCAPEM != "" {
		tlsOpts["certificate"] = pemLines(p.ServerCAPEM)
	}

	cfg := obj{
		"log": obj{"level": "info", "timestamp": true},
		"dns": obj{
			"servers": []obj{
				{"tag": "remote", "type": "https", "server": p.DNS, "detour": "proxy"},
				{"tag": "local", "type": "local"},
			},
			"final":    "remote",
			"strategy": "ipv4_only",
		},
		"inbounds": []obj{{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30"},
			"auto_route":   true,
			"strict_route": true,
			"stack":        "mixed",
		}},
		"outbounds": []obj{
			{
				"type":                        "anytls",
				"tag":                         "proxy",
				"server":                      p.Server,
				"server_port":                 p.ServerPort,
				"password":                    p.Password,
				"idle_session_check_interval": "30s",
				"idle_session_timeout":        "60s",
				"min_idle_session":            1,
				"tls":                         tlsOpts,
			},
			{"type": "direct", "tag": "direct"},
		},
		"route": obj{
			"rules": []obj{
				{"action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
				{"ip_is_private": true, "outbound": "direct"},
			},
			"final":                   "proxy",
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

type obj = map[string]any

// pemLines превращает PEM в массив строк — так sing-box принимает встроенные сертификаты.
func pemLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
