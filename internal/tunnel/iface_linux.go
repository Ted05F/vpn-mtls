// internal/tunnel/iface_linux.go — настройка TUN только под Linux (iproute2).
//go:build linux

package tunnel

import (
	"fmt"
	"os/exec"
)

// configureInterface: `ip addr add` для адреса на интерфейсе, поднять линк, добавить маршрут к subnet через этот dev.
// ipAddr должен быть с маской (например 10.8.0.5/24), subnet — CIDR VPN для статического маршрута клиента/шлюза.
func configureInterface(name, ipAddr, subnet string) error {
	cmds := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s", ipAddr), "dev", name},
		{"ip", "link", "set", "dev", name, "up"},
		{"ip", "route", "add", subnet, "dev", name},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			// Повторный запуск: игнорируем «уже существует», чтобы перезапуск процесса не падал.
			if isAlreadyExists(string(out)) {
				continue
			}
			return fmt.Errorf("cmd %v: %w (%s)", args, err, string(out))
		}
	}
	return nil
}

func isAlreadyExists(output string) bool {
	return contains(output, "RTNETLINK answers: File exists") ||
		contains(output, "already exists")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 &&
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
