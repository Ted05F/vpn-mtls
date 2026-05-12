// internal/tunnel/server.go — TUN interface server-side management
package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// TunServer manages the server-side TUN interface and IP address pool.
type TunServer struct {
	iface      *water.Interface
	subnet     *net.IPNet
	subnetCIDR string // исходная строка CIDR (для передачи клиенту и маршрутов)
	gateway    net.IP
	pool       *IPPool
	mu         sync.RWMutex
	clients    map[string]net.IP // clientID → assigned IP
}

// NewServer creates a TUN interface and sets up the IP pool.
func NewServer(subnetCIDR, gatewayIP string) (*TunServer, error) {
	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse subnet %s: %w", subnetCIDR, err)
	}
	gw := net.ParseIP(gatewayIP).To4()
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", gatewayIP)
	}

	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = "tun-vpn"
	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create TUN interface: %w", err)
	}

	// Шлюзу нужен полный CIDR для `ip addr add`, иначе маска может быть неочевидна.
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		iface.Close()
		return nil, fmt.Errorf("only IPv4 /32-based subnets are supported, got /%d", bits)
	}
	gwCIDR := fmt.Sprintf("%s/%d", gatewayIP, ones)

	// Назначаем IP шлюза на TUN и поднимаем интерфейс (Linux: ip addr / ip route).
	if err := configureInterface(iface.Name(), gwCIDR, subnetCIDR); err != nil {
		iface.Close()
		return nil, err
	}

	pool := newIPPool(subnet, gw)

	logrus.WithFields(logrus.Fields{
		"iface":   iface.Name(),
		"subnet":  subnetCIDR,
		"gateway": gatewayIP,
	}).Info("TUN server interface ready")

	return &TunServer{
		iface:      iface,
		subnet:     subnet,
		subnetCIDR: subnetCIDR,
		gateway:    gw,
		pool:       pool,
		clients:    make(map[string]net.IP),
	}, nil
}

// SubnetCIDR возвращает подсеть VPN в виде строки (как в NewServer), для клиентского маршрута.
func (s *TunServer) SubnetCIDR() string {
	return s.subnetCIDR
}

// AssignIP allocates an IP from the pool for the given client.
func (s *TunServer) AssignIP(clientID string) (net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ip, exists := s.clients[clientID]; exists {
		return ip, nil
	}
	ip, err := s.pool.Allocate()
	if err != nil {
		return nil, err
	}
	s.clients[clientID] = ip
	logrus.WithFields(logrus.Fields{
		"client_id": clientID,
		"ip":        ip,
	}).Debug("IP assigned")
	return ip, nil
}

// ReleaseIP returns the client's IP to the pool.
func (s *TunServer) ReleaseIP(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip, ok := s.clients[clientID]; ok {
		s.pool.Release(ip)
		delete(s.clients, clientID)
		logrus.WithField("client_id", clientID).Debug("IP released")
	}
}

// Bridge copies packets bidirectionally between the TLS conn and the TUN iface.
func (s *TunServer) Bridge(ctx context.Context, conn io.ReadWriter, clientIP net.IP) {
	var (
		bytesIn  int64
		bytesOut int64
	)

	done := make(chan struct{})

	// TUN → TLS (outbound to client)
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := s.iface.Read(buf)
			if err != nil {
				if ctx.Err() == nil {
					logrus.WithError(err).Debug("TUN read error")
				}
				return
			}
			// Route only packets destined for this client's IP
			if n < 20 || !packetDestinedFor(buf[:n], clientIP) {
				continue
			}
			if err := WriteFramed(conn, buf[:n]); err != nil {
				return
			}
			atomic.AddInt64(&bytesOut, int64(n))
		}
	}()

	// TLS → TUN (inbound from client)
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			goto done
		case <-done:
			goto done
		default:
		}
		packet, err := ReadFramed(conn, buf)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				logrus.WithError(err).Debug("conn read error")
			}
			goto done
		}
		if _, err := s.iface.Write(packet); err != nil {
			logrus.WithError(err).Debug("TUN write error")
			goto done
		}
		atomic.AddInt64(&bytesIn, int64(len(packet)))
	}
done:
	logrus.WithFields(logrus.Fields{
		"client_ip": clientIP,
		"bytes_in":  atomic.LoadInt64(&bytesIn),
		"bytes_out": atomic.LoadInt64(&bytesOut),
	}).Info("bridge session ended")
}

// Close shuts down the TUN interface.
func (s *TunServer) Close() error {
	return s.iface.Close()
}

// ── Framing helpers ──────────────────────────────────────────────────────────
// We use a simple 4-byte big-endian length prefix so multiple IP packets
// can be multiplexed over a single TCP (TLS) stream.

// WriteFramed записывает 4-байтовый big-endian размер и полезную нагрузку (один логический кадр поверх TLS).
func WriteFramed(w io.Writer, data []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFramed читает один кадр в buf (ёмкость должна быть ≥ длины полезной нагрузки).
func ReadFramed(r io.Reader, buf []byte) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr)
	if n > uint32(len(buf)) {
		return nil, fmt.Errorf("packet too large: %d bytes", n)
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// packetDestinedFor returns true if the IPv4 packet's destination matches ip.
func packetDestinedFor(packet []byte, ip net.IP) bool {
	if len(packet) < 20 {
		return false
	}
	dst := net.IP(packet[16:20])
	return dst.Equal(ip)
}

// ── IP Pool ──────────────────────────────────────────────────────────────────

// IPPool manages a pool of host IPs within a subnet.
type IPPool struct {
	mu        sync.Mutex
	available []net.IP
	inUse     map[string]bool
}

func newIPPool(subnet *net.IPNet, gateway net.IP) *IPPool {
	var available []net.IP
	for ip := cloneIP(subnet.IP.Mask(subnet.Mask)); subnet.Contains(ip); incrementIP(ip) {
		if ip.Equal(subnet.IP) || ip.Equal(gateway) || isBroadcast(ip, subnet) {
			continue
		}
		available = append(available, cloneIP(ip))
	}
	return &IPPool{available: available, inUse: make(map[string]bool)}
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ip := range p.available {
		key := ip.String()
		if !p.inUse[key] {
			p.inUse[key] = true
			return ip, nil
		}
	}
	return nil, fmt.Errorf("IP pool exhausted")
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.inUse, ip.String())
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, subnet *net.IPNet) bool {
	broadcast := make(net.IP, len(subnet.IP))
	for i := range subnet.IP {
		broadcast[i] = subnet.IP[i] | ^subnet.Mask[i]
	}
	return ip.Equal(broadcast)
}
