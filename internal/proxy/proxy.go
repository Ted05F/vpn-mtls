// Package proxy выполняет исходящие соединения от имени VPN-клиентов:
// TCP-потоки и UDP поверх TCP (sing UoT v2), с политикой запрета доступа
// к внутренним сетям сервера (Vault, Redis, Docker-сеть, localhost).
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yourorg/vpn-mtls/internal/anytls"
)

// UoTMagicAddress — «адрес», по которому sing-box клиент запрашивает UDP-over-TCP v2.
const UoTMagicAddress = "sp.v2.udp-over-tcp.arpa"

// ErrForbidden — назначение запрещено политикой исходящего трафика.
var ErrForbidden = errors.New("destination forbidden by egress policy")

// Policy — правила исходящего трафика.
type Policy struct {
	// AllowPrivate разрешает частные/служебные адреса (только для лабораторного стенда).
	AllowPrivate bool
	// DenyPorts — запрещённые порты назначения (например, 25/SMTP против спама).
	DenyPorts map[uint16]bool
}

var deniedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Check возвращает ErrForbidden, если адрес/порт запрещены.
func (p *Policy) Check(ip netip.Addr, port uint16) error {
	if p.DenyPorts[port] {
		return fmt.Errorf("%w: port %d", ErrForbidden, port)
	}
	if p.AllowPrivate {
		return nil
	}
	ip = ip.Unmap()
	for _, pfx := range deniedPrefixes {
		if pfx.Contains(ip) {
			return fmt.Errorf("%w: %s", ErrForbidden, ip)
		}
	}
	return nil
}

// Dialer устанавливает исходящие соединения. Доменные имена разрешаются
// самим сервером, и проверке подвергается уже IP-адрес — это исключает
// обход политики через DNS (DNS rebinding).
type Dialer struct {
	Policy      Policy
	Resolver    *net.Resolver
	DialTimeout time.Duration
}

func (d *Dialer) resolve(ctx context.Context, a anytls.Addr) ([]netip.Addr, error) {
	if !a.FQDN {
		ip, err := netip.ParseAddr(a.Host)
		if err != nil {
			return nil, err
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupNetIP(ctx, "ip", a.Host)
	if err != nil {
		return nil, err
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	// IPv4 первыми: на многих VPS нет рабочего IPv6.
	v4 := ips[:0:0]
	var v6 []netip.Addr
	for _, ip := range ips {
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return append(v4, v6...), nil
}

// DialTCP соединяется с первым разрешённым адресом назначения.
func (d *Dialer) DialTCP(ctx context.Context, a anytls.Addr) (net.Conn, error) {
	ips, err := d.resolve(ctx, a)
	if err != nil {
		return nil, err
	}
	nd := net.Dialer{Timeout: d.DialTimeout, KeepAlive: 30 * time.Second}
	var lastErr error = fmt.Errorf("no addresses for %s", a.Host)
	for _, ip := range ips {
		if err := d.Policy.Check(ip, a.Port); err != nil {
			lastErr = err
			continue
		}
		c, err := nd.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, a.Port).String())
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ResolveUDP возвращает первый разрешённый адрес для UDP-пакета.
func (d *Dialer) ResolveUDP(ctx context.Context, a anytls.Addr) (netip.AddrPort, error) {
	ips, err := d.resolve(ctx, a)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var lastErr error = fmt.Errorf("no addresses for %s", a.Host)
	for _, ip := range ips {
		if err := d.Policy.Check(ip, a.Port); err != nil {
			lastErr = err
			continue
		}
		return netip.AddrPortFrom(ip, a.Port), nil
	}
	return netip.AddrPort{}, lastErr
}

// Handler — обработчик потоков AnyTLS: TCP-проксирование или UoT.
type Handler struct {
	Dialer     *Dialer
	UDPTimeout time.Duration
	Log        *logrus.Entry
}

// HandleStream реализует anytls.StreamHandler.
func (h *Handler) HandleStream(ctx context.Context, st *anytls.Stream) {
	defer st.Close()
	dest, err := anytls.ReadSocksAddr(st)
	if err != nil {
		h.Log.WithError(err).Debug("read destination")
		return
	}
	if dest.FQDN && dest.Host == UoTMagicAddress {
		h.handleUoT(ctx, st)
		return
	}

	dctx, cancel := context.WithTimeout(ctx, h.Dialer.DialTimeout)
	out, err := h.Dialer.DialTCP(dctx, dest)
	cancel()
	if err != nil {
		h.Log.WithError(err).WithField("dest", dest.String()).Debug("dial failed")
		st.HandshakeFailure(err)
		return
	}
	defer out.Close()
	st.HandshakeSuccess()
	relay(ctx, st, out)
}

// relay копирует данные в обе стороны; AnyTLS не поддерживает half-close,
// поэтому завершение любого направления закрывает оба.
func relay(ctx context.Context, st *anytls.Stream, out net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, st); done <- struct{}{} }()
	go func() { _, _ = io.Copy(st, out); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = out.Close()
	_ = st.Close()
}

// handleUoT обслуживает sing UDP-over-TCP v2:
//
//	запрос:  isConnect [u8] | адрес назначения (SOCKS5)
//	пакеты (isConnect=1): length [u16be] | data
//	пакеты (isConnect=0): адрес (коды UoT) | length [u16be] | data
func (h *Handler) handleUoT(ctx context.Context, st *anytls.Stream) {
	var flag [1]byte
	if _, err := io.ReadFull(st, flag[:]); err != nil {
		return
	}
	reqDest, err := anytls.ReadSocksAddr(st)
	if err != nil {
		return
	}
	isConnect := flag[0] == 1

	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		st.HandshakeFailure(err)
		return
	}
	defer pc.Close()
	st.HandshakeSuccess()

	idle := h.UDPTimeout
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		_ = st.Close()
	}()

	var (
		cache   sync.Map // anytls.Addr -> netip.AddrPort, кэш разрешённых имён
		connDst netip.AddrPort
	)
	resolve := func(a anytls.Addr) (netip.AddrPort, error) {
		if v, ok := cache.Load(a); ok {
			return v.(netip.AddrPort), nil
		}
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		ap, err := h.Dialer.ResolveUDP(rctx, a)
		rcancel()
		if err == nil {
			cache.Store(a, ap)
		}
		return ap, err
	}
	if isConnect {
		if connDst, err = resolve(reqDest); err != nil {
			h.Log.WithError(err).Debug("uot: resolve")
			return
		}
	}

	// Ответы из интернета → клиенту.
	go func() {
		defer cancel()
		buf := make([]byte, 65535)
		out := make([]byte, 0, 65535+32)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(idle))
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			out = out[:0]
			if !isConnect {
				fromIP := from.Addr().Unmap()
				out = anytls.AppendUoTAddr(out, fromIP.AsSlice(), from.Port())
			}
			out = binary.BigEndian.AppendUint16(out, uint16(n))
			out = append(out, buf[:n]...)
			if _, err := st.Write(out); err != nil {
				return
			}
		}
	}()

	// Пакеты клиента → в интернет.
	buf := make([]byte, 65535)
	for {
		dst := connDst
		if !isConnect {
			a, err := anytls.ReadUoTAddr(st)
			if err != nil {
				return
			}
			if dst, err = resolve(a); err != nil {
				// Пакет всё равно нужно вычитать, чтобы не сбить кадрирование.
				dst = netip.AddrPort{}
			}
		}
		var l [2]byte
		if _, err := io.ReadFull(st, l[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(st, buf[:n]); err != nil {
			return
		}
		if dst.IsValid() {
			_, _ = pc.WriteToUDPAddrPort(buf[:n], dst)
		}
	}
}
