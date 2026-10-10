// Package anytls — собственная (серверная) реализация протокола AnyTLS,
// совместимая с клиентами на базе sing-box (Karing, sing-box CLI).
//
// Спецификация: https://github.com/anytls/anytls-go/blob/main/docs/protocol.md
//
// Поверх установленного TLS-соединения клиент отправляет:
//
//	sha256(password) [32] | padding0 length [u16be] | padding0
//
// после чего обе стороны работают с кадрами сессионного уровня:
//
//	command [u8] | streamId [u32be] | data length [u16be] | data
//
// Реализация написана с нуля (без sing-anytls, лицензия GPL-3.0), чтобы
// проект оставался под MIT.
package anytls

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Команды сессионного уровня.
const (
	cmdWaste               = 0  // заполнитель (padding), данные отбрасываются
	cmdSYN                 = 1  // клиент открывает поток
	cmdPSH                 = 2  // данные потока
	cmdFIN                 = 3  // закрытие потока
	cmdSettings            = 4  // настройки клиента
	cmdAlert               = 5  // текст ошибки от сервера, после него сессия закрывается
	cmdUpdatePaddingScheme = 6  // сервер присылает клиенту свою схему padding
	cmdSYNACK              = 7  // v2: результат открытия исходящего соединения
	cmdHeartRequest        = 8  // v2: keepalive
	cmdHeartResponse       = 9  // v2: keepalive
	cmdServerSettings      = 10 // v2: настройки сервера
)

const (
	headerSize   = 1 + 4 + 2
	maxFrameData = 0xFFFF
	// ProtocolVersion — версия протокола, которую реализует сервер.
	ProtocolVersion = 2
)

type header [headerSize]byte

func (h header) cmd() byte       { return h[0] }
func (h header) streamID() uint32 { return binary.BigEndian.Uint32(h[1:5]) }
func (h header) length() int      { return int(binary.BigEndian.Uint16(h[5:7])) }

// appendFrame дописывает в dst кадр (cmd, sid, data). len(data) <= maxFrameData.
func appendFrame(dst []byte, cmd byte, sid uint32, data []byte) []byte {
	var h header
	h[0] = cmd
	binary.BigEndian.PutUint32(h[1:5], sid)
	binary.BigEndian.PutUint16(h[5:7], uint16(len(data)))
	dst = append(dst, h[:]...)
	return append(dst, data...)
}

// ── key=value\n — формат cmdSettings / cmdServerSettings / padding scheme ──

func parseStringMap(b []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func encodeStringMap(kv ...string) []byte {
	var b bytes.Buffer
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(kv[i])
		b.WriteByte('=')
		b.WriteString(kv[i+1])
	}
	return b.Bytes()
}

// ── Padding scheme ──────────────────────────────────────────────────────────

// DefaultPaddingScheme — схема по умолчанию из спецификации; клиенты sing-box
// используют её для первой сессии, пока сервер не пришлёт свою.
var DefaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

// PaddingScheme — схема разбиения/дополнения первых пакетов клиента.
// Сервер сам padding не генерирует: он лишь раздаёт схему клиентам
// (cmdUpdatePaddingScheme), если её md5 отличается от присланного клиентом.
type PaddingScheme struct {
	Raw []byte
	MD5 string
}

// ParsePaddingScheme проверяет формат схемы так же строго, как это делает
// клиент: обязателен ключ stop, все диапазоны — "min-max" или "c".
func ParsePaddingScheme(raw []byte) (*PaddingScheme, error) {
	raw = bytes.TrimSpace(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	m := parseStringMap(raw)
	stop, err := strconv.Atoi(m["stop"])
	if err != nil || stop < 0 {
		return nil, errors.New("padding scheme: missing or invalid 'stop'")
	}
	for k, v := range m {
		if k == "stop" {
			continue
		}
		if _, err := strconv.Atoi(k); err != nil {
			return nil, fmt.Errorf("padding scheme: bad key %q", k)
		}
		for _, r := range strings.Split(v, ",") {
			if r == "c" {
				continue
			}
			lo, hi, ok := strings.Cut(r, "-")
			a, err1 := strconv.Atoi(lo)
			b, err2 := strconv.Atoi(hi)
			if !ok || err1 != nil || err2 != nil || a <= 0 || b <= 0 {
				return nil, fmt.Errorf("padding scheme: bad range %q in %q", r, k)
			}
		}
	}
	return &PaddingScheme{Raw: raw, MD5: fmt.Sprintf("%x", md5.Sum(raw))}, nil
}

// ── Адреса ──────────────────────────────────────────────────────────────────

// Addr — адрес назначения: IP или доменное имя плюс порт.
type Addr struct {
	Host string // IP-адрес в текстовом виде или FQDN
	Port uint16
	FQDN bool
}

func (a Addr) String() string {
	if strings.Contains(a.Host, ":") {
		return "[" + a.Host + "]:" + strconv.Itoa(int(a.Port))
	}
	return a.Host + ":" + strconv.Itoa(int(a.Port))
}

// Коды типа адреса. SOCKS5 (RFC 1928) используется для адреса назначения
// потока и для заголовка UDP-over-TCP; в пакетах UoT — собственные коды sing.
var (
	socksFamilies = [3]byte{0x01, 0x04, 0x03} // IPv4, IPv6, FQDN
	uotFamilies   = [3]byte{0x00, 0x01, 0x02}
)

// ReadSocksAddr читает адрес в формате SOCKS5 (ATYP, ADDR, PORT).
func ReadSocksAddr(r io.Reader) (Addr, error) { return readAddr(r, socksFamilies) }

// ReadUoTAddr читает адрес в формате пакетов sing UDP-over-TCP.
func ReadUoTAddr(r io.Reader) (Addr, error) { return readAddr(r, uotFamilies) }

// AppendUoTAddr сериализует IP-адрес с портом в формате пакетов UoT.
func AppendUoTAddr(dst []byte, ip []byte, port uint16) []byte {
	if len(ip) == 4 {
		dst = append(dst, uotFamilies[0])
	} else {
		dst = append(dst, uotFamilies[1])
	}
	dst = append(dst, ip...)
	return binary.BigEndian.AppendUint16(dst, port)
}

func readAddr(r io.Reader, fam [3]byte) (Addr, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Addr{}, err
	}
	var a Addr
	switch t[0] {
	case fam[0], fam[1]:
		n := 4
		if t[0] == fam[1] {
			n = 16
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return Addr{}, err
		}
		a.Host = ipString(ip)
	case fam[2]:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return Addr{}, err
		}
		a.Host, a.FQDN = string(name), true
	default:
		return Addr{}, fmt.Errorf("unknown address type 0x%02x", t[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Addr{}, err
	}
	a.Port = binary.BigEndian.Uint16(p[:])
	return a, nil
}

func ipString(b []byte) string {
	ip, _ := netip.AddrFromSlice(b)
	return ip.Unmap().String()
}
