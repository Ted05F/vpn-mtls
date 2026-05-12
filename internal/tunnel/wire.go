package tunnel

// ClientTunnelConfig — первое сообщение сервера после успешного mTLS (один length-prefixed фрейм).
// Клиент читает его до начала обмена IP-пакетами и настраивает TUN (адрес и маршрут в VPN-подсеть).
type ClientTunnelConfig struct {
	AddressCIDR string `json:"address"` // адрес клиента на TUN, например "10.8.0.5/24"
	RouteCIDR   string `json:"route"`   // подсеть VPN для `ip route add`, например "10.8.0.0/24"
}
