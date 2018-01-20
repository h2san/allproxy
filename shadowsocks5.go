package allproxy

import (
	"errors"
	"net"
	"strconv"

	"golang.org/x/net/proxy"
)

type ShadowSocks5 struct {
	user, password string
	network, addr  string
	mycipher       *Cipher
	forward        proxy.Dialer
}

func ShadowSocks5Dial(cipher *Cipher, network, addr string, auth *proxy.Auth, forward proxy.Dialer) (proxy.Dialer, error) {
	s := &ShadowSocks5{
		network:  network,
		addr:     addr,
		forward:  forward,
		mycipher: cipher,
	}
	if auth != nil {
		s.user = auth.User
		s.password = auth.Password
	}
	return s, nil
}

const socks5Version = 5
const (
	socks5AuthNone     = 0
	socks5AuthPassword = 2
)
const socks5Connect = 1
const (
	socks5IP4    = 1
	socks5Domain = 3
	socks5IP6    = 4
)

var socks5Errors = []string{
	"",
	"general failure",
	"connection forbidden",
	"network unreachable",
	"host unreachable",
	"connection refused",
	"TTL expired",
	"command not supported",
	"address type not supported",
}

// Dial connects to the address addr on the given network via the SOCKS5 proxy.
func (s *ShadowSocks5) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for SOCKS5 proxy connections of type " + network)
	}

	con, err := s.forward.Dial(s.network, s.addr)
	conn := NewConn(con, s.mycipher)
	if err != nil {
		return nil, err
	}
	if err := s.connect(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *ShadowSocks5) connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return errors.New("proxy: failed to parse port number: " + portStr)
	}
	if port < 1 || port > 0xffff {
		return errors.New("proxy: port number out of range: " + portStr)
	}

	// the size here is just an estimate
	buf := make([]byte, 0, 1+6+len(host))
	buf = buf[:0]

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, socks5IP4)
			ip = ip4
		} else {
			buf = append(buf, socks5IP6)
		}
		buf = append(buf, ip...)
	} else {
		if len(host) > 255 {
			return errors.New("proxy: destination host name too long: " + host)
		}
		buf = append(buf, socks5Domain)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))

	if _, err := conn.Write(buf); err != nil {
		return errors.New("proxy: failed to write connect request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}
	return nil
}
