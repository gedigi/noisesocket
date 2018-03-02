package noisesocket

import (
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *ConnectionConfig
}

// Accept waits for and returns the next incoming connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:   c,
		config: *l.config,
	}, nil
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
func Listen(laddr string, config *ConnectionConfig) (net.Listener, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		Listener: l,
		config:   config,
	}, nil
}

func Dial(addr string, localaddr string, config *ConnectionConfig) (*Conn, error) {
	dialer := new(net.Dialer)

	localAddrArray := strings.Split(localaddr, ":")
	if len(localAddrArray) != 2 {
		return nil, errors.New("invalid source address")
	}
	localPort, err := strconv.Atoi(localAddrArray[1])
	if err != nil {
		return nil, errors.New("invalid source port")
	}
	localAddress := net.ParseIP(localAddrArray[0])

	dialer.LocalAddr = &net.TCPAddr{
		IP:   localAddress,
		Port: localPort,
	}

	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	config.IsClient = true
	return &Conn{
		conn:   rawConn,
		config: *config,
	}, nil
}
