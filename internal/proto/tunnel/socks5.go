package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// SOCKS5, the useful third of it.
//
// CONNECT only: no BIND, no UDP ASSOCIATE. Both of those need the proxy to
// accept inbound traffic on the client's behalf, which is a second listening
// surface for a use case — active FTP, some peer-to-peer protocols — that has
// no place in reaching network equipment.
//
// No authentication either, and that is a deliberate consequence of where the
// listener sits rather than an omission: it binds the address in
// tunnels.bind, which defaults to loopback, and whoever can reach it is
// already on this machine. Adding a username and password here would suggest
// the port is safe to expose, which it is not.
//
// Domain names are passed through unresolved so the *far* side resolves them.
// That is the entire point of a SOCKS tunnel into another network: names
// there often do not resolve here, and resolving them locally would silently
// reach the wrong host or nothing at all.

const (
	socksVersion5 = 0x05
	socksNoAuth   = 0x00
	socksConnect  = 0x01

	socksAddrIPv4   = 0x01
	socksAddrDomain = 0x03
	socksAddrIPv6   = 0x04

	socksReplyOK              = 0x00
	socksReplyGeneralFailure  = 0x01
	socksReplyCommandNotBuilt = 0x07
)

// socksHandshake reads a SOCKS5 greeting and CONNECT request, returning where
// the client wants to go.
func socksHandshake(conn net.Conn) (host string, port int, err error) {
	// The handshake gets a deadline of its own; the forwarding that follows
	// must not inherit one, because an idle SSH session is normal.
	if err := conn.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return "", 0, fmt.Errorf("socks: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	// Greeting: version, how many methods, then the methods.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, fmt.Errorf("socks: reading the greeting: %w", err)
	}
	if header[0] != socksVersion5 {
		return "", 0, fmt.Errorf("socks: version %d is not supported", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, fmt.Errorf("socks: reading the methods: %w", err)
	}

	offered := false
	for _, method := range methods {
		if method == socksNoAuth {
			offered = true
			break
		}
	}
	if !offered {
		// 0xFF means "none acceptable", which is the honest answer: this
		// listener has no credential to check against.
		_, _ = conn.Write([]byte{socksVersion5, 0xFF})
		return "", 0, errors.New("socks: the client offered no method this proxy accepts")
	}
	if _, err := conn.Write([]byte{socksVersion5, socksNoAuth}); err != nil {
		return "", 0, fmt.Errorf("socks: %w", err)
	}

	// Request: version, command, reserved, address type.
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return "", 0, fmt.Errorf("socks: reading the request: %w", err)
	}
	if request[0] != socksVersion5 {
		return "", 0, fmt.Errorf("socks: version %d is not supported", request[0])
	}
	if request[1] != socksConnect {
		_ = socksReply(conn, socksReplyCommandNotBuilt)
		return "", 0, fmt.Errorf("socks: command %d is not supported; CONNECT only", request[1])
	}

	switch request[3] {
	case socksAddrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, fmt.Errorf("socks: reading the address: %w", err)
		}
		host = net.IP(addr).String()

	case socksAddrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, fmt.Errorf("socks: reading the address: %w", err)
		}
		host = net.IP(addr).String()

	case socksAddrDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", 0, fmt.Errorf("socks: reading the name length: %w", err)
		}
		if length[0] == 0 {
			return "", 0, errors.New("socks: an empty destination name")
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", 0, fmt.Errorf("socks: reading the name: %w", err)
		}
		host = string(name)

	default:
		_ = socksReply(conn, socksReplyGeneralFailure)
		return "", 0, fmt.Errorf("socks: address type %d is not supported", request[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, fmt.Errorf("socks: reading the port: %w", err)
	}
	port = int(binary.BigEndian.Uint16(portBytes))
	if port == 0 {
		return "", 0, errors.New("socks: port 0 is not a destination")
	}

	return host, port, nil
}

func socksReplySuccess(conn net.Conn) error { return socksReply(conn, socksReplyOK) }
func socksReplyFailure(conn net.Conn) error { return socksReply(conn, socksReplyGeneralFailure) }

// socksReply answers a CONNECT.
//
// The bound address is reported as 0.0.0.0:0. A client is entitled to the
// address the proxy bound on its behalf, but there isn't one — the connection
// was made from the far end of an SSH channel, and inventing a plausible
// address would be worse than admitting there is none. No client in practice
// uses this field for CONNECT.
func socksReply(conn net.Conn, code byte) error {
	reply := []byte{socksVersion5, code, 0x00, socksAddrIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}
