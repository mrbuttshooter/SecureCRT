//go:build tools

// Command testtelnetd is a telnet device for the browser suite.
//
// Small on purpose: it negotiates the way a switch does — taking echo and
// suppress-go-ahead, asking for the window size — demands a login, and then
// answers a couple of commands. Enough for the browser tests to prove that a
// telnet terminal opens, that the stored credential is typed at the prompt
// without appearing on screen, and that what comes back is drawn.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// Telnet protocol bytes, named as RFC 854 names them.
const (
	iac  byte = 255
	dont byte = 254
	do   byte = 253
	wont byte = 252
	will byte = 251
	sb   byte = 250
	se   byte = 240

	optEcho       byte = 1
	optSuppressGA byte = 3
	optNAWS       byte = 31
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	user := flag.String("user", "tester", "the only username accepted")
	password := flag.String("password", "", "the only password accepted")
	portFile := flag.String("port-file", "", "write the chosen port here once listening")
	flag.Parse()

	if *password == "" {
		log.Fatal("testtelnetd: -password is required")
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("testtelnetd: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	if *portFile != "" {
		if err := os.WriteFile(*portFile, []byte(fmt.Sprintf("%d\n", port)), 0o600); err != nil {
			log.Fatalf("testtelnetd: %v", err)
		}
	}
	log.Printf("testtelnetd: listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("testtelnetd: %v", err)
		}
		go serve(conn, *user, *password)
	}
}

func serve(conn net.Conn, user, password string) {
	defer func() { _ = conn.Close() }()

	// What a switch does: take echo and suppress-go-ahead, which is also what
	// keeps a password off the screen, and ask for the window size.
	send(conn, iac, will, optEcho, iac, will, optSuppressGA, iac, do, optNAWS)
	say(conn, "\r\nUser Access Verification\r\n\r\nUsername: ")

	if readLine(conn) != user {
		say(conn, "\r\n% Access denied\r\n")
		return
	}
	say(conn, "\r\nPassword: ")
	if readLine(conn) != password {
		say(conn, "\r\n% Access denied\r\n")
		return
	}

	say(conn, "\r\ntestsw>")

	for {
		line := readLine(conn)
		switch {
		case line == "":
		case strings.HasPrefix(line, "exit"), strings.HasPrefix(line, "quit"):
			return
		case strings.HasPrefix(line, "show ver"):
			say(conn, "\r\ntestsw software, version 1.0\r\n")
		case strings.HasPrefix(line, "echo "):
			say(conn, "\r\n"+strings.TrimPrefix(line, "echo ")+"\r\n")
		default:
			say(conn, "\r\n% Unknown command\r\n")
		}
		say(conn, "\r\ntestsw>")
	}
}

func send(conn net.Conn, b ...byte)  { _, _ = conn.Write(b) }
func say(conn net.Conn, text string) { _, _ = conn.Write([]byte(text)) }

// readLine reads one line of input, taking the commands out of it.
//
// A byte at a time, which is fine at these volumes and avoids a buffering
// layer this does not need. Subnegotiations — the window size arrives as one
// — are skipped to their terminator rather than parsed.
func readLine(conn net.Conn) string {
	var out []byte
	buf := make([]byte, 1)

	for {
		if _, err := conn.Read(buf); err != nil {
			return string(out)
		}

		switch buf[0] {
		case iac:
			if _, err := conn.Read(buf); err != nil {
				return string(out)
			}
			switch buf[0] {
			case will, wont, do, dont:
				// One option byte follows, and is ignored. Answering nothing
				// is what plenty of real equipment does.
				_, _ = conn.Read(buf)
			case sb:
				skipSubnegotiation(conn)
			}
		case '\r', '\n':
			if len(out) > 0 {
				return string(out)
			}
		default:
			out = append(out, buf[0])
		}
	}
}

func skipSubnegotiation(conn net.Conn) {
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if buf[0] != iac {
			continue
		}
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if buf[0] == se {
			return
		}
	}
}
