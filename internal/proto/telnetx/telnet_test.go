package telnetx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Telnet, against a peer that actually speaks it.
//
// The tests below drive a real socket with a real server on the other end
// rather than feeding byte slices to the parser, because most of what can go
// wrong here is timing and interleaving: a command split across two reads, a
// negotiation answered while the user is typing, an echo decision taken
// before the far end has said anything.

// peer is the other end of a telnet connection, under the test's control.
type peer struct {
	conn  net.Conn
	ready chan struct{}

	mu       sync.Mutex
	received []byte
	waiters  []chan struct{}
}

// startPeer listens, accepts one connection, and reads it forever.
func startPeer(t *testing.T) (*peer, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	p := &peer{ready: make(chan struct{})}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(p.ready)
			return
		}
		p.mu.Lock()
		p.conn = conn
		p.mu.Unlock()
		close(p.ready)

		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.received = append(p.received, buf[:n]...)
				for _, w := range p.waiters {
					select {
					case w <- struct{}{}:
					default:
					}
				}
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		p.mu.Lock()
		conn := p.conn
		p.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	})

	return p, listener.Addr().String()
}

// send writes raw bytes from the peer, once there is a peer to write from.
//
// Waiting on ready rather than assuming: the client dials after startPeer
// returns, so a test that sends immediately would otherwise race the accept
// and fail in a way that looks like a protocol bug.
func (p *peer) send(t *testing.T, b ...byte) {
	t.Helper()

	select {
	case <-p.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("no client ever connected")
	}

	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn == nil {
		t.Fatal("the peer has no connection")
	}
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("peer write: %v", err)
	}
}

// bytesReceived is everything the client has sent so far.
func (p *peer) bytesReceived() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.received...)
}

// waitFor blocks until the client has sent want, or the test gives up.
func (p *peer) waitFor(t *testing.T, want []byte, why string) {
	t.Helper()

	notify := make(chan struct{}, 8)
	p.mu.Lock()
	p.waiters = append(p.waiters, notify)
	p.mu.Unlock()

	deadline := time.After(5 * time.Second)
	for {
		if bytes.Contains(p.bytesReceived(), want) {
			return
		}
		select {
		case <-notify:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("%s: never received % x\ngot: % x", why, want, p.bytesReceived())
		}
	}
}

// readAll collects n bytes of application data, or fails.
//
// Read blocks, so the bound is a timeout around it rather than a deadline on
// the socket — the socket is drained by the connection's own goroutine now,
// and a deadline there would break negotiation rather than this read.
func readAll(t *testing.T, c *Conn, n int) []byte {
	t.Helper()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)

	go func() {
		out := make([]byte, 0, n)
		buf := make([]byte, n)
		for len(out) < n {
			read, err := c.Read(buf)
			out = append(out, buf[:read]...)
			if err != nil {
				ch <- result{out, err}
				return
			}
		}
		ch <- result{out, nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read: %v (got %q)", r.err, r.out)
		}
		return r.out
	case <-time.After(5 * time.Second):
		t.Fatalf("wanted %d bytes of application data, none arrived", n)
		return nil
	}
}

func dialPeer(t *testing.T, addr string, cfg Config) *Conn {
	t.Helper()
	cfg.Address = addr
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestTheOpeningOffersAreMade. A peer that never initiates — and plenty do
// not — would otherwise leave the session in line mode with no window size,
// which looks like a broken terminal rather than a protocol nobody started.
func TestTheOpeningOffersAreMade(t *testing.T) {
	p, addr := startPeer(t)
	dialPeer(t, addr, Config{})

	for _, want := range [][]byte{
		{IAC, WILL, OptSuppressGA},
		{IAC, WILL, OptTerminalType},
		{IAC, WILL, OptNAWS},
		{IAC, WILL, OptBinary},
		{IAC, DO, OptSuppressGA},
		{IAC, DO, OptEcho},
		{IAC, DO, OptBinary},
	} {
		p.waitFor(t, want, "opening negotiation")
	}
}

// TestAnAgreementIsNotAnsweredTwice is the loop RFC 1143 exists to prevent.
//
// Answering every WILL with a DO looks correct until the peer does the same:
// each agreement reads as a fresh offer to the other end, and two switches
// then exchange a hundred thousand packets a second. Old telnet stacks
// renegotiate at surprising moments, so this is not hypothetical.
func TestAnAgreementIsNotAnsweredTwice(t *testing.T) {
	p, addr := startPeer(t)
	dialPeer(t, addr, Config{})

	p.waitFor(t, []byte{IAC, DO, OptEcho}, "opening request")

	// The peer agrees, then says it again.
	p.send(t, IAC, WILL, OptEcho)
	time.Sleep(100 * time.Millisecond)
	before := bytes.Count(p.bytesReceived(), []byte{IAC, DO, OptEcho})

	p.send(t, IAC, WILL, OptEcho)
	p.send(t, IAC, WILL, OptEcho)
	time.Sleep(200 * time.Millisecond)

	after := bytes.Count(p.bytesReceived(), []byte{IAC, DO, OptEcho})
	if after != before {
		t.Errorf("re-confirming an agreed option drew %d more replies; "+
			"that is the negotiation loop", after-before)
	}
}

// TestAnUnknownOptionIsRefusedOutLoud. An option nobody implements still has
// to be answered: a peer waiting for the reply simply hangs, and the user
// sees a connection that opened and then did nothing.
func TestAnUnknownOptionIsRefusedOutLoud(t *testing.T) {
	p, addr := startPeer(t)
	dialPeer(t, addr, Config{})

	// 47 is unassigned; 34 is linemode, which this deliberately does not do.
	p.send(t, IAC, DO, 47)
	p.waitFor(t, []byte{IAC, WONT, 47}, "an option we cannot do")

	p.send(t, IAC, WILL, OptLinemode)
	p.waitFor(t, []byte{IAC, DONT, OptLinemode}, "an option we do not want")
}

// TestTheWindowSizeIsSentWhenAgreedAndFollowsAResize.
func TestTheWindowSizeIsSentWhenAgreedAndFollowsAResize(t *testing.T) {
	p, addr := startPeer(t)
	c := dialPeer(t, addr, Config{Cols: 100, Rows: 30})

	// Before agreement, a resize goes nowhere and is not an error — the
	// browser fires one on every window drag.
	if err := c.Resize(120, 40); err != nil {
		t.Fatalf("a resize before NAWS is agreed must not fail: %v", err)
	}

	p.send(t, IAC, DO, OptNAWS)

	// Agreeing sends the current size immediately: a peer that asks wants it
	// now, not at the next drag.
	p.waitFor(t, []byte{IAC, SB, OptNAWS, 0, 120, 0, 40, IAC, SE}, "the size on agreement")

	if err := c.Resize(132, 50); err != nil {
		t.Fatal(err)
	}
	p.waitFor(t, []byte{IAC, SB, OptNAWS, 0, 132, 0, 50, IAC, SE}, "the size after a resize")
}

// TestTheTerminalTypeIsReported, and is what xterm.js actually is rather than
// a vt100 claim that would lose colour on every device that checks.
func TestTheTerminalTypeIsReported(t *testing.T) {
	p, addr := startPeer(t)
	dialPeer(t, addr, Config{})

	p.send(t, IAC, DO, OptTerminalType)
	p.waitFor(t, []byte{IAC, WILL, OptTerminalType}, "agreeing to terminal-type")

	p.send(t, IAC, SB, OptTerminalType, terminalTypeSEND, IAC, SE)

	want := append([]byte{IAC, SB, OptTerminalType, terminalTypeIS},
		[]byte(DefaultTerminalType)...)
	want = append(want, IAC, SE)
	p.waitFor(t, want, "the terminal type")
}

// TestCommandsAreStrippedFromTheDataStream.
func TestCommandsAreStrippedFromTheDataStream(t *testing.T) {
	p, addr := startPeer(t)
	c := dialPeer(t, addr, Config{})

	p.send(t, 'h', 'i', IAC, WILL, OptEcho, ' ', 't', 'h', 'e', 'r', 'e')

	if got := string(readAll(t, c, 8)); got != "hi there" {
		t.Errorf("read %q, want the data with the command removed", got)
	}
}

// TestACommandSplitAcrossReadsIsStillACommand is the whole reason the parser
// keeps state between calls. Sockets split wherever they like, and treating
// the halves independently would print the option byte on somebody's screen.
func TestACommandSplitAcrossReadsIsStillACommand(t *testing.T) {
	p, addr := startPeer(t)
	c := dialPeer(t, addr, Config{})

	p.send(t, 'a', IAC)
	time.Sleep(50 * time.Millisecond)
	p.send(t, WILL)
	time.Sleep(50 * time.Millisecond)
	p.send(t, OptEcho, 'b')

	if got := string(readAll(t, c, 2)); got != "ab" {
		t.Errorf("read %q, want \"ab\" — the split command leaked into the data", got)
	}
	p.waitFor(t, []byte{IAC, DO, OptEcho}, "the reassembled command was acted on")
}

// TestADoubledIACIsOneLiteralByte, in both directions.
//
// 0xFF appears in plenty of UTF-8 sequences and in any binary paste. Getting
// this wrong corrupts exactly the data a person is least able to spot.
func TestADoubledIACIsOneLiteralByte(t *testing.T) {
	p, addr := startPeer(t)
	c := dialPeer(t, addr, Config{Echo: EchoRemote})

	p.send(t, 'a', IAC, IAC, 'b')
	got := readAll(t, c, 3)
	if !bytes.Equal(got, []byte{'a', IAC, 'b'}) {
		t.Errorf("read % x, want the doubled IAC collapsed to one byte", got)
	}

	if _, err := c.Write([]byte{'x', IAC, 'y'}); err != nil {
		t.Fatal(err)
	}
	p.waitFor(t, []byte{'x', IAC, IAC, 'y'}, "a literal 255 must be doubled on the way out")
}

// TestEchoFollowsNegotiation covers the decision that decides whether a
// session is usable at all, and whether a password appears on screen.
func TestEchoFollowsNegotiation(t *testing.T) {
	t.Run("the far end echoes by default", func(t *testing.T) {
		p, addr := startPeer(t)
		c := dialPeer(t, addr, Config{})

		// Nothing has been negotiated. Auto assumes the far end echoes, which
		// is what every interactive device does; assuming the opposite would
		// double every character on the common path.
		if _, err := c.Write([]byte("secret")); err != nil {
			t.Fatal(err)
		}
		p.waitFor(t, []byte("secret"), "the keystrokes reached the peer")

		p.send(t, 'X')
		if got := readAll(t, c, 1); string(got) != "X" {
			t.Fatalf("read %q", got)
		}
		// If it had echoed locally, "secret" would be sitting in front of the
		// X. Reading exactly the peer's byte is the assertion.
	})

	t.Run("a peer that declines echo gets local echo", func(t *testing.T) {
		p, addr := startPeer(t)
		c := dialPeer(t, addr, Config{})

		p.waitFor(t, []byte{IAC, DO, OptEcho}, "the request")
		p.send(t, IAC, WONT, OptEcho)
		time.Sleep(100 * time.Millisecond)

		if _, err := c.Write([]byte("ls\r")); err != nil {
			t.Fatal(err)
		}
		if got := string(readAll(t, c, 3)); got != "ls\r" {
			t.Errorf("read %q, want the keystrokes echoed locally — a peer "+
				"that will not echo leaves the user typing blind otherwise", got)
		}
	})

	t.Run("a password prompt suppresses local echo", func(t *testing.T) {
		p, addr := startPeer(t)
		c := dialPeer(t, addr, Config{})

		// Line mode: the peer declines echo, so this end echoes.
		p.send(t, IAC, WONT, OptEcho)
		time.Sleep(100 * time.Millisecond)

		// Then it takes echo back for the password prompt, which is exactly
		// how telnet hides a password and why following negotiation is not
		// optional.
		p.send(t, IAC, WILL, OptEcho)
		time.Sleep(100 * time.Millisecond)

		if _, err := c.Write([]byte("hunter2")); err != nil {
			t.Fatal(err)
		}
		p.waitFor(t, []byte("hunter2"), "the password reached the peer")

		p.send(t, '#')
		if got := readAll(t, c, 1); string(got) != "#" {
			t.Fatalf("read %q — the password was echoed to the screen", got)
		}
	})
}

// TestClosingEndsWaitAndReads.
func TestClosingEndsWaitAndReads(t *testing.T) {
	_, addr := startPeer(t)
	c := dialPeer(t, addr, Config{})

	done := make(chan error, 1)
	go func() { done <- c.Wait() }()

	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a deliberate close is not a failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Close")
	}

	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Error("reading a closed connection should fail")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Logf("read after close: %v", err)
	}
}

// TestTheSummaryNamesWhatWasAgreed. "Which options are in force" is the first
// question when a telnet session draws badly, and otherwise invisible.
func TestTheSummaryNamesWhatWasAgreed(t *testing.T) {
	p, addr := startPeer(t)
	c := dialPeer(t, addr, Config{})

	p.send(t, IAC, WILL, OptEcho)
	p.send(t, IAC, WILL, OptSuppressGA)
	p.send(t, IAC, DO, OptNAWS)
	time.Sleep(150 * time.Millisecond)

	summary := c.Summary()
	for _, want := range []string{"echo", "suppress-go-ahead", "naws"} {
		if !bytes.Contains([]byte(summary), []byte(want)) {
			t.Errorf("summary %q does not mention %q", summary, want)
		}
	}
}
