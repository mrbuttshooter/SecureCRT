package terminal

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// The terminal layer no longer knows what it is talking to.
//
// Everything valuable here — the replay buffer, reattachment, the reaper,
// the WebSocket bridge — was written against an SSH session and now runs
// against an interface. These tests drive the Manager with a shell that is
// not SSH at all, which is the only way to show the seam is real rather than
// SSH wearing a different name.

// TestAnSSHSessionIsAShell is a compile-time assertion with a sentence
// attached: the interface was extracted from this type, so it must keep
// fitting it, and a change to either that breaks the fit should fail here
// rather than at the first telnet connection.
func TestAnSSHSessionIsAShell(t *testing.T) {
	var _ Shell = (*sshx.Session)(nil)
}

// fakeShell is a two-way pipe with a size and an end.
type fakeShell struct {
	toTerminal   *io.PipeReader
	fromFarEnd   *io.PipeWriter
	fromTerminal chan []byte

	mu      sync.Mutex
	sizes   [][2]int
	closed  bool
	waitErr error
}

func newFakeShell() *fakeShell {
	r, w := io.Pipe()
	return &fakeShell{toTerminal: r, fromFarEnd: w, fromTerminal: make(chan []byte, 16)}
}

func (f *fakeShell) Read(p []byte) (int, error) { return f.toTerminal.Read(p) }

func (f *fakeShell) Write(p []byte) (int, error) {
	chunk := make([]byte, len(p))
	copy(chunk, p)
	f.fromTerminal <- chunk
	return len(p), nil
}

func (f *fakeShell) Resize(cols, rows int) error {
	f.mu.Lock()
	f.sizes = append(f.sizes, [2]int{cols, rows})
	f.mu.Unlock()
	return nil
}

func (f *fakeShell) Wait() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.waitErr
}

func (f *fakeShell) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	_ = f.toTerminal.Close()
	return nil
}

func (f *fakeShell) resizes() [][2]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]int(nil), f.sizes...)
}

func quietManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(slog.New(slog.DiscardHandler))
	t.Cleanup(m.Close)
	return m
}

// TestATerminalRunsOnAnythingThatIsAShell drives the whole terminal through a
// transport that has never heard of SSH.
func TestATerminalRunsOnAnythingThatIsAShell(t *testing.T) {
	m := quietManager(t)
	shell := newFakeShell()

	var released sync.WaitGroup
	released.Add(1)
	var releasedOnce int
	var mu sync.Mutex

	term, err := m.Open(shell, func() {
		mu.Lock()
		releasedOnce++
		mu.Unlock()
		released.Done()
	}, OpenParams{
		UserID: "u1", Label: "Old switch", Cols: 100, Rows: 30,
		Transport: Transport{
			Protocol: sessions.ProtocolTelnet,
			Host:     "10.0.0.9", Port: 23,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Output reaches the replay buffer, which is what makes a terminal
	// survive a browser going away.
	if _, err := shell.fromFarEnd.Write([]byte("Username: ")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		attached, err := term.Attach()
		if err != nil {
			t.Fatal(err)
		}
		defer term.Detach()
		return string(attached.Replay) == "Username: "
	})

	// Keystrokes reach the far end.
	if err := term.Write([]byte("netops\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-shell.fromTerminal:
		if string(got) != "netops\r" {
			t.Errorf("the far end received %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing reached the far end")
	}

	// And a resize is passed on rather than being an SSH-only trick.
	if err := term.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		sizes := shell.resizes()
		return len(sizes) > 0 && sizes[len(sizes)-1] == [2]int{120, 40}
	})

	// The transport is reported as what it is, including that it is not
	// encrypted — the thing a person needs to know about a telnet tab.
	infos := m.ListForUser("u1")
	if len(infos) != 1 {
		t.Fatalf("got %d terminals, want 1", len(infos))
	}
	if infos[0].Protocol != "telnet" {
		t.Errorf("protocol = %q", infos[0].Protocol)
	}
	if infos[0].Encrypted {
		t.Error("a telnet session must not be reported as encrypted")
	}

	// Closing closes the shell and gives back what it borrowed, once.
	if err := m.CloseTerminal("u1", term.ID); err != nil {
		t.Fatal(err)
	}
	released.Wait()

	shell.mu.Lock()
	closed := shell.closed
	shell.mu.Unlock()
	if !closed {
		t.Error("the shell was not closed")
	}

	mu.Lock()
	count := releasedOnce
	mu.Unlock()
	if count != 1 {
		t.Errorf("release ran %d times, want exactly 1", count)
	}
}

// TestTheFarEndHangingUpEndsTheTerminal: an EOF from any transport is a
// normal end, not a failure.
func TestTheFarEndHangingUpEndsTheTerminal(t *testing.T) {
	m := quietManager(t)
	shell := newFakeShell()

	term, err := m.Open(shell, nil, OpenParams{
		UserID: "u1", Label: "Console",
		Transport: Transport{Protocol: sessions.ProtocolSerial, Device: "/dev/ttyUSB0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := shell.fromFarEnd.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-term.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal did not notice the far end closing")
	}

	if err := term.Err(); err != nil {
		t.Errorf("a clean hangup should not be an error: %v", err)
	}
}

// TestAReleaseIsNotOptional guards the nil case, because a caller with
// nothing to give back is the ordinary case for telnet.
func TestAReleaseIsNotOptional(t *testing.T) {
	m := quietManager(t)
	shell := newFakeShell()

	term, err := m.Open(shell, nil, OpenParams{UserID: "u1", Label: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CloseTerminal("u1", term.ID); err != nil {
		t.Fatalf("closing a terminal with no release must not panic: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// TestAttachingAndDetachingWhileOutputFlowsDoesNotPanic reproduces a race that
// survived three phases.
//
// pump used to read t.attached under the lock, release it, and then send. A
// browser detaching in that window closes the channel the send is about to
// use — and a send on a closed channel is a panic, not an error, which takes
// the whole server with it rather than one terminal.
//
// The window is microseconds wide, so this hammers it: continuous output
// against continuous attach and detach. It passed against the broken version
// often enough to be useless without -race, and fails reliably with it.
func TestAttachingAndDetachingWhileOutputFlowsDoesNotPanic(t *testing.T) {
	m := quietManager(t)
	shell := newFakeShell()

	term, err := m.Open(shell, nil, OpenParams{UserID: "u1", Label: "busy"})
	if err != nil {
		t.Fatal(err)
	}

	// A device talking continuously, until the attach loop below is done.
	done := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := shell.fromFarEnd.Write([]byte("output\r\n")); err != nil {
				return
			}
		}
	}()

	// A browser that cannot make up its mind, on this goroutine so the
	// writer's stop signal cannot deadlock against its own wait.
	for range 2000 {
		attachment, err := term.Attach()
		if err != nil {
			break
		}
		// Drained, because a browser that never reads is a different test —
		// this one is about the channel being closed underneath a send.
		go func(ch <-chan []byte) {
			for range ch {
			}
		}(attachment.Output)
		term.Detach()
	}

	close(done)

	// The pipe is closed to release a writer parked mid-Write, which happens
	// whenever the loop above finishes between two of pump's reads.
	_ = shell.fromFarEnd.Close()
	writer.Wait()

	if err := m.CloseTerminal("u1", term.ID); err != nil {
		t.Fatalf("closing: %v", err)
	}
}
