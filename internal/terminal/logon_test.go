package terminal

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// scriptedShell plays a device: it emits what it is told to, and records what
// it is sent.
type scriptedShell struct {
	out     chan []byte
	partial []byte

	mu       sync.Mutex
	received []byte
	closed   bool
}

func newScriptedShell() *scriptedShell {
	return &scriptedShell{out: make(chan []byte, 16)}
}

func (s *scriptedShell) say(text string) { s.out <- []byte(text) }

func (s *scriptedShell) Read(p []byte) (int, error) {
	if len(s.partial) > 0 {
		n := copy(p, s.partial)
		s.partial = s.partial[n:]
		return n, nil
	}
	chunk, ok := <-s.out
	if !ok {
		return 0, errClosed
	}
	// A reader with a small buffer must not silently lose the rest of a
	// chunk — a fake that truncates would make the window test pass for the
	// wrong reason, by never delivering the banner it is meant to bury.
	n := copy(p, chunk)
	if n < len(chunk) {
		s.partial = append([]byte(nil), chunk[n:]...)
	}
	return n, nil
}

func (s *scriptedShell) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.received = append(s.received, p...)
	s.mu.Unlock()
	return len(p), nil
}

func (s *scriptedShell) Resize(int, int) error { return nil }
func (s *scriptedShell) Wait() error           { return nil }

func (s *scriptedShell) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.out)
	}
	s.mu.Unlock()
	return nil
}

func (s *scriptedShell) typed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.received)
}

var errClosed = &closedError{}

type closedError struct{}

func (*closedError) Error() string { return "closed" }

// drain reads the wrapper until it has seen want, which is what a terminal
// pump does and what drives the automation.
func drain(t *testing.T, shell Shell, want string) string {
	t.Helper()

	type result struct{ seen string }
	ch := make(chan result, 1)

	go func() {
		var seen strings.Builder
		buf := make([]byte, 256)
		for {
			n, err := shell.Read(buf)
			seen.Write(buf[:n])
			if strings.Contains(seen.String(), want) || err != nil {
				ch <- result{seen.String()}
				return
			}
		}
	}()

	select {
	case r := <-ch:
		return r.seen
	case <-time.After(5 * time.Second):
		t.Fatalf("never saw %q", want)
		return ""
	}
}

// TestTheLoginIsTypedWhenTheDeviceAsks.
func TestTheLoginIsTypedWhenTheDeviceAsks(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithLogon(device, sessions.DefaultLogonSteps(), "netops", "hunter2")

	device.say("\r\nUser Access Verification\r\n\r\nUsername: ")
	drain(t, shell, "Username: ")

	waitForTyped(t, device, "netops\r")

	device.say("\r\nPassword: ")
	drain(t, shell, "Password: ")

	waitForTyped(t, device, "netops\rhunter2\r")
}

// TestTheLoginAppearsInTheOutput is why this wraps the shell rather than
// running before one exists.
//
// A pre-roll would do the exchange before the terminal was created, and the
// user would arrive at a prompt with no idea what had been typed at their
// equipment on their behalf.
func TestTheLoginAppearsInTheOutput(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithLogon(device, sessions.DefaultLogonSteps(), "netops", "hunter2")

	device.say("Username: ")
	seen := drain(t, shell, "Username: ")
	if !strings.Contains(seen, "Username: ") {
		t.Errorf("the prompt did not reach the terminal: %q", seen)
	}
}

// TestSomebodyTypingTakesOver.
//
// Continuing to inject once a person has started typing means fighting them
// for the keyboard, and the classic result is a password sent into a shell
// prompt — and from there into the scrollback, the command history and the
// syslog of a device somebody else administers.
func TestSomebodyTypingTakesOver(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithLogon(device, sessions.DefaultLogonSteps(), "netops", "hunter2")

	if _, err := shell.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}

	device.say("Username: ")
	drain(t, shell, "Username: ")
	device.say("Password: ")
	drain(t, shell, "Password: ")

	time.Sleep(100 * time.Millisecond)
	if typed := device.typed(); strings.Contains(typed, "hunter2") {
		t.Errorf("the password was typed after the user took over: %q", typed)
	}
}

// TestAPromptInABannerDoesNotCount.
//
// A device whose legal notice contains the word "password" must not satisfy a
// step waiting for the password prompt, or the credential goes to the banner
// and the real prompt gets nothing.
func TestAPromptInABannerDoesNotCount(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	steps := []sessions.LogonStep{{Expect: "assword:", Send: "%PASSWORD%\\r"}}
	shell := WithLogon(device, steps, "netops", "hunter2")

	// Long enough to push the mention out of the matching window, which is
	// exactly what the window is for.
	banner := "Unauthorised access is prohibited. Your password: is your own " +
		"responsibility and must not be shared with anyone under any " +
		"circumstances whatsoever, including colleagues and contractors. " +
		"This system is monitored and all activity is recorded for the " +
		"purposes of security review and capacity planning by the network " +
		"operations team at this organisation.\r\n"
	device.say(banner)
	drain(t, shell, "operations team")

	time.Sleep(100 * time.Millisecond)
	if typed := device.typed(); typed != "" {
		t.Errorf("something was typed at a banner: %q", typed)
	}
}

// TestAStepWithNoExpectSendsImmediately, which is how a console line that
// needs a keypress before it says anything is woken up.
func TestAStepWithNoExpectSendsImmediately(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	steps := []sessions.LogonStep{{Send: "\\r"}, {Expect: "ogin:", Send: "%USERNAME%\\r"}}
	shell := WithLogon(device, steps, "netops", "")

	device.say("\x00")
	drain(t, shell, "\x00")

	waitForTyped(t, device, "\r")
}

// TestNoStepsMeansNoWrapper keeps the ordinary case free of a layer.
func TestNoStepsMeansNoWrapper(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	if got := WithLogon(device, nil, "u", "p"); got != Shell(device) {
		t.Error("a connection with no logon steps should not be wrapped at all")
	}
}

// TestThePasswordIsNotEscapedIntoKeystrokes is the ordering bug this nearly
// shipped with.
//
// Escapes belong to the template, which the user wrote. The password is data,
// and may have come from a device inventory or somebody's export. Resolving
// escapes after substitution would let a password containing the two
// characters \ and r become a carriage return — and a password chosen to
// contain one followed by a command would type that command into the device
// at whatever privilege the login had just granted.
func TestThePasswordIsNotEscapedIntoKeystrokes(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	nasty := `p\rwrite erase\r`
	steps := []sessions.LogonStep{{Expect: "assword:", Send: "%PASSWORD%\\r"}}
	shell := WithLogon(device, steps, "netops", nasty)

	device.say("Password: ")
	drain(t, shell, "Password: ")

	waitForTyped(t, device, nasty+"\r")

	typed := device.typed()
	if strings.Count(typed, "\r") != 1 {
		t.Errorf("the password's backslashes became carriage returns: %q", typed)
	}
}

func waitForTyped(t *testing.T, device *scriptedShell, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if device.typed() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the device received %q, want %q", device.typed(), want)
}
