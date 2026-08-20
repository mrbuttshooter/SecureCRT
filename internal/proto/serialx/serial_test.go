package serialx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

// Serial, against a real character device.
//
// A pseudo-terminal is a character device with real termios: opening one,
// setting its speed and framing, and reading and writing it exercises exactly
// the syscalls a USB console cable does. What it cannot exercise is a baud
// rate actually taking effect on a wire, which no test without hardware can.
//
// The guards are the part worth testing hardest. The device path comes from a
// user, and everything that stops "open this path" from being an
// arbitrary-file-read on a server full of credentials is in this package.

// openPTY returns the two ends of a pseudo-terminal.
func openPTY(t *testing.T) (controller, device *os.File) {
	t.Helper()

	controller, device, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() {
		_ = controller.Close()
		_ = device.Close()
	})
	return controller, device
}

// allowPTS permits the pseudo-terminal namespace, which is where the test's
// character device lives.
func allowPTS() []string { return []string{"/dev/pts/*"} }

func TestASerialPortCarriesBytes(t *testing.T) {
	controller, device := openPTY(t)

	port, err := Open(Config{Device: device.Name(), Allowed: allowPTS()})
	if err != nil {
		t.Fatalf("open %s: %v", device.Name(), err)
	}
	defer func() { _ = port.Close() }()

	// From the far end to the terminal.
	if _, err := controller.Write([]byte("switch> ")); err != nil {
		t.Fatal(err)
	}
	got := readWithin(t, port, len("switch> "))
	if got != "switch> " {
		t.Errorf("read %q", got)
	}

	// And back.
	if _, err := port.Write([]byte("show version\r")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := controller.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf[:n]), "show version") {
		t.Errorf("the far end received %q", buf[:n])
	}
}

// TestTheLineIsRaw is what makes a console usable.
//
// Canonical mode would hold input until a newline, so a switch would see
// nothing until Enter. Echo would double every character now that the far end
// is doing it. And ISIG would turn a Ctrl-C meant for the device into one for
// this process.
func TestTheLineIsRaw(t *testing.T) {
	controller, device := openPTY(t)

	port, err := Open(Config{Device: device.Name(), Allowed: allowPTS()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = port.Close() }()

	// One character, no newline. Canonical mode would swallow it.
	if _, err := port.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 16)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := controller.Read(buf)
	if err != nil {
		t.Fatalf("a single character never arrived, so the line is not raw: %v", err)
	}
	if string(buf[:n]) != "x" {
		t.Errorf("got %q, want a single unmodified character", buf[:n])
	}
}

// TestOnlyAllowedDevicesCanBeOpened is the guard that matters most.
//
// Without it, a saved connection naming /etc/shadow — or /dev/mem, which is a
// character device and so survives every other check here — would stream that
// file to a browser on a server holding every engineer's encrypted vault.
func TestOnlyAllowedDevicesCanBeOpened(t *testing.T) {
	_, device := openPTY(t)

	t.Run("an empty list opens nothing", func(t *testing.T) {
		_, err := Open(Config{Device: device.Name()})
		if !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("err = %v, want a refusal — an unconfigured server has no ports", err)
		}
	})

	t.Run("a device outside the list is refused", func(t *testing.T) {
		_, err := Open(Config{Device: device.Name(), Allowed: []string{"/dev/ttyUSB*"}})
		if !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})

	t.Run("an ordinary file is refused even when the glob allows it", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secrets")
		if err := os.WriteFile(path, []byte("not a device"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := Open(Config{Device: path, Allowed: []string{filepath.Join(dir, "*")}})
		if !errors.Is(err, ErrNotADevice) {
			t.Fatalf("err = %v, want a refusal — an operator's glob must not be "+
				"able to turn a file into a terminal", err)
		}
	})
}

// TestASymbolicLinkCannotReachPastTheList.
//
// The allowlist is matched after resolution, so a link inside an allowed
// directory pointing somewhere else does not smuggle that somewhere else in.
func TestASymbolicLinkCannotReachPastTheList(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "ttyUSB0")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}

	// The glob names the link, not the target.
	_, err := Open(Config{Device: link, Allowed: []string{filepath.Join(dir, "ttyUSB*")}})
	if err == nil {
		t.Fatal("a link to something that is not a device was opened")
	}
	if !errors.Is(err, ErrNotAllowed) && !errors.Is(err, ErrNotADevice) {
		t.Errorf("err = %v, want a refusal", err)
	}
}

// TestTheSettingsAreValidatedBeforeAnythingIsOpened.
func TestTheSettingsAreValidatedBeforeAnythingIsOpened(t *testing.T) {
	cases := map[string]Config{
		"no device":      {Baud: 9600},
		"odd baud":       {Device: "/dev/ttyUSB0", Baud: 12345},
		"too few bits":   {Device: "/dev/ttyUSB0", DataBits: 4},
		"three stops":    {Device: "/dev/ttyUSB0", StopBits: 3},
		"unknown parity": {Device: "/dev/ttyUSB0", Parity: Parity("sometimes")},
		"unknown flow":   {Device: "/dev/ttyUSB0", Flow: FlowControl("shouting")},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Error("must be refused")
			}
		})
	}

	if err := (Config{Device: "/dev/ttyUSB0"}).Validate(); err != nil {
		t.Errorf("the console defaults must be valid: %v", err)
	}
}

// TestTheSummaryReadsLikeAConsoleLabel. "9600 8N1" is the first thing
// somebody checks when a console shows nothing but rubbish.
func TestTheSummaryReadsLikeAConsoleLabel(t *testing.T) {
	cases := map[string]Config{
		"9600 8N1":        {Device: "x"},
		"115200 8N1":      {Device: "x", Baud: 115200},
		"9600 7E1":        {Device: "x", DataBits: 7, Parity: ParityEven},
		"19200 8O2":       {Device: "x", Baud: 19200, Parity: ParityOdd, StopBits: 2},
		"9600 8N1 rtscts": {Device: "x", Flow: FlowRTSCTS},
	}
	for want, cfg := range cases {
		if got := cfg.Summary(); got != want {
			t.Errorf("Summary() = %q, want %q", got, want)
		}
	}
}

// TestOneLineOneTerminal.
//
// A serial port is a single wire. Two writers produce two people's keystrokes
// interleaved character by character into a device that has no idea anything
// is wrong — a switch receiving "cofnigure tremrinal" and reporting a syntax
// error nobody typed.
func TestOneLineOneTerminal(t *testing.T) {
	registry := NewRegistry()

	release, err := registry.Claim("/dev/ttyUSB0", "alice", "Lab switch")
	if err != nil {
		t.Fatal(err)
	}

	// Somebody else is told it is taken, but not by whom — a device name and
	// a colleague's session label are more than a refusal needs to disclose.
	_, err = registry.Claim("/dev/ttyUSB0", "bob", "Console")
	var inUse *InUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("err = %v, want an in-use error", err)
	}
	if inUse.SameUser {
		t.Error("a different user was reported as the same one")
	}
	if !errors.Is(err, ErrBusy) {
		t.Error("callers matching on ErrBusy would miss this")
	}

	// The same person gets a sentence they can act on: it is their own tab.
	_, err = registry.Claim("/dev/ttyUSB0", "alice", "Lab switch")
	if !errors.As(err, &inUse) || !inUse.SameUser {
		t.Fatalf("err = %v, want a same-user report", err)
	}

	// Releasing frees it, and releasing twice is safe — a claim that outlived
	// its port would lock the line out until a restart, which on a bench
	// means walking over to unplug something.
	release()
	release()
	if registry.Held() != 0 {
		t.Errorf("%d claims still held", registry.Held())
	}

	if _, err := registry.Claim("/dev/ttyUSB0", "bob", "Console"); err != nil {
		t.Errorf("the line was not free after release: %v", err)
	}
}

// TestClaimsAreConcurrencySafe: exactly one of many racing claims wins.
func TestClaimsAreConcurrencySafe(t *testing.T) {
	registry := NewRegistry()

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		won int
	)
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := registry.Claim("/dev/ttyUSB0", "u", "t"); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if won != 1 {
		t.Errorf("%d claims succeeded on one wire, want exactly 1", won)
	}
}

// TestClosingUnblocksAReadOnASilentConsole.
//
// A console with nothing to say is the ordinary state of a console. The port
// is left non-blocking so Go's poller owns the descriptor, which is what makes
// Close wake a Read that is waiting on it rather than parking a goroutine
// until the process exits.
func TestClosingUnblocksAReadOnASilentConsole(t *testing.T) {
	_, device := openPTY(t)

	port, err := Open(Config{Device: device.Name(), Allowed: allowPTS()})
	if err != nil {
		t.Fatal(err)
	}

	reading := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := port.Read(buf)
		reading <- err
	}()

	time.Sleep(100 * time.Millisecond)
	if err := port.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-reading:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wake a Read waiting on a silent line")
	}
}

func readWithin(t *testing.T, port *Port, n int) string {
	t.Helper()

	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)

	go func() {
		out := make([]byte, 0, n)
		buf := make([]byte, n)
		for len(out) < n {
			read, err := port.Read(buf)
			out = append(out, buf[:read]...)
			if err != nil {
				ch <- result{string(out), err}
				return
			}
		}
		ch <- result{string(out), nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read: %v (got %q)", r.err, r.out)
		}
		return r.out
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived on the line")
		return ""
	}
}
