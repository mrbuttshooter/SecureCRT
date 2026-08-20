package api

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Serial, from the browser to a real character device.
//
// A pseudo-terminal has real termios, so this exercises the same syscalls a
// USB console cable does. What it cannot exercise is a baud rate taking effect
// on a wire, which nothing without hardware can.

// openConsole returns a pseudo-terminal standing in for a cabled device.
func openConsole(t *testing.T) (controller *os.File, path string) {
	t.Helper()

	controller, device, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() {
		_ = controller.Close()
		_ = device.Close()
	})
	return controller, device.Name()
}

// allowSerial turns the feature on and names the pseudo-terminal namespace.
func allowSerial(c *config.Config) {
	c.Policy.AllowSerial = true
	c.Serial.AllowedDevices = []string{"/dev/pts/*"}
}

// savedSerialLine stores a serial connection. The device path lives in the
// hostname field, which is the one place a connection addresses a device
// rather than a host.
func (h *harness) savedSerialLine(t *testing.T, name, device string) string {
	t.Helper()

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": name, "protocol": "serial", "hostname": device,
		"settings": map[string]any{"serial_baud": 115200},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %s = %d: %v", name, resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// TestASerialTerminalCarriesTheConsole.
func TestASerialTerminalCarriesTheConsole(t *testing.T) {
	h := signedInWithVault(t, allowSerial)
	controller, device := openConsole(t)
	sessionID := h.savedSerialLine(t, "Lab switch console", device)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	if _, err := controller.Write([]byte("switch> ")); err != nil {
		t.Fatal(err)
	}
	view.waitFor(t, "switch> ", "", 20*time.Second)

	view.type_(t, "show ver\r")
	readFromConsole(t, controller, "show ver")
}

// readFromConsole reads until want appears.
//
// A loop rather than one read, because the pseudo-terminal echoes anything
// written to it back to this side until serialx has cleared ECHO on the
// device end — and the terminal is opened asynchronously, so a write from
// this test can land in the window before that happens. A real console has no
// echo of its own; this is the stand-in leaking through.
func readFromConsole(t *testing.T, controller *os.File, want string) {
	t.Helper()

	var seen strings.Builder
	buf := make([]byte, 256)
	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		_ = controller.SetReadDeadline(time.Now().Add(time.Second))
		n, err := controller.Read(buf)
		seen.Write(buf[:n])
		if strings.Contains(seen.String(), want) {
			return
		}
		if err != nil && !os.IsTimeout(err) {
			t.Fatalf("reading the console: %v (saw %q)", err, seen.String())
		}
	}
	t.Fatalf("the console never received %q, only %q", want, seen.String())
}

// TestASerialTerminalReportsItsLineSettings. "9600 8N1" — or here 115200 —
// is the first thing somebody checks when a console shows nothing but
// rubbish, so it is on the terminal rather than in a config file.
func TestASerialTerminalReportsItsLineSettings(t *testing.T) {
	h := signedInWithVault(t, allowSerial)
	controller, device := openConsole(t)
	sessionID := h.savedSerialLine(t, "Lab switch console", device)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	_, _ = controller.Write([]byte("ready"))
	view.waitFor(t, "ready", "", 20*time.Second)

	_, body := h.get("/api/terminals")
	terminals, _ := body["terminals"].([]any)
	if len(terminals) != 1 {
		t.Fatalf("got %d terminals: %v", len(terminals), body)
	}
	info, _ := terminals[0].(map[string]any)

	if protocol, _ := info["protocol"].(string); protocol != "serial" {
		t.Errorf("protocol = %v", info["protocol"])
	}
	if got, _ := info["device"].(string); got != device {
		t.Errorf("device = %q, want %q", got, device)
	}
	// A serial line addresses a device, not a host: no hostname is correct
	// here rather than a missing field.
	if host, _ := info["host"].(string); host != "" {
		t.Errorf("host = %q, want empty for a serial line", host)
	}
	if encrypted, _ := info["encrypted"].(bool); encrypted {
		t.Error("a serial line is not encrypted")
	}
}

// TestOneWireOneTerminal.
//
// Two terminals on one serial line would interleave two people's keystrokes
// into a device that has no idea anything is wrong.
func TestOneWireOneTerminal(t *testing.T) {
	h := signedInWithVault(t, allowSerial)
	controller, device := openConsole(t)
	sessionID := h.savedSerialLine(t, "Lab switch console", device)

	first := newSocketView(h.dialTerminal(t, "session="+sessionID))
	_, _ = controller.Write([]byte("ready"))
	first.waitFor(t, "ready", "", 20*time.Second)

	second := newSocketView(h.dialTerminal(t, "session="+sessionID))
	control := second.waitFor(t, "", terminal.ControlError, 20*time.Second)

	// The same person gets a sentence they can act on rather than "busy".
	if !strings.Contains(control.Message, "another tab") {
		t.Errorf("the refusal does not say where the port went: %q", control.Message)
	}
}

// TestSerialIsOffByDefault, and the refusal names the setting.
func TestSerialIsOffByDefault(t *testing.T) {
	h := signedInWithVault(t) // nothing enabled
	_, device := openConsole(t)
	sessionID := h.savedSerialLine(t, "Lab switch console", device)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	control := view.waitFor(t, "", terminal.ControlError, 20*time.Second)
	if !strings.Contains(control.Message, "allow_serial") {
		t.Errorf("the refusal does not name the setting: %q", control.Message)
	}
}

// TestADeviceOutsideTheAllowedListIsRefused is the guard that stops a saved
// connection from being an arbitrary-file-read on a server holding every
// engineer's encrypted vault.
func TestADeviceOutsideTheAllowedListIsRefused(t *testing.T) {
	h := signedInWithVault(t, func(c *config.Config) {
		c.Policy.AllowSerial = true
		// The feature is on and the pseudo-terminal namespace is not listed.
		c.Serial.AllowedDevices = []string{"/dev/ttyUSB*"}
	})
	_, device := openConsole(t)
	sessionID := h.savedSerialLine(t, "Not a real port", device)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	control := view.waitFor(t, "", terminal.ControlError, 20*time.Second)
	if !strings.Contains(control.Message, "allowed_devices") {
		t.Errorf("the refusal does not name the list: %q", control.Message)
	}
}

// TestAFileIsNotAConsole. An operator's glob must not be able to turn a file
// into a terminal, whatever it names.
func TestAFileIsNotAConsole(t *testing.T) {
	dir := t.TempDir()
	secrets := dir + "/master.key"
	if err := os.WriteFile(secrets, []byte("a secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := signedInWithVault(t, func(c *config.Config) {
		c.Policy.AllowSerial = true
		c.Serial.AllowedDevices = []string{dir + "/*"}
	})
	sessionID := h.savedSerialLine(t, "Definitely a console", secrets)

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)

	view.waitFor(t, "", terminal.ControlError, 20*time.Second)
	if strings.Contains(view.screen.String(), "a secret") {
		t.Fatal("the file's contents were streamed to the browser")
	}
}
