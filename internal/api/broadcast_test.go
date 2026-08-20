package api

import (
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Broadcast: one keyboard, several devices.
//
// The fan-out is server-side rather than the browser writing to several
// sockets, which is the difference between a feature audited by construction
// and one audited if the client remembers to say so. These check that
// difference and the two refusals that keep it safe.

// TestOneKeyboardReachesSeveralTerminals.
func TestOneKeyboardReachesSeveralTerminals(t *testing.T) {
	h := signedInWithVault(t)
	first := startSSH(t, "hunter2")
	second := startSSH(t, "hunter2")

	firstView, firstTerm := h.openTerminalOn(t, h.savedConnection(t, first, "hunter2"))
	secondView, secondTerm := h.openTerminalOn(t, h.savedConnection(t, second, "hunter2"))

	// The second terminal joins the first's keyboard.
	firstView.sendControl(t, terminal.Control{
		Type: terminal.ControlBroadcast, Terminals: []string{secondTerm},
	})
	ack := firstView.waitFor(t, "", terminal.ControlBroadcast, 20*time.Second)
	if len(ack.Terminals) != 1 || ack.Terminals[0] != secondTerm {
		t.Fatalf("the acknowledgement names %v, want just the joined terminal", ack.Terminals)
	}
	_ = firstTerm

	firstView.type_(t, "echo both-of-them\r")

	firstView.waitFor(t, "both-of-them", "", 20*time.Second)
	secondView.waitFor(t, "both-of-them", "", 20*time.Second)
}

// TestLeavingABroadcastGroupStopsTheMirroring.
func TestLeavingABroadcastGroupStopsTheMirroring(t *testing.T) {
	h := signedInWithVault(t)
	first := startSSH(t, "hunter2")
	second := startSSH(t, "hunter2")

	firstView, _ := h.openTerminalOn(t, h.savedConnection(t, first, "hunter2"))
	secondView, secondTerm := h.openTerminalOn(t, h.savedConnection(t, second, "hunter2"))

	firstView.sendControl(t, terminal.Control{
		Type: terminal.ControlBroadcast, Terminals: []string{secondTerm},
	})
	firstView.waitFor(t, "", terminal.ControlBroadcast, 20*time.Second)

	firstView.type_(t, "echo while-joined\r")
	secondView.waitFor(t, "while-joined", "", 20*time.Second)

	// An empty list leaves the group.
	firstView.sendControl(t, terminal.Control{Type: terminal.ControlBroadcast})
	ack := firstView.waitFor(t, "", terminal.ControlBroadcast, 20*time.Second)
	if len(ack.Terminals) != 0 {
		t.Fatalf("still joined to %v", ack.Terminals)
	}

	firstView.type_(t, "echo after-leaving\r")
	firstView.waitFor(t, "after-leaving", "", 20*time.Second)

	time.Sleep(300 * time.Millisecond)
	if strings.Contains(secondView.screen.String(), "after-leaving") {
		t.Error("keystrokes are still being mirrored after leaving the group")
	}
}

// TestABroadcastGroupIsAllOrNothing.
//
// Somebody who believes they are typing at forty devices and is typing at
// thirty-nine has a problem they will not discover until it matters.
func TestABroadcastGroupIsAllOrNothing(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")
	view, _ := h.openTerminalOn(t, h.savedConnection(t, srv, "hunter2"))

	view.sendControl(t, terminal.Control{
		Type: terminal.ControlBroadcast,
		Terminals: []string{
			"01920000-0000-7000-8000-000000000000", // never existed
		},
	})

	control := view.waitFor(t, "", terminal.ControlError, 20*time.Second)
	if !strings.Contains(control.Message, "nothing was joined") {
		t.Errorf("the refusal does not say the group was abandoned: %q", control.Message)
	}
}

// TestABroadcastGroupCannotReachSomebodyElsesTerminal.
//
// The group is resolved with the signed-in user's identity, so a terminal
// belonging to somebody else is a not-found rather than a way to type into a
// colleague's session.
func TestABroadcastGroupCannotReachSomebodyElsesTerminal(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSSH(t, "hunter2")

	// Mallory, with her own terminal on the same instance.
	h.createLocalUser("mallory@example.com", "another long password", false)
	h.post("/api/auth/logout", nil)
	h.login("mallory@example.com", "another long password")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "mallory's long passphrase"})

	mallorySession := h.savedConnection(t, srv, "hunter2")
	_, mallorysTerminal := h.openTerminalOn(t, mallorySession)

	// Back to Alice, who tries to put Mallory's terminal on her keyboard.
	h.post("/api/auth/logout", nil)
	h.login("alice@example.com", "correct horse battery staple")
	h.post("/api/vault/unlock", map[string]string{"passphrase": "a long enough passphrase"})

	view, _ := h.openTerminalOn(t, h.savedConnection(t, srv, "hunter2"))
	view.sendControl(t, terminal.Control{
		Type: terminal.ControlBroadcast, Terminals: []string{mallorysTerminal},
	})

	view.waitFor(t, "", terminal.ControlError, 20*time.Second)
}
