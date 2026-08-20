package terminal

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// collector gathers trigger events for assertions.
type collector struct {
	mu     sync.Mutex
	events []TriggerEvent
}

func (c *collector) sink(event TriggerEvent) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func (c *collector) seen() []TriggerEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]TriggerEvent(nil), c.events...)
}

func (c *collector) waitFor(t *testing.T, name string) TriggerEvent {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, event := range c.seen() {
			if event.Name == name {
				return event
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the trigger %q never fired; saw %v", name, c.seen())
	return TriggerEvent{}
}

// startPump reads a shell continuously, the way a real terminal does.
//
// drain stops at its marker, which is fine for a test that says one thing and
// hopeless for one that says twenty: the fake shell's channel fills, say
// blocks, and the test hangs before it has asserted anything. Anything
// emitting more than a line or two needs something reading the whole time.
func startPump(t *testing.T, shell Shell) func() {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for {
			if _, err := shell.Read(buf); err != nil {
				return
			}
		}
	}()

	return func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the pump did not stop")
		}
	}
}

// TestATriggerAnswersAPrompt is the case the feature exists for: a confirm
// prompt during a long operation, answered while nobody is watching.
func TestATriggerAnswersAPrompt(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	events := &collector{}
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "confirm", Pattern: `\[confirm\]`,
		Action: sessions.TriggerSend, Send: "y\\r",
	}}, "netops", "hunter2", events.sink)

	device.say("Proceed with reload? [confirm]\r\n")
	drain(t, shell, "[confirm]")

	events.waitFor(t, "confirm")
	waitForTyped(t, device, "y\r")
}

// TestATriggerCanJustTellYou. The most useful action there is, and the only
// one that cannot go wrong.
func TestATriggerCanJustTellYou(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	events := &collector{}
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "link flap", Pattern: `%LINK-3-UPDOWN`,
		Action: sessions.TriggerNotify,
	}}, "", "", events.sink)

	device.say("Mar  4 05:06:07: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\r\n")
	drain(t, shell, "UPDOWN")

	event := events.waitFor(t, "link flap")
	if !strings.Contains(event.Line, "Gi0/1") {
		t.Errorf("the notice does not carry what it saw: %q", event.Line)
	}
	if typed := device.typed(); typed != "" {
		t.Errorf("a notify trigger typed something: %q", typed)
	}
}

// TestCaptureGroupsReachTheSend, which is what makes a rule about a device's
// own output expressible at all.
func TestCaptureGroupsReachTheSend(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "enable", Pattern: `Enable password for (\w+):`,
		Action: sessions.TriggerSend, Send: "$1-secret\\r",
	}}, "", "", nil)

	device.say("Enable password for netops:\r\n")
	drain(t, shell, "netops:")

	waitForTyped(t, device, "netops-secret\r")
}

// TestADeviceCannotInjectKeystrokesThroughACaptureGroup.
//
// A capture group holds whatever the far end printed. If the expansion ran in
// two passes — captures in, then escapes resolved — a device could print a
// backslash and an r followed by a command and have that command typed back
// at whatever privilege this session holds. It is the same ordering bug as
// the one in the logon steps, with the attacker on the other side of the wire
// rather than in the settings.
func TestADeviceCannotInjectKeystrokesThroughACaptureGroup(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "echo it back", Pattern: `name is (.+)$`,
		Action: sessions.TriggerSend, Send: "hello $1\\r",
	}}, "", "", nil)

	// The device names itself with something that would become a carriage
	// return and a command if anything re-scanned it.
	device.say(`name is bob\rwrite erase` + "\r\n")
	drain(t, shell, "name is")

	waitForTyped(t, device, `hello bob\rwrite erase`+"\r")

	if strings.Count(device.typed(), "\r") != 1 {
		t.Errorf("the device's own output became keystrokes: %q", device.typed())
	}
}

// TestATriggerStopsFiringAtItsCap.
//
// Two things need this. A trigger whose Send produces output matching its own
// pattern is an infinite loop; and a device printing "assword:" in a loop
// must not be handed the credential ten thousand times.
func TestATriggerStopsFiringAtItsCap(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	events := &collector{}
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "greedy", Pattern: `ping`,
		Action: sessions.TriggerSend, Send: "pong\\r", MaxFires: 3,
	}}, "", "", events.sink)

	stop := startPump(t, shell)
	for range 20 {
		device.say("ping\r\n")
	}

	// Long enough for anything still firing to have fired.
	time.Sleep(300 * time.Millisecond)
	_ = device.Close()
	stop()

	if got := strings.Count(device.typed(), "pong"); got != 3 {
		t.Errorf("the trigger fired %d times, want its cap of 3", got)
	}
	if got := len(events.seen()); got != 3 {
		t.Errorf("%d events, want 3", got)
	}
}

// TestASendTriggerThatFeedsItselfTerminates is the loop above, arranged the
// way it would actually happen: a rule whose output matches its own pattern.
func TestASendTriggerThatFeedsItselfTerminates(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	// The device echoes whatever it is sent, so "loop" begets "loop".
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "self feeding", Pattern: `loop`,
		Action: sessions.TriggerSend, Send: "loop\\r",
	}}, "", "", nil)

	stop := startPump(t, shell)
	for range 50 {
		device.say("loop\r\n")
	}
	time.Sleep(300 * time.Millisecond)
	_ = device.Close()
	stop()

	if got := strings.Count(device.typed(), "loop"); got > sessions.DefaultTriggerFires {
		t.Errorf("a self-feeding trigger fired %d times, past the default cap of %d",
			got, sessions.DefaultTriggerFires)
	}
}

// TestARuleFiresOncePerLineHoweverItArrives.
//
// Output arrives in whatever pieces the network chose. A rule is matched
// against the line so far — that is what makes a prompt, which has no newline
// after it, match at all — so the same line passing the pattern twice as it
// grows must still be one firing.
//
// The other half is that a line which does not match stays not matching:
// "Errors: 0" is not an error, however it is split.
func TestARuleFiresOncePerLineHoweverItArrives(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	events := &collector{}
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "errors only", Pattern: `^Error: `,
		Action: sessions.TriggerNotify,
	}}, "", "", events.sink)

	// Arriving in pieces, as a real socket delivers it.
	device.say("Err")
	device.say("ors: 0\r\n")
	device.say("Error: ")
	device.say("interface down\r\n")

	drain(t, shell, "interface down")
	events.waitFor(t, "errors only")

	// Settled, so a second firing would have happened by now.
	time.Sleep(200 * time.Millisecond)

	if got := len(events.seen()); got != 1 {
		t.Errorf("%d events, want 1: \"Errors: 0\" is not an error, and one "+
			"line arriving in two pieces is still one line — saw %v",
			got, events.seen())
	}
}

// TestARuleCanWaitForAPromptThatHasNoNewline is the case the first version of
// this could not do at all.
//
// The most common trigger anybody writes waits for a prompt, and a prompt is
// the last thing on the screen with nothing after it. Matching only completed
// lines meant waiting forever.
func TestARuleCanWaitForAPromptThatHasNoNewline(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	events := &collector{}
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "at the prompt", Pattern: `switch#\s*$`,
		Action: sessions.TriggerNotify,
	}}, "", "", events.sink)

	device.say("Last login: Tuesday\r\nswitch# ")
	drain(t, shell, "switch#")

	events.waitFor(t, "at the prompt")
}

// TestADisabledTriggerDoesNothing, which is what people want at three in the
// morning when a rule misfires.
func TestADisabledTriggerDoesNothing(t *testing.T) {
	settings := sessions.Settings{Triggers: &[]sessions.Trigger{
		{Name: "on", Pattern: "x", Action: sessions.TriggerNotify},
		{Name: "off", Pattern: "x", Action: sessions.TriggerNotify, Disabled: true},
	}}

	effective := settings.EffectiveTriggers()
	if len(effective) != 1 || effective[0].Name != "on" {
		t.Fatalf("effective triggers = %v", effective)
	}
}

// TestHighlightingIsNotTheServersJob.
//
// The server has no idea what a colour is, and the text has to be marked as
// it is drawn. A highlight rule travels to the interface and does nothing
// here — and a connection carrying only highlight rules is not wrapped at all.
func TestHighlightingIsNotTheServersJob(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "warnings", Pattern: `WARN`,
		Action: sessions.TriggerHighlight, Colour: "amber",
	}}, "", "", nil)

	if shell != Shell(device) {
		t.Error("a connection with only highlight rules should not be wrapped")
	}
}

// TestAStopTriggerEndsTheSession, for a match that means continuing would
// make things worse.
func TestAStopTriggerEndsTheSession(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	events := &collector{}
	shell := WithTriggers(device, []sessions.Trigger{{
		Name: "wrong box", Pattern: `PRODUCTION`,
		Action: sessions.TriggerStop,
	}}, "", "", events.sink)

	device.say("Welcome to PRODUCTION-core-01\r\n")
	drain(t, shell, "PRODUCTION")

	events.waitFor(t, "wrong box")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		device.mu.Lock()
		closed := device.closed
		device.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a stop trigger fired and the session stayed open")
}

// TestABrokenPatternDoesNotStopAConnection.
//
// Patterns are validated when they are saved, so one reaching here is
// something else having gone wrong — and refusing to open a terminal to a
// production device because a highlight rule is malformed is the wrong trade.
func TestABrokenPatternDoesNotStopAConnection(t *testing.T) {
	device := newScriptedShell()
	defer func() { _ = device.Close() }()

	shell := WithTriggers(device, []sessions.Trigger{
		{Name: "broken", Pattern: `([`, Action: sessions.TriggerNotify},
		{Name: "fine", Pattern: `ok`, Action: sessions.TriggerNotify},
	}, "", "", nil)

	device.say("ok\r\n")
	if seen := drain(t, shell, "ok"); !strings.Contains(seen, "ok") {
		t.Errorf("the session did not work: %q", seen)
	}
}
