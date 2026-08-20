package terminal

import (
	"regexp"
	"strings"
	"sync"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// Running the trigger rules against a session's output.
//
// A Shell wrapper, like the logon sequence and the transcript, which is what
// makes it work while the browser is detached. That is not incidental: a
// trigger that answers a `[confirm]` prompt during a twenty-minute upgrade is
// most needed precisely when nobody is watching it.
//
// # Matching against the line so far, not only against finished lines
//
// The first version of this buffered to a newline and matched complete lines.
// It is a tidier rule and it is wrong, because the single most common trigger
// anybody writes waits for a prompt — and a prompt has no newline after it.
// `PROMPT>` or `switch#` sits there being the last thing on the screen, and a
// rule waiting for a finished line waits forever.
//
// So each rule is matched against the line as it stands, every time more of
// it arrives, and a rule that has fired on the current line does not fire
// again until the line ends. That is what makes "when you see the prompt"
// work and stops "when you see an error" firing once per packet.
//
// The consequence to be honest about: an unanchored pattern can match a
// prefix that the rest of the line would have changed. `^Error` fires on a
// line that turns out to say `Errors: 0` — but so would matching the
// completed line, since the pattern genuinely matches it. What is lost is
// only the ability to write a pattern that depends on the line being over,
// and `$` still works once it is.
//
// The buffer is bounded. A device that prints megabytes without a newline is
// unusual but not impossible — a progress bar redrawing with carriage returns
// does exactly that — so beyond the bound it is reset.

const (
	// triggerLineLimit bounds one unterminated line.
	//
	// Generous enough for any real prompt or log line, small enough that a
	// device emitting a progress bar forever costs a fixed amount of memory.
	triggerLineLimit = 8 << 10
)

// TriggerEvent is one rule firing, for the interface and the audit log.
type TriggerEvent struct {
	// Name is the rule's name rather than its pattern, so somebody reading
	// the record can tell which rule fired without matching regexes by eye.
	Name string `json:"name"`

	Action sessions.TriggerAction `json:"action"`

	// Line is the output that matched, trimmed. Included because a notice
	// saying "your trigger fired" without saying what it saw is not much of
	// a notice.
	//
	// Never the Send: that may contain a password.
	Line string `json:"line"`

	Colour string `json:"colour,omitempty"`
}

// TriggerSink receives events as they happen.
//
// Called from the read path, so an implementation must not block: the
// WebSocket bridge queues onto a channel with a default arm, and anything
// slower would stall the terminal it is reporting on.
type TriggerSink func(TriggerEvent)

// compiledTrigger is a rule with its pattern ready.
type compiledTrigger struct {
	rule    sessions.Trigger
	pattern *regexp.Regexp
	fired   int

	// firedThisLine stops a rule firing once per packet as a line arrives in
	// pieces. Cleared when the line ends.
	firedThisLine bool
}

// triggerShell watches output and acts on it.
type triggerShell struct {
	Shell

	username string
	password string
	sink     TriggerSink

	mu       sync.Mutex
	triggers []*compiledTrigger
	line     []byte
	stopped  bool

	// lineEnded records that a terminator was seen and the fired-this-line
	// marks are due to be cleared.
	//
	// Deferred rather than done at the terminator, and the ordering is the
	// whole of it: the completed line is matched after this loop, so clearing
	// eagerly would let a rule that already fired on the partial line fire
	// again on the same line finished. The marks clear when the next line
	// actually starts, which is the first byte after the terminator.
	lineEnded bool
}

// WithTriggers returns shell with the rules running against its output.
//
// Rules whose patterns do not compile are dropped rather than failing the
// connection. They were validated when they were saved, so reaching here
// means something else went wrong — and refusing to open a terminal to a
// production device because a highlight rule is malformed is the wrong trade.
func WithTriggers(
	shell Shell, rules []sessions.Trigger, username, password string, sink TriggerSink,
) Shell {
	compiled := make([]*compiledTrigger, 0, len(rules))
	for _, rule := range rules {
		if !rule.Action.RunsOnTheServer() {
			// Highlighting is the browser's job. The rule still travels to
			// the interface; it simply does nothing here.
			continue
		}
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, &compiledTrigger{rule: rule, pattern: pattern})
	}

	if len(compiled) == 0 {
		return shell
	}

	return &triggerShell{
		Shell:    shell,
		username: username,
		password: password,
		sink:     sink,
		triggers: compiled,
	}
}

// Read passes output through, matching complete lines as they appear.
func (t *triggerShell) Read(p []byte) (int, error) {
	n, err := t.Shell.Read(p)
	if n > 0 {
		t.observe(p[:n])
	}
	return n, err
}

// observe accumulates output and runs the rules over the line so far.
//
// Matches are collected under the lock and acted on outside it, because
// acting means writing to the far end and that can block.
func (t *triggerShell) observe(chunk []byte) {
	var lines []string

	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}

	for _, b := range chunk {
		switch b {
		case '\n', '\r':
			if len(t.line) > 0 {
				lines = append(lines, string(t.line))
				t.line = t.line[:0]
			}
			t.lineEnded = true
		default:
			if t.lineEnded {
				// A new line is starting, so every rule may fire again.
				for _, trigger := range t.triggers {
					trigger.firedThisLine = false
				}
				t.lineEnded = false
			}
			t.line = append(t.line, b)
			if len(t.line) >= triggerLineLimit {
				// A device printing without newlines. Taken as it stands
				// rather than growing without bound.
				lines = append(lines, string(t.line))
				t.line = t.line[:0]
				t.lineEnded = true
			}
		}
	}

	// And the unfinished line, which is where every prompt lives.
	if len(t.line) > 0 {
		lines = append(lines, string(t.line))
	}
	t.mu.Unlock()

	for _, line := range lines {
		t.match(line)
	}
}

// match runs every rule against one line.
func (t *triggerShell) match(line string) {
	type pending struct {
		event TriggerEvent
		send  string
		stop  bool
	}
	var actions []pending

	t.mu.Lock()
	for _, trigger := range t.triggers {
		if trigger.firedThisLine || trigger.fired >= trigger.rule.Fires() {
			continue
		}
		if !trigger.pattern.MatchString(line) {
			continue
		}
		trigger.fired++
		trigger.firedThisLine = true

		event := TriggerEvent{
			Name:   trigger.rule.Name,
			Action: trigger.rule.Action,
			Line:   trimLine(line),
			Colour: trigger.rule.Colour,
		}

		action := pending{event: event}
		switch trigger.rule.Action {
		case sessions.TriggerSend:
			// One pass over the template, with the captures, the username and
			// the password all written verbatim. A capture group holds
			// whatever the device printed, so a two-pass expansion would hand
			// the far end an escape-sequence primitive: print a backslash and
			// an r followed by a command, and the command gets typed back at
			// whatever privilege this session has. See sessions.Expand.
			action.send = sessions.Expand(
				trigger.rule.Send, t.username, t.password,
				trigger.pattern.FindStringSubmatch(line))
		case sessions.TriggerStop:
			action.stop = true
			t.stopped = true
		}
		actions = append(actions, action)
	}
	t.mu.Unlock()

	// Outside the lock: Write reaches the far end and can block, and holding
	// the mutex through it would stall the Read that is the only thing that
	// will ever release it.
	for _, action := range actions {
		if t.sink != nil {
			t.sink(action.event)
		}
		if action.send != "" {
			if _, err := t.Shell.Write([]byte(action.send)); err != nil {
				return
			}
		}
		if action.stop {
			_ = t.Shell.Close()
			return
		}
	}
}

// trimLine bounds what a notice carries.
func trimLine(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 200 {
		return line[:200] + "…"
	}
	return line
}
