package sessions

import (
	"fmt"
	"regexp"
	"strings"
)

// Watching the output for something, and doing something about it.
//
// The roadmap called for "triggers and expect automation in a sandboxed JS
// runtime". This is not that, deliberately, and the reasoning belongs beside
// the code rather than only in a changelog.
//
// A JavaScript engine evaluating per-user scripts against device output, in
// the process that holds every engineer's encrypted credentials, is a large
// surface to get right: an interpreter to keep patched, an interrupt
// mechanism for scripts that never return, a memory bound, and a careful
// account of exactly which host functions are reachable. What it buys over
// the declarative form is conditional logic and string manipulation — real,
// but wanted by a small fraction of the cases.
//
// What people actually configure is "when you see X, send Y", "when you see
// X, tell me", and "when you see X, stop". That is what this does.
//
// # Why regular expressions are safe here and would not be elsewhere
//
// Go's regexp is RE2: it runs in time linear in the input, with no
// backtracking, so there is no pattern a user can write — by accident or on
// purpose — that turns a busy console into a hung goroutine. In a language
// with a backtracking engine this feature would need a complexity analysis
// and a timeout; here it needs neither, and users get capture groups.

// MaxTriggers bounds how many rules one connection may carry.
//
// Every rule is matched against every line of output, so this is a bound on
// work per byte as much as on configuration. Sixteen is more than anybody
// has, and small enough that a chatty device cannot become expensive.
const MaxTriggers = 16

// DefaultTriggerFires is how many times a rule may fire in one session unless
// it says otherwise.
//
// A cap rather than unlimited, and it is load-bearing in two ways. A trigger
// whose Send produces output matching its own Expect is an infinite loop, and
// this is what stops it. And a device that prints "assword:" in a loop must
// not be handed the credential ten thousand times.
const DefaultTriggerFires = 25

// TriggerAction is what a rule does when it matches.
type TriggerAction string

const (
	// TriggerSend types something at the device.
	TriggerSend TriggerAction = "send"

	// TriggerNotify raises a notice in the browser and nothing else. The
	// most useful action there is, and the only one that cannot go wrong.
	TriggerNotify TriggerAction = "notify"

	// TriggerHighlight marks the matching text. Handled entirely in the
	// browser — the server does not draw anything — but the rule lives here
	// with the others so there is one list to read rather than two.
	TriggerHighlight TriggerAction = "highlight"

	// TriggerStop ends the session. For a match that means something has
	// gone badly wrong and continuing would make it worse.
	TriggerStop TriggerAction = "stop"
)

// Validate rejects an unknown action.
func (a TriggerAction) Validate() error {
	switch a {
	case TriggerSend, TriggerNotify, TriggerHighlight, TriggerStop:
		return nil
	}
	return fmt.Errorf("sessions: %q is not a trigger action", a)
}

// RunsOnTheServer reports whether this action is the server's to perform.
//
// Highlighting is the browser's: the server has no idea what a colour is, and
// the text has to be marked as it is drawn. Everything else has to be the
// server's, because a trigger that answers a prompt during a long operation
// is most needed precisely when nobody is watching.
func (a TriggerAction) RunsOnTheServer() bool { return a != TriggerHighlight }

// Trigger is one rule.
type Trigger struct {
	// Name is what the interface shows and what the audit record names, so a
	// person reading either can tell which rule fired without matching
	// patterns by eye.
	Name string `json:"name"`

	// Pattern is a regular expression matched against each line of output.
	//
	// RE2, so no pattern can be slow. Capture groups are available in Send as
	// $1, $2 and so on, which is what makes "when you see 'Enable password
	// for (\w+)' send the password for that account" expressible at all.
	Pattern string `json:"pattern"`

	Action TriggerAction `json:"action"`

	// Send is what to type, for a send action. Understands %USERNAME%,
	// %PASSWORD% and the escapes, exactly as a logon step does — one syntax
	// for both, because they are the same idea at different moments.
	Send string `json:"send,omitempty"`

	// Colour names a highlight, for the browser. Free text rather than an
	// enumeration: the interface offers a palette and anything else is that
	// person's business.
	Colour string `json:"colour,omitempty"`

	// MaxFires bounds how many times this rule may fire in one session.
	// Zero means DefaultTriggerFires.
	MaxFires int `json:"max_fires,omitempty"`

	// Disabled keeps a rule without running it, which is what people
	// actually want when a trigger misfires at three in the morning.
	Disabled bool `json:"disabled,omitempty"`
}

// Validate checks one rule, compiling its pattern.
func (t Trigger) Validate() error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("sessions: a trigger needs a name")
	}
	if len(t.Name) > 64 {
		return fmt.Errorf("sessions: a trigger's name is limited to 64 characters")
	}
	if strings.TrimSpace(t.Pattern) == "" {
		return fmt.Errorf("sessions: %q has no pattern", t.Name)
	}
	if len(t.Pattern) > 512 {
		return fmt.Errorf("sessions: %q has a pattern longer than 512 characters", t.Name)
	}
	if err := t.Action.Validate(); err != nil {
		return err
	}
	if t.Action == TriggerSend && t.Send == "" {
		return fmt.Errorf("sessions: %q is a send trigger with nothing to send", t.Name)
	}
	if len(t.Send) > 512 {
		return fmt.Errorf("sessions: %q sends more than 512 characters", t.Name)
	}
	if t.MaxFires < 0 || t.MaxFires > 1000 {
		return fmt.Errorf("sessions: %q may fire at most 1000 times", t.Name)
	}

	// Compiled here so a pattern that does not parse is refused while
	// somebody is looking at the form, rather than silently never matching
	// on a device three weeks later.
	if _, err := regexp.Compile(t.Pattern); err != nil {
		return fmt.Errorf("sessions: %q has an invalid pattern: %w", t.Name, err)
	}
	return nil
}

// Fires reports how many times this rule may fire.
func (t Trigger) Fires() int {
	if t.MaxFires > 0 {
		return t.MaxFires
	}
	return DefaultTriggerFires
}

// ValidateTriggers checks a whole set.
func ValidateTriggers(triggers []Trigger) error {
	if len(triggers) > MaxTriggers {
		return fmt.Errorf("sessions: %d triggers is more than the %d allowed",
			len(triggers), MaxTriggers)
	}

	seen := map[string]bool{}
	for _, trigger := range triggers {
		if err := trigger.Validate(); err != nil {
			return err
		}
		if seen[trigger.Name] {
			// Two rules with one name make an audit record ambiguous, which
			// defeats the point of naming them.
			return fmt.Errorf("sessions: two triggers are both called %q", trigger.Name)
		}
		seen[trigger.Name] = true
	}
	return nil
}
