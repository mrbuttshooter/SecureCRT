package sessions

import (
	"fmt"
	"strings"
)

// Typing the password in, because telnet has nowhere to put it.
//
// SSH authenticates inside the protocol. Telnet does not, and neither does a
// serial line: there is a login prompt, and somebody types at it. So a stored
// credential stops being something the transport uses and becomes a sequence
// of keystrokes to send when the device asks — which is what SecureCRT calls
// Logon Actions and what makes an imported telnet tree usable rather than
// merely present.
//
// # Why the password is a placeholder and not a string
//
// Settings is a JSON document in an unencrypted column. That is deliberate
// and fine for a font size; it is emphatically not fine for a password. So a
// step sends %PASSWORD%, and the value is substituted at connect time from
// the credential the connection already names — decrypted under the user's
// vault key, used for the length of the logon, never written down.
//
// A user who types a literal password into a step instead has put a plaintext
// password in the database. The interface offers the placeholders rather than
// a free-text field for exactly that reason, and the documentation says so in
// as many words.

// Substitutions available in a step's Send.
const (
	// PlaceholderUsername is replaced by the connection's effective username.
	PlaceholderUsername = "%USERNAME%"

	// PlaceholderPassword is replaced by the named credential's secret.
	PlaceholderPassword = "%PASSWORD%"
)

// MaxLogonSteps bounds a sequence.
//
// Eight is more than any real login needs — the longest in practice is
// username, password, enable, enable password — and small enough that a
// pasted loop cannot turn a connection into a keystroke generator.
const MaxLogonSteps = 8

// LogonStep waits for something and then sends something.
type LogonStep struct {
	// Expect is matched against recent output, case-insensitively, as a
	// substring rather than a pattern. Alternatives are separated by "|" and
	// any one of them satisfies the step.
	//
	// Substrings and not regular expressions, on purpose. The things people
	// wait for are "ogin:" and "assword:" — deliberately clipped to survive
	// both "Login:" and "login:", which is the trick every terminal handbook
	// teaches — and a regular expression here would buy nothing but a way to
	// hang a connection on catastrophic backtracking.
	//
	// Alternation is not optional decoration either. Steps run in order, so a
	// sequence waiting for "ogin:" is stuck forever in front of a Cisco
	// device that says "Username:" — the step never matches, and every step
	// behind it waits on one that never fires. One step matching either is
	// the difference between a default that works on both and one that works
	// on Unix.
	//
	// Empty means send immediately, without waiting. Useful as a first step
	// for a console line that needs a keypress before it says anything.
	Expect string `json:"expect"`

	// Send is what to type. Understands %USERNAME% and %PASSWORD%, and the
	// escapes \r, \n and \t.
	Send string `json:"send"`
}

// Validate checks one step.
func (s LogonStep) Validate() error {
	if len(s.Expect) > 128 {
		return fmt.Errorf("sessions: a logon step's expect is limited to 128 characters")
	}
	if len(s.Send) > 512 {
		return fmt.Errorf("sessions: a logon step's send is limited to 512 characters")
	}
	if s.Expect == "" && s.Send == "" {
		return fmt.Errorf("sessions: a logon step must wait for something or send something")
	}
	return nil
}

// ValidateLogonSteps checks a whole sequence.
func ValidateLogonSteps(steps []LogonStep) error {
	if len(steps) > MaxLogonSteps {
		return fmt.Errorf("sessions: %d logon steps is more than the %d allowed",
			len(steps), MaxLogonSteps)
	}
	for i, step := range steps {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
	}
	return nil
}

// DefaultLogonSteps is what to send when a connection names a password and
// nobody has said how to use it.
//
// The clipped prompts are the point: "ogin:" matches Login, login and
// "Username login:", and "assword:" matches Password and password. Every
// network device and every Unix host in the world says one of those.
//
// Returned rather than applied silently — the interface shows this sequence
// as the default so a person can see what will be typed at their equipment
// before it is, which is not a courtesy anybody should have to ask for.
func DefaultLogonSteps() []LogonStep {
	return []LogonStep{
		{Expect: "ogin:|sername:", Send: PlaceholderUsername + "\\r"},
		{Expect: "assword:", Send: PlaceholderPassword + "\\r"},
	}
}

// Matches reports whether recent output satisfies this step.
//
// Case-insensitive, because the prompts are written both ways by different
// vendors and "Password:" failing to match a step that says "password:" is
// the kind of thing somebody debugs for an hour.
func (s LogonStep) Matches(recent string) bool {
	if s.Expect == "" {
		return true
	}
	lower := strings.ToLower(recent)
	for _, alternative := range strings.Split(s.Expect, "|") {
		alternative = strings.TrimSpace(alternative)
		if alternative == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(alternative)) {
			return true
		}
	}
	return false
}

// ExpandSend fills in a template's placeholders and escapes.
//
// See Expand. This is the case with no capture groups.
func ExpandSend(send, username, password string) string {
	return Expand(send, username, password, nil)
}

// Expand resolves a send template in a single pass.
//
// One pass is the security property, and it is worth being precise about why.
// A template contains three kinds of thing: escapes the user wrote, named
// placeholders standing for credentials, and — for a trigger — $1..$9
// standing for whatever the *device* printed. The first is trusted, the
// second is a secret, and the third is arbitrary bytes chosen by whatever is
// at the other end of the wire.
//
// Any "substitute, then scan again" arrangement lets something inserted by an
// earlier step be interpreted by a later one. Resolve escapes after
// substitution and a password containing the two characters \ and r becomes
// a carriage return, so a password chosen to hold \r followed by a command
// types that command at whatever privilege the login just granted. Expand
// captures before the escapes and a device gets the same primitive for free,
// by printing it.
//
// So this walks the template once and appends every substituted value
// verbatim. Nothing that goes in is ever looked at again.
func Expand(send, username, password string, captures []string) string {
	var b strings.Builder
	b.Grow(len(send))

	for i := 0; i < len(send); {
		switch {
		case send[i] == '\\' && i+1 < len(send):
			i++
			switch send[i] {
			case 'r':
				b.WriteByte('\r')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '\\':
				b.WriteByte('\\')
			default:
				// An escape nobody defined is left as written, so a Windows
				// path in a step does not quietly lose characters.
				b.WriteByte('\\')
				b.WriteByte(send[i])
			}
			i++

		case strings.HasPrefix(send[i:], PlaceholderUsername):
			b.WriteString(username)
			i += len(PlaceholderUsername)

		case strings.HasPrefix(send[i:], PlaceholderPassword):
			b.WriteString(password)
			i += len(PlaceholderPassword)

		case send[i] == '$' && i+1 < len(send) && send[i+1] >= '1' && send[i+1] <= '9':
			// A capture group holds whatever the device printed. Written
			// verbatim and never re-examined, which is the whole point.
			index := int(send[i+1] - '0')
			if index < len(captures) {
				b.WriteString(captures[index])
			}
			i += 2

		default:
			b.WriteByte(send[i])
			i++
		}
	}

	return b.String()
}

// SendsPassword reports whether a step would type the credential's secret.
//
// Used to decide whether a connection needs the vault open before it can be
// dialled, and to keep the audit record honest about what was sent without
// recording any of it.
func (s LogonStep) SendsPassword() bool {
	return strings.Contains(s.Send, PlaceholderPassword)
}
