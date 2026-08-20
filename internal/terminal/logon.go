package terminal

import (
	"sync"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// Running a login sequence, in band.
//
// This wraps a Shell rather than running before one is handed over, and that
// is the design decision worth defending. A pre-roll that read and wrote the
// socket directly would be simpler — and the whole exchange would happen
// before the terminal existed, so the user would arrive at a prompt with no
// idea what had been typed at their equipment on their behalf. Wrapping means
// every byte still passes through to the replay buffer: the login appears in
// the scrollback exactly as though they had typed it, which is what makes an
// automated login auditable by the person it was done for.
//
// It also means a sequence that goes wrong is visible rather than mysterious.
// A device that asks something unexpected shows the question, the automation
// runs out of steps, and the user takes over mid-screen.

const (
	// LogonTimeout bounds the whole sequence.
	//
	// Generous, because the thing being waited for is a device that may take
	// twenty seconds to print a banner over a 9600-baud console. When it
	// expires the automation simply stops and the user types; the terminal is
	// not closed, because a login that did not complete is a session somebody
	// can still rescue by hand.
	LogonTimeout = 90 * time.Second

	// logonWindow is how much recent output a prompt is matched against.
	//
	// Sized to a prompt, not to a screen. A device that prints a legal notice
	// containing the word "password" must not satisfy a step waiting for a
	// password prompt several lines later, and the only thing standing
	// between those two is how far back this looks. Two lines is enough to
	// span a prompt split across several reads and short enough that a
	// banner a paragraph earlier has already scrolled out.
	//
	// It is not a guarantee. A banner whose last line mentions a password
	// immediately before the real prompt will still match, which is a
	// limitation this shares with every expect-style tool ever written. The
	// mitigation is that the whole exchange is visible in the scrollback,
	// so a sequence that went to the wrong place can be seen to have done so.
	logonWindow = 128
)

// logonShell performs a login sequence while passing everything through.
type logonShell struct {
	Shell

	mu       sync.Mutex
	steps    []sessions.LogonStep
	username string
	password string
	window   []byte
	deadline time.Time
	done     bool

	// sent counts the steps that fired, for the audit record. The steps
	// themselves are never recorded: one of them contains a password.
	sent int
}

// WithLogon returns shell wrapped in a login sequence.
//
// Returns the shell unchanged when there is nothing to do, so the ordinary
// case adds no layer and no allocation.
func WithLogon(shell Shell, steps []sessions.LogonStep, username, password string) Shell {
	if len(steps) == 0 {
		return shell
	}
	return &logonShell{
		Shell:    shell,
		steps:    steps,
		username: username,
		password: password,
		deadline: time.Now().Add(LogonTimeout),
	}
}

// Read passes output through, watching it for the prompt the next step wants.
func (l *logonShell) Read(p []byte) (int, error) {
	n, err := l.Shell.Read(p)
	if n > 0 {
		l.observe(p[:n])
	}
	return n, err
}

// observe advances the sequence as far as the new output allows.
func (l *logonShell) observe(chunk []byte) {
	l.mu.Lock()

	if l.done {
		l.mu.Unlock()
		return
	}
	if time.Now().After(l.deadline) {
		// Out of time. The terminal keeps working; the user finishes the
		// login themselves, which they can only do because this never took
		// the shell away from them.
		l.done = true
		l.mu.Unlock()
		return
	}

	l.window = append(l.window, chunk...)
	if len(l.window) > logonWindow {
		l.window = l.window[len(l.window)-logonWindow:]
	}

	var toSend []string
	for len(l.steps) > 0 {
		step := l.steps[0]
		if !step.Matches(string(l.window)) {
			break
		}

		l.steps = l.steps[1:]
		l.sent++
		if step.Send != "" {
			toSend = append(toSend,
				sessions.ExpandSend(step.Send, l.username, l.password))
		}

		// The window is cleared after a step fires, so the prompt that
		// satisfied this one cannot also satisfy the next. Without it a
		// device echoing "Username: admin" would match a second step waiting
		// for "sername:" and send the username twice.
		l.window = l.window[:0]
	}

	if len(l.steps) == 0 {
		l.done = true
	}
	l.mu.Unlock()

	// Written outside the lock: Write goes to the far end and can block, and
	// holding the mutex through it would stall the next Read — which is the
	// only thing that will ever release it.
	for _, out := range toSend {
		if _, err := l.Shell.Write([]byte(out)); err != nil {
			l.mu.Lock()
			l.done = true
			l.mu.Unlock()
			return
		}
	}
}

// Write passes keystrokes through and abandons the sequence.
//
// Somebody typing has taken over. Continuing to inject would fight them for
// the keyboard, and the classic result is a password sent into a shell prompt
// and then into the scrollback, the command history and the syslog of a
// device somebody else administers.
func (l *logonShell) Write(p []byte) (int, error) {
	if len(p) > 0 {
		l.mu.Lock()
		l.done = true
		l.mu.Unlock()
	}
	return l.Shell.Write(p)
}

// StepsSent reports how many steps fired, for the record.
func (l *logonShell) StepsSent() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sent
}
