package serialx

import (
	"fmt"
	"sync"
)

// One line, one terminal.
//
// A serial port is a single wire. The kernel will happily let two processes
// write to the same tty at once, and the result is two people's keystrokes
// interleaved character by character into a device that has no idea anything
// is wrong — a switch receiving "cofnigure tremrinal" and reporting a syntax
// error nobody typed.
//
// TIOCEXCL exists for this and is worth setting, but it only defends against
// other processes on this machine and says nothing useful to the second
// person here. So the claim is tracked in this process too, where it can
// answer the question somebody actually has: not "the device is busy" but
// "Priya has it open".

// Registry tracks which device each user's terminal holds.
type Registry struct {
	mu   sync.Mutex
	held map[string]claim
}

type claim struct {
	// UserID and Label describe who has it, so the refusal can say.
	UserID string
	Label  string
}

// InUseError names the holder.
type InUseError struct {
	Device string
	Label  string

	// SameUser distinguishes "somebody else has this" from "you have this
	// open in another tab", which need different sentences: one is a request
	// to wait, the other is a reminder.
	SameUser bool
}

func (e *InUseError) Error() string {
	if e.SameUser {
		return fmt.Sprintf("serialx: %s is already open in your %s session",
			e.Device, e.Label)
	}
	return fmt.Sprintf("serialx: %s is in use by somebody else", e.Device)
}

func (e *InUseError) Unwrap() error { return ErrBusy }

// NewRegistry builds a Registry.
func NewRegistry() *Registry {
	return &Registry{held: map[string]claim{}}
}

// Claim takes a device, or reports who has it.
//
// The returned release is idempotent and safe to call from a deferred
// close — a port whose claim outlived it would lock the line out until a
// restart, which on a lab bench means walking over to unplug something.
func (r *Registry) Claim(device, userID, label string) (release func(), err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, taken := r.held[device]; taken {
		return nil, &InUseError{
			Device:   device,
			Label:    existing.Label,
			SameUser: existing.UserID == userID,
		}
	}

	r.held[device] = claim{UserID: userID, Label: label}

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.held, device)
			r.mu.Unlock()
		})
	}, nil
}

// Held reports how many devices are claimed, for tests and metrics.
func (r *Registry) Held() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.held)
}
