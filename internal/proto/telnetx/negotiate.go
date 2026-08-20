package telnetx

import "sync"

// Option negotiation, by RFC 1143's state machine rather than by reflex.
//
// The naive implementation — answer every WILL with a DO, every DO with a
// WILL — loops forever against a peer that does the same, because each
// agreement looks like a fresh offer to the other end. RFC 1143 calls this the
// Q Method and exists entirely to stop it: each option is tracked in one of
// four states, and an agreement that merely confirms what is already agreed
// is answered with silence.
//
// It matters here more than it would elsewhere. The equipment this talks to
// is old, and old telnet stacks renegotiate at moments that surprise people —
// after a login, on a terminal-type change, when a console server switches
// lines. A loop against a switch is not a hung goroutine, it is a switch
// receiving a hundred thousand packets a second.

// optionState is one side of one option.
type optionState int

const (
	// stateNo is not enabled and not asked for.
	stateNo optionState = iota

	// stateYes is enabled.
	stateYes

	// stateWantNo is a disable in flight.
	stateWantNo

	// stateWantYes is an enable in flight.
	stateWantYes
)

// options tracks both directions for every option.
//
// "us" is what this end will do; "him" is what the far end will do. The RFC's
// vocabulary, kept deliberately: anybody reading this alongside RFC 1143 is
// having a bad enough day already.
type options struct {
	mu  sync.Mutex
	us  map[byte]optionState
	him map[byte]optionState
}

func newOptions() *options {
	return &options{
		us:  map[byte]optionState{},
		him: map[byte]optionState{},
	}
}

// enabledLocally reports whether this end has agreed to do opt.
func (o *options) enabledLocally(opt byte) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.us[opt] == stateYes
}

// enabledRemotely reports whether the far end has agreed to do opt.
func (o *options) enabledRemotely(opt byte) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.him[opt] == stateYes
}

// reply is what to send in response to a negotiation, or nothing.
type reply struct {
	send    bool
	command byte
	option  byte
}

// wantLocal is what this end offers to do, unasked, at the start of a session.
//
// Kept short on purpose. Every option offered is one the peer must answer, and
// a device from 2004 answering four questions is more reliable than the same
// device answering fourteen.
func wantLocal() []byte {
	return []byte{OptSuppressGA, OptTerminalType, OptNAWS, OptBinary}
}

// wantRemote is what this end asks the peer to do.
func wantRemote() []byte {
	return []byte{OptSuppressGA, OptEcho, OptBinary}
}

// supportedLocal reports whether this end is willing to do opt when asked.
//
// Anything absent gets a WONT, which is the part people forget: an option
// nobody implements still has to be refused out loud, because a peer that
// waits for the answer simply hangs.
func supportedLocal(opt byte) bool {
	switch opt {
	case OptSuppressGA, OptTerminalType, OptNAWS, OptBinary:
		return true
	}
	return false
}

// supportedRemote reports whether this end wants the peer to do opt.
func supportedRemote(opt byte) bool {
	switch opt {
	case OptSuppressGA, OptEcho, OptBinary, OptEndOfRecord:
		return true
	}
	return false
}

// offerLocal starts negotiation for something this end wants to do.
func (o *options) offerLocal(opt byte) reply {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.us[opt] != stateNo {
		return reply{} // already agreed, or already asked
	}
	o.us[opt] = stateWantYes
	return reply{send: true, command: WILL, option: opt}
}

// askRemote starts negotiation for something this end wants the peer to do.
func (o *options) askRemote(opt byte) reply {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.him[opt] != stateNo {
		return reply{}
	}
	o.him[opt] = stateWantYes
	return reply{send: true, command: DO, option: opt}
}

// receiveWill handles the peer offering to do opt.
func (o *options) receiveWill(opt byte) reply {
	o.mu.Lock()
	defer o.mu.Unlock()

	switch o.him[opt] {
	case stateNo:
		if supportedRemote(opt) {
			o.him[opt] = stateYes
			return reply{send: true, command: DO, option: opt}
		}
		return reply{send: true, command: DONT, option: opt}

	case stateYes:
		// Already agreed. Answering would restart the exchange, which is the
		// loop this whole file exists to prevent.
		return reply{}

	case stateWantNo:
		// A disable was in flight and the peer says it will after all. Take
		// it as done and say nothing; the RFC's error case, resolved the
		// quiet way.
		o.him[opt] = stateNo
		return reply{}

	case stateWantYes:
		o.him[opt] = stateYes
		return reply{}
	}
	return reply{}
}

// receiveWont handles the peer declining, or withdrawing, opt.
func (o *options) receiveWont(opt byte) reply {
	o.mu.Lock()
	defer o.mu.Unlock()

	switch o.him[opt] {
	case stateNo:
		return reply{}
	case stateYes:
		o.him[opt] = stateNo
		return reply{send: true, command: DONT, option: opt}
	case stateWantNo, stateWantYes:
		o.him[opt] = stateNo
		return reply{}
	}
	return reply{}
}

// receiveDo handles the peer asking this end to do opt.
func (o *options) receiveDo(opt byte) reply {
	o.mu.Lock()
	defer o.mu.Unlock()

	switch o.us[opt] {
	case stateNo:
		if supportedLocal(opt) {
			o.us[opt] = stateYes
			return reply{send: true, command: WILL, option: opt}
		}
		return reply{send: true, command: WONT, option: opt}

	case stateYes:
		return reply{}

	case stateWantNo:
		o.us[opt] = stateNo
		return reply{}

	case stateWantYes:
		o.us[opt] = stateYes
		return reply{}
	}
	return reply{}
}

// receiveDont handles the peer asking this end to stop doing opt.
func (o *options) receiveDont(opt byte) reply {
	o.mu.Lock()
	defer o.mu.Unlock()

	switch o.us[opt] {
	case stateNo:
		return reply{}
	case stateYes:
		o.us[opt] = stateNo
		return reply{send: true, command: WONT, option: opt}
	case stateWantNo, stateWantYes:
		o.us[opt] = stateNo
		return reply{}
	}
	return reply{}
}

// agreed lists the options in force, for the terminal header.
func (o *options) agreed() []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	var out []string
	for _, opt := range []byte{OptBinary, OptEcho, OptSuppressGA, OptTerminalType, OptNAWS} {
		switch {
		case o.us[opt] == stateYes && o.him[opt] == stateYes:
			out = append(out, optionName(opt))
		case o.him[opt] == stateYes:
			out = append(out, optionName(opt)+"(remote)")
		case o.us[opt] == stateYes:
			out = append(out, optionName(opt)+"(local)")
		}
	}
	return out
}
