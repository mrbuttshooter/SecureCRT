// Package telnetx speaks Telnet to network equipment.
//
// Telnet is a 1983 protocol with no authentication, no integrity and no
// encryption, and it is the only way into a great deal of equipment that is
// still carrying production traffic — console servers, older switches, PDUs,
// anything whose management plane predates its owner's security policy. bkd
// supports it for the same reason it reads SecureCRT's password format: the
// alternative is not that people stop, it is that they use something with no
// audit log.
//
// What that costs is stated wherever a person can see it rather than buried
// here: the tab is marked, the audit record carries encrypted=false, and the
// logon automation that types a password into a device is refused unless the
// operator has allowed telnet at all.
//
// # What this implements
//
// RFC 854 (the protocol), RFC 855 (options), and the four options that decide
// whether a session is usable:
//
//   - ECHO (RFC 857). Who echoes typed characters. Get this wrong and the
//     user sees every keystroke twice, or sees their password on screen.
//   - SUPPRESS-GO-AHEAD (RFC 858). Character-at-a-time rather than
//     line-at-a-time. Every modern peer wants it; without it an interactive
//     shell does not work at all.
//   - TERMINAL-TYPE (RFC 1091). What the far end thinks it is drawing to.
//   - NAWS (RFC 1073). The window size, so full-screen tools draw correctly
//     and follow a browser resize.
//
// BINARY (RFC 856) is negotiated in both directions, which is what makes a
// UTF-8 terminal work: without it the protocol is 7-bit and every accented
// character or box-drawing glyph arrives mangled.
//
// Everything else the far end offers is refused, politely and by the rules —
// DONT to a WILL, WONT to a DO. An option this does not implement must be
// answered rather than ignored, or a peer that waits for the answer hangs.
package telnetx

// Protocol bytes. Named as RFC 854 names them, because anybody debugging this
// will have the RFC open beside it.
const (
	// IAC introduces a command. 255, which is also why a literal 255 in the
	// data stream has to be doubled.
	IAC byte = 255

	DONT byte = 254
	DO   byte = 253
	WONT byte = 252
	WILL byte = 251

	// SB and SE bracket a subnegotiation — the option's own payload.
	SB byte = 250
	SE byte = 240

	// The commands below are read and discarded rather than acted on. A peer
	// may send them; none needs a response, and treating an unknown one as
	// data would corrupt the stream.
	GA   byte = 249 // go ahead
	EL   byte = 248 // erase line
	EC   byte = 247 // erase character
	AYT  byte = 246 // are you there
	AO   byte = 245 // abort output
	IP   byte = 244 // interrupt process
	BRK  byte = 243 // break
	DM   byte = 242 // data mark
	NOP  byte = 241 // no operation
	EOR  byte = 239 // end of record
	ABRT byte = 238
	SUSP byte = 237
	EOF_ byte = 236
)

// Options.
const (
	OptBinary        byte = 0  // RFC 856
	OptEcho          byte = 1  // RFC 857
	OptSuppressGA    byte = 3  // RFC 858
	OptStatus        byte = 5  // RFC 859
	OptTimingMark    byte = 6  // RFC 860
	OptTerminalType  byte = 24 // RFC 1091
	OptEndOfRecord   byte = 25 // RFC 885
	OptNAWS          byte = 31 // RFC 1073
	OptTerminalSpeed byte = 32 // RFC 1079
	OptRemoteFlow    byte = 33 // RFC 1372
	OptLinemode      byte = 34 // RFC 1184
	OptEnvironment   byte = 36 // RFC 1408
	OptNewEnviron    byte = 39 // RFC 1572
)

// Terminal-type subnegotiation commands, RFC 1091.
const (
	terminalTypeIS   byte = 0
	terminalTypeSEND byte = 1
)

// optionName renders an option for a log line. Unknown numbers are printed as
// numbers rather than guessed at.
func optionName(opt byte) string {
	switch opt {
	case OptBinary:
		return "binary"
	case OptEcho:
		return "echo"
	case OptSuppressGA:
		return "suppress-go-ahead"
	case OptStatus:
		return "status"
	case OptTimingMark:
		return "timing-mark"
	case OptTerminalType:
		return "terminal-type"
	case OptEndOfRecord:
		return "end-of-record"
	case OptNAWS:
		return "naws"
	case OptTerminalSpeed:
		return "terminal-speed"
	case OptRemoteFlow:
		return "remote-flow-control"
	case OptLinemode:
		return "linemode"
	case OptEnvironment, OptNewEnviron:
		return "environment"
	}
	return "option " + itoa(int(opt))
}

// itoa avoids pulling strconv into a file that is otherwise all constants.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
