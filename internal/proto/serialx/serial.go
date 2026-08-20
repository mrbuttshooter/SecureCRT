// Package serialx opens a serial line as a terminal.
//
// This only does anything where the machine running bkd is physically cabled
// to the device, which for a central deployment serving a whole company is
// almost never true. It suits a lab box on somebody's bench. The remote case
// — a rack of equipment reached over the network — is what console servers
// are for, and those speak SSH or telnet, which this system already does.
//
// # The security decision in this package
//
// The device path comes from a saved connection, which means it comes from a
// user. Without a guard, "open this path and stream it to my browser" is an
// arbitrary-file-read primitive on a server that holds every engineer's
// encrypted credentials — and a character-device check alone does not save
// it, because /dev/mem and /dev/sda are character and block devices that
// nobody should be able to hand themselves.
//
// So there are three gates, and all of them apply:
//
//  1. policy.allow_serial, off by default. Most installations are not cabled
//     to anything and should not carry the code path at all.
//  2. serial.allowed_devices, a list of globs with no default. An operator
//     names the ports that exist — /dev/ttyUSB*, /dev/ttyS[0-3] — and nothing
//     else can be opened whatever anybody types.
//  3. The opened file must be a character device, checked on the descriptor
//     after opening rather than on the path before, so nothing can be swapped
//     underneath in between.
//
// Symbolic links are resolved before the allowlist is consulted and the final
// component is opened with O_NOFOLLOW, so a link cannot be used to reach
// something the globs do not name.
package serialx

import (
	"errors"
	"fmt"
	"strings"
)

// Errors callers distinguish.
var (
	// ErrNotAllowed means the path is not one this server may open.
	ErrNotAllowed = errors.New("serialx: that device is not in the allowed list")

	// ErrNotADevice means the path is not a character device.
	ErrNotADevice = errors.New("serialx: that path is not a serial device")

	// ErrBusy means something already has the port.
	ErrBusy = errors.New("serialx: that device is already open")

	// ErrUnsupported means this build cannot open serial ports.
	ErrUnsupported = errors.New("serialx: serial ports are not supported on this platform")
)

// Parity is the parity setting.
type Parity string

const (
	ParityNone Parity = "none"
	ParityEven Parity = "even"
	ParityOdd  Parity = "odd"
)

// Validate rejects an unknown parity.
func (p Parity) Validate() error {
	switch p {
	case ParityNone, ParityEven, ParityOdd:
		return nil
	}
	return fmt.Errorf("serialx: unknown parity %q", p)
}

// FlowControl is the handshaking setting.
type FlowControl string

const (
	// FlowNone is what console cables almost always want. Half the reason a
	// console shows nothing is a cable with no handshake lines and a port
	// configured to wait for them.
	FlowNone FlowControl = "none"

	// FlowRTSCTS is hardware handshaking.
	FlowRTSCTS FlowControl = "rtscts"

	// FlowXONXOFF is software handshaking, which eats Ctrl-S and Ctrl-Q.
	FlowXONXOFF FlowControl = "xonxoff"
)

// Validate rejects an unknown flow control setting.
func (f FlowControl) Validate() error {
	switch f {
	case FlowNone, FlowRTSCTS, FlowXONXOFF:
		return nil
	}
	return fmt.Errorf("serialx: unknown flow control %q", f)
}

// Defaults, which are the console defaults of essentially all network
// equipment: 9600 8N1, no handshaking.
const (
	DefaultBaud     = 9600
	DefaultDataBits = 8
	DefaultStopBits = 1
)

// Config describes a serial line.
type Config struct {
	// Device is the port's path.
	Device string

	Baud     int
	DataBits int
	StopBits int
	Parity   Parity
	Flow     FlowControl

	// Allowed is the operator's list of globs. An empty list opens nothing,
	// which is the safe default rather than an oversight: a server with the
	// feature switched on and no ports named is a server with no ports.
	Allowed []string
}

// withDefaults fills in the console settings for anything unset.
func (c Config) withDefaults() Config {
	if c.Baud == 0 {
		c.Baud = DefaultBaud
	}
	if c.DataBits == 0 {
		c.DataBits = DefaultDataBits
	}
	if c.StopBits == 0 {
		c.StopBits = DefaultStopBits
	}
	if c.Parity == "" {
		c.Parity = ParityNone
	}
	if c.Flow == "" {
		c.Flow = FlowNone
	}
	return c
}

// Validate checks the settings without opening anything.
func (c Config) Validate() error {
	c = c.withDefaults()

	if strings.TrimSpace(c.Device) == "" {
		return errors.New("serialx: a device path is required")
	}
	if !validBaud(c.Baud) {
		return fmt.Errorf("serialx: %d is not a baud rate this supports", c.Baud)
	}
	if c.DataBits < 5 || c.DataBits > 8 {
		return fmt.Errorf("serialx: %d data bits is out of range", c.DataBits)
	}
	if c.StopBits != 1 && c.StopBits != 2 {
		return fmt.Errorf("serialx: %d stop bits is out of range", c.StopBits)
	}
	if err := c.Parity.Validate(); err != nil {
		return err
	}
	return c.Flow.Validate()
}

// Summary renders the line settings the way a console label does.
//
// "9600 8N1" is the first thing somebody checks when a console shows nothing
// but rubbish, so the terminal header says it without being asked.
func (c Config) Summary() string {
	c = c.withDefaults()

	parity := "N"
	switch c.Parity {
	case ParityEven:
		parity = "E"
	case ParityOdd:
		parity = "O"
	}

	out := fmt.Sprintf("%d %d%s%d", c.Baud, c.DataBits, parity, c.StopBits)
	if c.Flow != FlowNone {
		out += " " + string(c.Flow)
	}
	return out
}

// validBaud reports whether a rate is one termios can be told about.
func validBaud(baud int) bool {
	_, ok := baudRates[baud]
	return ok
}

// BaudRates lists the supported rates, for the interface's dropdown.
func BaudRates() []int {
	return []int{
		300, 1200, 2400, 4800, 9600, 19200, 38400,
		57600, 115200, 230400, 460800, 921600,
	}
}
