//go:build !linux

package serialx

// Serial ports are a Linux facility here.
//
// The deployment target is a Linux server, and termios is not portable in any
// way that would survive being written once. Other platforms build — the rest
// of this package is configuration and validation, and the tests for it run
// everywhere — and opening a port reports that it cannot.

// baudRates keeps Validate working off-Linux, so a configuration can be
// checked on a developer's machine even where a port cannot be opened.
var baudRates = map[int]uint32{
	300: 0, 1200: 0, 2400: 0, 4800: 0, 9600: 0, 19200: 0, 38400: 0,
	57600: 0, 115200: 0, 230400: 0, 460800: 0, 921600: 0,
}

// Port is not available on this platform.
type Port struct{}

// Open reports that this build cannot open serial ports.
func Open(Config) (*Port, error) { return nil, ErrUnsupported }

func (p *Port) Read([]byte) (int, error)  { return 0, ErrUnsupported }
func (p *Port) Write([]byte) (int, error) { return 0, ErrUnsupported }
func (p *Port) Resize(int, int) error     { return nil }
func (p *Port) Wait() error               { return ErrUnsupported }
func (p *Port) Close() error              { return nil }
func (p *Port) Device() string            { return "" }
func (p *Port) Summary() string           { return "" }
