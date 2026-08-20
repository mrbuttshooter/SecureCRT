//go:build linux

package serialx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// baudRates maps a rate to its termios constant.
//
// Written out rather than computed: the constants are not a sequence, and
// termios has no arithmetic relationship between the number and the flag.
var baudRates = map[int]uint32{
	300:    unix.B300,
	1200:   unix.B1200,
	2400:   unix.B2400,
	4800:   unix.B4800,
	9600:   unix.B9600,
	19200:  unix.B19200,
	38400:  unix.B38400,
	57600:  unix.B57600,
	115200: unix.B115200,
	230400: unix.B230400,
	460800: unix.B460800,
	921600: unix.B921600,
}

// Port is an open serial line, satisfying terminal.Shell.
type Port struct {
	file   *os.File
	cfg    Config
	device string // the resolved path, which is what was actually opened

	closeOnce sync.Once
	done      chan struct{}

	mu      sync.Mutex
	failure error
}

// Open configures and opens a serial port.
func Open(cfg Config) (*Port, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Resolved before the allowlist is consulted, so a symbolic link cannot
	// be used to reach something the globs do not name.
	device, err := filepath.EvalSymlinks(cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("serialx: %s: %w", cfg.Device, err)
	}
	if !allowed(device, cfg.Allowed) {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowed, cfg.Device)
	}

	// O_NOCTTY so this never becomes the process's controlling terminal — a
	// hangup on the far end would otherwise deliver SIGHUP to bkd itself.
	// O_NONBLOCK because a port whose carrier-detect line is low blocks in
	// open() forever otherwise, and a console cable with no DCD is the
	// ordinary case rather than a fault.
	// O_NOFOLLOW because the final component was already resolved; anything
	// still a link here appeared between then and now.
	fd, err := unix.Open(device,
		unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("%w: %s", ErrBusy, device)
		}
		return nil, fmt.Errorf("serialx: opening %s: %w", device, err)
	}

	// Checked on the descriptor rather than on the path, so nothing can be
	// swapped underneath between the check and the open.
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("serialx: %s: %w", device, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s", ErrNotADevice, device)
	}

	if err := applyTermios(fd, cfg); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	// Left non-blocking so Go's poller owns the descriptor: that is what
	// makes Close unblock a Read that is waiting on a silent console, rather
	// than leaving a goroutine parked on it until the process exits.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("serialx: %s: %w", device, err)
	}

	return &Port{
		file:   os.NewFile(uintptr(fd), device),
		cfg:    cfg,
		device: device,
		done:   make(chan struct{}),
	}, nil
}

// applyTermios puts the line into raw mode with the requested framing.
func applyTermios(fd int, cfg Config) error {
	term, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return fmt.Errorf("serialx: reading the line settings: %w", err)
	}

	speed := baudRates[cfg.Baud]

	// Raw. Every one of these off matters for a console: canonical mode would
	// hold input until a newline, echo would double every character now that
	// the far end is doing it, and the signal characters would turn a Ctrl-C
	// meant for a switch into one for bkd.
	term.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	term.Oflag &^= unix.OPOST
	term.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	term.Cflag &^= unix.CSIZE | unix.PARENB | unix.PARODD | unix.CSTOPB | unix.CRTSCTS

	// CLOCAL: ignore the modem control lines. A three-wire console cable has
	// no carrier detect, and without this the port waits for one that will
	// never come. CREAD: actually receive.
	term.Cflag |= unix.CLOCAL | unix.CREAD

	switch cfg.DataBits {
	case 5:
		term.Cflag |= unix.CS5
	case 6:
		term.Cflag |= unix.CS6
	case 7:
		term.Cflag |= unix.CS7
	default:
		term.Cflag |= unix.CS8
	}

	switch cfg.Parity {
	case ParityEven:
		term.Cflag |= unix.PARENB
	case ParityOdd:
		term.Cflag |= unix.PARENB | unix.PARODD
	}

	if cfg.StopBits == 2 {
		term.Cflag |= unix.CSTOPB
	}

	switch cfg.Flow {
	case FlowRTSCTS:
		term.Cflag |= unix.CRTSCTS
	case FlowXONXOFF:
		term.Iflag |= unix.IXON | unix.IXOFF
	}

	// The speed lives in the low bits of Cflag on Linux, in both the input
	// and output positions.
	term.Cflag &^= unix.CBAUD
	term.Cflag |= speed
	term.Ispeed = speed
	term.Ospeed = speed

	// VMIN 1, VTIME 0: return as soon as there is a byte, wait forever if
	// there is not. The poller handles the waiting.
	term.Cc[unix.VMIN] = 1
	term.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, term); err != nil {
		return fmt.Errorf("serialx: applying the line settings: %w", err)
	}
	return nil
}

// allowed reports whether a resolved path matches any of the globs.
func allowed(device string, globs []string) bool {
	for _, glob := range globs {
		glob = filepath.Clean(glob)
		if ok, err := filepath.Match(glob, device); err == nil && ok {
			return true
		}
	}
	return false
}

// Read returns bytes from the line.
func (p *Port) Read(b []byte) (int, error) {
	n, err := p.file.Read(b)
	if err != nil {
		p.fail(err)
	}
	return n, err
}

// Write sends bytes down the line.
func (p *Port) Write(b []byte) (int, error) {
	n, err := p.file.Write(b)
	if err != nil {
		p.fail(err)
	}
	return n, err
}

// Resize does nothing.
//
// A serial line has no window: it is a wire carrying characters, and the
// device at the far end knows what it thinks the terminal is because
// somebody typed `terminal width 132` into it years ago. Returning an error
// would make every browser resize look like a failure.
func (p *Port) Resize(int, int) error { return nil }

// Wait blocks until the port is closed.
//
// A serial line has no end of its own — no hangup, no exit status, nothing to
// report. It stops when this end stops.
func (p *Port) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failure
}

// Close releases the port.
func (p *Port) Close() error {
	var err error
	p.closeOnce.Do(func() {
		err = p.file.Close()
		close(p.done)
	})
	return err
}

func (p *Port) fail(err error) {
	p.mu.Lock()
	if p.failure == nil && err != nil && !errors.Is(err, os.ErrClosed) {
		p.failure = err
	}
	p.mu.Unlock()
}

// Device is the path that was actually opened, after symbolic links.
func (p *Port) Device() string { return p.device }

// Summary renders the line settings.
func (p *Port) Summary() string { return p.cfg.Summary() }
