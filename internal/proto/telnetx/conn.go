package telnetx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Defaults.
const (
	// DefaultConnectTimeout matches the SSH dialler's. Equipment on a slow
	// out-of-band link is exactly what this is for.
	DefaultConnectTimeout = 60 * time.Second

	// DefaultTerminalType is what the far end is told it is drawing to.
	// xterm-256color because that is what xterm.js actually is, and claiming
	// vt100 would lose colour on every device that checks.
	DefaultTerminalType = "xterm-256color"

	// readBufferSize is one TCP-ish chunk. Telnet peers send small writes;
	// this is comfortably larger than anything a switch emits at once.
	readBufferSize = 8 * 1024
)

// ErrClosed is returned by a connection that has been closed.
var ErrClosed = errors.New("telnetx: connection closed")

// EchoMode decides who echoes typed characters.
type EchoMode int

const (
	// EchoAuto follows negotiation, assuming the far end echoes until it says
	// otherwise. This is what every interactive device does and what PuTTY
	// calls "auto"; the alternative default — echo locally until told not to
	// — shows every character twice on the overwhelmingly common path.
	EchoAuto EchoMode = iota

	// EchoLocal always echoes here. For a peer that negotiates nothing and
	// echoes nothing, which is rare but does exist.
	EchoLocal

	// EchoRemote never echoes here.
	EchoRemote
)

// Config describes a telnet session.
type Config struct {
	// Address is host:port.
	Address string

	// TerminalType is reported to the far end. Empty uses the default.
	TerminalType string

	// Echo decides who echoes. EchoAuto is almost always right.
	Echo EchoMode

	// ConnectTimeout bounds reaching the host.
	ConnectTimeout time.Duration

	// Cols and Rows seed the window size sent once NAWS is agreed.
	Cols, Rows int

	// Dial opens the byte stream. Nil dials TCP directly; a console server
	// behind a jump host supplies one that opens a channel instead — the same
	// injection sshx uses, and for the same reason.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
}

// Conn is one telnet session, satisfying terminal.Shell.
type Conn struct {
	conn net.Conn
	cfg  Config
	opts *options

	// writeMu serialises the two writers: the user's keystrokes and the
	// negotiation replies the read loop emits. Interleaving them would splice
	// an IAC sequence through the middle of somebody's command.
	writeMu sync.Mutex

	// data carries application bytes from the reader goroutine to Read.
	//
	// A goroutine rather than parsing inside Read, and that is not a style
	// choice. Negotiation is a conversation: a peer that offers an option
	// waits for the answer before doing anything else, and if the answer only
	// gets sent when the application happens to call Read, a session where
	// nobody is reading yet — one being logged into automatically, one whose
	// window was resized before the first byte arrived — stalls with both
	// ends waiting for the other. The socket is drained always.
	//
	// Bounded, so a device flooding output pushes back through TCP rather
	// than into this process's heap. The same flow control the SSH path gets
	// from its window.
	data    chan []byte
	partial []byte
	scratch []byte

	// state is the IAC parser's position between reads. A command can be
	// split across two socket reads, and treating the halves independently
	// would emit the option byte as data.
	state    parserState
	command  byte
	sbOption byte
	sbSeen   bool
	sbBuf    []byte

	cols, rows int

	// remoteRefusedEcho is set when the far end has explicitly said it will
	// not echo. Not the same as "has not agreed": before anything is
	// negotiated the far end is assumed to echo, because every interactive
	// device does, and assuming otherwise doubles every character on the
	// overwhelmingly common path.
	remoteRefusedEcho bool

	closeOnce sync.Once
	done      chan struct{}

	mu      sync.Mutex
	closed  bool
	failure error
}

type parserState int

const (
	stateData parserState = iota
	stateIAC
	stateOption
	stateSubneg
	stateSubnegIAC
)

// Dial opens a telnet session.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	if cfg.Address == "" {
		return nil, errors.New("telnetx: an address is required")
	}
	if cfg.TerminalType == "" {
		cfg.TerminalType = DefaultTerminalType
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.Cols <= 0 {
		cfg.Cols = 80
	}
	if cfg.Rows <= 0 {
		cfg.Rows = 24
	}

	dial := cfg.Dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	netConn, err := dial(dialCtx, cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("telnetx: reaching %s: %w", cfg.Address, err)
	}

	c := &Conn{
		conn:    netConn,
		cfg:     cfg,
		opts:    newOptions(),
		scratch: make([]byte, readBufferSize),
		data:    make(chan []byte, 64),
		cols:    cfg.Cols,
		rows:    cfg.Rows,
		done:    make(chan struct{}),
	}

	// Offered immediately rather than waiting to be asked. A peer that never
	// initiates — plenty do not — would otherwise leave the session in line
	// mode with no window size, which looks to the user like a broken
	// terminal rather than a protocol nobody started.
	if err := c.startNegotiation(); err != nil {
		_ = netConn.Close()
		return nil, err
	}

	go c.readLoop()

	return c, nil
}

// readLoop drains the socket for as long as the connection lives.
func (c *Conn) readLoop() {
	defer close(c.data)

	for {
		n, err := c.conn.Read(c.scratch)
		if n > 0 {
			c.consume(c.scratch[:n])
		}
		if err != nil {
			c.fail(err)
			return
		}
	}
}

// consume runs the parser over one socket read, emitting the data it finds.
func (c *Conn) consume(chunk []byte) {
	// Sized to the input: a chunk that is all data produces exactly one
	// allocation, and one that is all negotiation produces none.
	var out []byte

	for _, b := range chunk {
		if data, ok := c.step(b); ok {
			if out == nil {
				out = make([]byte, 0, len(chunk))
			}
			out = append(out, data)
		}
	}

	if len(out) > 0 {
		c.emit(out)
	}
}

// emit hands data to Read, or drops it if the connection is going away.
func (c *Conn) emit(b []byte) {
	select {
	case c.data <- b:
	case <-c.done:
	}
}

// startNegotiation sends the opening offers and requests.
func (c *Conn) startNegotiation() error {
	var out []byte
	for _, opt := range wantLocal() {
		if r := c.opts.offerLocal(opt); r.send {
			out = append(out, IAC, r.command, r.option)
		}
	}
	for _, opt := range wantRemote() {
		if r := c.opts.askRemote(opt); r.send {
			out = append(out, IAC, r.command, r.option)
		}
	}
	if len(out) == 0 {
		return nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(out); err != nil {
		return fmt.Errorf("telnetx: opening negotiation: %w", err)
	}
	return nil
}

// Read returns application data, with every command taken out of the stream.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(c.partial) > 0 {
		n := copy(p, c.partial)
		c.partial = c.partial[n:]
		if len(c.partial) == 0 {
			c.partial = nil
		}
		return n, nil
	}

	chunk, ok := <-c.data
	if !ok {
		// The reader goroutine has finished. Whatever went wrong is on the
		// connection; a clean hangup reports EOF, which the terminal treats
		// as the session ending normally.
		c.mu.Lock()
		failure := c.failure
		c.mu.Unlock()
		if failure != nil {
			return 0, failure
		}
		return 0, io.EOF
	}

	n := copy(p, chunk)
	if n < len(chunk) {
		c.partial = chunk[n:]
	}
	return n, nil
}

// step feeds one byte to the parser, returning a data byte when there is one.
//
// A byte at a time because a command can be split across socket reads at any
// point — after the IAC, after the WILL, in the middle of a subnegotiation —
// and treating each read independently would put an option number on
// somebody's screen. The state lives on the Conn for exactly that reason.
func (c *Conn) step(b byte) (byte, bool) {
	switch c.state {
	case stateData:
		if b == IAC {
			c.state = stateIAC
			return 0, false
		}
		return b, true

	case stateIAC:
		switch b {
		case IAC:
			// A doubled IAC is a literal 255 in the data.
			c.state = stateData
			return IAC, true
		case WILL, WONT, DO, DONT:
			c.command = b
			c.state = stateOption
		case SB:
			c.state = stateSubneg
			c.sbOption = 0
			c.sbSeen = false
			c.sbBuf = c.sbBuf[:0]
		default:
			// Every other command is a one-byte thing this end does not act
			// on. Discarded rather than passed through: emitting it as data
			// would put a control byte on somebody's screen.
			c.state = stateData
		}
		return 0, false

	case stateOption:
		c.negotiate(c.command, b)
		c.state = stateData
		return 0, false

	case stateSubneg:
		if b == IAC {
			c.state = stateSubnegIAC
			return 0, false
		}
		if !c.sbSeen {
			c.sbOption = b
			c.sbSeen = true
			return 0, false
		}
		// Bounded, because a peer that never sends IAC SE would otherwise
		// grow this without limit. Nothing this file implements defines a
		// subnegotiation anywhere near that long.
		if len(c.sbBuf) < 256 {
			c.sbBuf = append(c.sbBuf, b)
		}
		return 0, false

	case stateSubnegIAC:
		switch b {
		case IAC:
			if len(c.sbBuf) < 256 {
				c.sbBuf = append(c.sbBuf, IAC)
			}
			c.state = stateSubneg
		case SE:
			c.subnegotiation(c.sbOption, c.sbBuf)
			c.state = stateData
		default:
			// Malformed. Abandoning the subnegotiation beats guessing at it.
			c.state = stateData
		}
		return 0, false
	}

	return 0, false
}

// negotiate answers one WILL/WONT/DO/DONT.
func (c *Conn) negotiate(command, opt byte) {
	var r reply
	switch command {
	case WILL:
		r = c.opts.receiveWill(opt)
	case WONT:
		r = c.opts.receiveWont(opt)
	case DO:
		r = c.opts.receiveDo(opt)
	case DONT:
		r = c.opts.receiveDont(opt)
	}

	if r.send {
		c.sendCommand(r.command, r.option)
	}

	// Echo is tracked as an explicit refusal rather than as "not yet agreed",
	// because those mean opposite things. A peer that has said nothing is
	// assumed to echo; only one that has said WONT is taken at its word.
	if opt == OptEcho {
		switch command {
		case WONT:
			c.mu.Lock()
			c.remoteRefusedEcho = true
			c.mu.Unlock()
		case WILL:
			c.mu.Lock()
			c.remoteRefusedEcho = false
			c.mu.Unlock()
		}
	}

	// Agreeing to NAWS means the far end wants a size, and wants it now
	// rather than at the next browser resize.
	if command == DO && opt == OptNAWS && c.opts.enabledLocally(OptNAWS) {
		c.mu.Lock()
		cols, rows := c.cols, c.rows
		c.mu.Unlock()
		c.sendNAWS(cols, rows)
	}
}

// subnegotiation handles an option's own payload.
func (c *Conn) subnegotiation(opt byte, payload []byte) {
	switch opt {
	case OptTerminalType:
		// The only request defined for this end: "tell me what you are".
		if len(payload) > 0 && payload[0] == terminalTypeSEND {
			out := []byte{IAC, SB, OptTerminalType, terminalTypeIS}
			out = append(out, escape([]byte(c.cfg.TerminalType))...)
			out = append(out, IAC, SE)
			c.writeRaw(out)
		}
	}
}

// sendCommand writes one three-byte negotiation.
func (c *Conn) sendCommand(command, opt byte) {
	c.writeRaw([]byte{IAC, command, opt})
}

// sendNAWS reports the window size, RFC 1073.
func (c *Conn) sendNAWS(cols, rows int) {
	if cols < 0 || cols > 0xFFFF || rows < 0 || rows > 0xFFFF {
		return
	}
	size := []byte{
		byte(cols >> 8), byte(cols & 0xFF),
		byte(rows >> 8), byte(rows & 0xFF),
	}
	out := []byte{IAC, SB, OptNAWS}
	out = append(out, escape(size)...)
	out = append(out, IAC, SE)
	c.writeRaw(out)
}

// writeRaw sends protocol bytes, which are already escaped where they need to
// be. Failures are recorded rather than returned: this is called from the read
// loop, where there is nobody to hand an error to, and the socket error will
// arrive on the next read anyway.
func (c *Conn) writeRaw(b []byte) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if _, err := c.conn.Write(b); err != nil {
		c.fail(err)
	}
}

// escape doubles IAC bytes, which is what stops a 0xFF in the data — a byte
// that appears in plenty of UTF-8 sequences and in any binary paste — from
// being read as the start of a command.
func escape(b []byte) []byte {
	if !containsIAC(b) {
		return b
	}
	out := make([]byte, 0, len(b)+8)
	for _, x := range b {
		out = append(out, x)
		if x == IAC {
			out = append(out, IAC)
		}
	}
	return out
}

func containsIAC(b []byte) bool {
	for _, x := range b {
		if x == IAC {
			return true
		}
	}
	return false
}

// Write sends keystrokes.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.isClosed() {
		return 0, ErrClosed
	}

	if c.localEcho() {
		// Fed back into the read stream so the user sees what they typed,
		// exactly as a telnet client does in line mode. The far end that
		// asked for this — by sending WONT ECHO — is also the far end that
		// sends WILL ECHO before a password prompt, which is how password
		// suppression works and why following negotiation is not optional.
		echo := make([]byte, len(p))
		copy(echo, p)
		c.emit(echo)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if _, err := c.conn.Write(escape(p)); err != nil {
		c.fail(err)
		return 0, err
	}
	return len(p), nil
}

// localEcho reports whether this end should echo what is typed.
func (c *Conn) localEcho() bool {
	switch c.cfg.Echo {
	case EchoLocal:
		return true
	case EchoRemote:
		return false
	}
	// Auto: the far end echoes unless it has explicitly said it will not.
	// Assuming the opposite — echoing until told to stop — would double every
	// character against every device that negotiates properly, which is
	// nearly all of them, for however long negotiation takes.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteRefusedEcho
}

// Resize reports a new window size.
//
// Silently does nothing when the far end refused NAWS, which is the right
// answer rather than an error: the browser resizes on every window drag, and
// a peer that does not want sizes has said so once.
func (c *Conn) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return fmt.Errorf("telnetx: invalid terminal size %dx%d", cols, rows)
	}

	c.mu.Lock()
	c.cols, c.rows = cols, rows
	c.mu.Unlock()

	if !c.opts.enabledLocally(OptNAWS) {
		return nil
	}
	c.sendNAWS(cols, rows)
	return nil
}

// Wait blocks until the session ends.
//
// Telnet has no exit status — there is no protocol layer above the byte
// stream to carry one — so this reports how the transport ended and nothing
// more. A terminal opened over telnet shows no exit code, which is correct
// rather than missing.
func (c *Conn) Wait() error {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failure
}

// Close ends the session.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()

		err = c.conn.Close()
		close(c.done)
	})
	return err
}

func (c *Conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// fail records the first thing that went wrong and releases Wait.
//
// Three things are not failures, and conflating them would report a normal
// session ending as a fault:
//
//   - io.EOF. The far end hung up, which is how a telnet session usually ends.
//   - net.ErrClosed. This end hung up; the reader goroutine is simply finding
//     out about it.
//   - Anything at all after a deliberate Close, for the same reason.
func (c *Conn) fail(err error) {
	c.mu.Lock()
	deliberate := c.closed
	if c.failure == nil && err != nil && !deliberate &&
		!errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		c.failure = err
	}
	c.mu.Unlock()

	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		_ = c.conn.Close()
		close(c.done)
	})
}

// Summary describes the negotiated session, for the terminal header.
//
// Worth showing: "which options did we agree on" is the first question when a
// telnet session draws badly, and the answer is otherwise invisible.
func (c *Conn) Summary() string {
	agreed := c.opts.agreed()
	if len(agreed) == 0 {
		return "no options negotiated"
	}
	return strings.Join(agreed, ", ")
}

// RemoteAddr is where this is connected, for the record.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
