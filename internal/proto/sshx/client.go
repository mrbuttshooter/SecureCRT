// Package sshx opens SSH sessions on behalf of a signed-in user.
//
// The private keys it uses are decrypted from the user's vault for the
// duration of a single dial and are never written anywhere. The browser never
// receives them: it receives terminal bytes, which is the whole point of
// holding the keys server-side.
//
// Host key verification is not optional here. The caller supplies a decision
// function; there is no mode in which an unrecognised key is accepted
// silently, and a changed key is refused before authentication is attempted —
// so credentials are never offered to a host that failed to prove itself.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"golang.org/x/crypto/ssh"
)

// Errors callers distinguish.
var (
	// ErrHostKeyRejected means the user declined an unknown key, or the key
	// had changed. The connection was abandoned before authentication.
	ErrHostKeyRejected = errors.New("sshx: host key was not accepted")

	// ErrAuthFailed means the server refused the credential. Kept distinct
	// from a network failure because the remedies are unrelated: one is "fix
	// your key", the other "fix your route".
	ErrAuthFailed = errors.New("sshx: the host rejected the credential")

	// ErrUnreachable means the host could not be contacted.
	ErrUnreachable = errors.New("sshx: could not reach the host")

	// ErrNoCredential means no usable credential was supplied.
	ErrNoCredential = errors.New("sshx: no credential was supplied")
)

// Credential is the material used to authenticate.
//
// Exactly one of PrivateKey or Password is normally set. Both may be present
// for hosts that demand a key and then a further password, which some network
// appliances do.
type Credential struct {
	Username string

	// PrivateKey is an OpenSSH or PEM private key. Decrypted from the vault
	// by the caller and passed in for the life of the dial only.
	PrivateKey []byte

	// Passphrase decrypts PrivateKey, when the stored key still carries one.
	Passphrase string

	// Password is used for password authentication, and to answer
	// keyboard-interactive prompts.
	Password string
}

// HasMaterial reports whether anything usable was supplied.
func (c Credential) HasMaterial() bool {
	return len(c.PrivateKey) > 0 || c.Password != ""
}

// Zero clears the secret material.
//
// Best-effort, as everywhere in Go: the byte slice is wiped, but the password
// is a string and cannot be. Callers holding secrets for a long time should
// use bytes; these live only for the length of a dial.
func (c *Credential) Zero() {
	for i := range c.PrivateKey {
		c.PrivateKey[i] = 0
	}
	c.PrivateKey = nil
	c.Passphrase = ""
	c.Password = ""
}

// HostKeyDecision is asked to approve a host key.
//
// Called during the handshake, before any credential is offered. Returning an
// error abandons the connection. The caller uses this to consult the trust
// store and, when the key is unknown, to ask the user — which is why it takes
// a context and may block for as long as the dial timeout allows.
type HostKeyDecision func(ctx context.Context, check hostkeys.Check) error

// Target describes where to connect.
type Target struct {
	Hostname string
	Port     int
}

// Addr renders the dial address.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Hostname, strconv.Itoa(t.Port))
}

// Config controls a dial.
type Config struct {
	Target     Target
	Credential Credential

	// Verify consults the trust store for a presented key.
	Verify func(ctx context.Context, hostname string, port int, key ssh.PublicKey) (hostkeys.Check, error)

	// Decide approves or refuses the result of Verify.
	Decide HostKeyDecision

	// ConnectTimeout bounds the TCP connect and handshake. It has to allow
	// for a user thinking about an unknown host key, since that decision
	// happens inside the handshake.
	ConnectTimeout time.Duration

	// KeepAlive is how often to send a keepalive request. Terminals sit idle
	// for long stretches, and a NAT or firewall in between will drop an idle
	// flow without telling either end; the keepalive is what stops a session
	// silently dying while someone reads a man page.
	KeepAlive time.Duration
}

// DefaultConnectTimeout allows for a slow network plus a moment of human
// hesitation over a host key prompt.
const DefaultConnectTimeout = 60 * time.Second

// DefaultKeepAlive is comfortably below the idle timeout of typical network
// equipment.
const DefaultKeepAlive = 30 * time.Second

// Client is a live SSH connection.
type Client struct {
	conn    *ssh.Client
	target  Target
	closed  chan struct{}
	stopped bool
}

// Dial opens an SSH connection.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if !cfg.Credential.HasMaterial() {
		return nil, ErrNoCredential
	}
	if cfg.Credential.Username == "" {
		return nil, errors.New("sshx: a username is required")
	}
	if cfg.Verify == nil || cfg.Decide == nil {
		// Refusing to run without a verifier is deliberate: a default of
		// "accept anything" is how this protection gets lost.
		return nil, errors.New("sshx: host key verification is required")
	}

	timeout := cfg.ConnectTimeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}

	auths, err := authMethods(cfg.Credential)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.Credential.Username,
		Auth:            auths,
		Timeout:         timeout,
		HostKeyCallback: hostKeyCallback(ctx, cfg),
		// Deliberately not restricted further. This connects to network
		// equipment that may be a decade old; excluding older key exchanges
		// would make the tool unable to reach the hosts it exists for. The
		// protection here is host key verification, which is enforced.
		ClientVersion: "SSH-2.0-Bridgekeeper",
	}

	dialer := net.Dialer{Timeout: timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", cfg.Target.Addr())
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, cfg.Target.Addr(), err)
	}

	// The handshake gets its own deadline so a host that accepts a connection
	// and then says nothing cannot hold the dial open indefinitely.
	if err := netConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("sshx: set handshake deadline: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, cfg.Target.Addr(), clientCfg)
	if err != nil {
		_ = netConn.Close()
		return nil, classifyHandshakeError(err)
	}

	// Clear the deadline: from here the connection is long-lived, and a
	// deadline would kill an idle terminal.
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		_ = sshConn.Close()
		return nil, fmt.Errorf("sshx: clear handshake deadline: %w", err)
	}

	client := &Client{
		conn:   ssh.NewClient(sshConn, chans, reqs),
		target: cfg.Target,
		closed: make(chan struct{}),
	}

	keepAlive := cfg.KeepAlive
	if keepAlive <= 0 {
		keepAlive = DefaultKeepAlive
	}
	go client.keepAlive(keepAlive)

	return client, nil
}

// classifyHandshakeError separates the failures a user can act on.
func classifyHandshakeError(err error) error {
	if errors.Is(err, ErrHostKeyRejected) {
		return err
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "no supported methods remain"),
		strings.Contains(msg, "permission denied"):
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	case strings.Contains(msg, "host key"):
		return fmt.Errorf("%w: %v", ErrHostKeyRejected, err)
	default:
		return fmt.Errorf("sshx: handshake failed: %w", err)
	}
}

// hostKeyCallback wires trust verification into the handshake.
//
// Running inside the handshake matters: it happens before any credential is
// offered, so a host that fails to prove its identity never sees the user's
// key or password.
func hostKeyCallback(ctx context.Context, cfg Config) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		check, err := cfg.Verify(ctx, cfg.Target.Hostname, cfg.Target.Port, key)
		if err != nil {
			return fmt.Errorf("sshx: checking host key: %w", err)
		}
		if err := cfg.Decide(ctx, check); err != nil {
			return err
		}
		return nil
	}
}

// authMethods builds the authentication methods from a credential.
//
// Ordered key first, then password, then keyboard-interactive. The
// keyboard-interactive fallback matters for network equipment, which
// frequently asks for the password through that mechanism rather than the
// password method proper, and would otherwise refuse a perfectly good
// credential.
func authMethods(c Credential) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if len(c.PrivateKey) > 0 {
		var (
			signer ssh.Signer
			err    error
		)
		if c.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(c.PrivateKey, []byte(c.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(c.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("sshx: the stored private key could not be used: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if c.Password != "" {
		password := c.Password
		methods = append(methods, ssh.Password(password))
		methods = append(methods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					// Only answer non-echoed prompts, which are password
					// prompts. Echoed ones are asking for something else —
					// a one-time code, a menu choice — and blindly sending
					// the password there would disclose it.
					if i < len(echos) && !echos[i] {
						answers[i] = password
					}
				}
				return answers, nil
			}))
	}

	if len(methods) == 0 {
		return nil, ErrNoCredential
	}
	return methods, nil
}

// keepAlive sends periodic requests so idle sessions are not silently dropped
// by intermediate network equipment.
func (c *Client) keepAlive(every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			// The reply is ignored; what matters is that a packet crossed the
			// path. A failure means the connection is already gone, and the
			// session's read loop will observe that.
			_, _, _ = c.conn.SendRequest("keepalive@openssh.com", true, nil)
		}
	}
}

// Target reports where this client is connected.
func (c *Client) Target() Target { return c.target }

// Conn exposes the underlying SSH connection.
//
// Subsystems this package does not itself implement — SFTP above all — need
// it to open their own channels. Keeping the dependency this way round means
// sshx stays about the transport and host key verification, and does not grow
// an import of every protocol layered on top of it.
//
// The connection is shared: SSH multiplexes channels, so a file transfer and
// a shell coexist on one TCP connection, one authentication, and one vty line
// on equipment that counts them.
func (c *Client) Conn() *ssh.Client { return c.conn }

// Close ends the connection.
func (c *Client) Close() error {
	if !c.stopped {
		c.stopped = true
		close(c.closed)
	}
	return c.conn.Close()
}

// Wait blocks until the connection ends.
func (c *Client) Wait() error { return c.conn.Wait() }

// PTYConfig describes the terminal to allocate.
type PTYConfig struct {
	// Term is the TERM value. xterm-256color is what xterm.js implements, and
	// what makes colour work on the far side.
	Term string
	Cols int
	Rows int
}

func (p PTYConfig) withDefaults() PTYConfig {
	if p.Term == "" {
		p.Term = "xterm-256color"
	}
	if p.Cols <= 0 {
		p.Cols = 80
	}
	if p.Rows <= 0 {
		p.Rows = 24
	}
	return p
}

// Session is an interactive shell with a pseudo-terminal.
type Session struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

// Shell starts an interactive login shell on a new pseudo-terminal.
func (c *Client) Shell(pty PTYConfig) (*Session, error) {
	pty = pty.withDefaults()

	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshx: open session: %w", err)
	}

	modes := ssh.TerminalModes{
		// Echo is the remote side's business, not ours: the shell decides,
		// and a full-screen program will turn it off.
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := session.RequestPty(pty.Term, pty.Rows, pty.Cols, modes); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: stdin: %w", err)
	}

	// Standard error is merged into standard output. A terminal shows one
	// interleaved stream, and separating them here would reorder the output
	// relative to what the user would see on a real console.
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: stdout: %w", err)
	}
	session.Stderr = nil

	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: start shell: %w", err)
	}

	return &Session{session: session, stdin: stdin, stdout: stdout}, nil
}

// Read returns terminal output.
func (s *Session) Read(p []byte) (int, error) { return s.stdout.Read(p) }

// Write sends keystrokes.
func (s *Session) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Resize tells the remote side the terminal's new size.
//
// Without this, a full-screen program draws to the wrong dimensions after the
// browser window changes — the single most visible way a web terminal betrays
// that it is not a real one.
func (s *Session) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return fmt.Errorf("sshx: invalid terminal size %dx%d", cols, rows)
	}
	if err := s.session.WindowChange(rows, cols); err != nil {
		return fmt.Errorf("sshx: resize: %w", err)
	}
	return nil
}

// Close ends the shell session.
func (s *Session) Close() error {
	_ = s.stdin.Close()
	return s.session.Close()
}

// Wait blocks until the remote command exits, reporting its status.
func (s *Session) Wait() error { return s.session.Wait() }

// ExitStatus extracts a remote exit code from a Wait error, if it carries one.
func ExitStatus(err error) (int, bool) {
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), true
	}
	return 0, false
}
