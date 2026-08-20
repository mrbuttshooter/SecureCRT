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
	"sync"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// Transport opens the byte stream the SSH handshake runs over.
//
// Nil means a direct TCP connection to the target. A jump host supplies one
// that opens a direct-tcpip channel on an already-authenticated connection,
// which is how a chain of any depth is built: each hop's client becomes the
// next hop's transport.
//
// Injecting it here rather than dialling internally is what keeps host key
// verification on one path for every hop — a bastion is verified exactly as
// strictly as the host behind it, by the same code.
type Transport func(ctx context.Context, addr string) (net.Conn, error)

// ThroughClient returns a Transport that opens channels on an existing
// connection, so the next hop is dialled from that host rather than this one.
func ThroughClient(c *Client) Transport {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := c.Conn().DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s via %s: %v",
				ErrUnreachable, addr, c.Target().Addr(), err)
		}
		return conn, nil
	}
}

// directTransport dials from this host.
func directTransport(timeout time.Duration) Transport {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, addr, err)
		}
		return conn, nil
	}
}

// Config controls a dial.
type Config struct {
	Target     Target
	Credential Credential

	// Verify consults the trust store for a presented key.
	Verify func(ctx context.Context, hostname string, port int, key ssh.PublicKey) (hostkeys.Check, error)

	// Decide approves or refuses the result of Verify.
	Decide HostKeyDecision

	// Transport opens the byte stream the handshake runs over. Nil means a
	// direct TCP connection, which is what every caller wanted until jump
	// hosts arrived.
	Transport Transport

	// ConnectTimeout bounds reaching the host — the TCP connect, or opening
	// the channel on the hop in front of it. It does not cover the handshake:
	// see HandshakeTimeout for why those are two different numbers.
	ConnectTimeout time.Duration

	// HandshakeTimeout bounds the SSH handshake, which is a longer story than
	// it sounds. Host key verification happens inside the handshake, and an
	// unknown key stops to ask a human. So this has to exceed however long
	// the interface gives someone to answer that question, or a user who
	// thinks about it for a moment gets a connection failure instead of the
	// prompt they were answering.
	HandshakeTimeout time.Duration

	// Agent is an SSH agent to forward to the far end. Nil forwards nothing,
	// which is the default and stays the default.
	//
	// Not the user's own agent — there is no channel back to a browser — but
	// an in-memory keyring the server builds from credentials the user named.
	// The consequence for the remote host is identical to real agent
	// forwarding, and so is the risk: a compromised host can use these keys,
	// for anything they open, for as long as this connection lives. What is
	// better here is only the scope, which is the keys named rather than
	// whatever an agent happened to be holding.
	Agent agent.Agent

	// KeepAlive is how often to send a keepalive request. Terminals sit idle
	// for long stretches, and a NAT or firewall in between will drop an idle
	// flow without telling either end; the keepalive is what stops a session
	// silently dying while someone reads a man page.
	KeepAlive time.Duration
}

// DefaultConnectTimeout allows for a slow network and a distant host.
const DefaultConnectTimeout = 60 * time.Second

// DefaultHandshakeTimeout is deliberately generous: it has to outlast the
// host key prompt, which is two minutes in the interface today. A tighter
// value here would express itself as "connection failed" to somebody who was
// looking at a fingerprint deciding whether to trust it.
const DefaultHandshakeTimeout = 5 * time.Minute

// DefaultKeepAlive is comfortably below the idle timeout of typical network
// equipment.
const DefaultKeepAlive = 30 * time.Second

// Client is a live SSH connection.
type Client struct {
	conn   *ssh.Client
	target Target
	closed chan struct{}

	// mu guards stopped. Close is reachable from the connection pool, from a
	// tunnel giving up its lease and from the shutdown path, and closing a
	// channel twice panics — so "have we already stopped" cannot be an
	// unsynchronised bool.
	mu      sync.Mutex
	stopped bool

	// keyring is the agent forwarded on this connection, kept so each shell
	// can request forwarding for its own session. Nil forwards nothing.
	keyring agent.Agent
}

// ForwardsAgent reports whether this connection offers an agent.
func (c *Client) ForwardsAgent() bool { return c.keyring != nil }

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

	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = DefaultHandshakeTimeout
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

	transport := cfg.Transport
	if transport == nil {
		transport = directTransport(timeout)
	}

	// Reaching the host gets its own budget, as the TCP dial did before: a
	// bastion that never answers a channel request must not eat the time set
	// aside for the handshake behind it.
	dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
	netConn, err := transport(dialCtx, cfg.Target.Addr())
	cancelDial()
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := handshake(ctx, netConn, cfg.Target.Addr(), clientCfg,
		handshakeTimeout)
	if err != nil {
		return nil, err
	}

	client := &Client{
		conn:    ssh.NewClient(sshConn, chans, reqs),
		target:  cfg.Target,
		closed:  make(chan struct{}),
		keyring: cfg.Agent,
	}

	if cfg.Agent != nil {
		// Registers the handler for auth-agent@openssh.com channels the far
		// end opens back. Nothing is exposed until a session also asks for
		// forwarding, which Shell does — so a connection carrying a keyring
		// that never starts a shell has offered nothing.
		if err := agent.ForwardToAgent(client.conn, cfg.Agent); err != nil {
			_ = client.conn.Close()
			return nil, fmt.Errorf("sshx: forwarding the agent: %w", err)
		}
	}

	keepAlive := cfg.KeepAlive
	if keepAlive <= 0 {
		keepAlive = DefaultKeepAlive
	}
	go client.keepAlive(keepAlive)

	return client, nil
}

// handshake runs the SSH handshake with a bound that does not rely on the
// connection supporting deadlines.
//
// Deadlines would be the better mechanism and were what this used, but a
// channel-backed conn from a jump host cannot carry one: SetDeadline on an SSH
// channel always fails, so every tunnelled hop would have been refused before
// it began.
//
// Closing the conn is not sufficient on its own either. Closing an SSH channel
// only sends a close message, so a peer that has stopped answering entirely
// will never unblock the read underneath NewClientConn. The handshake is
// therefore *abandoned* rather than interrupted: the conn is closed, which
// unwedges a peer that is still listening, and the goroutine is left to end
// when the transport beneath it does. It holds nothing but the conn, and a
// jump host dying frees every one of them at once.
//
// One mechanism for both transports, and it gains something the deadline
// never had: a cancelled context now aborts the handshake, which matters
// because host key verification happens inside it and can be waiting on a
// person.
func handshake(
	ctx context.Context,
	netConn net.Conn,
	addr string,
	clientCfg *ssh.ClientConfig,
	timeout time.Duration,
) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	type result struct {
		conn  ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	}

	// Buffered, so an abandoned goroutine can finish and exit rather than
	// blocking forever on a send nobody is waiting for.
	done := make(chan result, 1)
	go func() {
		conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientCfg)
		done <- result{conn, chans, reqs, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-done:
		if r.err != nil {
			_ = netConn.Close()
			return nil, nil, nil, classifyHandshakeError(r.err)
		}
		return r.conn, r.chans, r.reqs, nil

	case <-timer.C:
		_ = netConn.Close()
		return nil, nil, nil, fmt.Errorf(
			"%w: %s accepted a connection but did not complete an SSH handshake within %s",
			ErrUnreachable, addr, timeout)

	case <-ctx.Done():
		_ = netConn.Close()
		return nil, nil, nil, ctx.Err()
	}
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
// maxMissedKeepAlives is how many unanswered keepalives end a connection.
//
// Three rather than one: network equipment under load genuinely does take
// longer than a keepalive interval to answer, and dropping somebody's session
// for that would be worse than the problem being solved.
const maxMissedKeepAlives = 3

// ping sends one keepalive and reports whether it was answered in time.
//
// The reply has to be waited for on a goroutine. SendRequest with wantReply
// blocks until the peer answers or the transport dies — so a peer that is up
// but no longer answering would hang this goroutine forever, and the
// connection would never be declared dead. That is exactly the failure this
// function exists to detect, so it cannot be allowed to hide it.
func (c *Client) ping(timeout time.Duration) bool {
	answered := make(chan bool, 1)

	go func() {
		// Only the error matters. A healthy peer answers this request with
		// SSH_MSG_REQUEST_FAILURE — OpenSSH does not implement it and says so
		// — which surfaces here as ok == false with a nil error. Treating
		// that as a missed reply would end every healthy connection after
		// three intervals. What proves liveness is that a reply came back at
		// all.
		_, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil)
		answered <- err == nil
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case ok := <-answered:
		return ok
	case <-timer.C:
		return false
	case <-c.closed:
		return true // shutting down; not a missed reply
	}
}

func (c *Client) keepAlive(every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	missed := 0

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			if c.ping(every) {
				missed = 0
				continue
			}

			// A missed reply is not proof of anything on its own — a busy
			// device can be slow. Three in a row is different: the peer is
			// wedged, and nothing else will ever notice.
			//
			// This matters far more with jump hosts than without. A bastion
			// that stops answering takes every connection riding its channels
			// with it, and none of those will report an error until something
			// tries to read. Declaring it dead here is what lets the pool
			// evict it and the next dial start fresh, rather than handing out
			// leases on a corpse.
			missed++
			if missed >= maxMissedKeepAlives {
				_ = c.Close()
				return
			}
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

// Close ends the connection. Safe to call more than once, and from more than
// one goroutine at a time.
func (c *Client) Close() error {
	c.mu.Lock()
	if !c.stopped {
		c.stopped = true
		close(c.closed)
	}
	c.mu.Unlock()

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

	// agentRefused is set when this connection carried an agent and the host
	// would not take it. Not an error for the shell — the terminal is fine —
	// but the user has to be told, or they will find out by watching an
	// authentication fail three hops away.
	agentRefused error
}

// AgentRefused reports the host declining a forwarded agent, or nil.
func (s *Session) AgentRefused() error { return s.agentRefused }

// Shell starts an interactive login shell on a new pseudo-terminal.
func (c *Client) Shell(pty PTYConfig) (*Session, error) {
	pty = pty.withDefaults()

	// Recorded rather than logged: this package has no logger, and the
	// caller is the one that can tell the user their keys are not there.
	var agentRefused error

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

	if c.keyring != nil {
		// Before Shell, and it has to be: a request after the shell has
		// started is answered by the shell's own channel handling rather than
		// the session's, and OpenSSH ignores it.
		//
		// A refusal is not fatal. Plenty of hosts are configured with
		// AllowAgentForwarding no, and a terminal that opens without the
		// agent is far better than one that does not open — the user finds
		// out when a key is not offered, which is the same way they would
		// find out with OpenSSH.
		if err := agent.RequestAgentForwarding(session); err != nil {
			agentRefused = err
		}
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

	return &Session{
		session: session, stdin: stdin, stdout: stdout,
		agentRefused: agentRefused,
	}, nil
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
