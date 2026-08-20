// Package tunnel forwards traffic over an SSH connection a user already has.
//
// Three shapes, and the differences between them are what a browser forces:
//
//   - A web tunnel serves a device's own HTTP interface — a switch or router
//     GUI — through bkd, over the SSH connection, with no listening port and
//     nothing to configure on anybody's laptop. It is served from a separate
//     origin, which is not a detail: see proxy.go.
//   - A local tunnel opens a listening port on this server for everything
//     that is not HTTP. That is a shared machine accepting inbound
//     connections, so it is off unless an operator turns it on.
//   - A SOCKS tunnel is the same listener with a handshake in front, reaching
//     wherever the client asks rather than one fixed address.
//   - A remote tunnel is the one shape that survives the move to a browser
//     unchanged: the *device* listens, and a connection arriving there is
//     carried back and dialled from this server. Nothing is opened here — but
//     what it exposes is this server's network rather than one host, which is
//     why it has a gate of its own and a destination guard. See forward.go.
//
// What a browser cannot do is listen, which is why "local forwarding" here
// means something different from the same words in OpenSSH. `ssh -L` opens a
// port on your machine; there is no such thing to open from a web page, so
// the port is on the server and the honest consequences of that are in the
// configuration comments.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/remote"
)

// Kind is what a tunnel carries.
type Kind string

const (
	// KindWeb proxies HTTP to a device's own interface. No listener.
	KindWeb Kind = "web"

	// KindLocal listens on this server and forwards to one fixed address.
	KindLocal Kind = "local"

	// KindSOCKS listens on this server and forwards wherever asked.
	KindSOCKS Kind = "socks"

	// KindRemote asks the far end to listen, and dials what arrives from
	// here. `ssh -R`, with the same meaning it has in OpenSSH.
	KindRemote Kind = "remote"
)

// Validate reports whether the kind is one this package implements.
func (k Kind) Validate() error {
	switch k {
	case KindWeb, KindLocal, KindSOCKS, KindRemote:
		return nil
	default:
		return fmt.Errorf("tunnel: %q is not a kind of tunnel", k)
	}
}

// NeedsListener reports whether this kind opens a port on this server.
//
// KindRemote does not, and the distinction is the point: it opens one on the
// device instead, which is a different permission with a different blast
// radius. ListensRemotely is the other half.
func (k Kind) NeedsListener() bool { return k == KindLocal || k == KindSOCKS }

// ListensRemotely reports whether this kind asks the far end to listen.
func (k Kind) ListensRemotely() bool { return k == KindRemote }

// State is where a tunnel is in its life.
type State string

const (
	StateOpen   State = "open"
	StateClosed State = "closed"
	StateFailed State = "failed"
)

// Errors callers distinguish.
var (
	ErrNotFound        = errors.New("tunnel: no such tunnel")
	ErrTooManyTunnels  = errors.New("tunnel: too many tunnels open")
	ErrListenersOff    = errors.New("tunnel: opening ports on this server is disabled")
	ErrRemoteOff       = errors.New("tunnel: remote forwarding is disabled")
	ErrRemoteBind      = errors.New("tunnel: the remote host refused to listen")
	ErrDestinationOff  = errors.New("tunnel: that destination may not be reached from this server")
	ErrWebTunnelsOff   = errors.New("tunnel: web tunnels need a domain configured")
	ErrNoPortAvailable = errors.New("tunnel: no port is free in the configured range")
	ErrManagerClosed   = errors.New("tunnel: the server is shutting down")
)

// Tunnel is one live forwarding.
type Tunnel struct {
	ID        string
	UserID    string
	SessionID string
	Kind      Kind
	Label     string

	// Host and Port are what a local tunnel forwards to. Unused by SOCKS,
	// which is told per connection. For a remote tunnel they are the
	// destination dialled *from this server* for each connection the device
	// accepts — the same direction reversal `ssh -R` has.
	Host string
	Port int

	// RemoteBind and RemotePort are where a remote tunnel asks the device to
	// listen. An empty bind means whatever the device's own configuration
	// defaults to, which for OpenSSH is loopback unless GatewayPorts says
	// otherwise; a zero port means the device chooses one and tells us.
	RemoteBind string
	RemotePort int

	// Via records the jump hosts the connection underneath went through, so
	// the interface can say a tunnel reaches a device behind a bastion.
	Via []remote.HopInfo

	OpenedAt time.Time

	conn     *remote.Connection
	listener net.Listener
	cancel   context.CancelFunc

	// live counts forwarded connections in flight, so a tunnel is never
	// reaped out from under one and Close waits for them.
	live sync.WaitGroup

	// Counters are atomic because they are written by every forwarded
	// connection and read by the listing endpoint.
	connections atomic.Int64
	active      atomic.Int64
	bytesUp     atomic.Int64
	bytesDown   atomic.Int64

	mu       sync.Mutex
	state    State
	lastUsed time.Time
	failure  string

	// listenAddr is what the listener actually bound, which is not always
	// what was asked for — port 0 means "anything free", on either side.
	listenAddr string

	// localPort is the port taken from the configured range, and zero for
	// every kind that did not take one.
	//
	// Recorded rather than read back off the listener, because a remote
	// tunnel's listener reports a port on the *device*: giving that number to
	// releasePort would free a port in our range that some other tunnel is
	// legitimately holding, whenever the two happened to coincide.
	localPort int
}

// Info is the snapshot handed to the interface.
type Info struct {
	ID        string           `json:"id"`
	Kind      Kind             `json:"kind"`
	State     State            `json:"state"`
	SessionID string           `json:"session_id"`
	Label     string           `json:"label"`
	Via       []remote.HopInfo `json:"via,omitempty"`

	// Listen is the address to point a client at, for the kinds that have one.
	Listen string `json:"listen,omitempty"`

	// Remote is the fixed address at the other end of the forwarding: what a
	// local tunnel reaches over SSH, and what a remote tunnel dials from here.
	Remote string `json:"remote,omitempty"`

	// URL is where a web tunnel is served.
	URL string `json:"url,omitempty"`

	Connections int64 `json:"connections"`
	Active      int64 `json:"active"`
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`

	OpenedAt   time.Time `json:"opened_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Error      string    `json:"error,omitempty"`
}

// touch records use, so the reaper leaves a busy tunnel alone.
func (t *Tunnel) touch() {
	t.mu.Lock()
	t.lastUsed = time.Now()
	t.mu.Unlock()
}

// Info builds the snapshot. urlFor is nil for kinds with no URL.
func (t *Tunnel) Info(urlFor func(*Tunnel) string) Info {
	t.mu.Lock()
	state, lastUsed, failure, listen := t.state, t.lastUsed, t.failure, t.listenAddr
	t.mu.Unlock()

	out := Info{
		ID: t.ID, Kind: t.Kind, State: state,
		SessionID: t.SessionID, Label: t.Label, Via: t.Via,
		Listen:      listen,
		Connections: t.connections.Load(),
		Active:      t.active.Load(),
		BytesUp:     t.bytesUp.Load(),
		BytesDown:   t.bytesDown.Load(),
		OpenedAt:    t.OpenedAt,
		LastUsedAt:  lastUsed,
		Error:       failure,
	}
	if t.Kind == KindLocal || t.Kind == KindRemote {
		out.Remote = net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
	}
	if urlFor != nil {
		out.URL = urlFor(t)
	}
	return out
}

// fail records why a tunnel stopped working.
func (t *Tunnel) fail(err error) {
	t.mu.Lock()
	if t.state == StateOpen {
		t.state = StateFailed
		t.failure = err.Error()
	}
	t.mu.Unlock()
}

// close stops the tunnel and gives back the connection underneath it.
//
// Release, not Close: the SSH connection is shared with any terminal or file
// session on the same host, and closing it would take those with it.
func (t *Tunnel) close() {
	t.mu.Lock()
	if t.state == StateOpen {
		t.state = StateClosed
	}
	t.mu.Unlock()

	t.cancel()

	// Closing the listener is what unblocks Accept; without it the accept
	// goroutine would sit there until something connected.
	if t.listener != nil {
		_ = t.listener.Close()
	}

	// Forwarded connections are given the chance to finish rather than being
	// cut mid-copy: cancel already told them to stop.
	t.live.Wait()

	if t.conn != nil {
		t.conn.Release()
	}
}

// newTunnel builds the shared parts.
func newTunnel(userID, sessionID, label string, kind Kind, conn *remote.Connection) *Tunnel {
	return &Tunnel{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    userID,
		SessionID: sessionID,
		Kind:      kind,
		Label:     label,
		Via:       conn.Via,
		OpenedAt:  time.Now(),
		conn:      conn,
		state:     StateOpen,
		lastUsed:  time.Now(),
	}
}
