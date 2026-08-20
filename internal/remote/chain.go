package remote

import (
	"context"
	"errors"
	"fmt"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// Reaching a host through jump hosts.
//
// Each hop is dialled from the one in front of it, so a chain of any depth is
// built by making each hop's client the next hop's transport. Every hop is a
// full SSH connection in its own right: its own credential, its own host key
// check, its own entry in the pool.
//
// That last part is what makes a bastion affordable. Fifty devices behind one
// bastion take fifty references on one bastion connection rather than opening
// fifty of them — which on network equipment counting vty lines is the
// difference between working and not.

// HopInfo names one jump host, for the interface, the audit log and error
// attribution.
type HopInfo struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	Port      int    `json:"port"`

	// Index is 1-based and Total is the length of the route, so a message can
	// say "hop 2 of 3" without the reader counting.
	Index int `json:"index"`
	Total int `json:"total"`
}

// String renders a hop the way an error message wants it.
func (h HopInfo) String() string {
	return fmt.Sprintf("%s (hop %d of %d)", h.Name, h.Index, h.Total)
}

// held is the set of hop leases a multi-hop connection borrowed, outermost
// first. Released in reverse, so an inner hop never outlives the transport it
// was reached through.
type held []*Lease

func (h held) release() {
	for i := len(h) - 1; i >= 0; i-- {
		h[i].Release()
	}
}

// hopInfo describes the route for the interface and the audit log.
func hopInfo(hops []sessions.Resolved) []HopInfo {
	if len(hops) == 0 {
		return nil
	}
	out := make([]HopInfo, len(hops))
	for i, hop := range hops {
		out[i] = HopInfo{
			SessionID: hop.ID, Name: hop.Name,
			Hostname: hop.Hostname, Port: hop.EffectivePort,
			Index: i + 1, Total: len(hops),
		}
	}
	return out
}

// dialThrough opens a connection to target, taking a shared lease on every hop
// of its route first.
//
// The returned release gives those leases back. The pool calls it once the
// connection it carried has closed, which is what makes a bastion outlive
// every connection riding on it and go only when the last one has.
func (d *Dialer) dialThrough(
	ctx context.Context,
	p Params,
	target sessions.Resolved,
	hops []sessions.Resolved,
	cred sshx.Credential,
	progress func(string),
) (*sshx.Client, func(), error) {
	var (
		borrowed held
		route    []string
		through  *sshx.Client // nil means dial from this host
	)

	// Any failure part-way along gives back everything taken so far. Without
	// this a chain that got three hops in and then failed would pin three
	// bastions for the life of the process.
	unwind := func(err error) (*sshx.Client, func(), error) {
		borrowed.release()
		return nil, nil, err
	}

	infos := hopInfo(hops)

	for i, hop := range hops {
		info := infos[i]

		hopCred, err := d.buildCredential(ctx, p, hop)
		if err != nil {
			return unwind(viaError(info, err))
		}

		// Captured per iteration: the transport for this hop is the client
		// from the previous one, which must not be re-read after the loop
		// moves on.
		parent := through
		key := PathKey(p.UserID, route, hop.ID)

		lease, err := d.pool.Acquire(ctx, key,
			func(ctx context.Context) (*sshx.Client, func(), error) {
				progress(StatusDiallingHop)
				client, err := d.dialOne(ctx, p, hop, hopCred, parent, &info, progress)
				// A hop borrows nothing of its own: its transport is held by
				// the entry of the hop in front of it, or is this host.
				return client, nil, err
			})

		// The decrypted material exists for the dial and no longer. If the
		// connection was already pooled the closure never ran, and zeroing is
		// simply the sooner the better.
		hopCred.Zero()

		if err != nil {
			return unwind(viaError(info, err))
		}

		borrowed = append(borrowed, lease)
		through = lease.Client()
		route = append(route, hop.ID)
	}

	client, err := d.dialOne(ctx, p, target, cred, through, nil, progress)
	if err != nil {
		return unwind(err)
	}

	return client, borrowed.release, nil
}

// viaError rewrites a hop's failure to say which hop it was.
//
// The inner code is preserved, so the interface still branches correctly — a
// changed key on a bastion is still host_key_changed, still critical, still
// audited as such. Only the sentence a person reads changes, and it has to,
// because "the host refused the credential" about a device the user did not
// know was involved sends them to debug the wrong thing.
func viaError(info HopInfo, err error) error {
	var inner *Error
	if !errors.As(err, &inner) {
		return &Error{
			Code:    CodeInternal,
			Message: fmt.Sprintf("Reaching this connection through %s failed.", info),
			Err:     err,
			Hop:     &info,
		}
	}

	return &Error{
		Code:    inner.Code,
		Message: fmt.Sprintf("Reaching this connection through %s: %s", info, inner.Message),
		Err:     inner.Err,
		HostKey: inner.HostKey,
		Hop:     &info,
	}
}
