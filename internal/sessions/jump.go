package sessions

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Jump hosts.
//
// A connection's JumpChain names the hosts to reach it through, in order,
// by session ID. The chain is expanded recursively the way OpenSSH's
// ProxyJump is: if the target jumps via B and B jumps via A, the route is
// A → B → target. That is what an imported ~/.ssh/config means, and what
// internal/portability/sshconfig.go writes.
//
// It is also why a cycle is dangerous rather than merely wrong. Expansion is
// a graph walk, and "A via B, B via A" is an infinite one — so the walk
// carries a visited set and every path into it validates.
//
// None of this was checked before. The column has existed since the first
// migration and accepted anything: a hop that does not exist, a hop belonging
// to somebody else, a session naming itself.

// MaxJumpChain bounds how many hosts a connection is reached through.
//
// Deliberately much smaller than MaxDepth. A folder nested thirty-two deep is
// untidy; a jump chain thirty-two deep is thirty-two TCP connections,
// thirty-two authentications and thirty-two host key checks behind one click.
// Three hops is already an unusual network.
const MaxJumpChain = 8

var (
	// ErrJumpNotFound means a hop names a connection that does not exist —
	// or one belonging to somebody else, which is reported identically on
	// purpose. Confirming that another user's connection exists would
	// disclose their infrastructure.
	ErrJumpNotFound = errors.New("sessions: a host in the jump chain does not exist")

	// ErrJumpSelf means a connection names itself as its own jump host.
	ErrJumpSelf = errors.New("sessions: a connection cannot be reached through itself")

	// ErrJumpCycle means the chain loops: following it would never arrive.
	ErrJumpCycle = errors.New("sessions: the jump chain loops back on itself")

	// ErrJumpTooLong means the expanded route exceeds MaxJumpChain.
	ErrJumpTooLong = errors.New("sessions: the jump chain has too many hops")

	// ErrJumpProtocol means a hop is not an SSH connection. Only SSH can
	// carry a channel to somewhere else; a serial console has nothing to
	// forward through.
	ErrJumpProtocol = errors.New("sessions: only SSH connections can be used as jump hosts")
)

// ErrJumpInUse reports that a connection cannot be deleted because others are
// reached through it, and names them so the message can say which.
type ErrJumpInUse struct {
	Names []string
}

func (e *ErrJumpInUse) Error() string {
	return fmt.Sprintf("sessions: %s reached through this connection", describeCount(e.Names))
}

// IsJumpInUse reports whether err is an ErrJumpInUse.
func IsJumpInUse(err error) bool {
	var target *ErrJumpInUse
	return errors.As(err, &target)
}

func describeCount(names []string) string {
	switch len(names) {
	case 1:
		return fmt.Sprintf("%q is", names[0])
	case 2, 3:
		return fmt.Sprintf("%s are", strings.Join(quoteAll(names), " and "))
	default:
		return fmt.Sprintf("%s and %d others are",
			strings.Join(quoteAll(names[:2]), ", "), len(names)-2)
	}
}

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = fmt.Sprintf("%q", name)
	}
	return out
}

// ValidateJumpChain checks a proposed chain before it is stored.
//
// sessionID is empty when the connection does not exist yet, which is the
// case on create — there is nothing to form a cycle with yet, but everything
// else still applies.
func (s *Store) ValidateJumpChain(ctx context.Context, ownerID, sessionID string, chain []string) error {
	if len(chain) == 0 {
		return nil
	}
	if len(chain) > MaxJumpChain {
		return fmt.Errorf("%w: %d hops, the limit is %d", ErrJumpTooLong, len(chain), MaxJumpChain)
	}

	seen := map[string]bool{}
	for _, hop := range chain {
		if hop == "" {
			return fmt.Errorf("%w: an empty hop", ErrJumpNotFound)
		}
		if hop == sessionID {
			return ErrJumpSelf
		}
		if seen[hop] {
			return fmt.Errorf("%w: %s appears twice", ErrJumpCycle, hop)
		}
		seen[hop] = true

		hopSession, err := s.GetSession(ctx, ownerID, hop)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: %s", ErrJumpNotFound, hop)
			}
			return err
		}
		if hopSession.Protocol != ProtocolSSH {
			return fmt.Errorf("%w: %q is %s", ErrJumpProtocol, hopSession.Name, hopSession.Protocol)
		}
	}

	// The transitive walk. Each hop has a chain of its own, and following
	// them is what turns a locally sensible chain into a loop.
	visited := map[string]bool{}
	if sessionID != "" {
		visited[sessionID] = true
	}
	_, err := s.walkChain(ctx, ownerID, chain, visited, 0)
	return err
}

// ExpandJumpChain returns every host that will be dialled to reach a
// connection, outermost first. The connection itself is not included.
//
// Each hop comes back Resolved, so a bastion sitting in a folder with a
// default credential authenticates with it — which it must, or a chain would
// work in the tree and fail at the dial.
func (s *Store) ExpandJumpChain(ctx context.Context, ownerID, sessionID string) ([]Resolved, error) {
	sess, err := s.GetSession(ctx, ownerID, sessionID)
	if err != nil {
		return nil, err
	}
	if len(sess.JumpChain) == 0 {
		return nil, nil
	}

	visited := map[string]bool{sessionID: true}
	return s.walkChain(ctx, ownerID, sess.JumpChain, visited, 0)
}

// walkChain expands a chain depth-first, outermost hop first.
//
// visited carries every session already on the route, so a loop is caught the
// moment it closes rather than by running out of stack.
func (s *Store) walkChain(
	ctx context.Context,
	ownerID string,
	chain []string,
	visited map[string]bool,
	depth int,
) ([]Resolved, error) {
	if depth > MaxJumpChain {
		return nil, fmt.Errorf("%w: more than %d hops once each hop's own chain is followed",
			ErrJumpTooLong, MaxJumpChain)
	}

	var route []Resolved

	for _, hop := range chain {
		if visited[hop] {
			return nil, fmt.Errorf("%w: %s is reached through itself", ErrJumpCycle, hop)
		}
		visited[hop] = true

		resolved, err := s.Resolve(ctx, ownerID, hop)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: %s", ErrJumpNotFound, hop)
			}
			return nil, err
		}
		if resolved.Protocol != ProtocolSSH {
			return nil, fmt.Errorf("%w: %q is %s", ErrJumpProtocol, resolved.Name, resolved.Protocol)
		}

		// This hop's own chain comes first: it has to be reached before it
		// can carry anything.
		if len(resolved.JumpChain) > 0 {
			inner, err := s.walkChain(ctx, ownerID, resolved.JumpChain, visited, depth+1)
			if err != nil {
				return nil, err
			}
			route = append(route, inner...)
		}

		route = append(route, resolved)

		if len(route) > MaxJumpChain {
			return nil, fmt.Errorf("%w: %d hops once each hop's own chain is followed, the limit is %d",
				ErrJumpTooLong, len(route), MaxJumpChain)
		}
	}

	return route, nil
}

// jumpDependents lists the connections reached through a given one.
func (s *Store) jumpDependents(ctx context.Context, ownerID, sessionID string) ([]string, error) {
	all, err := s.ListSessions(ctx, ownerID, false)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, sess := range all {
		if sess.ID == sessionID {
			continue
		}
		for _, hop := range sess.JumpChain {
			if hop == sessionID {
				names = append(names, sess.Name)
				break
			}
		}
	}
	return names, nil
}
