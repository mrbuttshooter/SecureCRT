package sessions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Jump chains, adversarially.
//
// The column accepted anything from the first migration until now: a hop that
// does not exist, one belonging to somebody else, a session naming itself, a
// loop. Every one of those is a connection that looks fine in the tree and
// fails — or hangs — at the moment somebody needs it.

// host creates a saved connection and returns it.
func host(t *testing.T, s *Store, ownerID, name string, chain ...string) Session {
	t.Helper()

	sess, err := s.CreateSession(context.Background(), CreateSessionParams{
		OwnerID: ownerID, Name: name, Hostname: name + ".example.com",
		JumpChain: chain,
	})
	if err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	return sess
}

func TestAChainNamingAMissingHostIsRefused(t *testing.T) {
	s, _, userID := fixture(t)

	_, err := s.CreateSession(context.Background(), CreateSessionParams{
		OwnerID: userID, Name: "target", Hostname: "10.0.0.1",
		JumpChain: []string{uuid.Must(uuid.NewV7()).String()},
	})
	if !errors.Is(err, ErrJumpNotFound) {
		t.Fatalf("error = %v, want ErrJumpNotFound", err)
	}
}

// TestAnotherUsersConnectionLooksMissing, rather than forbidden. Confirming
// that a connection exists but belongs to somebody else would disclose their
// infrastructure to anyone willing to guess identifiers.
func TestAnotherUsersConnectionLooksMissing(t *testing.T) {
	s, db, alice := fixture(t)
	ctx := context.Background()

	bob := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		bob, "bob@example.com", "bob@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	bobsBastion := host(t, s, bob, "bobs-bastion")

	_, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: alice, Name: "target", Hostname: "10.0.0.1",
		JumpChain: []string{bobsBastion.ID},
	})
	if !errors.Is(err, ErrJumpNotFound) {
		t.Fatalf("error = %v, want ErrJumpNotFound", err)
	}
}

func TestAConnectionCannotJumpThroughItself(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	target := host(t, s, userID, "target")

	chain := []string{target.ID}
	_, err := s.UpdateSession(ctx, userID, target.ID, UpdateSessionParams{JumpChain: &chain})
	if !errors.Is(err, ErrJumpSelf) {
		t.Fatalf("error = %v, want ErrJumpSelf", err)
	}
}

// TestACycleIsRefused is the one that matters most: expansion is a graph walk,
// so a loop is not merely wrong, it never terminates.
func TestACycleIsRefused(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	a := host(t, s, userID, "a")
	b := host(t, s, userID, "b")

	// b is reached through a. Fine.
	viaA := []string{a.ID}
	if _, err := s.UpdateSession(ctx, userID, b.ID, UpdateSessionParams{JumpChain: &viaA}); err != nil {
		t.Fatal(err)
	}

	// Now a through b, which closes the loop.
	viaB := []string{b.ID}
	_, err := s.UpdateSession(ctx, userID, a.ID, UpdateSessionParams{JumpChain: &viaB})
	if !errors.Is(err, ErrJumpCycle) {
		t.Fatalf("error = %v, want ErrJumpCycle", err)
	}
}

func TestADuplicateHopIsRefused(t *testing.T) {
	s, _, userID := fixture(t)

	a := host(t, s, userID, "a")

	_, err := s.CreateSession(context.Background(), CreateSessionParams{
		OwnerID: userID, Name: "target", Hostname: "10.0.0.1",
		JumpChain: []string{a.ID, a.ID},
	})
	if !errors.Is(err, ErrJumpCycle) {
		t.Fatalf("error = %v, want ErrJumpCycle", err)
	}
}

func TestAnOverlongChainIsRefused(t *testing.T) {
	s, _, userID := fixture(t)

	chain := make([]string, 0, MaxJumpChain+1)
	for i := range MaxJumpChain + 1 {
		chain = append(chain, host(t, s, userID, fmt.Sprintf("hop-%d", i)).ID)
	}

	_, err := s.CreateSession(context.Background(), CreateSessionParams{
		OwnerID: userID, Name: "target", Hostname: "10.0.0.1", JumpChain: chain,
	})
	if !errors.Is(err, ErrJumpTooLong) {
		t.Fatalf("error = %v, want ErrJumpTooLong", err)
	}
}

// TestALongChainAssembledOneHopAtATimeIsStillRefused. Each link is short and
// individually reasonable; the route is not. Checking only the chain being
// written would miss it entirely.
func TestALongChainAssembledOneHopAtATimeIsStillRefused(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	previous := host(t, s, userID, "hop-0")
	var err error

	for i := 1; i <= MaxJumpChain+1; i++ {
		next := host(t, s, userID, fmt.Sprintf("hop-%d", i))
		chain := []string{previous.ID}
		if _, err = s.UpdateSession(ctx, userID, next.ID,
			UpdateSessionParams{JumpChain: &chain}); err != nil {
			break
		}
		previous = next
	}

	if !errors.Is(err, ErrJumpTooLong) {
		t.Fatalf("a chain of %d single hops was accepted; error = %v", MaxJumpChain+1, err)
	}
}

// TestANonSSHHopIsRefused: a serial console has nothing to forward through.
func TestANonSSHHopIsRefused(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	console, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "console", Protocol: ProtocolSerial,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "target", Hostname: "10.0.0.1",
		JumpChain: []string{console.ID},
	})
	if !errors.Is(err, ErrJumpProtocol) {
		t.Fatalf("error = %v, want ErrJumpProtocol", err)
	}
}

// TestExpandFollowsEachHopsOwnChain is the ProxyJump semantic: if the target
// jumps via B and B jumps via A, the route is A then B.
func TestExpandFollowsEachHopsOwnChain(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	a := host(t, s, userID, "a")
	b := host(t, s, userID, "b", a.ID)
	target := host(t, s, userID, "target", b.ID)

	route, err := s.ExpandJumpChain(ctx, userID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(route) != 2 {
		t.Fatalf("route has %d hops, want 2: %v", len(route), names(route))
	}
	if route[0].ID != a.ID || route[1].ID != b.ID {
		t.Errorf("route = %v, want [a b]", names(route))
	}
}

// TestExpandResolvesEachHop. A bastion in a folder with a default credential
// or username must use it, or a chain works in the tree and fails at dial.
//
// Note what this does NOT assert: the folder's default *port*. That
// inheritance has never worked — CreateSession fills the port column with the
// protocol default when the caller gives none, so Resolve's fallback to the
// folder default is unreachable. It is a real bug, it predates this phase by
// three of them, and fixing it changes what /api/tree emits and how the tree
// displays a port, so it belongs in its own change rather than smuggled in
// here. Recorded rather than quietly worked around.
func TestExpandResolvesEachHop(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	folder, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID: userID, Name: "Bastions",
		Defaults: Settings{Username: Ptr("netops")},
	})
	if err != nil {
		t.Fatal(err)
	}

	bastion, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, FolderID: folder.ID, Name: "bastion",
		Hostname: "bastion.example.com", Port: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := host(t, s, userID, "target", bastion.ID)

	route, err := s.ExpandJumpChain(ctx, userID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(route) != 1 {
		t.Fatalf("route has %d hops", len(route))
	}
	if route[0].EffectiveUsername != "netops" {
		t.Errorf("hop username = %q, want the folder's default", route[0].EffectiveUsername)
	}
	if route[0].EffectivePort != 2222 {
		t.Errorf("hop port = %d, want the port set on the bastion", route[0].EffectivePort)
	}
}

// TestExpandCatchesALoopWrittenBehindItsBack. Validation refuses a loop on the
// way in, but a hop can be edited afterwards through a path that did not
// re-check, so expansion carries its own visited set rather than trusting
// that nothing upstream ever slipped.
func TestExpandCatchesALoopWrittenBehindItsBack(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	a := host(t, s, userID, "a")
	b := host(t, s, userID, "b", a.ID)
	target := host(t, s, userID, "target", b.ID)

	// Write the loop straight to the database, past every check.
	if _, err := s.db.Exec(ctx, `UPDATE sessions SET jump_chain = ? WHERE id = ?`,
		fmt.Sprintf("[%q]", target.ID), a.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ExpandJumpChain(ctx, userID, target.ID); !errors.Is(err, ErrJumpCycle) {
		t.Fatalf("error = %v, want ErrJumpCycle", err)
	}
}

// TestDeletingABastionOthersUseIsRefused, and the message names them — a jump
// chain has no foreign key behind it, so the alternative is a connection that
// fails later with an error about a host the user forgot was involved.
func TestDeletingABastionOthersUseIsRefused(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	bastion := host(t, s, userID, "bastion")
	host(t, s, userID, "core-sw-01", bastion.ID)
	host(t, s, userID, "core-sw-02", bastion.ID)

	err := s.DeleteSession(ctx, userID, bastion.ID)
	if !IsJumpInUse(err) {
		t.Fatalf("error = %v, want ErrJumpInUse", err)
	}
	if !strings.Contains(err.Error(), "core-sw-01") {
		t.Errorf("the message does not name a dependent: %v", err)
	}

	// It is still there.
	if _, err := s.GetSession(ctx, userID, bastion.ID); err != nil {
		t.Errorf("the refused delete removed it anyway: %v", err)
	}

	// And once nothing points at it, it goes.
	all, err := s.ListSessions(ctx, userID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, sess := range all {
		if sess.ID != bastion.ID {
			if err := s.DeleteSession(ctx, userID, sess.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.DeleteSession(ctx, userID, bastion.ID); err != nil {
		t.Errorf("deleting an unused bastion: %v", err)
	}
}

func names(route []Resolved) []string {
	out := make([]string, len(route))
	for i, r := range route {
		out[i] = r.Name
	}
	return out
}
