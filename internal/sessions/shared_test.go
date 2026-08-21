package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

// The shared tree's security properties, tested where they are enforced.
//
// Every test here is a sentence an auditor would ask to see proven: a member
// sees the team's tree, a non-member does not, and the dial path agrees with
// the listing about both.

func sharedFixture(t *testing.T) (*Store, *store.DB, string, string, string) {
	t.Helper()
	s, db, member := fixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	outsider := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		outsider, "mallory@example.com", "mallory@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	teamID := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(ctx,
		`INSERT INTO teams (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		teamID, "NOC "+teamID[:8], now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO team_members (team_id, user_id, role, wrapped_team_dek_enc, created_at)
		 VALUES (?, ?, 'member', '', ?)`, teamID, member, now); err != nil {
		t.Fatal(err)
	}

	return s, db, member, outsider, teamID
}

func TestMembersSeeTheSharedTreeAndOutsidersDoNot(t *testing.T) {
	s, _, member, outsider, teamID := sharedFixture(t)
	ctx := context.Background()

	folder, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID: teamID, IsTeam: true, Name: "Core network",
	})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: teamID, IsTeam: true, ActorID: member,
		FolderID: folder.ID, Name: "core-sw-01", Hostname: "10.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	memberTree, err := s.LoadTreeForUser(ctx, member)
	if err != nil {
		t.Fatal(err)
	}
	if len(memberTree.Folders) != 1 || len(memberTree.Sessions) != 1 {
		t.Fatalf("member sees %d folders and %d sessions, want the shared 1 and 1",
			len(memberTree.Folders), len(memberTree.Sessions))
	}
	if !memberTree.Sessions[0].IsTeam {
		t.Error("the shared session should be marked team-owned in the listing")
	}

	outsiderTree, err := s.LoadTreeForUser(ctx, outsider)
	if err != nil {
		t.Fatal(err)
	}
	if len(outsiderTree.Folders) != 0 || len(outsiderTree.Sessions) != 0 {
		t.Fatalf("an outsider sees %d folders and %d sessions of a team they are not in",
			len(outsiderTree.Folders), len(outsiderTree.Sessions))
	}

	// The dial path must agree with the listing — this is the enforcement
	// that matters, because hiding rows is not security.
	if _, err := s.Resolve(ctx, member, shared.ID); err != nil {
		t.Errorf("a member could not resolve the shared connection: %v", err)
	}
	if _, err := s.Resolve(ctx, outsider, shared.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("an outsider resolving a shared connection got %v, want ErrNotFound", err)
	}
}

func TestFolderCredentialOverlayFillsSharedConnections(t *testing.T) {
	s, db, member, outsider, teamID := sharedFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	folder, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID: teamID, IsTeam: true, Name: "Rack 4",
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID: teamID, IsTeam: true, ParentID: folder.ID, Name: "Top of rack",
	})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: teamID, IsTeam: true, ActorID: member,
		FolderID: child.ID, Name: "tor-1", Hostname: "10.0.4.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	credID := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(ctx, `
		INSERT INTO credentials (id, user_id, name, kind, created_at, updated_at)
		VALUES (?, ?, 'my tacacs', 'password', ?, ?)`,
		credID, member, now, now); err != nil {
		t.Fatal(err)
	}

	// Before any choice: resolves with no credential, which is what makes
	// the interface ask.
	resolved, err := s.Resolve(ctx, member, shared.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveCredentialID != "" {
		t.Fatalf("credential before choosing = %q, want empty", resolved.EffectiveCredentialID)
	}

	// Chosen on the PARENT folder: the overlay must walk up, so one choice
	// covers the whole rack.
	if err := s.SetFolderCredential(ctx, member, folder.ID, credID); err != nil {
		t.Fatal(err)
	}
	resolved, err = s.Resolve(ctx, member, shared.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveCredentialID != credID {
		t.Fatalf("credential after choosing = %q, want %q", resolved.EffectiveCredentialID, credID)
	}

	// The choice is personal: another member (or an outsider) never inherits
	// somebody else's credential selection.
	if err := s.SetFolderCredential(ctx, outsider, folder.ID, credID); !errors.Is(err, ErrNotFound) {
		t.Errorf("an outsider setting a folder credential got %v, want ErrNotFound", err)
	}
}

func TestPersonalTreesStayPersonal(t *testing.T) {
	s, _, member, outsider, _ := sharedFixture(t)
	ctx := context.Background()

	mine, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: member, Name: "my box", Hostname: "192.168.1.10",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Resolve(ctx, outsider, mine.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("an outsider resolving a personal connection got %v, want ErrNotFound", err)
	}
	tree, err := s.LoadTreeForUser(ctx, outsider)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Sessions) != 0 {
		t.Error("an outsider's tree contains someone else's personal connection")
	}
}
