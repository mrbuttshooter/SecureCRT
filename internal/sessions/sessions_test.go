package sessions

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

func fixture(t *testing.T) (*Store, *store.DB, string) {
	t.Helper()
	db := storetest.New(t)

	userID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, "alice@example.com", "alice@example.com", now, now); err != nil {
		t.Fatal(err)
	}
	return NewStore(db), db, userID
}

func TestCreateAndGetSession(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	created, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID:  userID,
		Name:     "Core router",
		Hostname: "core1.example.com",
		Username: "netops",
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if created.Protocol != ProtocolSSH {
		t.Errorf("protocol = %q, want ssh by default", created.Protocol)
	}
	if created.Port != 22 {
		t.Errorf("port = %d, want 22 by default", created.Port)
	}

	got, err := s.GetSession(ctx, userID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Core router" || got.Hostname != "core1.example.com" || got.Username != "netops" {
		t.Errorf("session did not round-trip: %+v", got)
	}
	if got.JumpChain == nil {
		t.Error("jump chain should be an empty slice, not nil, so JSON encodes as [] rather than null")
	}
}

func TestTelnetGetsItsOwnDefaultPort(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	created, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "Old switch", Protocol: ProtocolTelnet, Hostname: "switch1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Port != 23 {
		t.Errorf("port = %d, want 23 for telnet", created.Port)
	}
}

// TestFolderInheritance is the behaviour engineers actually rely on: set the
// username and credential once on a folder rather than on all three hundred
// devices inside it.
func TestFolderInheritance(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	production, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID: userID,
		Name:    "Production",
		Defaults: Settings{
			Username:     Ptr("netops"),
			CredentialID: Ptr("cred-production"),
			Scrollback:   Ptr(10000),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	edge, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID:  userID,
		ParentID: production.ID,
		Name:     "Edge",
		// Overrides the credential but inherits the username.
		Defaults: Settings{CredentialID: Ptr("cred-edge")},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("inherits from the nearest folder, then outward", func(t *testing.T) {
		sess, err := s.CreateSession(ctx, CreateSessionParams{
			OwnerID: userID, FolderID: edge.ID, Name: "edge1", Hostname: "edge1.example.com",
		})
		if err != nil {
			t.Fatal(err)
		}

		resolved, err := s.Resolve(ctx, userID, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.EffectiveUsername != "netops" {
			t.Errorf("username = %q; should come from the outer folder", resolved.EffectiveUsername)
		}
		if resolved.EffectiveCredentialID != "cred-edge" {
			t.Errorf("credential = %q; the nearer folder should win", resolved.EffectiveCredentialID)
		}
		if resolved.Settings.Scrollback == nil || *resolved.Settings.Scrollback != 10000 {
			t.Error("scrollback should be inherited from the outer folder")
		}

		// The interface needs to explain where a value came from.
		if len(resolved.InheritedFrom) != 2 ||
			resolved.InheritedFrom[0] != "Production" || resolved.InheritedFrom[1] != "Edge" {
			t.Errorf("InheritedFrom = %v, want [Production Edge] outermost first", resolved.InheritedFrom)
		}
	})

	t.Run("a value on the session beats every folder", func(t *testing.T) {
		sess, err := s.CreateSession(ctx, CreateSessionParams{
			OwnerID: userID, FolderID: edge.ID, Name: "edge2",
			Hostname: "edge2.example.com",
			Username: "root",
			Settings: Settings{CredentialID: Ptr("cred-specific")},
		})
		if err != nil {
			t.Fatal(err)
		}

		resolved, err := s.Resolve(ctx, userID, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.EffectiveUsername != "root" {
			t.Errorf("username = %q; the session's own value must win", resolved.EffectiveUsername)
		}
		if resolved.EffectiveCredentialID != "cred-specific" {
			t.Errorf("credential = %q; the session's own value must win", resolved.EffectiveCredentialID)
		}
	})

	t.Run("a session outside any folder inherits nothing", func(t *testing.T) {
		sess, err := s.CreateSession(ctx, CreateSessionParams{
			OwnerID: userID, Name: "standalone", Hostname: "standalone.example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := s.Resolve(ctx, userID, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.EffectiveUsername != "" {
			t.Errorf("username = %q, want empty", resolved.EffectiveUsername)
		}
		if len(resolved.InheritedFrom) != 0 {
			t.Errorf("InheritedFrom = %v, want empty", resolved.InheritedFrom)
		}
	})
}

// TestMoveRefusesCycles guards a class of bug that shows up much later as a
// hang rather than an error.
func TestMoveRefusesCycles(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	grandparent, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, ParentID: grandparent.ID, Name: "B"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, ParentID: parent.ID, Name: "C"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("into itself", func(t *testing.T) {
		_, err := s.UpdateFolder(ctx, userID, parent.ID, UpdateFolderParams{ParentID: &parent.ID})
		if !errors.Is(err, ErrCycle) {
			t.Fatalf("want ErrCycle, got %v", err)
		}
	})

	t.Run("into its own descendant", func(t *testing.T) {
		// Moving A inside C would detach the whole subtree from the tree.
		_, err := s.UpdateFolder(ctx, userID, grandparent.ID, UpdateFolderParams{ParentID: &child.ID})
		if !errors.Is(err, ErrCycle) {
			t.Fatalf("want ErrCycle, got %v", err)
		}
	})

	t.Run("a legitimate move is allowed", func(t *testing.T) {
		top := ""
		moved, err := s.UpdateFolder(ctx, userID, child.ID, UpdateFolderParams{ParentID: &top})
		if err != nil {
			t.Fatalf("moving to the top level should work: %v", err)
		}
		if moved.ParentID != "" {
			t.Errorf("parent = %q, want empty", moved.ParentID)
		}
	})
}

func TestDepthIsBounded(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	parent := ""
	for i := 0; i < MaxDepth+2; i++ {
		f, err := s.CreateFolder(ctx, CreateFolderParams{
			OwnerID: userID, ParentID: parent, Name: "level",
		})
		if err != nil {
			if errors.Is(err, ErrTooDeep) {
				return // the bound held
			}
			t.Fatalf("unexpected error at depth %d: %v", i, err)
		}
		parent = f.ID
	}
	t.Fatalf("nesting was never bounded; a pathological import could produce an unrenderable tree")
}

// TestDeletingANonEmptyFolderIsRefused is how somebody keeps an afternoon's
// work. The schema would otherwise cascade the sub-folders while dumping
// their connections at the top level, which is nobody's intent.
func TestDeletingANonEmptyFolderIsRefused(t *testing.T) {
	s, db, userID := fixture(t)
	ctx := context.Background()

	folder, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, Name: "Production"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, ParentID: folder.ID, Name: "Edge"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.CreateSession(ctx, CreateSessionParams{
			OwnerID: userID, FolderID: child.ID, Name: "device", Hostname: "d.example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}

	err = s.DeleteFolder(ctx, userID, folder.ID)
	if !IsNotEmpty(err) {
		t.Fatalf("want a non-empty refusal, got %v", err)
	}

	// The refusal must say what is inside, so the interface can name what
	// would be lost rather than asking a vague "are you sure?".
	var notEmpty *ErrFolderNotEmpty
	if errors.As(err, &notEmpty) && notEmpty.Folders != 1 {
		t.Errorf("reported %d sub-folders, want 1", notEmpty.Folders)
	}

	// Nothing may have been removed.
	var folders, sess int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM folders`).Scan(&folders); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sess); err != nil {
		t.Fatal(err)
	}
	if folders != 2 || sess != 3 {
		t.Fatalf("a refused delete changed something: %d folders, %d sessions", folders, sess)
	}
}

func TestRecursiveDeleteRemovesEverything(t *testing.T) {
	s, db, userID := fixture(t)
	ctx := context.Background()

	root, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, Name: "Production"})
	if err != nil {
		t.Fatal(err)
	}
	middle, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, ParentID: root.ID, Name: "Edge"})
	if err != nil {
		t.Fatal(err)
	}
	deep, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, ParentID: middle.ID, Name: "Site A"})
	if err != nil {
		t.Fatal(err)
	}

	for _, folderID := range []string{root.ID, middle.ID, deep.ID} {
		for i := 0; i < 2; i++ {
			if _, err := s.CreateSession(ctx, CreateSessionParams{
				OwnerID: userID, FolderID: folderID, Name: "device", Hostname: "d.example.com",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// A session outside the tree must be untouched.
	outside, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "elsewhere", Hostname: "e.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := s.DeleteFolderRecursive(ctx, userID, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The count is what the audit log records, so it must be right.
	if deleted != 6 {
		t.Errorf("reported %d deleted connections, want 6", deleted)
	}

	var folders, sess int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM folders`).Scan(&folders); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sess); err != nil {
		t.Fatal(err)
	}
	if folders != 0 {
		t.Errorf("%d folders survived", folders)
	}
	if sess != 1 {
		t.Errorf("%d sessions remain, want just the one outside the tree", sess)
	}
	if _, err := s.GetSession(ctx, userID, outside.ID); err != nil {
		t.Errorf("a session outside the deleted tree was removed: %v", err)
	}
}

func TestDeletingAnEmptyFolderWorks(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	folder, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, Name: "Empty"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFolder(ctx, userID, folder.ID); err != nil {
		t.Fatalf("an empty folder should delete without ceremony: %v", err)
	}
	if _, err := s.GetFolder(ctx, userID, folder.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestOwnershipIsEnforced(t *testing.T) {
	s, db, alice := fixture(t)
	ctx := context.Background()

	bob := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		bob, "bob@example.com", "bob@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	folder, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: alice, Name: "Alice's"})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: alice, FolderID: folder.ID, Name: "alice's router", Hostname: "r1.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reported as not-found: confirming a session exists but belongs to
	// someone else discloses their infrastructure.
	for name, fn := range map[string]func() error{
		"get session":    func() error { _, err := s.GetSession(ctx, bob, sess.ID); return err },
		"get folder":     func() error { _, err := s.GetFolder(ctx, bob, folder.ID); return err },
		"resolve":        func() error { _, err := s.Resolve(ctx, bob, sess.ID); return err },
		"delete session": func() error { return s.DeleteSession(ctx, bob, sess.ID) },
		"delete folder":  func() error { return s.DeleteFolder(ctx, bob, folder.ID) },
		"recursive delete": func() error {
			_, err := s.DeleteFolderRecursive(ctx, bob, folder.ID)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := fn(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("want ErrNotFound, got %v", err)
			}
		})
	}

	// And Bob's tree must be empty.
	tree, err := s.LoadTree(ctx, bob, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Folders) != 0 || len(tree.Sessions) != 0 {
		t.Fatalf("another user's tree leaked: %d folders, %d sessions", len(tree.Folders), len(tree.Sessions))
	}
}

func TestUpdateSession(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	sess, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "old", Hostname: "old.example.com", Username: "olduser", Port: 22,
	})
	if err != nil {
		t.Fatal(err)
	}

	newName := "new"
	newHost := "new.example.com"
	updated, err := s.UpdateSession(ctx, userID, sess.ID, UpdateSessionParams{
		Name: &newName, Hostname: &newHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "new" || updated.Hostname != "new.example.com" {
		t.Errorf("update did not apply: %+v", updated)
	}
	// Unspecified fields must be left alone, not blanked.
	if updated.Username != "olduser" || updated.Port != 22 {
		t.Errorf("a nil field was cleared: %+v", updated)
	}

	t.Run("port range is enforced", func(t *testing.T) {
		bad := 70000
		if _, err := s.UpdateSession(ctx, userID, sess.ID, UpdateSessionParams{Port: &bad}); err == nil {
			t.Fatal("an out-of-range port must be refused")
		}
	})

	t.Run("moving to a folder that is not yours is refused", func(t *testing.T) {
		ghost := "no-such-folder"
		if _, err := s.UpdateSession(ctx, userID, sess.ID, UpdateSessionParams{FolderID: &ghost}); err == nil {
			t.Fatal("expected rejection")
		}
	})
}

func TestJumpChainRoundTrips(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	bastion, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "bastion", Hostname: "bastion.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "inner", Hostname: "10.0.0.5",
	})
	if err != nil {
		t.Fatal(err)
	}

	chain := []string{bastion.ID, inner.ID}
	target, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "deep", Hostname: "10.1.0.9", JumpChain: chain,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSession(ctx, userID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.JumpChain) != 2 || got.JumpChain[0] != bastion.ID || got.JumpChain[1] != inner.ID {
		t.Fatalf("jump chain did not round-trip in order: %v", got.JumpChain)
	}
}

func TestCreateValidation(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	cases := map[string]CreateSessionParams{
		"no owner":    {Name: "x", Hostname: "h"},
		"no name":     {OwnerID: userID, Hostname: "h"},
		"blank name":  {OwnerID: userID, Name: "   ", Hostname: "h"},
		"no hostname": {OwnerID: userID, Name: "x"},
		"bad port":    {OwnerID: userID, Name: "x", Hostname: "h", Port: 70000},
		"bad proto":   {OwnerID: userID, Name: "x", Hostname: "h", Protocol: "carrier-pigeon"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.CreateSession(ctx, p); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	// Serial addresses a device, not a host, so an empty hostname is fine.
	t.Run("serial needs no hostname", func(t *testing.T) {
		if _, err := s.CreateSession(ctx, CreateSessionParams{
			OwnerID: userID, Name: "console", Protocol: ProtocolSerial,
		}); err != nil {
			t.Fatalf("serial without a hostname should be allowed: %v", err)
		}
	})
}

func TestLoadTree(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	folder, err := s.CreateFolder(ctx, CreateFolderParams{OwnerID: userID, Name: "Production"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.CreateSession(ctx, CreateSessionParams{
			OwnerID: userID, FolderID: folder.ID,
			Name: "device", Hostname: "device.example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}

	tree, err := s.LoadTree(ctx, userID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Folders) != 1 || len(tree.Sessions) != 3 {
		t.Fatalf("tree = %d folders, %d sessions", len(tree.Folders), len(tree.Sessions))
	}
}

func TestMarkUsed(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	sess, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "x", Hostname: "h.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.LastUsedAt != nil {
		t.Error("a new session should have no last-used timestamp")
	}

	if err := s.MarkUsed(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, userID, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("use was not recorded")
	}
}

// TestDanglingFolderReferencesCannotOccur documents why Resolve needs no
// special handling for one: the foreign key makes it impossible to point a
// session at a folder that does not exist.
func TestDanglingFolderReferencesCannotOccur(t *testing.T) {
	s, db, userID := fixture(t)
	ctx := context.Background()

	sess, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, Name: "x", Hostname: "h.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(ctx,
		`UPDATE sessions SET folder_id = ? WHERE id = ?`, "no-such-folder", sess.ID); err == nil {
		t.Fatal("the database allowed a session to reference a folder that does not exist")
	}
}

// TestSessionsSurviveTheirFolderBeingEmptied confirms a session moved out of a
// deleted folder still resolves, falling back to protocol defaults.
func TestSessionsSurviveTheirFolderBeingEmptied(t *testing.T) {
	s, _, userID := fixture(t)
	ctx := context.Background()

	folder, err := s.CreateFolder(ctx, CreateFolderParams{
		OwnerID: userID, Name: "Temp", Defaults: Settings{Username: Ptr("netops")},
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.CreateSession(ctx, CreateSessionParams{
		OwnerID: userID, FolderID: folder.ID, Name: "x", Hostname: "h.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Move it out, then remove the now-empty folder.
	top := ""
	if _, err := s.UpdateSession(ctx, userID, sess.ID, UpdateSessionParams{FolderID: &top}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFolder(ctx, userID, folder.ID); err != nil {
		t.Fatal(err)
	}

	resolved, err := s.Resolve(ctx, userID, sess.ID)
	if err != nil {
		t.Fatalf("the session should still resolve: %v", err)
	}
	if resolved.EffectiveUsername != "" {
		t.Errorf("username = %q; the folder's default should no longer apply", resolved.EffectiveUsername)
	}
	if resolved.EffectivePort != 22 {
		t.Errorf("port = %d, want the protocol default", resolved.EffectivePort)
	}
}

// TestAgentForwardingIsNeverInheritedFromAFolder pins the one omission in
// merge that is load-bearing.
//
// Every other setting is a convenience and inherits happily. This one is an
// authority: it lets the host use the user's keys to authenticate anywhere
// those keys are accepted, for as long as the connection lives. Inherited
// from a folder it would grant that to every host inside — including hosts
// somebody else adds next month — and the person who set the default would be
// the last to know.
//
// Adding the field to merge is a one-line change that looks like tidying up
// after an oversight. This is the test that says it is not one.
func TestAgentForwardingIsNeverInheritedFromAFolder(t *testing.T) {
	keys := []string{"cred-1", "cred-2"}
	parent := Settings{AgentForwardCredentials: &keys}

	child := Settings{}
	merged := child.merge(parent)

	if merged.ForwardsAgent() {
		t.Fatalf("a folder default forwarded an agent to a connection that never "+
			"asked for one: %v", merged.AgentCredentials())
	}

	// And the rest of inheritance still works, so this is an exclusion rather
	// than merge being broken.
	username := "alice"
	merged = Settings{}.merge(Settings{Username: &username, AgentForwardCredentials: &keys})
	if merged.Username == nil || *merged.Username != "alice" {
		t.Error("ordinary settings must still be inherited")
	}
	if merged.ForwardsAgent() {
		t.Error("the agent setting came through alongside one that should")
	}
}

// TestAConnectionsOwnAgentSettingSurvivesInheritance: excluded from merge
// must not mean discarded.
func TestAConnectionsOwnAgentSettingSurvivesInheritance(t *testing.T) {
	own := []string{"my-key"}
	parentKeys := []string{"somebody-elses-key"}

	merged := Settings{AgentForwardCredentials: &own}.
		merge(Settings{AgentForwardCredentials: &parentKeys})

	got := merged.AgentCredentials()
	if len(got) != 1 || got[0] != "my-key" {
		t.Fatalf("the connection's own keys = %v, want [my-key]", got)
	}
}
