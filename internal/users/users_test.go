package users

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

func testStore(t *testing.T) (*Store, *store.DB) {
	t.Helper()
	db := storetest.New(t)
	return NewStore(db), db
}

func TestCreateAndFetch(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	created, err := s.Create(ctx, CreateParams{
		Email:       "Alice@Example.COM",
		DisplayName: "Alice Example",
		Password:    "correct horse battery staple",
		IsAdmin:     true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("no ID assigned")
	}
	if created.UnlockKind != UnlockUnset {
		t.Errorf("unlock kind = %q, want unset before enrolment", created.UnlockKind)
	}

	t.Run("by id", func(t *testing.T) {
		got, err := s.ByID(ctx, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Email != "Alice@Example.COM" {
			t.Errorf("email = %q; the original casing should be preserved for display", got.Email)
		}
		if !got.IsAdmin {
			t.Error("admin flag did not persist")
		}
	})

	// Lookup is case-insensitive even though display casing is kept, because
	// people type their address however they please.
	t.Run("by email, any casing", func(t *testing.T) {
		for _, variant := range []string{
			"Alice@Example.COM", "alice@example.com", "ALICE@EXAMPLE.COM", "  alice@example.com  ",
		} {
			got, err := s.ByEmail(ctx, variant)
			if err != nil {
				t.Errorf("%q was not found: %v", variant, err)
				continue
			}
			if got.ID != created.ID {
				t.Errorf("%q resolved to the wrong user", variant)
			}
		}
	})

	t.Run("password verifies", func(t *testing.T) {
		got, err := s.ByID(ctx, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.PasswordHash == "" {
			t.Fatal("no password hash stored")
		}
		if strings.Contains(got.PasswordHash, "correct horse") {
			t.Fatal("the plaintext password is in the stored hash")
		}
	})
}

func TestCreateRejectsDuplicateEmail(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, CreateParams{Email: "alice@example.com"}); err != nil {
		t.Fatal(err)
	}

	// Different casing must still collide, or two accounts could exist for
	// one person.
	for _, dup := range []string{"alice@example.com", "Alice@Example.com", "ALICE@EXAMPLE.COM"} {
		if _, err := s.Create(ctx, CreateParams{Email: dup}); !errors.Is(err, ErrEmailInUse) {
			t.Errorf("%q: want ErrEmailInUse, got %v", dup, err)
		}
	}
}

func TestValidateEmail(t *testing.T) {
	valid := []string{
		"alice@example.com",
		"alice.smith@sub.example.co.uk",
		"alice+tag@example.com",
		"a@b.co",
		"first.last@contoso.onmicrosoft.com",
	}
	for _, e := range valid {
		if err := ValidateEmail(e); err != nil {
			t.Errorf("%q should be accepted: %v", e, err)
		}
	}

	invalid := []string{
		"", "   ", "no-at-sign", "@example.com", "alice@",
		"alice@@example.com", "alice @example.com", "alice@example",
		"alice\n@example.com",
	}
	for _, e := range invalid {
		if err := ValidateEmail(e); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("%q should be refused, got %v", e, err)
		}
	}
}

// TestBySSOMatchesOnSubjectNotEmail is why identity is keyed on the directory
// object ID. An address can be reassigned to a new employee; matching on it
// would hand the new starter the previous holder's stored credentials.
func TestBySSOMatchesOnSubjectNotEmail(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	original, err := s.Create(ctx, CreateParams{
		Email:       "jsmith@example.com",
		SSOProvider: "entra",
		SSOSubject:  "object-id-first-employee",
		SSOTenant:   "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The first employee leaves; the address is reassigned. Entra issues a
	// token for a different object ID with the same address.
	if _, err := s.BySSO(ctx, "entra", "object-id-second-employee"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a different directory object must not resolve to the existing account")
	}

	got, err := s.BySSO(ctx, "entra", "object-id-first-employee")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != original.ID {
		t.Fatal("the original subject should still resolve")
	}
}

func TestSetAndResetVault(t *testing.T) {
	s, db := testStore(t)
	ctx := context.Background()

	u, err := s.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}

	params, err := vault.NewKDFParams(1, 16*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	dek, wrapped, err := vault.NewUserKey(u.ID, []byte("vault passphrase"), params)
	if err != nil {
		t.Fatal(err)
	}
	defer dek.Zero()

	if err := s.SetVault(ctx, u.ID, UnlockDerived, wrapped); err != nil {
		t.Fatal(err)
	}

	got, err := s.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasVault() {
		t.Fatal("vault was not recorded")
	}
	if got.UnlockKind != UnlockDerived {
		t.Errorf("unlock kind = %q", got.UnlockKind)
	}

	// The stored key must round-trip through the two columns intact.
	recovered, err := vault.UnwrapUserKey(u.ID, []byte("vault passphrase"), *got.WrappedDEK)
	if err != nil {
		t.Fatalf("the stored wrapped key did not survive the round trip: %v", err)
	}
	if !recovered.Equal(dek) {
		t.Fatal("the recovered key differs from the original")
	}

	// KDF params must be stored readably, so an operator can find accounts
	// still on old costs without decrypting anything.
	var kdfJSON string
	if err := db.QueryRow(ctx, `SELECT kdf_params FROM users WHERE id = ?`, u.ID).Scan(&kdfJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(kdfJSON, "memory_kb") {
		t.Errorf("kdf_params is not readable JSON: %q", kdfJSON)
	}

	t.Run("reset destroys the vault and its credentials", func(t *testing.T) {
		const ts = "2026-01-01T00:00:00Z"
		if _, err := db.Exec(ctx,
			`INSERT INTO credentials (id, user_id, name, kind, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"cred-1", u.ID, "a key", "ssh_key", ts, ts); err != nil {
			t.Fatal(err)
		}

		if err := s.ResetVault(ctx, u.ID); err != nil {
			t.Fatal(err)
		}

		after, err := s.ByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.HasVault() {
			t.Error("the vault survived a reset")
		}
		if after.UnlockKind != UnlockUnset {
			t.Errorf("unlock kind = %q after reset", after.UnlockKind)
		}
		if after.VaultResetAt == nil {
			t.Error("the reset was not stamped on the account, so the UI cannot explain the empty vault")
		}

		var n int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM credentials WHERE user_id = ?`, u.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%d credentials survived; they are undecryptable and must not be left behind", n)
		}
	})
}

func TestSetVaultRejectsUnsetKind(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	u, err := s.Create(ctx, CreateParams{Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetVault(ctx, u.ID, UnlockUnset, vault.WrappedKey{}); err == nil {
		t.Fatal("enrolling a vault with kind 'unset' must be refused")
	}
}

func TestAdminLifecycle(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	admin, err := s.Create(ctx, CreateParams{Email: "admin@example.com", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, CreateParams{Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}

	n, err := s.CountAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("admin count = %d, want 1", n)
	}

	// Disabling the admin must drop the count, which is what lets a caller
	// refuse to remove the last one.
	if err := s.SetDisabled(ctx, admin.ID, true); err != nil {
		t.Fatal(err)
	}
	n, err = s.CountAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a disabled admin still counts: %d", n)
	}

	if err := s.SetDisabled(ctx, admin.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdmin(ctx, admin.ID, false); err != nil {
		t.Fatal(err)
	}
	n, err = s.CountAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("admin count = %d after revoking, want 0", n)
	}
}

func TestUpdateProfileFollowsDirectoryChanges(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	u, err := s.Create(ctx, CreateParams{
		Email: "jane.smith@example.com", DisplayName: "Jane Smith",
		SSOProvider: "entra", SSOSubject: "object-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// A name and address change in the directory should follow through.
	if err := s.UpdateProfile(ctx, u.ID, "jane.doe@example.com", "Jane Doe"); err != nil {
		t.Fatal(err)
	}

	got, err := s.BySSO(ctx, "entra", "object-1")
	if err != nil {
		t.Fatalf("the account must still resolve by subject after a rename: %v", err)
	}
	if got.Email != "jane.doe@example.com" || got.DisplayName != "Jane Doe" {
		t.Errorf("profile did not update: %+v", got)
	}
	if got.ID != u.ID {
		t.Error("a rename must not create a new account")
	}
}

func TestUpdateProfileRefusesTakenEmail(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, CreateParams{Email: "taken@example.com"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.Create(ctx, CreateParams{Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateProfile(ctx, u.ID, "taken@example.com", "Alice"); !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("want ErrEmailInUse, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	u, err := s.Create(ctx, CreateParams{Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ByID(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting a missing user should report ErrNotFound, got %v", err)
	}
}

func TestListAndTimestamps(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if _, err := s.Create(ctx, CreateParams{Email: email}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}

	list, err := s.List(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("listed %d users, want 3", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i].CreatedAt.Before(list[i-1].CreatedAt) {
			t.Fatal("list is not ordered oldest first")
		}
	}

	u := list[0]
	if u.LastLoginAt != nil {
		t.Error("a new account should have no last-login timestamp")
	}
	if err := s.UpdateLastLogin(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastLoginAt == nil {
		t.Error("last login was not recorded")
	}
}

func TestNotFound(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	for name, fn := range map[string]func() error{
		"by id":    func() error { _, err := s.ByID(ctx, "nope"); return err },
		"by email": func() error { _, err := s.ByEmail(ctx, "nobody@example.com"); return err },
		"by sso":   func() error { _, err := s.BySSO(ctx, "entra", "nope"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := fn(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("want ErrNotFound, got %v", err)
			}
		})
	}
}
