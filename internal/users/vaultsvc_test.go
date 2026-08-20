package users

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/vault"
)

func testVaultService(t *testing.T, mode SSOUnlockMode) (*VaultService, *Store, vault.Key) {
	t.Helper()

	us, _ := testStore(t)
	cache := vault.NewCache(time.Hour)
	t.Cleanup(cache.Close)

	master, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}

	// Cheap KDF costs; production costs are exercised in the vault package.
	vs, err := NewVaultService(us, cache, master, VaultServiceConfig{
		Argon2Time: 1, Argon2MemoryKB: 16 * 1024, Argon2Threads: 1,
		SSOUnlockMode: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vs, us, master
}

func TestEnrolAndUnlockLocalUser(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "login-password"})
	if err != nil {
		t.Fatal(err)
	}

	kind, err := vs.Enrol(ctx, u, "sess-1", "vault passphrase")
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if kind != UnlockDerived {
		t.Errorf("kind = %q, want derived for a local account", kind)
	}

	key, err := vs.Key(u.ID, "sess-1")
	if err != nil {
		t.Fatalf("the key should be cached after enrolment: %v", err)
	}
	if key.IsZero() {
		t.Fatal("cached key is all zeroes")
	}

	// A second session must unlock with the same passphrase.
	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Unlock(ctx, reloaded, "sess-2", "vault passphrase"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	second, err := vs.Key(u.ID, "sess-2")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Equal(key) {
		t.Fatal("the two sessions hold different keys for the same vault")
	}
}

func TestUnlockRejectsWrongPassphrase(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, u, "sess-1", "right passphrase"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{"wrong passphrase", "", "Right passphrase"} {
		if err := vs.Unlock(ctx, reloaded, "sess-2", wrong); !errors.Is(err, vault.ErrWrongPassphrase) {
			t.Errorf("passphrase %q: want ErrWrongPassphrase, got %v", wrong, err)
		}
		if _, err := vs.Key(u.ID, "sess-2"); !errors.Is(err, ErrVaultLocked) {
			t.Error("a failed unlock must leave the session locked")
		}
	}
}

// TestSSOUserGetsSeparatePassphrase pins the decision that shapes the whole
// phase: with SSO the server never sees a password, so there is nothing to
// derive a key from.
func TestSSOUserGetsSeparatePassphrase(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{
		Email: "alice@example.com", SSOProvider: "entra", SSOSubject: "object-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !vs.RequiresPassphrase(u) {
		t.Fatal("an SSO user in passphrase mode must be prompted")
	}

	kind, err := vs.Enrol(ctx, u, "sess-1", "vault passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if kind != UnlockSeparate {
		t.Errorf("kind = %q, want separate", kind)
	}

	// Enrolment without a passphrase must be refused in this mode.
	other, err := us.Create(ctx, CreateParams{
		Email: "bob@example.com", SSOProvider: "entra", SSOSubject: "object-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, other, "sess-2", ""); err == nil {
		t.Fatal("enrolling without a passphrase must be refused in passphrase mode")
	}
}

// TestServerManagedModeNeedsNoPassphrase covers the alternative an operator
// may knowingly choose, and confirms the trade-off is real: the master key
// alone opens the vault.
func TestServerManagedModeNeedsNoPassphrase(t *testing.T) {
	vs, us, master := testVaultService(t, SSOUnlockServerManaged)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{
		Email: "alice@example.com", SSOProvider: "entra", SSOSubject: "object-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if vs.RequiresPassphrase(u) {
		t.Fatal("server-managed mode must not prompt an SSO user")
	}

	kind, err := vs.Enrol(ctx, u, "sess-1", "")
	if err != nil {
		t.Fatalf("Enrol without a passphrase must succeed in this mode: %v", err)
	}
	if kind != UnlockServer {
		t.Errorf("kind = %q, want server", kind)
	}

	// A new session unlocks with no passphrase at all.
	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Unlock(ctx, reloaded, "sess-2", ""); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// And the master key alone is sufficient to open it — the exact property
	// this mode gives up. Asserted so the trade-off cannot be quietly lost.
	key, err := vault.OpenKeyFrom(master, vault.MasterAAD(u.ID, "user-dek"), reloaded.WrappedDEK.Envelope)
	if err != nil {
		t.Fatalf("server-managed vaults are meant to open with the master key: %v", err)
	}
	if key.IsZero() {
		t.Fatal("recovered key is empty")
	}

	if !SSOUnlockServerManaged.WeakensSecurity() {
		t.Error("server_managed must report that it weakens the security model")
	}
	if SSOUnlockPassphrase.WeakensSecurity() {
		t.Error("passphrase mode must not report weakening")
	}
}

// TestLocalUserAlwaysNeedsPassphrase confirms server-managed mode applies only
// to SSO accounts — a local account has a password to derive from, so there is
// no reason to weaken it.
func TestLocalUserAlwaysNeedsPassphrase(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockServerManaged)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "admin@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if !vs.RequiresPassphrase(u) {
		t.Fatal("a local account must be prompted even in server-managed mode")
	}

	kind, err := vs.Enrol(ctx, u, "sess-1", "vault passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if kind == UnlockServer {
		t.Error("a local account must not get a server-managed vault")
	}
}

func TestEnrolRefusesSecondVault(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, u, "sess-1", "first"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Re-enrolling would orphan every credential the first vault protected.
	if _, err := vs.Enrol(ctx, reloaded, "sess-2", "second"); !errors.Is(err, ErrVaultAlreadySetUp) {
		t.Fatalf("want ErrVaultAlreadySetUp, got %v", err)
	}
}

// TestChangePassphrasePreservesCredentials is the property that keeps a
// passphrase change a single row update rather than a bulk re-encryption.
func TestChangePassphrasePreservesCredentials(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, u, "sess-1", "old passphrase"); err != nil {
		t.Fatal(err)
	}

	key, err := vs.Key(u.ID, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	aad := vault.CredentialAAD(u.ID, "cred-1", "private_key")
	sealed, err := vault.Seal(key, aad, []byte("secret key material"))
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.ChangePassphrase(ctx, reloaded, "sess-1", "old passphrase", "new passphrase"); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}

	// The session keeps working without re-unlocking.
	after, err := vs.Key(u.ID, "sess-1")
	if err != nil {
		t.Fatalf("the current session should stay unlocked: %v", err)
	}
	got, err := vault.Open(after, aad, sealed)
	if err != nil {
		t.Fatalf("credentials must survive a passphrase change: %v", err)
	}
	if string(got) != "secret key material" {
		t.Fatalf("got %q", got)
	}

	// Old passphrase stops working; new one starts.
	final, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Unlock(ctx, final, "sess-3", "old passphrase"); !errors.Is(err, vault.ErrWrongPassphrase) {
		t.Errorf("the old passphrase must stop working, got %v", err)
	}
	if err := vs.Unlock(ctx, final, "sess-4", "new passphrase"); err != nil {
		t.Errorf("the new passphrase must work: %v", err)
	}
}

// TestChangePassphraseRequiresCurrent stops a hijacked session from locking
// the real owner out.
func TestChangePassphraseRequiresCurrent(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, u, "sess-1", "old passphrase"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = vs.ChangePassphrase(ctx, reloaded, "sess-1", "guessed wrong", "attacker passphrase")
	if !errors.Is(err, vault.ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}

	// The original passphrase must still work.
	final, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Unlock(ctx, final, "sess-2", "old passphrase"); err != nil {
		t.Fatalf("the vault must be untouched after a failed change: %v", err)
	}
}

// TestLockAllForUserIsScopedToThatUser is the regression test for a real bug:
// an earlier version of Reset cleared the entire cache, which would have
// logged out every user in the company when one person reset their vault.
func TestLockAllForUserIsScopedToThatUser(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	alice, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := us.Create(ctx, CreateParams{Email: "bob@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := vs.Enrol(ctx, alice, "alice-sess-1", "alice pass"); err != nil {
		t.Fatal(err)
	}
	aliceReloaded, err := us.ByID(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Unlock(ctx, aliceReloaded, "alice-sess-2", "alice pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, bob, "bob-sess-1", "bob pass"); err != nil {
		t.Fatal(err)
	}

	n := vs.LockAllForUser(alice.ID)
	if n != 2 {
		t.Errorf("locked %d of alice's sessions, want 2", n)
	}

	for _, sess := range []string{"alice-sess-1", "alice-sess-2"} {
		if _, err := vs.Key(alice.ID, sess); !errors.Is(err, ErrVaultLocked) {
			t.Errorf("alice's session %s should be locked", sess)
		}
	}
	if _, err := vs.Key(bob.ID, "bob-sess-1"); err != nil {
		t.Fatalf("another user's session must be untouched: %v", err)
	}
}

// TestKeyIsScopedToItsOwner confirms one user cannot read another's cached key
// by guessing a session ID.
func TestKeyIsScopedToItsOwner(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	alice, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := us.Create(ctx, CreateParams{Email: "bob@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, alice, "shared-session-id", "alice pass"); err != nil {
		t.Fatal(err)
	}

	if _, err := vs.Key(bob.ID, "shared-session-id"); !errors.Is(err, ErrVaultLocked) {
		t.Fatal("a session ID collision must not expose another user's key")
	}
}

func TestLockZeroesTheKey(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, u, "sess-1", "passphrase"); err != nil {
		t.Fatal(err)
	}

	key, err := vs.Key(u.ID, "sess-1")
	if err != nil {
		t.Fatal(err)
	}

	vs.Lock(u.ID, "sess-1")

	if !key.IsZero() {
		t.Fatal("logging out must zero the key, not merely drop the reference")
	}
	if _, err := vs.Key(u.ID, "sess-1"); !errors.Is(err, ErrVaultLocked) {
		t.Error("the session should read as locked after Lock")
	}
}

func TestResetClearsCachedKeys(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Enrol(ctx, u, "sess-1", "passphrase"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := us.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Reset(ctx, reloaded); err != nil {
		t.Fatal(err)
	}

	if _, err := vs.Key(u.ID, "sess-1"); !errors.Is(err, ErrVaultLocked) {
		t.Fatal("an open tab must not keep using a vault that was just destroyed")
	}
}

func TestUnlockRequiresAnEnrolledVault(t *testing.T) {
	vs, us, _ := testVaultService(t, SSOUnlockPassphrase)
	ctx := context.Background()

	u, err := us.Create(ctx, CreateParams{Email: "alice@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if err := vs.Unlock(ctx, u, "sess-1", "anything"); !errors.Is(err, ErrVaultNotSetUp) {
		t.Fatalf("want ErrVaultNotSetUp, got %v", err)
	}
}

func TestSSOUnlockModeValidate(t *testing.T) {
	for _, mode := range []SSOUnlockMode{SSOUnlockPassphrase, SSOUnlockServerManaged} {
		if err := mode.Validate(); err != nil {
			t.Errorf("%q should be valid: %v", mode, err)
		}
	}
	for _, mode := range []SSOUnlockMode{"", "yes", "server", "passphrase_mode"} {
		if err := mode.Validate(); err == nil {
			t.Errorf("%q should be refused", mode)
		}
	}
}

// TestNewVaultServiceRejectsWeakCosts makes a bad cost setting stop the server
// starting rather than surprising the first user to enrol.
func TestNewVaultServiceRejectsWeakCosts(t *testing.T) {
	us, _ := testStore(t)
	cache := vault.NewCache(time.Hour)
	defer cache.Close()

	master, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewVaultService(us, cache, master, VaultServiceConfig{
		Argon2Time: 1, Argon2MemoryKB: 1024, Argon2Threads: 1, // 1 MiB, far too low
		SSOUnlockMode: SSOUnlockPassphrase,
	})
	if err == nil {
		t.Fatal("weak Argon2id costs must prevent the service starting")
	}
}
