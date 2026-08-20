package credentials

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

// testFixture returns a store, a database, an owning user and their vault key.
func testFixture(t *testing.T) (*Store, *store.DB, string, vault.Key) {
	t.Helper()

	db := storetest.New(t)
	ctx := context.Background()

	userID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, "alice@example.com", "alice@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(db), db, userID, key
}

func TestCreateAndReveal(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	generated, err := GenerateKey(KeyEd25519, "alice@workstation")
	if err != nil {
		t.Fatal(err)
	}

	c, err := s.Create(ctx, key, CreateParams{
		OwnerID:     userID,
		Name:        "Production jump host",
		Kind:        KindSSHKey,
		Username:    "alice",
		Secret:      generated.PrivateKeyPEM,
		PublicKey:   generated.PublicKey,
		Fingerprint: generated.Fingerprint,
		KeyType:     string(generated.KeyType),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	secret, err := s.Reveal(ctx, key, userID, c.ID)
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if secret.Value != generated.PrivateKeyPEM {
		t.Fatal("the private key did not survive the round trip")
	}
}

// TestSecretIsEncryptedAtRest is the core storage guarantee.
func TestSecretIsEncryptedAtRest(t *testing.T) {
	s, db, userID, key := testFixture(t)
	ctx := context.Background()

	const password = "sup3rs3cret-passw0rd"
	c, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "router", Kind: KindPassword, Secret: password,
	})
	if err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := db.QueryRow(ctx, `SELECT secret_enc FROM credentials WHERE id = ?`, c.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, password) {
		t.Fatal("the plaintext password is in the database")
	}
	if stored == "" {
		t.Fatal("nothing was stored")
	}

	// A different key must not open it.
	other, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reveal(ctx, other, userID, c.ID); err == nil {
		t.Fatal("another user's key opened this credential")
	}
}

// TestCredentialStructCarriesNoSecret is a structural guarantee: a handler
// that serialises the whole Credential cannot leak key material, because
// there is no field to leak.
func TestCredentialStructCarriesNoSecret(t *testing.T) {
	forbidden := []string{"Secret", "Password", "PrivateKey", "Passphrase", "Extra", "Value"}

	typ := reflect.TypeOf(Credential{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		for _, bad := range forbidden {
			if strings.EqualFold(name, bad) {
				t.Errorf("Credential has a field %q; secret material must not be reachable "+
					"from the struct that list and detail views serialise", name)
			}
		}
	}
}

// TestAADBindingBlocksRelocation covers an attacker with database write
// access moving one user's ciphertext onto another user's credential row.
func TestAADBindingBlocksRelocation(t *testing.T) {
	s, db, alice, aliceKey := testFixture(t)
	ctx := context.Background()

	bob := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		bob, "bob@example.com", "bob@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	aliceCred, err := s.Create(ctx, aliceKey, CreateParams{
		OwnerID: alice, Name: "alice key", Kind: KindPassword, Secret: "alice-secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	bobKey, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	bobCred, err := s.Create(ctx, bobKey, CreateParams{
		OwnerID: bob, Name: "bob key", Kind: KindPassword, Secret: "bob-secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Copy Alice's ciphertext onto Bob's row.
	var aliceCipher string
	if err := db.QueryRow(ctx, `SELECT secret_enc FROM credentials WHERE id = ?`, aliceCred.ID).Scan(&aliceCipher); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE credentials SET secret_enc = ? WHERE id = ?`, aliceCipher, bobCred.ID); err != nil {
		t.Fatal(err)
	}

	// Even with Alice's own key, the relocated ciphertext must not decrypt,
	// because the AAD names the original owner and record.
	if _, err := s.Reveal(ctx, aliceKey, bob, bobCred.ID); err == nil {
		t.Fatal("a ciphertext moved to another user's row decrypted successfully")
	}
	if _, err := s.Reveal(ctx, bobKey, bob, bobCred.ID); err == nil {
		t.Fatal("the relocated ciphertext decrypted under the new owner's key")
	}
}

// TestSecondFieldCannotBeSwapped covers moving the key passphrase into the
// private key slot on the same credential.
func TestSecondFieldCannotBeSwapped(t *testing.T) {
	s, db, userID, key := testFixture(t)
	ctx := context.Background()

	c, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "key", Kind: KindSSHKey,
		Secret: "the private key", Extra: "the key passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}

	var extra string
	if err := db.QueryRow(ctx, `SELECT secret_extra_enc FROM credentials WHERE id = ?`, c.ID).Scan(&extra); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE credentials SET secret_enc = ? WHERE id = ?`, extra, c.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Reveal(ctx, key, userID, c.ID); err == nil {
		t.Fatal("a ciphertext swapped between fields decrypted successfully")
	}
}

func TestListDoesNotNeedTheVaultKey(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	generated, err := GenerateKey(KeyEd25519, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "a key", Kind: KindSSHKey,
		Secret: generated.PrivateKeyPEM, PublicKey: generated.PublicKey,
		Fingerprint: generated.Fingerprint, KeyType: string(generated.KeyType),
	}); err != nil {
		t.Fatal(err)
	}

	// List takes no key at all — the credential list must render on a locked
	// vault, or every page load would demand a passphrase.
	list, err := s.List(ctx, userID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("listed %d credentials, want 1", len(list))
	}
	if list[0].Fingerprint != generated.Fingerprint {
		t.Error("the fingerprint should be visible without unlocking")
	}
	if list[0].PublicKey == "" {
		t.Error("the public key should be visible without unlocking")
	}
}

func TestOwnershipIsEnforced(t *testing.T) {
	s, db, alice, aliceKey := testFixture(t)
	ctx := context.Background()

	bob := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		bob, "bob@example.com", "bob@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	c, err := s.Create(ctx, aliceKey, CreateParams{
		OwnerID: alice, Name: "alice's key", Kind: KindPassword, Secret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Every path must refuse, and must report not-found rather than
	// forbidden: confirming the credential exists is itself a disclosure.
	t.Run("get", func(t *testing.T) {
		if _, err := s.Get(ctx, bob, c.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("reveal", func(t *testing.T) {
		if _, err := s.Reveal(ctx, aliceKey, bob, c.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("update", func(t *testing.T) {
		name := "renamed by bob"
		if _, err := s.Update(ctx, bob, c.ID, UpdateParams{Name: &name}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		if err := s.Delete(ctx, bob, c.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
		// And it must still exist.
		if _, err := s.Get(ctx, alice, c.ID); err != nil {
			t.Fatalf("the credential was deleted by a non-owner: %v", err)
		}
	})
	t.Run("list", func(t *testing.T) {
		list, err := s.List(ctx, bob, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Fatalf("another user's credentials leaked into the list: %d", len(list))
		}
	})
}

func TestUpdateMetadata(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	c, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "old name", Kind: KindPassword,
		Username: "olduser", Secret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	newName := "new name"
	updated, err := s.Update(ctx, userID, c.ID, UpdateParams{Name: &newName})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "new name" {
		t.Errorf("name = %q", updated.Name)
	}
	// An unspecified field must be left alone, not blanked.
	if updated.Username != "olduser" {
		t.Errorf("username = %q; a nil field must not be cleared", updated.Username)
	}

	// The secret must be untouched by a metadata edit.
	secret, err := s.Reveal(ctx, key, userID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "secret" {
		t.Fatal("renaming a credential changed its secret")
	}

	t.Run("empty name refused", func(t *testing.T) {
		blank := "   "
		if _, err := s.Update(ctx, userID, c.ID, UpdateParams{Name: &blank}); err == nil {
			t.Fatal("a blank name must be refused")
		}
	})
}

func TestDelete(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	c, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "doomed", Kind: KindPassword, Secret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, userID, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, userID, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, userID, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting twice should report ErrNotFound, got %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	cases := map[string]CreateParams{
		"no owner":   {Name: "x", Kind: KindPassword, Secret: "s"},
		"no name":    {OwnerID: userID, Kind: KindPassword, Secret: "s"},
		"blank name": {OwnerID: userID, Name: "   ", Kind: KindPassword, Secret: "s"},
		"bad kind":   {OwnerID: userID, Name: "x", Kind: "not-a-kind", Secret: "s"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Create(ctx, key, p); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRevealMissingSecret(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	// A credential holding only public metadata — a key whose private half
	// lives on the user's own machine, for instance.
	c, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "public only", Kind: KindSSHKey,
		PublicKey: "ssh-ed25519 AAAA...", Fingerprint: "SHA256:abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reveal(ctx, key, userID, c.ID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("want ErrNoSecret, got %v", err)
	}
}

func TestMarkUsed(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	c, err := s.Create(ctx, key, CreateParams{
		OwnerID: userID, Name: "key", Kind: KindPassword, Secret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.LastUsedAt != nil {
		t.Error("a new credential should have no last-used timestamp")
	}

	if err := s.MarkUsed(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, userID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("last use was not recorded")
	}
}

func TestAllKindsRoundTrip(t *testing.T) {
	s, _, userID, key := testFixture(t)
	ctx := context.Background()

	for _, kind := range []Kind{KindSSHKey, KindPassword, KindPassphrase, KindEnableSecret} {
		t.Run(string(kind), func(t *testing.T) {
			c, err := s.Create(ctx, key, CreateParams{
				OwnerID: userID, Name: "cred " + string(kind), Kind: kind,
				Secret: "secret for " + string(kind),
			})
			if err != nil {
				t.Fatal(err)
			}
			secret, err := s.Reveal(ctx, key, userID, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if secret.Value != "secret for "+string(kind) {
				t.Errorf("got %q", secret.Value)
			}
		})
	}
}
