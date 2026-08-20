package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// testKDF returns deliberately cheap Argon2id parameters.
//
// Production costs (64 MiB, t=3) would make this suite take minutes. The
// parameters are exercised for real in TestDeriveKEKUsesConfiguredCost and
// TestKDFParamsValidate; everything else only needs a working KDF.
func testKDF(t *testing.T) KDFParams {
	t.Helper()
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	return KDFParams{Time: 1, MemoryKB: 16 * 1024, Threads: 1, Salt: salt}
}

func mustKey(t *testing.T) Key {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("user-1", "cred-1", "private_key")
	plaintext := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real key\n")

	env, err := Seal(key, aad, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(env.Ciphertext, plaintext) {
		t.Fatal("plaintext appears verbatim inside the ciphertext")
	}

	got, err := Open(key, aad, env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	aad := CredentialAAD("user-1", "cred-1", "password")
	env, err := Seal(mustKey(t), aad, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(mustKey(t), aad, env); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestOpenWithTamperedCiphertextFails(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("user-1", "cred-1", "password")
	env, err := Seal(key, aad, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	for i := range env.Ciphertext {
		tampered := Envelope{Version: env.Version, Nonce: env.Nonce, Ciphertext: bytes.Clone(env.Ciphertext)}
		tampered.Ciphertext[i] ^= 0x01

		if _, err := Open(key, aad, tampered); !errors.Is(err, ErrTampered) {
			t.Fatalf("flipping ciphertext byte %d must fail authentication, got %v", i, err)
		}
	}
}

func TestOpenWithTamperedNonceFails(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("user-1", "cred-1", "password")
	env, err := Seal(key, aad, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	tampered := Envelope{Version: env.Version, Nonce: bytes.Clone(env.Nonce), Ciphertext: env.Ciphertext}
	tampered.Nonce[0] ^= 0xff

	if _, err := Open(key, aad, tampered); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestOpenWithTruncatedNonceFails(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("user-1", "cred-1", "password")
	env, err := Seal(key, aad, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	env.Nonce = env.Nonce[:len(env.Nonce)-1]
	if _, err := Open(key, aad, env); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

// TestAADBindingRejectsRelocation is the core defence against an attacker who
// can write to the database: a credential ciphertext must not decrypt if it is
// moved to another user, another record, or another field.
func TestAADBindingRejectsRelocation(t *testing.T) {
	key := mustKey(t)
	original := CredentialAAD("alice", "cred-1", "private_key")
	env, err := Seal(key, original, []byte("secret material"))
	if err != nil {
		t.Fatal(err)
	}

	relocations := map[string]AAD{
		"different owner":  CredentialAAD("bob", "cred-1", "private_key"),
		"different record": CredentialAAD("alice", "cred-2", "private_key"),
		"different field":  CredentialAAD("alice", "cred-1", "password"),
		"different scope":  {Scope: "team-dek", OwnerID: "alice", RecordID: "cred-1", FieldName: "private_key"},
	}

	for name, aad := range relocations {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(key, aad, env); !errors.Is(err, ErrTampered) {
				t.Fatalf("relocating to %s must fail, got %v", name, err)
			}
		})
	}
}

// TestAADIsUnambiguous guards the length-prefixed encoding. With naive
// concatenation, ("ab","c") and ("a","bc") would serialise identically and a
// ciphertext could be relocated between them.
func TestAADIsUnambiguous(t *testing.T) {
	a := AAD{Scope: "credential", OwnerID: "ab", RecordID: "c"}
	b := AAD{Scope: "credential", OwnerID: "a", RecordID: "bc"}

	if bytes.Equal(a.bytes(), b.bytes()) {
		t.Fatalf("AAD encoding collides: %s", hex.EncodeToString(a.bytes()))
	}

	key := mustKey(t)
	env, err := Seal(key, a, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, b, env); !errors.Is(err, ErrTampered) {
		t.Fatalf("colliding AAD must not decrypt, got %v", err)
	}
}

func TestSealRejectsEmptyAAD(t *testing.T) {
	key := mustKey(t)
	for name, aad := range map[string]AAD{
		"no scope": {OwnerID: "alice"},
		"no owner": {Scope: "credential"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Seal(key, aad, []byte("x")); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSealRejectsBadKeys(t *testing.T) {
	aad := CredentialAAD("alice", "cred-1", "password")

	if _, err := Seal(make(Key, 16), aad, []byte("x")); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("short key: want ErrBadKeyLength, got %v", err)
	}
	if _, err := Seal(make(Key, KeyLen), aad, []byte("x")); err == nil {
		t.Error("all-zero key must be refused")
	}
}

// TestNoncesAreUnique guards against GCM's catastrophic failure mode. A
// repeated nonce under one key leaks the authentication subkey.
func TestNoncesAreUnique(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("alice", "cred-1", "password")

	const n = 2000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		env, err := Seal(key, aad, []byte("same plaintext every time"))
		if err != nil {
			t.Fatal(err)
		}
		h := string(env.Nonce)
		if _, dup := seen[h]; dup {
			t.Fatalf("nonce repeated after %d seals: %s", i, hex.EncodeToString(env.Nonce))
		}
		seen[h] = struct{}{}
	}
}

// TestSealIsNonDeterministic confirms two seals of identical plaintext do not
// produce identical ciphertext, so an observer cannot tell that two users
// share a password by comparing rows.
func TestSealIsNonDeterministic(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("alice", "cred-1", "password")

	a, err := Seal(key, aad, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, aad, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("identical plaintext produced identical ciphertext")
	}
}

func TestOpenRejectsVersionDowngrade(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("alice", "cred-1", "password")
	env, err := Seal(key, aad, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	env.Version = 0
	if _, err := Open(key, aad, env); err == nil {
		t.Fatal("an unknown envelope version must be refused")
	}
}

func TestSealHandlesEmptyPlaintext(t *testing.T) {
	key := mustKey(t)
	aad := CredentialAAD("alice", "cred-1", "password")

	env, err := Seal(key, aad, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, aad, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty plaintext, got %q", got)
	}
}

// TestAADRejectsOversizedComponents guards the length-prefix encoding. The
// prefix is 32 bits, so a component long enough to wrap that counter could
// make two different identities encode identically — the exact collision the
// prefixing exists to prevent. Validate bounds every component well below
// that, and Seal and Open both call Validate first.
func TestAADRejectsOversizedComponents(t *testing.T) {
	key := mustKey(t)
	oversized := strings.Repeat("a", MaxAADComponent+1)

	cases := map[string]AAD{
		"scope":  {Scope: oversized, OwnerID: "alice"},
		"owner":  {Scope: "credential", OwnerID: oversized},
		"record": {Scope: "credential", OwnerID: "alice", RecordID: oversized},
		"field":  {Scope: "credential", OwnerID: "alice", FieldName: oversized},
	}

	for name, aad := range cases {
		t.Run(name, func(t *testing.T) {
			if err := aad.Validate(); !errors.Is(err, ErrAADTooLong) {
				t.Fatalf("Validate: want ErrAADTooLong, got %v", err)
			}
			if _, err := Seal(key, aad, []byte("x")); !errors.Is(err, ErrAADTooLong) {
				t.Fatalf("Seal: want ErrAADTooLong, got %v", err)
			}
			if _, err := Open(key, aad, Envelope{Version: EnvelopeVersion}); !errors.Is(err, ErrAADTooLong) {
				t.Fatalf("Open: want ErrAADTooLong, got %v", err)
			}
		})
	}
}

func TestAADAcceptsMaximumLengthComponents(t *testing.T) {
	key := mustKey(t)
	atLimit := strings.Repeat("a", MaxAADComponent)
	aad := AAD{Scope: "credential", OwnerID: atLimit, RecordID: atLimit, FieldName: atLimit}

	env, err := Seal(key, aad, []byte("secret"))
	if err != nil {
		t.Fatalf("a component exactly at the limit must be accepted: %v", err)
	}
	got, err := Open(key, aad, env)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
}
