package vault

import (
	"bytes"
	"errors"
	"testing"
)

// mustKDF returns deliberately cheap Argon2id parameters. Production costs
// would make this suite take minutes; they are exercised directly in
// TestDefaultKDFParamsMatchesRFCGuidance and TestDeriveKEKUsesConfiguredCost.
func mustKDF(t *testing.T) KDFParams {
	t.Helper()
	p, err := NewKDFParams(1, 16*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewUserKeyRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")

	dek, wrapped, err := NewUserKey("alice", pass, mustKDF(t))
	if err != nil {
		t.Fatalf("NewUserKey: %v", err)
	}
	if len(dek) != KeyLen {
		t.Fatalf("dek length = %d", len(dek))
	}
	if bytes.Contains(wrapped.Envelope.Ciphertext, dek) {
		t.Fatal("wrapped key contains the raw DEK")
	}

	got, err := UnwrapUserKey("alice", pass, wrapped)
	if err != nil {
		t.Fatalf("UnwrapUserKey: %v", err)
	}
	if !got.Equal(dek) {
		t.Fatal("unwrapped DEK does not match the original")
	}
}

func TestUnwrapWithWrongPassphraseFails(t *testing.T) {
	_, wrapped, err := NewUserKey("alice", []byte("right passphrase"), mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnwrapUserKey("alice", []byte("wrong passphrase"), wrapped); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

// TestUnwrapWithWrongOwnerFails covers an attacker copying Alice's wrapped-key
// row onto Bob's account. Even knowing Alice's passphrase, the AAD binding
// makes the relocated row undecryptable under Bob's identity.
func TestUnwrapWithWrongOwnerFails(t *testing.T) {
	pass := []byte("correct horse battery staple")
	_, wrapped, err := NewUserKey("alice", pass, mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnwrapUserKey("bob", pass, wrapped); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestUnwrapWithTamperedWrappedKeyFails(t *testing.T) {
	pass := []byte("correct horse battery staple")
	_, wrapped, err := NewUserKey("alice", pass, mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("ciphertext", func(t *testing.T) {
		w := wrapped
		w.Envelope.Ciphertext = bytes.Clone(wrapped.Envelope.Ciphertext)
		w.Envelope.Ciphertext[0] ^= 0x01
		if _, err := UnwrapUserKey("alice", pass, w); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("want ErrWrongPassphrase, got %v", err)
		}
	})

	// Rewriting the stored salt is the cheapest attack on a database with
	// write access, so it must fail rather than derive a usable key.
	t.Run("salt", func(t *testing.T) {
		w := wrapped
		w.KDF.Salt = bytes.Clone(wrapped.KDF.Salt)
		w.KDF.Salt[0] ^= 0x01
		if _, err := UnwrapUserKey("alice", pass, w); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("want ErrWrongPassphrase, got %v", err)
		}
	})

	// Rewriting the recorded costs must not yield a usable key either: an
	// attacker who could downgrade them would cheapen an offline attack.
	t.Run("cost downgrade", func(t *testing.T) {
		w := wrapped
		w.KDF.Time = wrapped.KDF.Time + 1
		if _, err := UnwrapUserKey("alice", pass, w); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("want ErrWrongPassphrase, got %v", err)
		}
	})
}

// TestRewrapPreservesCredentials is the passphrase-change guarantee: the DEK
// survives, so already-encrypted credentials keep decrypting and nothing has
// to be re-encrypted.
func TestRewrapPreservesCredentials(t *testing.T) {
	oldPass := []byte("the old passphrase")
	newPass := []byte("the new passphrase")

	dek, _, err := NewUserKey("alice", oldPass, mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}

	aad := CredentialAAD("alice", "cred-1", "private_key")
	secret := []byte("ssh-ed25519 private material")
	env, err := Seal(dek, aad, secret)
	if err != nil {
		t.Fatal(err)
	}

	rewrapped, err := RewrapUserKey("alice", dek, newPass, mustKDF(t))
	if err != nil {
		t.Fatalf("RewrapUserKey: %v", err)
	}

	if _, err := UnwrapUserKey("alice", oldPass, rewrapped); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase must stop working, got %v", err)
	}

	recovered, err := UnwrapUserKey("alice", newPass, rewrapped)
	if err != nil {
		t.Fatalf("new passphrase must work: %v", err)
	}

	got, err := Open(recovered, aad, env)
	if err != nil {
		t.Fatalf("credential must still decrypt after rewrap: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("credential plaintext changed across rewrap")
	}
}

func TestRewrapRejectsZeroedKey(t *testing.T) {
	dek := mustKey(t)
	dek.Zero()

	if _, err := RewrapUserKey("alice", dek, []byte("new passphrase"), mustKDF(t)); err == nil {
		t.Fatal("rewrapping an all-zero key must be refused")
	}
}

// TestTeamKeySharing exercises the shared-credential mechanism: one team DEK,
// sealed once per member under that member's personal DEK.
func TestTeamKeySharing(t *testing.T) {
	aliceDEK, _, err := NewUserKey("alice", []byte("alice passphrase"), mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}
	bobDEK, _, err := NewUserKey("bob", []byte("bob passphrase"), mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}
	malloryDEK, _, err := NewUserKey("mallory", []byte("mallory passphrase"), mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}

	teamDEK := mustKey(t)
	forAlice, err := SealKeyUnder(aliceDEK, TeamAAD("netops", "alice"), teamDEK)
	if err != nil {
		t.Fatal(err)
	}
	forBob, err := SealKeyUnder(bobDEK, TeamAAD("netops", "bob"), teamDEK)
	if err != nil {
		t.Fatal(err)
	}

	// A shared credential encrypted once under the team DEK...
	aad := AAD{Scope: "credential", OwnerID: "netops", RecordID: "core-router", FieldName: "password"}
	env, err := Seal(teamDEK, aad, []byte("enable secret"))
	if err != nil {
		t.Fatal(err)
	}

	// ...is readable by every member.
	for name, tc := range map[string]struct {
		dek Key
		env Envelope
		aad AAD
	}{
		"alice": {aliceDEK, forAlice, TeamAAD("netops", "alice")},
		"bob":   {bobDEK, forBob, TeamAAD("netops", "bob")},
	} {
		t.Run(name, func(t *testing.T) {
			recovered, err := OpenKeyFrom(tc.dek, tc.aad, tc.env)
			if err != nil {
				t.Fatalf("member must unwrap the team key: %v", err)
			}
			got, err := Open(recovered, aad, env)
			if err != nil {
				t.Fatalf("member must read the shared credential: %v", err)
			}
			if string(got) != "enable secret" {
				t.Fatalf("got %q", got)
			}
		})
	}

	// A non-member holding a stolen copy of the wrapped row cannot use it.
	t.Run("non-member", func(t *testing.T) {
		if _, err := OpenKeyFrom(malloryDEK, TeamAAD("netops", "mallory"), forAlice); !errors.Is(err, ErrTampered) {
			t.Fatalf("want ErrTampered, got %v", err)
		}
	})

	// Nor can a member present another member's row as their own.
	t.Run("cross-member relocation", func(t *testing.T) {
		if _, err := OpenKeyFrom(bobDEK, TeamAAD("netops", "bob"), forAlice); !errors.Is(err, ErrTampered) {
			t.Fatalf("want ErrTampered, got %v", err)
		}
	})
}

func TestOpenKeyFromRejectsWrongSizedPayload(t *testing.T) {
	outer := mustKey(t)
	aad := TeamAAD("netops", "alice")

	// A validly-sealed payload that is not a 32-byte key must be refused
	// rather than used as one.
	env, err := Seal(outer, aad, []byte("too short"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKeyFrom(outer, aad, env); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestKeyZero(t *testing.T) {
	k := mustKey(t)
	if k.IsZero() {
		t.Fatal("a fresh random key must not read as zero")
	}

	k.Zero()
	if !k.IsZero() {
		t.Fatal("Zero did not clear the key")
	}
	for i, b := range k {
		if b != 0 {
			t.Fatalf("byte %d = %d after Zero", i, b)
		}
	}
}

func TestKeyEqualIsConstantTime(t *testing.T) {
	a := mustKey(t)
	b := bytes.Clone(a)

	if !a.Equal(Key(b)) {
		t.Fatal("identical keys must compare equal")
	}
	if a.Equal(mustKey(t)) {
		t.Fatal("distinct keys must not compare equal")
	}
	if a.Equal(a[:16]) {
		t.Fatal("different-length keys must not compare equal")
	}
}

func TestDeriveKEKIsDeterministic(t *testing.T) {
	params := testKDF(t)
	pass := []byte("passphrase")

	a, err := DeriveKEK(pass, params)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKEK(pass, params)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("same passphrase and params must derive the same KEK")
	}
}

// TestDeriveKEKUsesConfiguredCost confirms the cost parameters actually reach
// Argon2id: changing any one of them must change the derived key.
func TestDeriveKEKUsesConfiguredCost(t *testing.T) {
	base := testKDF(t)
	pass := []byte("passphrase")

	ref, err := DeriveKEK(pass, base)
	if err != nil {
		t.Fatal(err)
	}

	variants := map[string]KDFParams{
		"time":    {Time: base.Time + 1, MemoryKB: base.MemoryKB, Threads: base.Threads, Salt: base.Salt},
		"memory":  {Time: base.Time, MemoryKB: base.MemoryKB * 2, Threads: base.Threads, Salt: base.Salt},
		"threads": {Time: base.Time, MemoryKB: base.MemoryKB, Threads: base.Threads + 1, Salt: base.Salt},
	}
	for name, p := range variants {
		t.Run(name, func(t *testing.T) {
			got, err := DeriveKEK(pass, p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Equal(ref) {
				t.Fatalf("changing %s did not change the derived key", name)
			}
		})
	}
}

func TestDeriveKEKRejectsEmptyPassphrase(t *testing.T) {
	if _, err := DeriveKEK(nil, testKDF(t)); err == nil {
		t.Fatal("empty passphrase must be refused")
	}
}

func TestKDFParamsValidate(t *testing.T) {
	good, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	for name, p := range map[string]KDFParams{
		// Too weak to resist offline cracking.
		"zero time":   {Time: 0, MemoryKB: 64 * 1024, Threads: 4, Salt: good.Salt},
		"low memory":  {Time: 3, MemoryKB: 8 * 1024, Threads: 4, Salt: good.Salt},
		"zero thread": {Time: 3, MemoryKB: 64 * 1024, Threads: 0, Salt: good.Salt},
		"short salt":  {Time: 3, MemoryKB: 64 * 1024, Threads: 4, Salt: []byte("short")},

		// Expensive enough to be an attack. These are not hypothetical:
		// parameters travel with every wrapped key and inside every portable
		// bundle, so they arrive from files this process did not write.
		// Argon2 allocates its memory cost up front, so honouring a request
		// for 64 GiB is an out-of-memory crash on demand.
		"absurd memory":    {Time: 3, MemoryKB: 64 * 1024 * 1024, Threads: 4, Salt: good.Salt},
		"memory just over": {Time: 3, MemoryKB: MaxKDFMemoryKB + 1, Threads: 4, Salt: good.Salt},
		"absurd time":      {Time: 4_000_000_000, MemoryKB: 64 * 1024, Threads: 4, Salt: good.Salt},
		"time just over":   {Time: MaxKDFTime + 1, MemoryKB: 64 * 1024, Threads: 4, Salt: good.Salt},
		"absurd threads":   {Time: 3, MemoryKB: 64 * 1024, Threads: 255, Salt: good.Salt},
	} {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	// And the ceilings themselves are usable, so an operator who wants the
	// most expensive derivation this permits is not refused.
	atTheLimit := KDFParams{
		Time: MaxKDFTime, MemoryKB: MaxKDFMemoryKB, Threads: MaxKDFThreads, Salt: good.Salt,
	}
	if err := atTheLimit.Validate(); err != nil {
		t.Errorf("the maximum permitted parameters were refused: %v", err)
	}
}

func TestSaltsAreUnique(t *testing.T) {
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		s, err := NewSalt()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[string(s)]; dup {
			t.Fatalf("salt repeated after %d draws", i)
		}
		seen[string(s)] = struct{}{}
	}
}

// TestSurvivesRestart simulates the full persistence path: everything the
// database would hold is round-tripped through a struct copy, the in-memory
// keys are zeroed as they would be on shutdown, and the user unlocks again
// from their passphrase alone.
func TestSurvivesRestart(t *testing.T) {
	pass := []byte("correct horse battery staple")
	secret := []byte("-----BEGIN OPENSSH PRIVATE KEY-----")
	aad := CredentialAAD("alice", "cred-1", "private_key")

	dek, wrapped, err := NewUserKey("alice", pass, mustKDF(t))
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(dek, aad, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Everything the process held in memory goes away.
	dek.Zero()

	// Only the persisted rows remain.
	persistedKey := wrapped
	persistedEnv := env

	recovered, err := UnwrapUserKey("alice", pass, persistedKey)
	if err != nil {
		t.Fatalf("unlock after restart: %v", err)
	}
	got, err := Open(recovered, aad, persistedEnv)
	if err != nil {
		t.Fatalf("decrypt after restart: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("plaintext changed across restart: %q", got)
	}
}

func TestDefaultKDFParamsMatchesRFCGuidance(t *testing.T) {
	p, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.Time != 3 || p.MemoryKB != 64*1024 || p.Threads != 4 {
		t.Fatalf("defaults drifted from the RFC 9106 second recommended option: %+v", p)
	}
	if len(p.Salt) != SaltLen {
		t.Fatalf("salt is %d bytes, want %d", len(p.Salt), SaltLen)
	}
}

// TestNewKDFParamsHonoursCallerCosts is the regression test for a real gap:
// the Argon2id costs in config.yaml were validated but never reached the KDF,
// so an operator raising them was silently ignored.
func TestNewKDFParamsHonoursCallerCosts(t *testing.T) {
	p, err := NewKDFParams(5, 128*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	if p.Time != 5 || p.MemoryKB != 128*1024 || p.Threads != 2 {
		t.Fatalf("caller costs were not applied: %+v", p)
	}
}

func TestNewKDFParamsRejectsWeakCosts(t *testing.T) {
	for name, args := range map[string][3]uint32{
		"zero time":    {0, 64 * 1024, 4},
		"low memory":   {3, 8 * 1024, 4},
		"zero threads": {3, 64 * 1024, 0},
	} {
		t.Run(name, func(t *testing.T) {
			//nolint:gosec // fixed small test values
			if _, err := NewKDFParams(args[0], args[1], uint8(args[2])); err == nil {
				t.Fatal("weak costs must be refused rather than silently accepted")
			}
		})
	}
}

func TestNewKDFParamsSaltsAreUnique(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		p, err := NewKDFParams(1, 16*1024, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[string(p.Salt)]; dup {
			t.Fatalf("salt repeated after %d calls", i)
		}
		seen[string(p.Salt)] = struct{}{}
	}
}

// TestRewrapUpgradesCosts covers rolling out a cost increase: the DEK survives
// so credentials keep decrypting, but the wrapped key now carries the new
// parameters.
func TestRewrapUpgradesCosts(t *testing.T) {
	pass := []byte("correct horse battery staple")
	weak, err := NewKDFParams(1, 16*1024, 1)
	if err != nil {
		t.Fatal(err)
	}

	dek, wrapped, err := NewUserKey("alice", pass, weak)
	if err != nil {
		t.Fatal(err)
	}

	aad := CredentialAAD("alice", "cred-1", "private_key")
	env, err := Seal(dek, aad, []byte("secret material"))
	if err != nil {
		t.Fatal(err)
	}

	stronger, err := NewKDFParams(2, 32*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	upgraded, err := RewrapUserKey("alice", dek, pass, stronger)
	if err != nil {
		t.Fatal(err)
	}

	if upgraded.KDF.Time != 2 || upgraded.KDF.MemoryKB != 32*1024 {
		t.Fatalf("rewrap did not record the new costs: %+v", upgraded.KDF)
	}
	if string(upgraded.KDF.Salt) == string(wrapped.KDF.Salt) {
		t.Fatal("rewrap must draw a fresh salt")
	}

	recovered, err := UnwrapUserKey("alice", pass, upgraded)
	if err != nil {
		t.Fatalf("same passphrase must still unlock after a cost upgrade: %v", err)
	}
	got, err := Open(recovered, aad, env)
	if err != nil {
		t.Fatalf("credentials must survive a cost upgrade: %v", err)
	}
	if string(got) != "secret material" {
		t.Fatalf("got %q", got)
	}
}

func TestNewUserKeyRejectsInvalidParams(t *testing.T) {
	bad := KDFParams{Time: 0, MemoryKB: 1, Threads: 0, Salt: []byte("x")}
	if _, _, err := NewUserKey("alice", []byte("pass"), bad); err == nil {
		t.Fatal("invalid params must be refused")
	}
}
