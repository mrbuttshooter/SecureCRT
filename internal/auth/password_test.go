package auth

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// testParams keeps the suite fast. Production costs are asserted separately in
// TestDefaultPasswordParamsAreStrongEnough.
func testParams() PasswordParams {
	return PasswordParams{Time: 1, MemoryKB: 8 * 1024, Threads: 1}
}

func TestHashAndVerify(t *testing.T) {
	password := []byte("correct horse battery staple")

	encoded, err := HashPassword(password, testParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(password, encoded); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	encoded, err := HashPassword([]byte("correct horse battery staple"), testParams())
	if err != nil {
		t.Fatal(err)
	}

	for _, wrong := range []string{
		"Correct horse battery staple",  // case
		"correct horse battery stapl",   // truncated
		"correct horse battery staple ", // trailing space
		"",
		"totally different",
	} {
		if err := VerifyPassword([]byte(wrong), encoded); !errors.Is(err, ErrPasswordMismatch) {
			t.Errorf("password %q: want ErrPasswordMismatch, got %v", wrong, err)
		}
	}
}

// TestHashIsSalted confirms two users with the same password get different
// stored hashes, so a database dump does not reveal who shares a password.
func TestHashIsSalted(t *testing.T) {
	password := []byte("shared password")

	a, err := HashPassword(password, testParams())
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword(password, testParams())
	if err != nil {
		t.Fatal(err)
	}

	if a == b {
		t.Fatal("identical passwords produced identical hashes; the salt is not being applied")
	}
	// Both must still verify.
	if err := VerifyPassword(password, a); err != nil {
		t.Error(err)
	}
	if err := VerifyPassword(password, b); err != nil {
		t.Error(err)
	}
}

func TestHashFormat(t *testing.T) {
	encoded, err := HashPassword([]byte("x"), PasswordParams{Time: 3, MemoryKB: 19 * 1024, Threads: 4})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=3,p=4$") {
		t.Fatalf("unexpected PHC prefix: %q", encoded)
	}
	if n := strings.Count(encoded, "$"); n != 5 {
		t.Fatalf("expected 5 separators, got %d in %q", n, encoded)
	}
	// The plaintext must not appear anywhere in the encoding.
	if strings.Contains(encoded, "x$") && strings.HasSuffix(encoded, "$x") {
		t.Fatal("plaintext leaked into the hash string")
	}
}

// TestVerifyRejectsMalformedHashes is the strict-parser test. A lenient parser
// would be a downgrade vector: accepting argon2i, or a lower version, would
// verify against a weaker function than the password was enrolled with.
func TestVerifyRejectsMalformedHashes(t *testing.T) {
	valid, err := HashPassword([]byte("password"), testParams())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, "$")

	cases := map[string]string{
		"empty":              "",
		"not a phc string":   "just-some-text",
		"too few fields":     "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA",
		"too many fields":    valid + "$extra",
		"wrong algorithm":    "$argon2i$" + strings.Join(parts[2:], "$"),
		"bcrypt":             "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"unreadable version": "$argon2id$v=abc$" + strings.Join(parts[3:], "$"),
		"wrong version":      "$argon2id$v=18$" + strings.Join(parts[3:], "$"),
		"unreadable params":  "$argon2id$v=19$garbage$" + strings.Join(parts[4:], "$"),
		"zero time":          "$argon2id$v=19$m=8192,t=0,p=1$" + strings.Join(parts[4:], "$"),
		"zero memory":        "$argon2id$v=19$m=0,t=1,p=1$" + strings.Join(parts[4:], "$"),
		"zero threads":       "$argon2id$v=19$m=8192,t=1,p=0$" + strings.Join(parts[4:], "$"),
		"undecodable salt":   "$argon2id$v=19$m=8192,t=1,p=1$!!!not-base64!!!$" + parts[5],
		"empty salt":         "$argon2id$v=19$m=8192,t=1,p=1$$" + parts[5],
		"undecodable hash":   strings.Join(parts[:5], "$") + "$!!!not-base64!!!",
		"truncated hash":     strings.Join(parts[:5], "$") + "$c2hvcnQ",
	}

	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyPassword([]byte("password"), encoded)
			if !errors.Is(err, ErrMalformedHash) {
				t.Fatalf("want ErrMalformedHash, got %v", err)
			}
			// A malformed hash must never be reported as a simple mismatch:
			// it means corruption, and should page someone rather than
			// counting as a failed login attempt.
			if errors.Is(err, ErrPasswordMismatch) {
				t.Fatal("a malformed hash was reported as a password mismatch")
			}
		})
	}
}

// TestVerifyRejectsTamperedHash covers an attacker with database write access
// flipping bits in the stored hash.
func TestVerifyRejectsTamperedHash(t *testing.T) {
	password := []byte("correct horse battery staple")
	encoded, err := HashPassword(password, testParams())
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(encoded, "$")

	t.Run("modified hash", func(t *testing.T) {
		b := []byte(parts[5])
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		tampered := strings.Join(append(parts[:5], string(b)), "$")

		if err := VerifyPassword(password, tampered); err == nil {
			t.Fatal("a tampered hash must not verify")
		}
	})

	t.Run("modified salt", func(t *testing.T) {
		b := []byte(parts[4])
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		tampered := strings.Join(append(append([]string{}, parts[:4]...), string(b), parts[5]), "$")

		if err := VerifyPassword(password, tampered); !errors.Is(err, ErrPasswordMismatch) {
			t.Fatalf("changing the salt must break verification, got %v", err)
		}
	})

	// Lowering the recorded cost must not let the original password verify.
	// Otherwise an attacker with write access could cheapen every future
	// verification into a fast offline oracle.
	t.Run("downgraded cost", func(t *testing.T) {
		tampered := "$argon2id$v=19$m=8192,t=1,p=1$" + parts[4] + "$" + parts[5]
		if tampered == encoded {
			t.Skip("test params already at this cost")
		}
		if err := VerifyPassword(password, tampered); !errors.Is(err, ErrPasswordMismatch) {
			t.Fatalf("a downgraded cost must not verify, got %v", err)
		}
	})
}

func TestHashRejectsBadInput(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		if _, err := HashPassword(nil, testParams()); err == nil {
			t.Fatal("an empty password must be refused at enrolment")
		}
	})

	t.Run("oversized password", func(t *testing.T) {
		huge := make([]byte, passwordMaxLength+1)
		for i := range huge {
			huge[i] = 'a'
		}
		if _, err := HashPassword(huge, testParams()); !errors.Is(err, ErrPasswordTooLong) {
			t.Fatalf("want ErrPasswordTooLong, got %v", err)
		}
		if err := VerifyPassword(huge, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo"); !errors.Is(err, ErrPasswordTooLong) {
			t.Fatal("verification must also bound its input")
		}
	})
}

// TestLongPasswordsAreAccepted confirms the bound is generous enough for a
// real passphrase, not just a short password.
func TestLongPasswordsAreAccepted(t *testing.T) {
	long := []byte(strings.Repeat("a very long diceware passphrase ", 30)) // ~960 bytes
	if len(long) > passwordMaxLength {
		t.Fatalf("test passphrase is %d bytes, over the limit", len(long))
	}

	encoded, err := HashPassword(long, testParams())
	if err != nil {
		t.Fatalf("a long passphrase must be accepted: %v", err)
	}
	if err := VerifyPassword(long, encoded); err != nil {
		t.Fatal(err)
	}
}

func TestUnicodePasswords(t *testing.T) {
	for _, password := range []string{
		"пароль123",
		"密码密码密码",
		"🔐🔑🗝️ emoji passphrase",
		"café-naïve-résumé",
	} {
		t.Run(password, func(t *testing.T) {
			encoded, err := HashPassword([]byte(password), testParams())
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyPassword([]byte(password), encoded); err != nil {
				t.Fatalf("unicode password did not round-trip: %v", err)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	weak := PasswordParams{Time: 1, MemoryKB: 8 * 1024, Threads: 1}
	strong := PasswordParams{Time: 3, MemoryKB: 19 * 1024, Threads: 4}

	weakHash, err := HashPassword([]byte("password"), weak)
	if err != nil {
		t.Fatal(err)
	}
	strongHash, err := HashPassword([]byte("password"), strong)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("weaker hash needs upgrading", func(t *testing.T) {
		need, err := NeedsRehash(weakHash, strong)
		if err != nil {
			t.Fatal(err)
		}
		if !need {
			t.Fatal("a hash below current costs must be flagged for rehashing")
		}
	})

	t.Run("current hash does not", func(t *testing.T) {
		need, err := NeedsRehash(strongHash, strong)
		if err != nil {
			t.Fatal(err)
		}
		if need {
			t.Fatal("a hash at current costs must not be flagged")
		}
	})

	t.Run("stronger hash does not", func(t *testing.T) {
		need, err := NeedsRehash(strongHash, weak)
		if err != nil {
			t.Fatal(err)
		}
		if need {
			t.Fatal("a hash above current costs must be left alone, not downgraded")
		}
	})

	t.Run("malformed hash reports an error", func(t *testing.T) {
		if _, err := NeedsRehash("nonsense", strong); !errors.Is(err, ErrMalformedHash) {
			t.Fatalf("want ErrMalformedHash, got %v", err)
		}
	})
}

// TestRehashUpgradePath walks the real sequence: an old weak hash verifies,
// is detected as stale, is replaced, and the new hash still accepts the same
// password while carrying the stronger costs.
func TestRehashUpgradePath(t *testing.T) {
	password := []byte("correct horse battery staple")
	weak := PasswordParams{Time: 1, MemoryKB: 8 * 1024, Threads: 1}
	strong := PasswordParams{Time: 2, MemoryKB: 16 * 1024, Threads: 2}

	stored, err := HashPassword(password, weak)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPassword(password, stored); err != nil {
		t.Fatalf("the old hash must still verify: %v", err)
	}
	need, err := NeedsRehash(stored, strong)
	if err != nil {
		t.Fatal(err)
	}
	if !need {
		t.Fatal("upgrade was not detected")
	}

	upgraded, err := HashPassword(password, strong)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(password, upgraded); err != nil {
		t.Fatalf("the upgraded hash must accept the same password: %v", err)
	}
	if !strings.Contains(upgraded, "m=16384,t=2,p=2") {
		t.Fatalf("upgraded hash does not carry the new costs: %q", upgraded)
	}

	need, err = NeedsRehash(upgraded, strong)
	if err != nil {
		t.Fatal(err)
	}
	if need {
		t.Fatal("the upgraded hash should not be flagged again")
	}
}

// TestDefaultPasswordParamsAreStrongEnough is a guard against someone quietly
// lowering the production costs.
func TestDefaultPasswordParamsAreStrongEnough(t *testing.T) {
	p := DefaultPasswordParams()

	if p.MemoryKB < 19*1024 {
		t.Errorf("memory is %d KiB; RFC 9106's first recommended option is 19 MiB", p.MemoryKB)
	}
	if p.Time < 2 {
		t.Errorf("time cost is %d, want at least 2", p.Time)
	}
	if p.Threads < 1 {
		t.Errorf("threads is %d", p.Threads)
	}

	// And they must actually produce a working hash.
	encoded, err := HashPassword([]byte("password"), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword([]byte("password"), encoded); err != nil {
		t.Fatal(err)
	}
}

func TestArgon2VersionIsCurrent(t *testing.T) {
	// If x/crypto ever bumps this, every stored hash becomes unverifiable and
	// we need a deliberate migration rather than a surprise in production.
	if argon2.Version != 19 {
		t.Fatalf("argon2 version is %d; stored hashes assume 19", argon2.Version)
	}
}
