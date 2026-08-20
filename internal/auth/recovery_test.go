package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateRecoveryCodes(t *testing.T) {
	display, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if len(display) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("got %d codes and %d hashes, want %d of each", len(display), len(hashes), RecoveryCodeCount)
	}

	seen := make(map[string]struct{}, len(display))
	for i, code := range display {
		if _, dup := seen[code]; dup {
			t.Errorf("code %d is a duplicate: %s", i, code)
		}
		seen[code] = struct{}{}

		// Shape: groups of the right length, hyphen-separated.
		groups := strings.Split(code, "-")
		if len(groups) != recoveryGroups {
			t.Errorf("code %q has %d groups, want %d", code, len(groups), recoveryGroups)
		}
		for _, g := range groups {
			if len(g) != recoveryGroupLen {
				t.Errorf("code %q has a group of length %d, want %d", code, len(g), recoveryGroupLen)
			}
		}

		// The plaintext must never appear inside its own hash.
		if strings.Contains(hashes[i], NormalizeRecoveryCode(code)) {
			t.Errorf("code %d leaked into its hash", i)
		}
	}
}

// TestRecoveryAlphabetAvoidsConfusableCharacters matters because these get
// transcribed from paper by hand.
func TestRecoveryAlphabetAvoidsConfusableCharacters(t *testing.T) {
	for _, bad := range []rune{'0', 'O', '1', 'I', 'L', 'A', 'E', 'U'} {
		if strings.ContainsRune(recoveryAlphabet, bad) {
			t.Errorf("alphabet contains %q, which is easily mistyped or spells words", bad)
		}
	}
	if len(recoveryAlphabet) < 20 {
		t.Errorf("alphabet is only %d characters; entropy per code would be too low", len(recoveryAlphabet))
	}
}

func TestVerifyRecoveryCode(t *testing.T) {
	display, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	stored := make([]StoredRecoveryCode, len(hashes))
	for i, h := range hashes {
		stored[i] = StoredRecoveryCode{ID: string(rune('a' + i)), Hash: h}
	}

	t.Run("each issued code verifies exactly once", func(t *testing.T) {
		for i, code := range display {
			id, err := VerifyRecoveryCode(code, stored)
			if err != nil {
				t.Fatalf("code %d did not verify: %v", i, err)
			}
			if id != stored[i].ID {
				t.Errorf("code %d matched ID %q, want %q", i, id, stored[i].ID)
			}
		}
	})

	t.Run("a used code is refused", func(t *testing.T) {
		local := make([]StoredRecoveryCode, len(stored))
		copy(local, stored)
		local[0].Used = true

		if _, err := VerifyRecoveryCode(display[0], local); !errors.Is(err, ErrRecoveryCodeInvalid) {
			t.Fatalf("want ErrRecoveryCodeInvalid, got %v", err)
		}
		// The others must still work.
		if _, err := VerifyRecoveryCode(display[1], local); err != nil {
			t.Fatalf("marking one code used must not affect the rest: %v", err)
		}
	})

	t.Run("an unissued code is refused", func(t *testing.T) {
		for _, wrong := range []string{
			"BCDFG-HJKMN-PQRST-VWXYZ",
			"",
			"nonsense",
			strings.Repeat("B", 20),
		} {
			if _, err := VerifyRecoveryCode(wrong, stored); !errors.Is(err, ErrRecoveryCodeInvalid) {
				t.Errorf("code %q: want ErrRecoveryCodeInvalid, got %v", wrong, err)
			}
		}
	})

	t.Run("another user's codes are refused", func(t *testing.T) {
		otherDisplay, _, err := GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRecoveryCode(otherDisplay[0], stored); !errors.Is(err, ErrRecoveryCodeInvalid) {
			t.Fatalf("want ErrRecoveryCodeInvalid, got %v", err)
		}
	})

	t.Run("empty store refuses everything", func(t *testing.T) {
		if _, err := VerifyRecoveryCode(display[0], nil); !errors.Is(err, ErrRecoveryCodeInvalid) {
			t.Fatalf("want ErrRecoveryCodeInvalid, got %v", err)
		}
	})
}

// TestVerifyRecoveryCodeToleratesTypingVariations covers what actually happens
// when someone reads a code off a printed sheet.
func TestVerifyRecoveryCodeToleratesTypingVariations(t *testing.T) {
	display, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	stored := []StoredRecoveryCode{{ID: "a", Hash: hashes[0]}}
	code := display[0]

	variants := map[string]string{
		"as printed":     code,
		"lowercase":      strings.ToLower(code),
		"no hyphens":     strings.ReplaceAll(code, "-", ""),
		"spaces":         strings.ReplaceAll(code, "-", " "),
		"leading space":  "  " + code,
		"trailing space": code + "  ",
		"mixed case":     strings.ToLower(code[:6]) + code[6:],
	}

	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRecoveryCode(variant, stored); err != nil {
				t.Fatalf("%q should be accepted: %v", variant, err)
			}
		})
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	cases := map[string]string{
		"BCDFG-HJKMN-PQRST-VWXYZ": "BCDFGHJKMNPQRSTVWXYZ",
		"bcdfg hjkmn pqrst vwxyz": "BCDFGHJKMNPQRSTVWXYZ",
		"  BCDFG--HJKMN  ":        "BCDFGHJKMN",
		"":                        "",
		"!!!":                     "",
		"abc123":                  "ABC123",
	}
	for input, want := range cases {
		if got := NormalizeRecoveryCode(input); got != want {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestRecoveryCodesAreUniqueAcrossEnrolments guards the randomness source.
func TestRecoveryCodesAreUniqueAcrossEnrolments(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		display, _, err := GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range display {
			if _, dup := seen[code]; dup {
				t.Fatalf("code %q was issued twice across enrolments", code)
			}
			seen[code] = struct{}{}
		}
	}
	if len(seen) != 20*RecoveryCodeCount {
		t.Fatalf("expected %d distinct codes, got %d", 20*RecoveryCodeCount, len(seen))
	}
}
