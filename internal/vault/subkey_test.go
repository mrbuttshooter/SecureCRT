package vault

import (
	"errors"
	"testing"
)

func TestDeriveSubkeyIsDeterministic(t *testing.T) {
	master := mustKey(t)

	a, err := DeriveSubkey(master, SubkeyCSRF)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSubkey(master, SubkeyCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("the same master key and purpose must derive the same subkey")
	}
	if len(a) != KeyLen {
		t.Fatalf("subkey length = %d, want %d", len(a), KeyLen)
	}
}

// TestDeriveSubkeyPurposesAreIndependent is the property that makes one secret
// on disk sufficient: compromising the key used for one purpose must reveal
// nothing about the others.
func TestDeriveSubkeyPurposesAreIndependent(t *testing.T) {
	master := mustKey(t)

	purposes := []string{SubkeyOIDCState, SubkeyCSRF, SubkeySessionID, "some-future-purpose"}
	seen := make(map[string]string, len(purposes))

	for _, purpose := range purposes {
		k, err := DeriveSubkey(master, purpose)
		if err != nil {
			t.Fatal(err)
		}
		if prior, dup := seen[string(k)]; dup {
			t.Fatalf("purposes %q and %q derived the same key", prior, purpose)
		}
		seen[string(k)] = purpose

		if k.Equal(master) {
			t.Fatalf("subkey for %q equals the master key", purpose)
		}
	}
}

func TestDeriveSubkeyDependsOnMaster(t *testing.T) {
	a, err := DeriveSubkey(mustKey(t), SubkeyCSRF)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSubkey(mustKey(t), SubkeyCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(b) {
		t.Fatal("different master keys must derive different subkeys")
	}
}

// TestDeriveSubkeyDetectsSingleBitMasterChange guards against a derivation
// that only mixes in part of the master key.
func TestDeriveSubkeyDetectsSingleBitMasterChange(t *testing.T) {
	master := mustKey(t)
	ref, err := DeriveSubkey(master, SubkeyCSRF)
	if err != nil {
		t.Fatal(err)
	}

	for i := range master {
		flipped := make(Key, len(master))
		copy(flipped, master)
		flipped[i] ^= 0x01

		got, err := DeriveSubkey(flipped, SubkeyCSRF)
		if err != nil {
			t.Fatal(err)
		}
		if got.Equal(ref) {
			t.Fatalf("flipping master byte %d did not change the subkey", i)
		}
	}
}

func TestDeriveSubkeyRejectsBadInput(t *testing.T) {
	t.Run("empty info", func(t *testing.T) {
		if _, err := DeriveSubkey(mustKey(t), ""); err == nil {
			t.Fatal("an empty purpose must be refused; it would collide with any future caller")
		}
	})

	t.Run("short master", func(t *testing.T) {
		if _, err := DeriveSubkey(make(Key, 16), SubkeyCSRF); !errors.Is(err, ErrBadKeyLength) {
			t.Fatalf("want ErrBadKeyLength, got %v", err)
		}
	})

	t.Run("zeroed master", func(t *testing.T) {
		if _, err := DeriveSubkey(make(Key, KeyLen), SubkeyCSRF); err == nil {
			t.Fatal("an all-zero master key must be refused")
		}
	})
}

// TestDeriveSubkeySurvivesRestart confirms derivation needs nothing but the
// master key file — no stored salt, no extra state.
func TestDeriveSubkeySurvivesRestart(t *testing.T) {
	master := mustKey(t)
	before, err := DeriveSubkey(master, SubkeyOIDCState)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a restart: the only thing carried across is the master key
	// bytes, as loaded from disk.
	reloaded := make(Key, len(master))
	copy(reloaded, master)

	after, err := DeriveSubkey(reloaded, SubkeyOIDCState)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(after) {
		t.Fatal("subkey changed across a restart; signed cookies would be invalidated")
	}
}
