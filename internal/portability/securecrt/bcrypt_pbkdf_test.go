package securecrt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestBcryptPBKDFGoldenVector pins the KDF to the OpenBSD reference output.
//
// This is the vector golang.org/x/crypto tests against, which is in turn the
// vector OpenBSD's own implementation produces. If this passes, the "03:"
// password format is decrypting under a correct key derivation, and a
// recovery failure is a wrong passphrase rather than wrong code.
func TestBcryptPBKDFGoldenVector(t *testing.T) {
	got, err := bcryptPBKDF([]byte("password"), []byte("salt"), 32, 12)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(
		"1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a")
	if !bytes.Equal(got, want) {
		t.Errorf("bcryptPBKDF = %x, want %x", got, want)
	}
}

// TestV3RoundTrip proves the 03: reader against a value this package encrypts,
// so the format is exercised end to end even without a real SecureCRT file:
// key derivation, salt handling, AES layer and the checksum all have to agree
// for a password to survive the trip.
func TestV3RoundTrip(t *testing.T) {
	const pass = "s3cr3t-enable"
	const configPassphrase = "the-config-passphrase"

	blob, err := encryptV3ForTest(pass, configPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	got, err := decryptV3(blob, configPassphrase)
	if err != nil {
		t.Fatalf("decryptV3: %v", err)
	}
	if got != pass {
		t.Errorf("decryptV3 = %q, want %q", got, pass)
	}

	// A wrong passphrase is caught by the checksum, not mistaken for a
	// different password.
	if _, err := decryptV3(blob, "wrong"); err == nil {
		t.Error("decryptV3 accepted a wrong configuration passphrase")
	}
}
