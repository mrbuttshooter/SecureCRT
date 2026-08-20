package credentials

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateKey(t *testing.T) {
	for _, kt := range SupportedKeyTypes() {
		t.Run(string(kt), func(t *testing.T) {
			key, err := GenerateKey(kt, "alice@workstation")
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			if !strings.HasPrefix(key.PrivateKeyPEM, "-----BEGIN OPENSSH PRIVATE KEY-----") {
				t.Errorf("private key is not in OpenSSH format: %.60q", key.PrivateKeyPEM)
			}
			if !strings.HasSuffix(strings.TrimSpace(key.PublicKey), "alice@workstation") {
				t.Errorf("comment missing from public key: %q", key.PublicKey)
			}
			if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
				t.Errorf("fingerprint = %q, want a SHA256: prefix", key.Fingerprint)
			}

			// The private key must actually work.
			signer, err := ssh.ParsePrivateKey([]byte(key.PrivateKeyPEM))
			if err != nil {
				t.Fatalf("the generated private key does not parse: %v", err)
			}

			// And the published public key must match it, or the key is
			// useless once deployed.
			derived := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			if !strings.HasPrefix(strings.TrimSpace(key.PublicKey), derived) {
				t.Error("the public key does not correspond to the private key")
			}
			if got := ssh.FingerprintSHA256(signer.PublicKey()); got != key.Fingerprint {
				t.Errorf("fingerprint mismatch: %s vs %s", got, key.Fingerprint)
			}
		})
	}
}

func TestGenerateKeyRejectsUnsupportedType(t *testing.T) {
	for _, kt := range []KeyType{"", "dsa", "rsa-1024", "ed448"} {
		if _, err := GenerateKey(kt, ""); err == nil {
			t.Errorf("%q must be refused", kt)
		}
	}
}

// TestGeneratedKeysAreUnique guards the randomness source. Two users
// generating a key a moment apart must never receive the same one.
func TestGeneratedKeysAreUnique(t *testing.T) {
	seen := make(map[string]struct{}, 20)
	for i := 0; i < 20; i++ {
		key, err := GenerateKey(KeyEd25519, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[key.Fingerprint]; dup {
			t.Fatalf("fingerprint repeated after %d keys", i)
		}
		seen[key.Fingerprint] = struct{}{}
	}
}

// TestRSAKeyIs4096Bits pins the size. Anything shorter would be creating a
// known weakness deliberately.
func TestRSAKeyIs4096Bits(t *testing.T) {
	key, err := GenerateKey(KeyRSA4096, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(key.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if bits := rsaBits(signer.PublicKey()); bits != 4096 {
		t.Fatalf("RSA key is %d bits, want 4096", bits)
	}
}

func TestImportGeneratedKey(t *testing.T) {
	for _, kt := range SupportedKeyTypes() {
		t.Run(string(kt), func(t *testing.T) {
			generated, err := GenerateKey(kt, "comment")
			if err != nil {
				t.Fatal(err)
			}

			imported, err := ImportKey([]byte(generated.PrivateKeyPEM), "")
			if err != nil {
				t.Fatalf("ImportKey: %v", err)
			}
			if imported.Fingerprint != generated.Fingerprint {
				t.Errorf("fingerprint changed on import: %s then %s", generated.Fingerprint, imported.Fingerprint)
			}
			if imported.WasEncrypted {
				t.Error("an unencrypted key was reported as encrypted")
			}
		})
	}
}

func TestImportRejectsRubbish(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"plain text":    "this is not a key",
		"truncated pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n",
		"a public key":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExa alice@host",
		"certificate":   "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ImportKey([]byte(input), ""); !errors.Is(err, ErrNotAPrivateKey) {
				t.Fatalf("want ErrNotAPrivateKey, got %v", err)
			}
		})
	}
}

// TestImportEncryptedKey covers the common case of someone pasting a
// passphrase-protected key exported from another tool.
func TestImportEncryptedKey(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")

	// A real encrypted key, produced by the tool people actually use.
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath,
		"-N", "the file passphrase", "-C", "imported@host", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen failed: %v: %s", err, out)
	}

	pemBytes, err := readFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("without a passphrase it reports the key is encrypted", func(t *testing.T) {
		_, err := ImportKey(pemBytes, "")
		if !errors.Is(err, ErrKeyEncrypted) {
			t.Fatalf("want ErrKeyEncrypted, got %v", err)
		}
	})

	t.Run("with the wrong passphrase", func(t *testing.T) {
		_, err := ImportKey(pemBytes, "not the passphrase")
		if !errors.Is(err, ErrKeyPassphrase) {
			t.Fatalf("want ErrKeyPassphrase, got %v", err)
		}
	})

	t.Run("with the right passphrase", func(t *testing.T) {
		imported, err := ImportKey(pemBytes, "the file passphrase")
		if err != nil {
			t.Fatalf("ImportKey: %v", err)
		}
		if !imported.WasEncrypted {
			t.Error("WasEncrypted should be set, so the UI can explain the vault now protects it")
		}

		// It must be stored without the file passphrase — otherwise the user
		// would type two secrets for every connection.
		if _, err := ssh.ParsePrivateKey([]byte(imported.PrivateKeyPEM)); err != nil {
			t.Fatalf("the stored key still needs a passphrase: %v", err)
		}

		// And it must be the same key.
		pubBytes, err := readFile(keyPath + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		want, err := PublicKeyFingerprint(string(pubBytes))
		if err != nil {
			t.Fatal(err)
		}
		if imported.Fingerprint != want {
			t.Errorf("fingerprint = %s, ssh-keygen says %s", imported.Fingerprint, want)
		}
	})
}

// TestImportAcceptsFormatsPeopleActuallyHave covers keys from older tooling.
func TestImportAcceptsFormatsPeopleActuallyHave(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}

	cases := []struct {
		name string
		args []string
	}{
		{"rsa PEM", []string{"-t", "rsa", "-b", "2048", "-m", "PEM"}},
		{"rsa OpenSSH", []string{"-t", "rsa", "-b", "2048"}},
		{"ecdsa", []string{"-t", "ecdsa", "-b", "256"}},
		{"ed25519", []string{"-t", "ed25519"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "key")
			args := append(tc.args, "-f", keyPath, "-N", "", "-q")

			if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
				t.Skipf("ssh-keygen failed: %v: %s", err, out)
			}

			pemBytes, err := readFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}

			imported, err := ImportKey(pemBytes, "")
			if err != nil {
				t.Fatalf("ImportKey: %v", err)
			}

			pubBytes, err := readFile(keyPath + ".pub")
			if err != nil {
				t.Fatal(err)
			}
			want, err := PublicKeyFingerprint(string(pubBytes))
			if err != nil {
				t.Fatal(err)
			}
			if imported.Fingerprint != want {
				t.Errorf("fingerprint = %s, ssh-keygen says %s", imported.Fingerprint, want)
			}
		})
	}
}

// TestImportPassphraseOnUnencryptedKeyIsForgiven covers a user who types a
// passphrase out of habit for a key that has none. Refusing would be
// technically correct and needlessly unhelpful.
func TestImportPassphraseOnUnencryptedKeyIsForgiven(t *testing.T) {
	generated, err := GenerateKey(KeyEd25519, "")
	if err != nil {
		t.Fatal(err)
	}

	imported, err := ImportKey([]byte(generated.PrivateKeyPEM), "an unnecessary passphrase")
	if err != nil {
		t.Fatalf("a needless passphrase should be tolerated: %v", err)
	}
	if imported.Fingerprint != generated.Fingerprint {
		t.Error("wrong key imported")
	}
	if imported.WasEncrypted {
		t.Error("the key was not actually encrypted")
	}
}

// TestImportedRSAKeepsItsRealSize confirms an imported 2048-bit key is
// labelled honestly rather than being reported as the 4096 we would generate.
func TestImportedRSAKeepsItsRealSize(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}

	keyPath := filepath.Join(t.TempDir(), "key")
	if out, err := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048",
		"-f", keyPath, "-N", "", "-q").CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen failed: %v: %s", err, out)
	}

	pemBytes, err := readFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportKey(pemBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	if imported.KeyType != KeyType("rsa-2048") {
		t.Errorf("key type = %q, want rsa-2048 so the weaker key is visible", imported.KeyType)
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	generated, err := GenerateKey(KeyEd25519, "alice@host")
	if err != nil {
		t.Fatal(err)
	}

	got, err := PublicKeyFingerprint(generated.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != generated.Fingerprint {
		t.Errorf("fingerprint = %s, want %s", got, generated.Fingerprint)
	}

	if _, err := PublicKeyFingerprint("not a public key"); err == nil {
		t.Error("rubbish must be refused")
	}
}
