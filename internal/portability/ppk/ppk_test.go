package ppk

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Every file under testdata was produced by PuTTY's own puttygen 0.81, not by
// this package. That is the point: a parser tested against its own encoder
// proves only that it is self-consistent. Alongside each .ppk is the OpenSSH
// private key and the public key puttygen exported from that same file, so
// what this package produces can be checked against what PuTTY says the
// answer is.
//
// Regenerate with scripts/gen-ppk-testdata.sh. The passphrase on the
// encrypted files is below.

const testPassphrase = "correct horse battery staple"

// cases lists every file in the matrix: two format versions, three key types,
// encrypted and not.
var cases = []struct {
	name      string
	encrypted bool
	version   int
	algorithm string
}{
	{"v2-ed25519", false, 2, ssh.KeyAlgoED25519},
	{"v2-ed25519-enc", true, 2, ssh.KeyAlgoED25519},
	{"v2-rsa", false, 2, ssh.KeyAlgoRSA},
	{"v2-rsa-enc", true, 2, ssh.KeyAlgoRSA},
	{"v2-ecdsa", false, 2, ssh.KeyAlgoECDSA256},
	{"v2-ecdsa384-enc", true, 2, ssh.KeyAlgoECDSA384},
	{"v3-ed25519", false, 3, ssh.KeyAlgoED25519},
	{"v3-ed25519-enc", true, 3, ssh.KeyAlgoED25519},
	{"v3-rsa", false, 3, ssh.KeyAlgoRSA},
	{"v3-rsa-enc", true, 3, ssh.KeyAlgoRSA},
	{"v3-ecdsa", false, 3, ssh.KeyAlgoECDSA256},
	{"v3-ecdsa384-enc", true, 3, ssh.KeyAlgoECDSA384},
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestTheConvertedKeyIsTheKeyPuTTYExported is the whole point of the package.
//
// It converts each .ppk and compares the result against the OpenSSH key
// puttygen exported from that same file — by fingerprint, so the comparison
// is of the key material rather than of an encoding. If these agree, a user
// who imports a .ppk here gets exactly what they would have got by opening
// PuTTYgen and clicking "Export OpenSSH key" themselves.
func TestTheConvertedKeyIsTheKeyPuTTYExported(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var passphrase []byte
			if tc.encrypted {
				passphrase = []byte(testPassphrase)
			}

			key, err := Parse(read(t, tc.name+".ppk"), passphrase)
			if err != nil {
				t.Fatalf("parsing: %v", err)
			}
			if key.Version != tc.version {
				t.Errorf("version = %d, want %d", key.Version, tc.version)
			}
			if key.Encrypted != tc.encrypted {
				t.Errorf("encrypted = %v, want %v", key.Encrypted, tc.encrypted)
			}
			if key.Algorithm != tc.algorithm {
				t.Errorf("algorithm = %q, want %q", key.Algorithm, tc.algorithm)
			}
			if key.Comment != "migrated@example.com" {
				t.Errorf("comment = %q", key.Comment)
			}

			converted, err := key.OpenSSH()
			if err != nil {
				t.Fatalf("converting: %v", err)
			}

			ours, err := ssh.ParsePrivateKey(converted)
			if err != nil {
				t.Fatalf("our own output does not parse as an OpenSSH key: %v", err)
			}

			// puttygen's export of the same file, decrypted by puttygen.
			theirs, err := ssh.ParsePrivateKey(read(t, tc.name+".openssh"))
			if err != nil {
				t.Fatalf("reading puttygen's export: %v", err)
			}

			if got, want := ssh.FingerprintSHA256(ours.PublicKey()),
				ssh.FingerprintSHA256(theirs.PublicKey()); got != want {
				t.Fatalf("converted key is %s, puttygen exported %s", got, want)
			}

			// And against the public key file, which is a third independent
			// statement of what this key is.
			published, _, _, _, err := ssh.ParseAuthorizedKey(read(t, tc.name+".pub"))
			if err != nil {
				t.Fatalf("reading the exported public key: %v", err)
			}
			if got, want := ssh.FingerprintSHA256(ours.PublicKey()),
				ssh.FingerprintSHA256(published); got != want {
				t.Errorf("converted key is %s, the .pub file says %s", got, want)
			}

			// A fingerprint match proves the public halves agree. This proves
			// the private half works: sign with the converted key and verify
			// under the public key puttygen published.
			message := make([]byte, 64)
			if _, err := rand.Read(message); err != nil {
				t.Fatal(err)
			}
			signature, err := ours.Sign(rand.Reader, message)
			if err != nil {
				t.Fatalf("signing with the converted key: %v", err)
			}
			if err := published.Verify(message, signature); err != nil {
				t.Fatalf("a signature from the converted key does not verify "+
					"under the published public key: %v", err)
			}
		})
	}
}

// TestPublicKeyMatchesWithoutConverting checks the accessor an import preview
// uses to show a fingerprint before anything is written.
func TestPublicKeyMatchesWithoutConverting(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var passphrase []byte
			if tc.encrypted {
				passphrase = []byte(testPassphrase)
			}
			key, err := Parse(read(t, tc.name+".ppk"), passphrase)
			if err != nil {
				t.Fatal(err)
			}
			public, err := key.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			published, _, _, _, err := ssh.ParseAuthorizedKey(read(t, tc.name+".pub"))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := ssh.FingerprintSHA256(public),
				ssh.FingerprintSHA256(published); got != want {
				t.Errorf("public half = %s, want %s", got, want)
			}
		})
	}
}

// TestAnEncryptedKeyWithoutItsPassphrase must ask rather than accuse: an
// interface needs to tell "I need the passphrase" apart from "that was the
// wrong one".
func TestAnEncryptedKeyWithoutItsPassphrase(t *testing.T) {
	for _, tc := range cases {
		if !tc.encrypted {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(read(t, tc.name+".ppk"), nil); err != ErrPassphraseRequired {
				t.Fatalf("error = %v, want ErrPassphraseRequired", err)
			}
		})
	}
}

func TestAWrongPassphraseIsRejected(t *testing.T) {
	for _, tc := range cases {
		if !tc.encrypted {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(read(t, tc.name+".ppk"), []byte("not the passphrase"))
			if err != ErrWrongPassphrase {
				t.Fatalf("error = %v, want ErrWrongPassphrase", err)
			}
		})
	}
}

// TestAPassphraseOnAnUnencryptedKeyIsIgnored matters for bulk import, where
// one passphrase is offered for a directory of keys that may be a mixture.
func TestAPassphraseOnAnUnencryptedKeyIsIgnored(t *testing.T) {
	key, err := Parse(read(t, "v3-ed25519.ppk"), []byte("irrelevant"))
	if err != nil {
		t.Fatalf("a passphrase for an unencrypted key must be harmless: %v", err)
	}
	if key.Encrypted {
		t.Error("the key reports itself as encrypted")
	}
}

// TestATamperedFileIsRefused: the MAC covers the algorithm, the encryption
// mode, the comment and both halves. Flipping a bit in any of them must be
// caught before the key material reaches anything that would use it.
func TestATamperedFileIsRefused(t *testing.T) {
	original := read(t, "v3-ed25519.ppk")

	edits := map[string]func(string) string{
		"a changed comment": func(s string) string {
			return strings.Replace(s, "Comment: migrated@example.com", "Comment: someone@else", 1)
		},
		"a flipped bit in the private half": func(s string) string {
			return flipInBlock(s, "Private-Lines:")
		},
		"a flipped bit in the public half": func(s string) string {
			return flipInBlock(s, "Public-Lines:")
		},
	}

	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(edit(string(original))), nil); err == nil {
				t.Fatal("a tampered file was accepted")
			}
		})
	}
}

// flipInBlock changes one base64 character in the block under a header.
func flipInBlock(file, header string) string {
	lines := strings.Split(file, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, header) && i+1 < len(lines) {
			next := []byte(lines[i+1])
			if next[0] == 'A' {
				next[0] = 'B'
			} else {
				next[0] = 'A'
			}
			lines[i+1] = string(next)
			break
		}
	}
	return strings.Join(lines, "\n")
}

// TestHalvesFromDifferentKeysAreRefused is the attack the MAC alone does not
// stop on an encrypted file: someone who knows the passphrase can re-MAC
// whatever they like. So the halves are checked against each other too — a
// key that claims a public identity its private half cannot produce must not
// be imported under that identity.
func TestHalvesFromDifferentKeysAreRefused(t *testing.T) {
	for _, algorithm := range []string{"ed25519", "ecdsa", "rsa"} {
		t.Run(algorithm, func(t *testing.T) {
			donor, err := Parse(read(t, "v3-"+algorithm+".ppk"), nil)
			if err != nil {
				t.Fatal(err)
			}
			victim, err := Parse(read(t, "v2-"+algorithm+".ppk"), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Graft one key's public half onto the other's private half,
			// exactly as a re-MACed forgery would.
			forged := &Key{
				Algorithm: victim.Algorithm,
				Comment:   victim.Comment,
				Version:   victim.Version,
				public:    donor.public,
				private:   victim.private,
			}

			if _, err := forged.OpenSSH(); err == nil {
				t.Fatal("a key whose halves disagree was converted anyway")
			}
		})
	}
}

// TestVersionOneIsRefused. PuTTY withdrew it in 1999 because its integrity
// check could be forged. Accepting one now would mean accepting a file whose
// contents nothing vouches for.
func TestVersionOneIsRefused(t *testing.T) {
	file := "PuTTY-User-Key-File-1: ssh-rsa\nEncryption: none\nComment: old\n" +
		"Public-Lines: 1\nAAAA\nPrivate-Lines: 1\nAAAA\nPrivate-Hash: 00\n"

	_, err := Parse([]byte(file), nil)
	if err == nil {
		t.Fatal("a version 1 key was accepted")
	}
	if !strings.Contains(err.Error(), "withdrawn") {
		t.Errorf("error = %v, want it to say why", err)
	}
}

// TestMalformedFilesAreRefusedWithoutPanicking. These arrive as uploads from
// whoever is migrating, so every one of them is untrusted input.
func TestMalformedFilesAreRefusedWithoutPanicking(t *testing.T) {
	good := read(t, "v3-ed25519.ppk")

	files := map[string][]byte{
		"empty":                     {},
		"not a key file":            []byte("hello\n"),
		"header only":               []byte("PuTTY-User-Key-File-3: ssh-ed25519\n"),
		"truncated mid-file":        good[:len(good)/2],
		"a single colon":            []byte(":"),
		"absurd line count":         []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: x\nPublic-Lines: 99999999\n"),
		"negative-looking count":    []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: x\nPublic-Lines: -1\n"),
		"unknown encryption":        []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: rot13\nComment: x\n"),
		"argon memory beyond reach": argonWith(good, "Argon2-Memory", "999999999"),
		"argon zero passes":         argonWith(good, "Argon2-Passes", "0"),
		"argon absurd parallelism":  argonWith(good, "Argon2-Parallelism", "100000"),
	}

	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data, []byte(testPassphrase)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// argonWith turns an unencrypted file into one that claims to be encrypted
// with the named Argon2 parameter set to value, so the parameter bounds are
// exercised on a file that is otherwise well formed.
func argonWith(file []byte, header, value string) []byte {
	joined := strings.Replace(string(file), "Encryption: none", "Encryption: aes256-cbc", 1)
	joined = strings.Replace(joined, "Private-Lines:",
		"Key-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 13\n"+
			"Argon2-Parallelism: 1\nArgon2-Salt: 0011223344556677\nPrivate-Lines:", 1)

	var rewritten []string
	for _, line := range strings.Split(joined, "\n") {
		if strings.HasPrefix(line, header+":") {
			line = header + ": " + value
		}
		rewritten = append(rewritten, line)
	}
	return []byte(strings.Join(rewritten, "\n"))
}

// TestCRLFFilesAreRead. PuTTY writes CRLF on Windows, which is where almost
// every one of these files comes from.
func TestCRLFFilesAreRead(t *testing.T) {
	unix := read(t, "v3-rsa.ppk")
	windows := bytes.ReplaceAll(bytes.ReplaceAll(unix, []byte("\r\n"), []byte("\n")),
		[]byte("\n"), []byte("\r\n"))

	key, err := Parse(windows, nil)
	if err != nil {
		t.Fatalf("a CRLF file must read the same: %v", err)
	}
	if key.Algorithm != ssh.KeyAlgoRSA {
		t.Errorf("algorithm = %q", key.Algorithm)
	}
}

// TestAnOversizedFileIsRefused before any of it is decoded.
func TestAnOversizedFileIsRefused(t *testing.T) {
	if _, err := Parse(make([]byte, MaxFileBytes+1), nil); err == nil {
		t.Fatal("accepted")
	}
}

// TestTheMACBodyRefusesAnImpossibleValue covers a guard that Parse itself
// makes unreachable — the file size limit bounds every field long before this.
// It exists because the length prefix is four bytes: a value too long to
// express in one would otherwise be written with a wrapped length, and MAC as
// something other than what it is. A later caller constructing fields by hand
// gets an error rather than a silent forgery.
func TestTheMACBodyRefusesAnImpossibleValue(t *testing.T) {
	f := &fields{
		version:   3,
		algorithm: ssh.KeyAlgoED25519,
		private:   make([]byte, MaxFileBytes+1),
		mac:       make([]byte, 32),
	}

	if err := f.verifyMAC(make([]byte, 32)); err == nil {
		t.Fatal("a value too long for the format was accepted")
	}
}
