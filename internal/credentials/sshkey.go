// Package credentials stores and generates the secrets used to reach hosts:
// SSH private keys, passwords, key passphrases and device enable secrets.
//
// Every secret is encrypted under the owner's vault key before it reaches the
// database, and decrypted only for the duration of a single operation. No
// method on this package returns private key material in a shape intended for
// display; the one method that can return it is named Reveal and is audited.
package credentials

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyType names a supported SSH key algorithm.
type KeyType string

const (
	// KeyEd25519 is the default. Small, fast, no parameter choices to get
	// wrong, and supported by every SSH implementation still in service.
	KeyEd25519 KeyType = "ed25519"

	// KeyRSA4096 exists for older network gear that predates ed25519 support.
	// Nothing below 4096 bits is offered: shorter RSA keys are still accepted
	// on import for compatibility, but generating one would be creating a
	// weakness on purpose.
	KeyRSA4096 KeyType = "rsa-4096"

	KeyECDSA256 KeyType = "ecdsa-p256"
	KeyECDSA384 KeyType = "ecdsa-p384"
)

// SupportedKeyTypes lists what can be generated, best first.
func SupportedKeyTypes() []KeyType {
	return []KeyType{KeyEd25519, KeyRSA4096, KeyECDSA256, KeyECDSA384}
}

// Validate rejects an unsupported key type.
func (k KeyType) Validate() error {
	for _, ok := range SupportedKeyTypes() {
		if k == ok {
			return nil
		}
	}
	return fmt.Errorf("credentials: unsupported key type %q; supported types are %v", k, SupportedKeyTypes())
}

// Key errors.
var (
	// ErrKeyEncrypted means an imported key is passphrase-protected and no
	// passphrase was supplied.
	ErrKeyEncrypted = errors.New("credentials: this private key is protected by a passphrase")

	// ErrKeyPassphrase means the supplied passphrase did not decrypt the key.
	ErrKeyPassphrase = errors.New("credentials: wrong passphrase for this private key")

	// ErrNotAPrivateKey means the input was not recognised as one.
	ErrNotAPrivateKey = errors.New("credentials: not a recognisable private key")
)

// GeneratedKey is a freshly created keypair.
type GeneratedKey struct {
	// PrivateKeyPEM is in OpenSSH format, which is what ssh-keygen writes and
	// what every current client reads.
	PrivateKeyPEM string

	// PublicKey is the single-line authorized_keys form, ready to paste onto
	// a server.
	PublicKey string

	Fingerprint string
	KeyType     KeyType
}

// GenerateKey creates a new SSH keypair.
//
// comment is appended to the public key, as ssh-keygen does. It is cosmetic
// but genuinely useful: an authorized_keys file with a dozen unlabelled
// entries is one nobody dares prune.
func GenerateKey(kt KeyType, comment string) (GeneratedKey, error) {
	if err := kt.Validate(); err != nil {
		return GeneratedKey{}, err
	}

	var (
		privateKey any
		err        error
	)

	switch kt {
	case KeyEd25519:
		_, priv, genErr := ed25519.GenerateKey(rand.Reader)
		privateKey, err = priv, genErr
	case KeyRSA4096:
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case KeyECDSA256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyECDSA384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("credentials: generate %s key: %w", kt, err)
	}

	block, err := ssh.MarshalPrivateKey(privateKey, comment)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("credentials: encode private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("credentials: derive public key: %w", err)
	}

	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		pub += " " + comment
	}

	return GeneratedKey{
		PrivateKeyPEM: string(pem.EncodeToMemory(block)),
		PublicKey:     pub,
		Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
		KeyType:       kt,
	}, nil
}

// ImportedKey describes a private key supplied by the user.
type ImportedKey struct {
	// PrivateKeyPEM is the key as it will be stored. An encrypted key is
	// decrypted on import and stored under the vault instead: keeping a
	// second passphrase on top would mean the user typing two secrets for
	// every connection, and the vault already provides at-rest protection.
	PrivateKeyPEM string

	PublicKey   string
	Fingerprint string
	KeyType     KeyType

	// WasEncrypted records that the imported file carried its own passphrase,
	// so the interface can tell the user it is now protected by their vault
	// rather than by the passphrase they just typed.
	WasEncrypted bool
}

// ImportKey parses a private key, decrypting it if a passphrase is supplied.
//
// Accepts what ssh-keygen writes and what people paste: OpenSSH format, PKCS#1
// and PKCS#8 PEM, and SEC1 EC keys, encrypted or not.
func ImportKey(pemBytes []byte, passphrase string) (ImportedKey, error) {
	if len(pemBytes) == 0 {
		return ImportedKey{}, fmt.Errorf("%w: empty input", ErrNotAPrivateKey)
	}

	var (
		signer       ssh.Signer
		err          error
		wasEncrypted bool
	)

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
		wasEncrypted = true
		if err != nil {
			// Distinguish "wrong passphrase" from "not a key at all", because
			// the remedies are completely different.
			if _, plainErr := ssh.ParsePrivateKey(pemBytes); plainErr == nil {
				// It parsed without a passphrase, so the supplied one was
				// simply unnecessary.
				signer, err, wasEncrypted = mustParse(pemBytes), nil, false
			} else {
				return ImportedKey{}, fmt.Errorf("%w: %v", ErrKeyPassphrase, err)
			}
		}
	} else {
		signer, err = ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			var missing *ssh.PassphraseMissingError
			if errors.As(err, &missing) {
				return ImportedKey{}, ErrKeyEncrypted
			}
			return ImportedKey{}, fmt.Errorf("%w: %v", ErrNotAPrivateKey, err)
		}
	}

	stored := string(pemBytes)
	if wasEncrypted {
		// Re-encode without the file passphrase; the vault protects it now.
		reencoded, encErr := reencodeUnencrypted(pemBytes, passphrase)
		if encErr != nil {
			return ImportedKey{}, encErr
		}
		stored = reencoded
	}

	pub := signer.PublicKey()
	return ImportedKey{
		PrivateKeyPEM: stored,
		PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint:   ssh.FingerprintSHA256(pub),
		KeyType:       classifyPublicKey(pub),
		WasEncrypted:  wasEncrypted,
	}, nil
}

// mustParse re-parses a key already known to parse cleanly.
func mustParse(pemBytes []byte) ssh.Signer {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		// Unreachable: the caller has just parsed this successfully.
		panic("credentials: key that parsed once failed to parse again: " + err.Error())
	}
	return signer
}

// reencodeUnencrypted strips a private key's own passphrase.
func reencodeUnencrypted(pemBytes []byte, passphrase string) (string, error) {
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyPassphrase, err)
	}

	block, err := ssh.MarshalPrivateKey(raw, "")
	if err != nil {
		return "", fmt.Errorf("credentials: re-encode imported key: %w", err)
	}
	return string(pem.EncodeToMemory(block)), nil
}

// classifyPublicKey maps an SSH public key to a KeyType label.
//
// Imported keys may use algorithms this system would not generate — RSA-2048
// from an older estate, for instance — so the returned label is descriptive
// and not restricted to SupportedKeyTypes.
func classifyPublicKey(pub ssh.PublicKey) KeyType {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return KeyEd25519
	case ssh.KeyAlgoECDSA256:
		return KeyECDSA256
	case ssh.KeyAlgoECDSA384:
		return KeyECDSA384
	case ssh.KeyAlgoECDSA521:
		return KeyType("ecdsa-p521")
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		if bits := rsaBits(pub); bits > 0 {
			return KeyType(fmt.Sprintf("rsa-%d", bits))
		}
		return KeyType("rsa")
	default:
		return KeyType(pub.Type())
	}
}

// rsaBits reports an RSA public key's modulus size, or 0 if it cannot be
// determined.
func rsaBits(pub ssh.PublicKey) int {
	ck, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	rsaPub, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return 0
	}
	return rsaPub.N.BitLen()
}

// PublicKeyFingerprint returns the SHA-256 fingerprint of an authorized_keys
// line, for confirming a key matches what is deployed on a host.
func PublicKeyFingerprint(authorizedKey string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", fmt.Errorf("credentials: parse public key: %w", err)
	}
	return ssh.FingerprintSHA256(pub), nil
}
