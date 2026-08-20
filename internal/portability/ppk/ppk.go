// Package ppk reads PuTTY private key files.
//
// PuTTY's format is not OpenSSH's, and PuTTYgen's "Export OpenSSH key" is a
// manual step per key. A team migrating a few hundred saved sessions would
// have to do it a few hundred times, which is the sort of friction that stops
// a migration, so the format is read directly here and converted.
//
// Three versions exist. Version 1 was withdrawn in 1999 for being trivially
// forgeable and is deliberately not supported: a file claiming it is either
// twenty-five years old or an attempt to downgrade the integrity check.
// Version 2 authenticates with HMAC-SHA-1 over the key material and derives
// its cipher key from SHA-1; version 3 replaced both with HMAC-SHA-256 and
// Argon2. Both of the supported versions are read, encrypted or not.
package ppk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- required by the version 2 file format, not a choice
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

// ErrPassphraseRequired reports that the file is encrypted and no passphrase
// was supplied. Distinguished from a wrong one so an interface can ask rather
// than accuse.
var ErrPassphraseRequired = errors.New("ppk: this key is encrypted and needs its passphrase")

// ErrWrongPassphrase reports that decryption produced something that failed
// the file's own integrity check.
var ErrWrongPassphrase = errors.New("ppk: that passphrase did not decrypt this key")

// MaxFileBytes bounds a key file. The largest legitimate one — an encrypted
// RSA-16384 key with a long comment — is a few tens of kilobytes.
const MaxFileBytes = 1 << 20

// Key is a decoded PuTTY private key.
type Key struct {
	// Algorithm is the SSH key type, e.g. "ssh-ed25519".
	Algorithm string

	// Comment is PuTTY's own label, usually the address it was generated for.
	Comment string

	// Version is 2 or 3, kept so a warning can say which file it came from.
	Version int

	// Encrypted records whether the file was passphrase-protected. The
	// converted OpenSSH key is written out unencrypted, because the vault
	// encrypts it again on the way in and a second passphrase the user has to
	// remember would defeat the point of importing it.
	Encrypted bool

	private []byte
	public  []byte
}

// PublicKey returns the authorized_keys line for this key.
func (k *Key) PublicKey() (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(k.public)
}

// Parse reads a .ppk file, decrypting it when a passphrase is supplied.
//
// Passing a passphrase for an unencrypted key is not an error; it is simply
// unused. That matters for bulk import, where one passphrase is offered for a
// directory of keys that may be a mixture.
func Parse(data, passphrase []byte) (*Key, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("ppk: file is %d bytes, larger than the %d byte limit",
			len(data), MaxFileBytes)
	}

	f, err := parseFields(data)
	if err != nil {
		return nil, err
	}

	key := &Key{
		Algorithm: f.algorithm,
		Comment:   f.comment,
		Version:   f.version,
		Encrypted: f.encryption != "none",
		public:    f.public,
	}

	if !key.Encrypted {
		// An unencrypted file still carries a MAC. Checking it costs nothing
		// and catches a truncated or tampered file before the key material is
		// handed to anything that will try to use it. Both versions MAC an
		// unencrypted file under the empty passphrase.
		_, _, macKey, err := f.derive(nil)
		if err != nil {
			return nil, err
		}
		if err := f.verifyMAC(macKey); err != nil {
			return nil, err
		}
		key.private = f.private
		return key, nil
	}

	if len(passphrase) == 0 {
		return nil, ErrPassphraseRequired
	}

	cipherKey, iv, macKey, err := f.derive(passphrase)
	if err != nil {
		return nil, err
	}

	plain, err := decryptCBC(cipherKey, iv, f.private)
	if err != nil {
		return nil, err
	}
	f.private = plain

	if err := f.verifyMAC(macKey); err != nil {
		// The MAC covers the decrypted private half, so a failure here is a
		// wrong passphrase far more often than a corrupt file. Reported as
		// such, with the other possibility named rather than hidden.
		return nil, ErrWrongPassphrase
	}

	key.private = plain
	return key, nil
}

// OpenSSH re-encodes the key as an unencrypted OpenSSH private key.
//
// The two halves of a PuTTY file are the same SSH wire-format values OpenSSH
// uses, in the same order, so this is a re-assembly rather than a conversion:
// the numbers that make up the key are carried across untouched.
func (k *Key) OpenSSH() ([]byte, error) {
	signer, err := k.signer()
	if err != nil {
		return nil, err
	}

	block, err := ssh.MarshalPrivateKey(signer, k.Comment)
	if err != nil {
		return nil, fmt.Errorf("ppk: encoding %s as OpenSSH: %w", k.Algorithm, err)
	}
	return encodePEM(block), nil
}

// --- the file itself ---------------------------------------------------------

type fields struct {
	version    int
	algorithm  string
	encryption string
	comment    string
	public     []byte
	private    []byte
	mac        []byte

	// Version 3 key-derivation parameters, absent in version 2.
	argonFlavour string
	argonMemory  uint32
	argonPasses  uint32
	argonThreads uint8
	argonSalt    []byte
}

// parseFields reads the header lines and the two base64 blocks.
func parseFields(data []byte) (*fields, error) {
	// PuTTY writes CRLF on Windows and LF elsewhere, and a file that has been
	// through a mail client or a text editor may have either.
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	f := &fields{}
	i := 0

	next := func() (string, string, bool) {
		for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
		if i >= len(lines) {
			return "", "", false
		}
		name, value, ok := strings.Cut(lines[i], ":")
		if !ok {
			return "", "", false
		}
		i++
		return strings.TrimSpace(name), strings.TrimSpace(value), true
	}

	// block reads a "<name>-Lines: n" header and the n base64 lines under it.
	block := func(want string) ([]byte, error) {
		name, value, ok := next()
		if !ok || name != want {
			return nil, fmt.Errorf("ppk: expected %s, found %q", want, name)
		}
		count, err := strconv.Atoi(value)
		if err != nil || count < 0 || count > 4096 {
			return nil, fmt.Errorf("ppk: %s claims %q lines", want, value)
		}
		if i+count > len(lines) {
			return nil, fmt.Errorf("ppk: %s claims %d lines and the file ends first", want, count)
		}
		joined := strings.Join(lines[i:i+count], "")
		i += count

		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(joined))
		if err != nil {
			return nil, fmt.Errorf("ppk: %s is not valid base64: %w", want, err)
		}
		return decoded, nil
	}

	name, value, ok := next()
	if !ok {
		return nil, errors.New("ppk: this is not a PuTTY key file")
	}
	switch name {
	case "PuTTY-User-Key-File-2":
		f.version = 2
	case "PuTTY-User-Key-File-3":
		f.version = 3
	case "PuTTY-User-Key-File-1":
		return nil, errors.New("ppk: version 1 keys were withdrawn in 1999 for a " +
			"forgeable integrity check and are not accepted; re-export the key from PuTTYgen")
	default:
		return nil, errors.New("ppk: this is not a PuTTY key file")
	}
	f.algorithm = value

	if name, value, ok = next(); !ok || name != "Encryption" {
		return nil, errors.New("ppk: no Encryption header")
	}
	f.encryption = value
	switch f.encryption {
	case "none", "aes256-cbc":
	default:
		return nil, fmt.Errorf("ppk: unsupported encryption %q", f.encryption)
	}

	if name, value, ok = next(); !ok || name != "Comment" {
		return nil, errors.New("ppk: no Comment header")
	}
	f.comment = value

	var err error
	if f.public, err = block("Public-Lines"); err != nil {
		return nil, err
	}

	// Version 3 puts the Argon2 parameters between the two blocks, and only
	// when the file is actually encrypted.
	if f.version == 3 && f.encryption != "none" {
		if err := f.readArgonParams(next); err != nil {
			return nil, err
		}
	}

	if f.private, err = block("Private-Lines"); err != nil {
		return nil, err
	}

	name, value, ok = next()
	if !ok || (name != "Private-MAC" && name != "Private-Hash") {
		return nil, errors.New("ppk: no Private-MAC")
	}
	if name == "Private-Hash" {
		// Only ever written by version 1, which is refused above.
		return nil, errors.New("ppk: Private-Hash belongs to the withdrawn version 1 format")
	}
	if f.mac, err = hexBytes(value); err != nil {
		return nil, err
	}

	return f, nil
}

func (f *fields) readArgonParams(next func() (string, string, bool)) error {
	name, value, ok := next()
	if !ok || name != "Key-Derivation" {
		return errors.New("ppk: an encrypted version 3 key with no Key-Derivation header")
	}
	switch value {
	case "Argon2id", "Argon2i", "Argon2d":
		f.argonFlavour = value
	default:
		return fmt.Errorf("ppk: unsupported key derivation %q", value)
	}

	num := func(want string, dst *uint32, max uint32) error {
		name, value, ok := next()
		if !ok || name != want {
			return fmt.Errorf("ppk: expected %s, found %q", want, name)
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf("ppk: %s = %q is not a number", want, value)
		}
		// Bounded at the top as well as parsed. These come from the file, and
		// Argon2 will happily try to allocate whatever it is told to: an
		// uploaded key claiming 64 GiB would take the server down.
		if n == 0 || uint32(n) > max {
			return fmt.Errorf("ppk: %s = %d is out of range", want, n)
		}
		*dst = uint32(n)
		return nil
	}

	if err := num("Argon2-Memory", &f.argonMemory, 1<<20); err != nil { // 1 GiB
		return err
	}
	if err := num("Argon2-Passes", &f.argonPasses, 64); err != nil {
		return err
	}

	// Parallelism is kept as a uint8 because that is what argon2 takes; a
	// wider field here would mean a narrowing conversion later, on a number
	// that came out of an uploaded file.
	var threads uint32
	if err := num("Argon2-Parallelism", &threads, 64); err != nil {
		return err
	}
	f.argonThreads = uint8(threads)

	name, value, ok = next()
	if !ok || name != "Argon2-Salt" {
		return fmt.Errorf("ppk: expected Argon2-Salt, found %q", name)
	}
	salt, err := hexBytes(value)
	if err != nil {
		return err
	}
	if len(salt) == 0 || len(salt) > 64 {
		return fmt.Errorf("ppk: Argon2-Salt is %d bytes", len(salt))
	}
	f.argonSalt = salt
	return nil
}

// derive produces the cipher key, IV and MAC key from a passphrase.
func (f *fields) derive(passphrase []byte) (cipherKey, iv, macKey []byte, err error) {
	switch f.version {
	case 2:
		// The cipher key is two SHA-1 hashes of a counter and the passphrase,
		// concatenated and truncated to 32 bytes. The IV is zero, which is the
		// format's choice and not one this code can make differently.
		var material []byte
		for counter := range uint32(2) {
			h := sha1.New() // #nosec G401 -- mandated by the version 2 format
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], counter)
			h.Write(prefix[:])
			h.Write(passphrase)
			material = append(material, h.Sum(nil)...)
		}

		// The MAC key is a separate hash of a fixed string and the same
		// passphrase — the passphrase matters here too, which is easy to miss
		// because an unencrypted file simply supplies an empty one.
		mac := sha1.New() // #nosec G401 -- mandated by the version 2 format
		mac.Write([]byte("putty-private-key-file-mac-key"))
		mac.Write(passphrase)

		// #nosec G407 -- a zero IV is what the version 2 format specifies; the
		// alternative is being unable to read files PuTTY wrote.
		return material[:32], make([]byte, aes.BlockSize), mac.Sum(nil), nil

	case 3:
		if f.encryption == "none" {
			// An unencrypted version 3 file carries no Argon2 parameters and
			// MACs under an all-zero key.
			return nil, nil, make([]byte, 32), nil
		}

		// One Argon2 call yields 80 bytes: 32 cipher key, 16 IV, 32 MAC key.
		var material []byte
		switch f.argonFlavour {
		case "Argon2id":
			material = argon2.IDKey(passphrase, f.argonSalt, f.argonPasses, f.argonMemory, f.argonThreads, 80)
		case "Argon2i":
			material = argon2.Key(passphrase, f.argonSalt, f.argonPasses, f.argonMemory, f.argonThreads, 80)
		default:
			// Argon2d has no implementation in x/crypto, and PuTTYgen does not
			// offer it — a file using it was hand-made.
			return nil, nil, nil, fmt.Errorf("ppk: %s is not supported", f.argonFlavour)
		}
		return material[:32], material[32:48], material[48:80], nil
	}
	return nil, nil, nil, fmt.Errorf("ppk: version %d", f.version)
}

// verifyMAC checks the file's integrity tag over the decrypted contents.
func (f *fields) verifyMAC(macKey []byte) error {
	var mac []byte

	switch f.version {
	case 2:
		h := hmac.New(sha1.New, macKey) // #nosec G401 -- mandated by the version 2 format
		if err := f.writeMACBody(h); err != nil {
			return err
		}
		mac = h.Sum(nil)

	case 3:
		h := hmac.New(sha256.New, macKey)
		if err := f.writeMACBody(h); err != nil {
			return err
		}
		mac = h.Sum(nil)
	}

	if subtle.ConstantTimeCompare(mac, f.mac) != 1 {
		return errors.New("ppk: the integrity check failed; the file is corrupt or was altered")
	}
	return nil
}

// writeMACBody writes the five length-prefixed values the MAC covers.
//
// Every one of them came out of the uploaded file, so their lengths are
// checked rather than assumed: a value too long to express in the format's
// own four-byte prefix would otherwise be written with a wrapped length and
// MAC as something it is not.
func (f *fields) writeMACBody(w interface{ Write([]byte) (int, error) }) error {
	var failure error

	writeString := func(b []byte) {
		if failure != nil {
			return
		}
		if len(b) > MaxFileBytes {
			failure = fmt.Errorf("ppk: a %d byte value cannot be part of a key file", len(b))
			return
		}
		var length [4]byte
		// #nosec G115 -- bounded by the check immediately above; MaxFileBytes
		// is a fifth of what a uint32 holds.
		binary.BigEndian.PutUint32(length[:], uint32(len(b)))
		_, _ = w.Write(length[:])
		_, _ = w.Write(b)
	}

	writeString([]byte(f.algorithm))
	writeString([]byte(f.encryption))
	writeString([]byte(f.comment))
	writeString(f.public)
	writeString(f.private)
	return failure
}

func decryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ppk: the encrypted half is %d bytes, not a whole number of blocks",
			len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ppk: %w", err)
	}
	out := make([]byte, len(data))
	// #nosec G407 -- the IV comes from the file format's own derivation above.
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

// hexBytes decodes a lowercase hex string, rejecting anything unreasonable.
func hexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s)%2 != 0 || len(s) > 4096 {
		return nil, fmt.Errorf("ppk: %q is not a hex string", s)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		var b byte
		for j := range 2 {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				b = b<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				b = b<<4 | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				b = b<<4 | (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("ppk: %q is not a hex string", s)
			}
		}
		out[i] = b
	}
	return out, nil
}

// encodePEM writes a pem.Block without pulling in encoding/pem's line
// wrapping differences.
func encodePEM(block *pemBlock) []byte {
	var out bytes.Buffer
	out.WriteString("-----BEGIN " + block.Type + "-----\n")

	encoded := base64.StdEncoding.EncodeToString(block.Bytes)
	for len(encoded) > 64 {
		out.WriteString(encoded[:64] + "\n")
		encoded = encoded[64:]
	}
	if encoded != "" {
		out.WriteString(encoded + "\n")
	}
	out.WriteString("-----END " + block.Type + "-----\n")
	return out.Bytes()
}
