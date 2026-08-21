// Package securecrt reads SecureCRT's own configuration, so a team can leave
// it with everything they had.
//
// # On reading someone else's format
//
// This decrypts passwords out of the user's own SecureCRT configuration, on
// their own machine, at their request. It is interoperability with a format
// the user owns the files of — the same thing a mail client does when it
// imports from another. The obfuscation SecureCRT applies is not a secret
// between VanDyke and the user; it is a fixed transformation with a published
// description, and it protects nothing from anyone who has the files.
//
// # What is and is not verified
//
// The two schemes below are implemented from the public description of the
// format. Both round-trip against themselves, and the V2 scheme carries a
// SHA-256 of its own plaintext, so a wrong configuration passphrase is
// detected rather than yielding rubbish.
//
// What that does not prove is agreement with VanDyke's implementation on a
// real file — no copy of SecureCRT was available to test against. So the
// importer never asserts success it has not earned: it reports, per session,
// whether a password decoded, and "bkd import securecrt --dry-run" prints
// that tally without writing anything. docs/MIGRATING.md says to check one
// password against the real thing before trusting the rest.
package securecrt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/blowfish"
)

// Errors callers distinguish.
var (
	// ErrNotEncrypted means the value is not in either password format.
	ErrNotEncrypted = errors.New("securecrt: not an encrypted password")

	// ErrWrongConfigPassphrase means a V2 password did not decode. Detected
	// rather than guessed: the format carries a digest of its own plaintext.
	ErrWrongConfigPassphrase = errors.New("securecrt: the configuration passphrase is wrong")

	// ErrCorrupt means the value decoded to something structurally impossible.
	ErrCorrupt = errors.New("securecrt: the stored password is corrupt")
)

// Legacy Blowfish keys.
//
// Fixed constants compiled into every copy of SecureCRT before version 7.
// They are not a secret and never were: anyone with the binary has them, and
// anyone with the configuration file can apply them.
var (
	legacyKey1 = []byte{
		0x24, 0xA6, 0x3D, 0xDE, 0x5B, 0xD3, 0xB3, 0x82,
		0x9C, 0x7E, 0x06, 0xF4, 0x08, 0x16, 0xAA, 0x07,
	}
	legacyKey2 = []byte{
		0x5F, 0xB0, 0x45, 0xA2, 0x94, 0x17, 0xD9, 0x16,
		0xC6, 0xC6, 0xA2, 0xFF, 0x06, 0x41, 0x82, 0xB7,
	}
)

// ZeroIV records why every cipher below is constructed with an all-zero
// initialisation vector, and what it costs.
//
// It is what the format does. SecureCRT derives a fixed key — from a constant
// before version 7, from SHA-256 of the configuration passphrase after it —
// and encrypts with a zero IV. Using a random one would produce files
// SecureCRT cannot read, which defeats the point of implementing the format
// at all.
//
// The consequence is worth stating rather than hiding behind a suppression.
// A fixed key and a fixed IV mean CBC is deterministic from the first block:
// two sessions with the same password produce the same leading ciphertext.
// Anyone holding a configuration file can therefore see which devices share a
// password without decrypting anything — and can decrypt all of them anyway,
// because the key is not a secret. TestTheFormatLeaksSharedPasswords
// demonstrates it, so nobody discovers it by accident later.
//
// This is a property of SecureCRT's storage, faithfully reproduced. It is
// also the reason bkd's own storage does none of these things: a fresh random
// key per user, a fresh random nonce per value, and AAD binding each
// ciphertext to the record it belongs to.
const ZeroIV = "SecureCRT encrypts with an all-zero IV under a fixed key; see the comment on ZeroIV"

// maxPasswordBytes bounds a decoded password.
//
// The V2 format carries its own length field, read from a file this process
// did not write; without a bound, a four-gigabyte length would be honoured
// before anything noticed it was nonsense.
const maxPasswordBytes = 64 * 1024

// DecryptPassword decodes a stored password.
//
// value is the right-hand side of a Password or Password V2 line, with or
// without its version prefix. configPassphrase is the SecureCRT
// "Configuration Passphrase" when one is set, and empty otherwise — which is
// the common case, because it is off by default.
func DecryptPassword(value, configPassphrase string) (string, error) {
	value = strings.TrimSpace(value)

	switch {
	case strings.HasPrefix(value, "03:"):
		return decryptV3(strings.TrimPrefix(value, "03:"), configPassphrase)
	case strings.HasPrefix(value, "02:"):
		return decryptV2(strings.TrimPrefix(value, "02:"), configPassphrase)
	case strings.HasPrefix(value, "01:"):
		return decryptLegacy(strings.TrimPrefix(value, "01:"))
	case value == "":
		return "", ErrNotEncrypted
	default:
		// No prefix. Which scheme applies is decided by the caller from the
		// key name — "Password V2" or "Password" — and passed through the
		// dedicated entry points below.
		return "", ErrNotEncrypted
	}
}

// DecryptV2 decodes a "Password V2" value, whichever generation it is: a 9.x
// file writes 03: under this key, older files write 02:, and a bare value is
// the 02: scheme without its prefix.
func DecryptV2(value, configPassphrase string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "03:") {
		return decryptV3(strings.TrimPrefix(value, "03:"), configPassphrase)
	}
	return decryptV2(strings.TrimPrefix(value, "02:"), configPassphrase)
}

// decryptV3 is the hardened format SecureCRT 9.x writes when a configuration
// passphrase is in effect: a random 16-byte salt, a bcrypt_pbkdf of the
// passphrase and salt for the AES key and IV, then the same length-prefixed,
// self-checksummed plaintext the V2 format carries.
//
// The KDF is what the 2022 advisory added to resist brute force. Everything
// after the AES layer is shared with decryptV2, including the checksum that
// tells a wrong passphrase apart from a right one.
func decryptV3(hexValue, configPassphrase string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexValue))
	if err != nil {
		return "", fmt.Errorf("%w: not hexadecimal", ErrNotEncrypted)
	}
	if len(raw) < 16+aes.BlockSize {
		return "", fmt.Errorf("%w: too short to hold a salt and a block", ErrCorrupt)
	}
	salt, body := raw[:16], raw[16:]
	if len(body)%aes.BlockSize != 0 {
		return "", fmt.Errorf("%w: length %d is not a whole number of blocks", ErrCorrupt, len(body))
	}

	// 32 bytes of key and 16 of IV, 16 rounds — the parameters SecureCRT uses.
	kdf, err := bcryptPBKDF([]byte(configPassphrase), salt, 32+aes.BlockSize, 16)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(kdf[:32])
	if err != nil {
		return "", err
	}

	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, kdf[32:32+aes.BlockSize]).CryptBlocks(plain, body)
	return parseCheckedPlaintext(plain)
}

// encryptV3ForTest produces a "03:" body the way SecureCRT 9.x does, for the
// round-trip test. Not used at run time — the product only ever reads these.
func encryptV3ForTest(password, configPassphrase string) (string, error) {
	plain := []byte(password)
	digest := sha256.Sum256(plain)
	body := make([]byte, 0, 4+len(plain)+sha256.Size)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(plain))) // #nosec G115 -- short
	body = append(body, plain...)
	body = append(body, digest[:]...)
	padded, err := padRandom(body, aes.BlockSize)
	if err != nil {
		return "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	kdf, err := bcryptPBKDF([]byte(configPassphrase), salt, 32+aes.BlockSize, 16)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(kdf[:32])
	if err != nil {
		return "", err
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, kdf[32:32+aes.BlockSize]).CryptBlocks(out, padded)
	return hex.EncodeToString(append(salt, out...)), nil
}

// DecryptLegacy decodes a pre-version-7 "Password" value.
func DecryptLegacy(value string) (string, error) {
	return decryptLegacy(strings.TrimPrefix(strings.TrimSpace(value), "01:"))
}

// decryptV2 is AES-256-CBC with a zero IV under SHA-256 of the configuration
// passphrase.
//
// The plaintext is length-prefixed and followed by a SHA-256 of itself, which
// is what makes a wrong passphrase detectable instead of silently producing
// a password that would then be offered to a host.
func decryptV2(hexValue, configPassphrase string) (string, error) {
	raw, err := hex.DecodeString(hexValue)
	if err != nil {
		return "", fmt.Errorf("%w: not hexadecimal", ErrNotEncrypted)
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", fmt.Errorf("%w: length %d is not a whole number of blocks", ErrCorrupt, len(raw))
	}

	sum := sha256.Sum256([]byte(configPassphrase))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}

	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, raw)
	return parseCheckedPlaintext(plain)
}

// parseCheckedPlaintext reads the length-prefixed, SHA-256-checksummed body
// both V2 and V3 produce, and is where a wrong passphrase is caught: random
// bytes almost never carry a length that points at their own valid digest.
func parseCheckedPlaintext(plain []byte) (string, error) {
	if len(plain) < 4+sha256.Size {
		return "", fmt.Errorf("%w: too short to hold a length and a digest", ErrCorrupt)
	}

	length := int(binary.LittleEndian.Uint32(plain[:4]))
	if length < 0 || length > maxPasswordBytes || 4+length+sha256.Size > len(plain) {
		return "", ErrWrongConfigPassphrase
	}

	password := plain[4 : 4+length]
	digest := plain[4+length : 4+length+sha256.Size]
	want := sha256.Sum256(password)

	if subtle.ConstantTimeCompare(digest, want[:]) != 1 {
		return "", ErrWrongConfigPassphrase
	}
	return string(password), nil
}

// decryptLegacy is the pre-version-7 double-Blowfish scheme.
//
// Two CBC passes under different fixed keys, with four random bytes glued to
// each end of the inner ciphertext. The plaintext is UTF-16LE with a NUL
// terminator and random padding after it.
func decryptLegacy(hexValue string) (string, error) {
	raw, err := hex.DecodeString(hexValue)
	if err != nil {
		return "", fmt.Errorf("%w: not hexadecimal", ErrNotEncrypted)
	}
	// Eight bytes of jacket plus at least one block.
	if len(raw) < 8+blowfish.BlockSize || len(raw)%blowfish.BlockSize != 0 {
		return "", fmt.Errorf("%w: length %d", ErrCorrupt, len(raw))
	}

	outer, err := blowfish.NewCipher(legacyKey1)
	if err != nil {
		return "", err
	}
	inner, err := blowfish.NewCipher(legacyKey2)
	if err != nil {
		return "", err
	}

	jacketed := make([]byte, len(raw))
	cipher.NewCBCDecrypter(outer, make([]byte, blowfish.BlockSize)).CryptBlocks(jacketed, raw)

	body := jacketed[4 : len(jacketed)-4]
	if len(body)%blowfish.BlockSize != 0 {
		return "", fmt.Errorf("%w: inner length %d", ErrCorrupt, len(body))
	}

	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(inner, make([]byte, blowfish.BlockSize)).CryptBlocks(plain, body)

	return decodeUTF16(plain)
}

// decodeUTF16 reads a NUL-terminated little-endian UTF-16 string.
//
// The terminator matters: what follows it is random padding, and decoding
// that too would append rubbish to every password.
func decodeUTF16(b []byte) (string, error) {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		unit := binary.LittleEndian.Uint16(b[i : i+2])
		if unit == 0 {
			return string(utf16.Decode(units)), nil
		}
		units = append(units, unit)
	}
	// No terminator: the keys were wrong, or the value was not this format.
	return "", ErrCorrupt
}

// EncryptV2 produces a "Password V2" value.
//
// Here so a bkd export can be read back by SecureCRT — nobody should be
// locked in, in either direction — and so the decoder above can be tested
// against something other than itself.
func EncryptV2(password, configPassphrase string) (string, error) {
	plain := []byte(password)
	if len(plain) > maxPasswordBytes {
		return "", fmt.Errorf("securecrt: password of %d bytes is too long", len(plain))
	}

	digest := sha256.Sum256(plain)

	body := make([]byte, 0, 4+len(plain)+sha256.Size)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(plain))) // #nosec G115 -- bounded above
	body = append(body, plain...)
	body = append(body, digest[:]...)

	// Padded to a block boundary with random bytes, which is what SecureCRT
	// writes: the length field says where the meaning stops, so the padding
	// carries no structure to strip.
	padded, err := padRandom(body, aes.BlockSize)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(configPassphrase))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}

	out := make([]byte, len(padded))
	// #nosec G407 -- the zero IV is the format, not a choice. See ZeroIV.
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, padded)

	return "02:" + hex.EncodeToString(out), nil
}

// EncryptLegacy produces a pre-version-7 "Password" value.
func EncryptLegacy(password string) (string, error) {
	units := utf16.Encode([]rune(password))

	body := make([]byte, 0, len(units)*2+2)
	for _, unit := range units {
		body = binary.LittleEndian.AppendUint16(body, unit)
	}
	body = append(body, 0x00, 0x00) // the terminator

	padded, err := padRandom(body, blowfish.BlockSize)
	if err != nil {
		return "", err
	}

	inner, err := blowfish.NewCipher(legacyKey2)
	if err != nil {
		return "", err
	}
	innerOut := make([]byte, len(padded))
	// #nosec G407 -- the zero IV is the format, not a choice. See ZeroIV.
	cipher.NewCBCEncrypter(inner, make([]byte, blowfish.BlockSize)).CryptBlocks(innerOut, padded)

	jacket := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, jacket); err != nil {
		return "", fmt.Errorf("securecrt: random: %w", err)
	}
	tail := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, tail); err != nil {
		return "", fmt.Errorf("securecrt: random: %w", err)
	}

	jacketed := make([]byte, 0, 8+len(innerOut))
	jacketed = append(jacketed, jacket...)
	jacketed = append(jacketed, innerOut...)
	jacketed = append(jacketed, tail...)

	outer, err := blowfish.NewCipher(legacyKey1)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(jacketed))
	// #nosec G407 -- the zero IV is the format, not a choice. See ZeroIV.
	cipher.NewCBCEncrypter(outer, make([]byte, blowfish.BlockSize)).CryptBlocks(out, jacketed)

	return hex.EncodeToString(out), nil
}

// padRandom extends b to a multiple of size with random bytes.
func padRandom(b []byte, size int) ([]byte, error) {
	remainder := len(b) % size
	if remainder == 0 {
		return b, nil
	}

	padding := make([]byte, size-remainder)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, fmt.Errorf("securecrt: random padding: %w", err)
	}
	return append(bytes.Clone(b), padding...), nil
}

// encryptRawForTest seals a block of bytes the way the V2 format seals its
// body, without adding the length prefix and digest.
//
// Exists so a test can build values the decoder must refuse — one claiming an
// absurd length, one with no digest — which is otherwise impossible with an
// encoder that always writes well-formed output.
func encryptRawForTest(plain []byte, configPassphrase string) (string, error) {
	padded, err := padRandom(plain, aes.BlockSize)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(configPassphrase))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}

	out := make([]byte, len(padded))
	// #nosec G407 -- the zero IV is the format, not a choice. See ZeroIV.
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, padded)
	return "02:" + hex.EncodeToString(out), nil
}
