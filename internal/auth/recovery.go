package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Recovery code shape.
//
// Codes are shown once, at enrolment, for the user to print or store in a
// password manager. They are the way back in when someone loses their phone,
// so they are deliberately readable: grouped, and drawn from an alphabet with
// no characters that get confused when transcribed by hand.
const (
	// RecoveryCodeCount is how many codes are issued per enrolment.
	RecoveryCodeCount = 10

	// recoveryGroups × recoveryGroupLen characters, hyphen-separated.
	// 4 groups of 5 from a 26-character alphabet is about 94 bits — far
	// beyond guessing, while still being something a person can read aloud.
	recoveryGroups   = 4
	recoveryGroupLen = 5

	// recoveryAlphabet omits 0/O, 1/I/L, and the vowels that let a random
	// string spell something unfortunate on a printed sheet.
	recoveryAlphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"
)

// ErrRecoveryCodeInvalid means the code did not match any unused code for
// this user. Used codes and never-issued codes are indistinguishable to the
// caller, so an attacker cannot learn which codes exist.
var ErrRecoveryCodeInvalid = errors.New("auth: invalid or already-used recovery code")

// recoveryParams are the Argon2id costs for hashing recovery codes.
//
// Much lower than for passwords, and safely so: a recovery code is 94 bits of
// uniform randomness, not a human-chosen secret, so brute force is hopeless
// regardless of the KDF cost. Verification may have to try every unused code
// for the account, which is why the cost is kept modest.
func recoveryParams() PasswordParams {
	return PasswordParams{Time: 1, MemoryKB: 8 * 1024, Threads: 1}
}

// GenerateRecoveryCodes returns fresh codes in display form together with
// their hashes for storage.
//
// The two slices are parallel: display[i] corresponds to hashes[i]. The
// display forms exist only in this return value — once shown to the user they
// are unrecoverable, which is the point.
func GenerateRecoveryCodes() (display []string, hashes []string, err error) {
	display = make([]string, 0, RecoveryCodeCount)
	hashes = make([]string, 0, RecoveryCodeCount)

	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, nil, err
		}

		hash, err := HashPassword([]byte(NormalizeRecoveryCode(code)), recoveryParams())
		if err != nil {
			return nil, nil, fmt.Errorf("auth: hash recovery code: %w", err)
		}

		display = append(display, code)
		hashes = append(hashes, hash)
	}
	return display, hashes, nil
}

func newRecoveryCode() (string, error) {
	groups := make([]string, recoveryGroups)
	max := big.NewInt(int64(len(recoveryAlphabet)))

	for g := range groups {
		var b strings.Builder
		for i := 0; i < recoveryGroupLen; i++ {
			// crypto/rand.Int, not math/rand: these are credentials.
			n, err := rand.Int(rand.Reader, max)
			if err != nil {
				return "", fmt.Errorf("auth: generate recovery code: %w", err)
			}
			b.WriteByte(recoveryAlphabet[n.Int64()])
		}
		groups[g] = b.String()
	}
	return strings.Join(groups, "-"), nil
}

// NormalizeRecoveryCode canonicalises a code the user typed.
//
// People retype these from paper, so hyphens, spaces and case are all
// forgiven. Normalisation happens before hashing at generation time too, so
// both sides always compare the same form.
func NormalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// StoredRecoveryCode is one persisted code.
type StoredRecoveryCode struct {
	ID   string
	Hash string
	Used bool
}

// VerifyRecoveryCode checks a submitted code against a user's stored codes and
// returns the ID of the one that matched, so the caller can mark it used.
//
// Every unused code is checked even after a match is found. Returning early
// would make response time depend on the code's position in the list, which
// leaks how many codes remain — a small leak, but a free one to avoid.
//
// Already-used codes are skipped rather than matched-then-rejected: a used
// code and a wrong code must be indistinguishable to the caller.
func VerifyRecoveryCode(submitted string, stored []StoredRecoveryCode) (string, error) {
	normalized := NormalizeRecoveryCode(submitted)
	if normalized == "" {
		return "", ErrRecoveryCodeInvalid
	}

	matchedID := ""
	for _, sc := range stored {
		if sc.Used {
			continue
		}
		if err := VerifyPassword([]byte(normalized), sc.Hash); err == nil && matchedID == "" {
			matchedID = sc.ID
		}
	}

	if matchedID == "" {
		return "", ErrRecoveryCodeInvalid
	}
	return matchedID, nil
}
