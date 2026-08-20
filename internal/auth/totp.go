package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 mandates SHA-1 for authenticator interoperability
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters.
//
// SHA-1, 6 digits and a 30-second step are what every authenticator app
// actually implements. RFC 6238 permits SHA-256 and SHA-512, and this
// implementation supports them, but enrolling with anything other than the
// defaults will silently fail in most apps — so the defaults are what the
// enrolment path uses.
const (
	TOTPDigits    = 6
	TOTPPeriod    = 30 * time.Second
	TOTPSecretLen = 20 // 160 bits, the RFC 4226 recommendation

	// totpSkew is how many steps either side of "now" are accepted, to
	// tolerate clock drift between the server and the user's phone. One step
	// gives a ~90-second acceptance window in total.
	//
	// Widening this weakens replay resistance in proportion, so it is a
	// constant rather than a setting: an operator debugging a clock problem
	// should fix the clock, not widen the window.
	totpSkew = 1
)

// TOTP errors.
var (
	// ErrTOTPInvalid means the code did not match any accepted time step.
	ErrTOTPInvalid = errors.New("auth: invalid authentication code")

	// ErrTOTPReplayed means the code was valid but has already been used.
	// Distinguished from ErrTOTPInvalid so the audit log can tell an attacker
	// replaying an observed code from someone fat-fingering a digit.
	ErrTOTPReplayed = errors.New("auth: authentication code has already been used")

	// ErrTOTPBadSecret means the stored secret is unusable.
	ErrTOTPBadSecret = errors.New("auth: malformed TOTP secret")
)

// TOTPAlgorithm selects the HMAC hash.
type TOTPAlgorithm string

const (
	TOTPSHA1   TOTPAlgorithm = "SHA1"
	TOTPSHA256 TOTPAlgorithm = "SHA256"
	TOTPSHA512 TOTPAlgorithm = "SHA512"
)

func (a TOTPAlgorithm) new() (func() hash.Hash, error) {
	switch a {
	case TOTPSHA1, "":
		return sha1.New, nil
	case TOTPSHA256:
		return sha256.New, nil
	case TOTPSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("auth: unsupported TOTP algorithm %q", a)
	}
}

// NewTOTPSecret returns a fresh random secret, base32-encoded without padding
// as authenticator apps expect.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, TOTPSecretLen)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("auth: generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// decodeTOTPSecret accepts a base32 secret with or without padding, and with
// or without the spaces and lowercase letters people introduce when typing a
// secret in by hand instead of scanning the QR code.
func decodeTOTPSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(secret))
	if cleaned == "" {
		return nil, fmt.Errorf("%w: empty", ErrTOTPBadSecret)
	}

	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	cleaned = strings.TrimRight(cleaned, "=")

	raw, err := enc.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base32", ErrTOTPBadSecret)
	}
	if len(raw) < 10 {
		return nil, fmt.Errorf("%w: %d bytes is below the 80-bit minimum", ErrTOTPBadSecret, len(raw))
	}
	return raw, nil
}

// TOTPCodeAt computes the code for a given time step counter.
func TOTPCodeAt(secret string, counter uint64, alg TOTPAlgorithm, digits int) (string, error) {
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	newHash, err := alg.new()
	if err != nil {
		return "", err
	}
	if digits < 6 || digits > 10 {
		return "", fmt.Errorf("auth: TOTP digits must be between 6 and 10, got %d", digits)
	}

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(newHash, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	// RFC 4226 dynamic truncation.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod), nil
}

// TOTPCode computes the code for a wall-clock time using the default
// parameters.
func TOTPCode(secret string, at time.Time) (string, error) {
	return TOTPCodeAt(secret, totpCounter(at), TOTPSHA1, TOTPDigits)
}

func totpCounter(at time.Time) uint64 {
	//nolint:gosec // Unix() is positive for any time this system will see
	return uint64(at.Unix()) / uint64(TOTPPeriod.Seconds())
}

// TOTPResult reports a successful verification and the time step that matched.
type TOTPResult struct {
	// Step is the accepted counter value. Callers must persist it and pass it
	// back as lastStep on the next verification; that is what makes replay
	// detection work.
	Step uint64
}

// VerifyTOTP checks a code against a secret, tolerating clock skew and
// rejecting replays.
//
// lastStep is the highest counter previously accepted for this user. A code
// whose step is not strictly greater is refused with ErrTOTPReplayed, so an
// attacker who shoulder-surfs or intercepts a code cannot reuse it inside its
// ~90-second validity window. Pass 0 for a user who has never verified.
//
// The comparison is constant-time, and every candidate step is evaluated
// rather than short-circuiting on the first match, so the response time does
// not reveal which step matched.
func VerifyTOTP(secret, code string, at time.Time, lastStep uint64) (TOTPResult, error) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != TOTPDigits {
		return TOTPResult{}, ErrTOTPInvalid
	}
	if _, err := decodeTOTPSecret(secret); err != nil {
		return TOTPResult{}, err
	}

	current := totpCounter(at)

	var (
		matched     bool
		matchedStep uint64
		replayed    bool
	)

	for delta := -totpSkew; delta <= totpSkew; delta++ {
		step := current
		switch {
		case delta < 0:
			shift := uint64(-delta)
			if shift > step {
				continue
			}
			step -= shift
		case delta > 0:
			step += uint64(delta)
		}

		candidate, err := TOTPCodeAt(secret, step, TOTPSHA1, TOTPDigits)
		if err != nil {
			return TOTPResult{}, err
		}

		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			// Keep scanning rather than returning, so timing stays flat.
			if step > lastStep {
				matched = true
				matchedStep = step
			} else {
				replayed = true
			}
		}
	}

	switch {
	case matched:
		return TOTPResult{Step: matchedStep}, nil
	case replayed:
		return TOTPResult{}, ErrTOTPReplayed
	default:
		return TOTPResult{}, ErrTOTPInvalid
	}
}

// TOTPProvisioningURI builds the otpauth:// URI that authenticator apps read
// from a QR code.
//
// issuer appears both as a path prefix and as a parameter: the prefix is what
// older apps display, the parameter is what current ones read, and omitting
// either causes some app somewhere to show the wrong label.
func TOTPProvisioningURI(secret, accountName, issuer string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("%w: empty", ErrTOTPBadSecret)
	}
	if accountName == "" {
		return "", errors.New("auth: account name must not be empty")
	}
	if issuer == "" {
		return "", errors.New("auth: issuer must not be empty")
	}
	// A colon in either field would corrupt the issuer:account label.
	if strings.Contains(issuer, ":") || strings.Contains(accountName, ":") {
		return "", errors.New("auth: issuer and account name must not contain a colon")
	}

	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", string(TOTPSHA1))
	q.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	q.Set("period", fmt.Sprintf("%d", int(TOTPPeriod.Seconds())))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + accountName,
		RawQuery: q.Encode(),
	}
	return u.String(), nil
}
