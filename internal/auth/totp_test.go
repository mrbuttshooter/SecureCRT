package auth

import (
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfc6238Secret is the seed from RFC 6238 Appendix B: the ASCII string
// "12345678901234567890", which the RFC gives as hex 3132...3930.
var rfc6238Secret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

// TestRFC6238Vectors checks this implementation against the test vectors
// published in RFC 6238 Appendix B. These are the authoritative values; if
// this test passes, real authenticator apps will agree with us.
//
// The RFC prints 8-digit codes; we take the low 6 digits, which is what a
// 6-digit configuration produces from the same truncation.
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix     int64
		expected string // 8-digit value from the RFC, SHA-1 column
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range cases {
		at := time.Unix(tc.unix, 0).UTC()

		t.Run(at.Format(time.RFC3339), func(t *testing.T) {
			got8, err := TOTPCodeAt(rfc6238Secret, totpCounter(at), TOTPSHA1, 8)
			if err != nil {
				t.Fatal(err)
			}
			if got8 != tc.expected {
				t.Errorf("8-digit code = %s, RFC 6238 says %s", got8, tc.expected)
			}

			got6, err := TOTPCode(rfc6238Secret, at)
			if err != nil {
				t.Fatal(err)
			}
			if want := tc.expected[2:]; got6 != want {
				t.Errorf("6-digit code = %s, want %s", got6, want)
			}
		})
	}
}

// TestRFC6238VectorsSHA256And512 covers the other two hash columns of the
// same table. The RFC uses longer seeds for these.
func TestRFC6238VectorsSHA256And512(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret256 := enc.EncodeToString([]byte("12345678901234567890123456789012"))
	secret512 := enc.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	cases := []struct {
		unix   int64
		sha256 string
		sha512 string
	}{
		{59, "46119246", "90693936"},
		{1111111109, "68084774", "25091201"},
		{1111111111, "67062674", "99943326"},
		{1234567890, "91819424", "93441116"},
		{2000000000, "90698825", "38618901"},
		{20000000000, "77737706", "47863826"},
	}

	for _, tc := range cases {
		counter := totpCounter(time.Unix(tc.unix, 0).UTC())

		got, err := TOTPCodeAt(secret256, counter, TOTPSHA256, 8)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.sha256 {
			t.Errorf("t=%d SHA256: got %s, RFC says %s", tc.unix, got, tc.sha256)
		}

		got, err = TOTPCodeAt(secret512, counter, TOTPSHA512, 8)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.sha512 {
			t.Errorf("t=%d SHA512: got %s, RFC says %s", tc.unix, got, tc.sha512)
		}
	}
}

func TestNewTOTPSecret(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		s, err := NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("secret repeated after %d draws", i)
		}
		seen[s] = struct{}{}

		raw, err := decodeTOTPSecret(s)
		if err != nil {
			t.Fatalf("generated secret did not decode: %v", err)
		}
		if len(raw) != TOTPSecretLen {
			t.Fatalf("secret is %d bytes, want %d", len(raw), TOTPSecretLen)
		}
	}
}

func TestVerifyTOTPHappyPath(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifyTOTP(secret, code, now, 0)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if res.Step != totpCounter(now) {
		t.Errorf("step = %d, want %d", res.Step, totpCounter(now))
	}
}

// TestVerifyTOTPRejectsReplay is the property that stops an observed code
// being reused inside its ~90-second window.
func TestVerifyTOTPRejectsReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifyTOTP(secret, code, now, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Same code, same window, but the step has now been recorded.
	_, err = VerifyTOTP(secret, code, now, res.Step)
	if !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("want ErrTOTPReplayed, got %v", err)
	}

	// And a few seconds later, still inside the same step.
	_, err = VerifyTOTP(secret, code, now.Add(5*time.Second), res.Step)
	if !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("replay later in the same step: want ErrTOTPReplayed, got %v", err)
	}
}

// TestVerifyTOTPRejectsOlderStep covers an attacker replaying a code captured
// from an earlier window, which must not be accepted just because it is
// within the skew tolerance.
func TestVerifyTOTPRejectsOlderStep(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	previous, err := TOTPCode(secret, now.Add(-TOTPPeriod))
	if err != nil {
		t.Fatal(err)
	}

	// The user has already authenticated in the current step.
	_, err = VerifyTOTP(secret, previous, now, totpCounter(now))
	if !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("a code from an earlier step must be refused, got %v", err)
	}
}

// TestVerifyTOTPToleratesClockSkew keeps a user with a slightly wrong phone
// clock able to log in.
func TestVerifyTOTPToleratesClockSkew(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for _, drift := range []time.Duration{-TOTPPeriod, 0, TOTPPeriod} {
		t.Run(drift.String(), func(t *testing.T) {
			code, err := TOTPCode(secret, now.Add(drift))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyTOTP(secret, code, now, 0); err != nil {
				t.Fatalf("a code %v out must still be accepted: %v", drift, err)
			}
		})
	}
}

// TestVerifyTOTPRejectsExcessiveSkew confirms the window does not stretch
// indefinitely — otherwise old codes would stay valid for minutes.
func TestVerifyTOTPRejectsExcessiveSkew(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for _, drift := range []time.Duration{-5 * TOTPPeriod, -2 * TOTPPeriod, 2 * TOTPPeriod, 10 * TOTPPeriod} {
		t.Run(drift.String(), func(t *testing.T) {
			code, err := TOTPCode(secret, now.Add(drift))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyTOTP(secret, code, now, 0); !errors.Is(err, ErrTOTPInvalid) {
				t.Fatalf("a code %v out must be refused, got %v", drift, err)
			}
		})
	}
}

func TestVerifyTOTPRejectsBadCodes(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	valid, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"empty":        "",
		"too short":    valid[:5],
		"too long":     valid + "0",
		"non-numeric":  "abcdef",
		"all zeros":    "000000",
		"wrong digits": shiftDigits(valid),
	}

	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			if code == valid {
				t.Skip("randomly collided with the valid code")
			}
			if _, err := VerifyTOTP(secret, code, now, 0); err == nil {
				t.Fatalf("code %q must be refused", code)
			}
		})
	}
}

// shiftDigits returns a different 6-digit string of the same length.
func shiftDigits(code string) string {
	b := []byte(code)
	for i := range b {
		b[i] = '0' + (b[i]-'0'+5)%10
	}
	return string(b)
}

// TestVerifyTOTPRejectsAnotherUsersCode confirms codes are bound to a secret.
func TestVerifyTOTPRejectsAnotherUsersCode(t *testing.T) {
	alice, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	bobsCode, err := TOTPCode(bob, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTOTP(alice, bobsCode, now, 0); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("one user's code must not verify against another's secret, got %v", err)
	}
}

func TestDecodeTOTPSecret(t *testing.T) {
	base := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

	t.Run("accepts what users actually type", func(t *testing.T) {
		// Apps display secrets in spaced, sometimes lowercase groups, and
		// people paste them with the padding still attached.
		for _, variant := range []string{
			base,
			strings.ToLower(base),
			"JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP",
			"jbsw-y3dp-ehpk-3pxp-jbsw-y3dp-ehpk-3pxp",
			base + "======",
		} {
			got, err := decodeTOTPSecret(variant)
			if err != nil {
				t.Errorf("%q was rejected: %v", variant, err)
				continue
			}
			want, err := decodeTOTPSecret(base)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("%q decoded differently from the canonical form", variant)
			}
		}
	})

	t.Run("rejects unusable secrets", func(t *testing.T) {
		for name, secret := range map[string]string{
			"empty":       "",
			"whitespace":  "   ",
			"not base32":  "!!!!!!!!!!!!!!!!",
			"has 1 and 0": "10101010101010101010101010101010",
			"too short":   "JBSWY3DP", // 5 bytes, below the 80-bit floor
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := decodeTOTPSecret(secret); !errors.Is(err, ErrTOTPBadSecret) {
					t.Fatalf("want ErrTOTPBadSecret, got %v", err)
				}
			})
		}
	})
}

func TestVerifyTOTPRejectsBadSecret(t *testing.T) {
	if _, err := VerifyTOTP("not-base32!!!", "123456", time.Now(), 0); !errors.Is(err, ErrTOTPBadSecret) {
		t.Fatalf("want ErrTOTPBadSecret, got %v", err)
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	raw, err := TOTPProvisioningURI(secret, "alice@example.com", "Bridgekeeper")
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the URI must parse: %v", err)
	}
	if u.Scheme != "otpauth" {
		t.Errorf("scheme = %q", u.Scheme)
	}
	if u.Host != "totp" {
		t.Errorf("host = %q", u.Host)
	}
	// Both forms of the issuer must be present: older apps read the label
	// prefix, current ones read the parameter.
	if u.Path != "/Bridgekeeper:alice@example.com" {
		t.Errorf("path = %q", u.Path)
	}

	q := u.Query()
	for key, want := range map[string]string{
		"secret":    secret,
		"issuer":    "Bridgekeeper",
		"algorithm": "SHA1",
		"digits":    "6",
		"period":    "30",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestTOTPProvisioningURIRejectsBadInput(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][3]string{
		"empty secret":  {"", "alice@example.com", "Bridgekeeper"},
		"empty account": {secret, "", "Bridgekeeper"},
		"empty issuer":  {secret, "alice@example.com", ""},
		"colon issuer":  {secret, "alice@example.com", "Bridge:keeper"},
		"colon account": {secret, "ali:ce@example.com", "Bridgekeeper"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := TOTPProvisioningURI(args[0], args[1], args[2]); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestTOTPEnrolmentFlow walks what a user actually does: scan the QR, type the
// first code to confirm, then use it to sign in later.
func TestTOTPEnrolmentFlow(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	uri, err := TOTPProvisioningURI(secret, "alice@example.com", "Bridgekeeper")
	if err != nil {
		t.Fatal(err)
	}

	// The app reads the secret back out of the QR code.
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	scanned := u.Query().Get("secret")

	enrolTime := time.Now()
	code, err := TOTPCode(scanned, enrolTime)
	if err != nil {
		t.Fatal(err)
	}

	confirm, err := VerifyTOTP(secret, code, enrolTime, 0)
	if err != nil {
		t.Fatalf("confirmation code must verify: %v", err)
	}
	lastStep := confirm.Step

	// A later sign-in, in a new time step.
	loginTime := enrolTime.Add(2 * TOTPPeriod)
	loginCode, err := TOTPCode(secret, loginTime)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyTOTP(secret, loginCode, loginTime, lastStep)
	if err != nil {
		t.Fatalf("later sign-in must verify: %v", err)
	}
	if res.Step <= lastStep {
		t.Fatalf("step did not advance: %d then %d", lastStep, res.Step)
	}
}

func TestTOTPCodeAtRejectsBadDigits(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	for _, digits := range []int{0, 5, 11, -1} {
		if _, err := TOTPCodeAt(secret, 1, TOTPSHA1, digits); err == nil {
			t.Errorf("digits=%d must be refused", digits)
		}
	}
}

func TestTOTPUnsupportedAlgorithm(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TOTPCodeAt(secret, 1, TOTPAlgorithm("MD5"), 6); err == nil {
		t.Fatal("an unsupported algorithm must be refused")
	}
}

// TestTOTPCodesAreStable guards against an accidental change to truncation or
// counter arithmetic: the same inputs must always produce the same code.
func TestTOTPCodesAreStable(t *testing.T) {
	at := time.Unix(1234567890, 0).UTC()
	first, err := TOTPCode(rfc6238Secret, at)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		got, err := TOTPCode(rfc6238Secret, at)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("code changed between calls: %s then %s", first, got)
		}
	}
}
