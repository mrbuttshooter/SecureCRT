package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

const testRedirectURL = "https://bkd.test/auth/callback"

func testMasterKey(t *testing.T) vault.Key {
	t.Helper()
	k, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newTestProvider wires a provider to the mock issuer. The mock serves TLS
// with a self-signed certificate, so its client is injected into the context
// the way go-oidc expects.
func newTestProvider(t *testing.T, m *mockIssuer, mutate func(*OIDCConfig)) (*OIDCProvider, context.Context) {
	t.Helper()

	cfg := OIDCConfig{
		Enabled:        true,
		Issuer:         m.issuerURL(),
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		RedirectURL:    testRedirectURL,
		AllowedTenants: []string{mockTenantID},
		AutoProvision:  true,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	ctx := oidc.ClientContext(context.Background(), m.httpClient())

	// Validate() insists on an https issuer; the mock is https, but its host
	// is a loopback address, which is fine.
	p, err := NewOIDCProvider(ctx, cfg, testMasterKey(t))
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	return p, ctx
}

// TestOIDCHappyPath walks a complete sign-in: redirect out, code back,
// exchange, verification, claims.
func TestOIDCHappyPath(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	req := mockLogin(t, m, p, "/sessions")

	res, err := p.Callback(ctx, req)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if res.Claims.Subject != "user-object-id-0001" {
		t.Errorf("subject = %q; must come from the oid claim, not sub", res.Claims.Subject)
	}
	if res.Claims.TenantID != mockTenantID {
		t.Errorf("tenant = %q", res.Claims.TenantID)
	}
	if res.Claims.Email != "alice@example.com" {
		t.Errorf("email = %q", res.Claims.Email)
	}
	if res.Claims.Name != "Alice Example" {
		t.Errorf("name = %q", res.Claims.Name)
	}
	if res.ReturnTo != "/sessions" {
		t.Errorf("returnTo = %q", res.ReturnTo)
	}
	// The mock signs in with a password only, so MFA must not be claimed.
	if res.Claims.MFASatisfied {
		t.Error("MFA reported satisfied when amr contained only pwd")
	}
}

// TestOIDCUsesObjectIDNotSubject pins the identity choice. Entra's `sub` is
// per-application and changes if the app registration is recreated, which
// would orphan every account and their stored credentials.
func TestOIDCUsesObjectIDNotSubject(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	res, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Claims.Subject == "pairwise-subject-value" {
		t.Fatal("identity was taken from sub; it must come from oid")
	}
}

// TestOIDCHonoursEntraMFA is why SSO users are not asked for a second factor
// this system would only be duplicating.
func TestOIDCHonoursEntraMFA(t *testing.T) {
	cases := map[string]struct {
		amr  []string
		want bool
	}{
		"password only":      {[]string{"pwd"}, false},
		"mfa":                {[]string{"pwd", "mfa"}, true},
		"fido":               {[]string{"fido"}, true},
		"phishing resistant": {[]string{"phrmfa"}, true},
		"otp":                {[]string{"pwd", "otp"}, true},
		"empty":              {nil, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := newMockIssuer(t)
			m.overrideClaims = func(c map[string]any) { c["amr"] = tc.amr }
			p, ctx := newTestProvider(t, m, nil)

			res, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
			if err != nil {
				t.Fatal(err)
			}
			if res.Claims.MFASatisfied != tc.want {
				t.Errorf("amr %v: MFASatisfied = %v, want %v", tc.amr, res.Claims.MFASatisfied, tc.want)
			}
		})
	}
}

// TestOIDCRejectsWrongTenant is the check that stops any Microsoft account in
// the world signing in to a multi-tenant app registration.
func TestOIDCRejectsWrongTenant(t *testing.T) {
	m := newMockIssuer(t)
	m.tenantID = "99999999-8888-7777-6666-555555555555"
	p, ctx := newTestProvider(t, m, nil)

	_, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if !errors.Is(err, ErrOIDCWrongTenant) {
		t.Fatalf("want ErrOIDCWrongTenant, got %v", err)
	}
}

func TestOIDCRejectsMissingTenantClaim(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) { delete(c, "tid") }
	p, ctx := newTestProvider(t, m, nil)

	_, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if !errors.Is(err, ErrOIDCWrongTenant) {
		t.Fatalf("want ErrOIDCWrongTenant, got %v", err)
	}
}

// TestOIDCRejectsStateMismatch covers login cross-site request forgery: an
// attacker feeding a victim's browser their own authorization code, which
// would silently sign the victim into the attacker's account.
func TestOIDCRejectsStateMismatch(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	req := mockLogin(t, m, p, "/")

	// Keep the cookie, but tamper with the returned state.
	u := req.URL
	q := u.Query()
	q.Set("state", "attacker-supplied-state")
	u.RawQuery = q.Encode()

	tampered := &http.Request{Method: http.MethodGet, URL: u, Header: req.Header}

	_, err := p.Callback(ctx, tampered)
	if !errors.Is(err, ErrOIDCStateMismatch) {
		t.Fatalf("want ErrOIDCStateMismatch, got %v", err)
	}
}

func TestOIDCRejectsMissingState(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	_, cookie, err := p.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}

	req := callbackRequest(t, cookie, map[string]string{"code": "some-code"})
	if _, err := p.Callback(ctx, req); !errors.Is(err, ErrOIDCStateMismatch) {
		t.Fatalf("want ErrOIDCStateMismatch, got %v", err)
	}
}

func TestOIDCRejectsMissingStateCookie(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	req := callbackRequest(t, nil, map[string]string{"code": "c", "state": "s"})
	if _, err := p.Callback(ctx, req); !errors.Is(err, ErrOIDCStateExpired) {
		t.Fatalf("want ErrOIDCStateExpired, got %v", err)
	}
}

// TestOIDCRejectsForgedStateCookie confirms the cookie's signature is checked,
// so an attacker cannot mint a state cookie matching a state they chose.
func TestOIDCRejectsForgedStateCookie(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	_, real, err := p.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}

	forged := map[string]*http.Cookie{
		"garbage":         {Name: OIDCStateCookieName, Value: "not-even-structured"},
		"no signature":    {Name: OIDCStateCookieName, Value: strings.Split(real.Value, ".")[0]},
		"bad signature":   {Name: OIDCStateCookieName, Value: strings.Split(real.Value, ".")[0] + ".AAAA"},
		"swapped payload": {Name: OIDCStateCookieName, Value: "eyJzIjoiYXR0YWNrZXIifQ." + strings.Split(real.Value, ".")[1]},
	}

	for name, cookie := range forged {
		t.Run(name, func(t *testing.T) {
			req := callbackRequest(t, cookie, map[string]string{"code": "c", "state": "s"})
			if _, err := p.Callback(ctx, req); !errors.Is(err, ErrOIDCStateMismatch) {
				t.Fatalf("want ErrOIDCStateMismatch, got %v", err)
			}
		})
	}
}

// TestOIDCRejectsStateFromAnotherInstance covers a deployment where two
// servers hold different master keys: a state cookie from one must not be
// accepted by the other.
func TestOIDCRejectsStateFromAnotherInstance(t *testing.T) {
	m := newMockIssuer(t)
	first, _ := newTestProvider(t, m, nil)
	second, ctx := newTestProvider(t, m, nil) // different master key

	_, cookie, err := first.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}

	req := callbackRequest(t, cookie, map[string]string{"code": "c", "state": "s"})
	if _, err := second.Callback(ctx, req); !errors.Is(err, ErrOIDCStateMismatch) {
		t.Fatalf("want ErrOIDCStateMismatch, got %v", err)
	}
}

func TestOIDCRejectsExpiredState(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	req := mockLogin(t, m, p, "/")

	// The user left the Microsoft page open over lunch.
	p.now = func() time.Time { return time.Now().Add(OIDCStateTTL + time.Minute) }

	if _, err := p.Callback(ctx, req); !errors.Is(err, ErrOIDCStateExpired) {
		t.Fatalf("want ErrOIDCStateExpired, got %v", err)
	}
}

// TestOIDCRejectsNonceMismatch catches a replayed or substituted ID token.
func TestOIDCRejectsNonceMismatch(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) { c["nonce"] = "not-the-nonce-we-asked-for" }
	p, ctx := newTestProvider(t, m, nil)

	_, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if !errors.Is(err, ErrOIDCNonceMismatch) {
		t.Fatalf("want ErrOIDCNonceMismatch, got %v", err)
	}
}

func TestOIDCRejectsMissingNonce(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) { delete(c, "nonce") }
	p, ctx := newTestProvider(t, m, nil)

	_, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if !errors.Is(err, ErrOIDCNonceMismatch) {
		t.Fatalf("want ErrOIDCNonceMismatch, got %v", err)
	}
}

// TestOIDCRejectsBadSignature is the fundamental check: a token this issuer
// did not sign must not be accepted.
func TestOIDCRejectsBadSignature(t *testing.T) {
	m := newMockIssuer(t)
	m.signWithWrongKey = true
	p, ctx := newTestProvider(t, m, nil)

	_, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if err == nil {
		t.Fatal("a token signed with the wrong key must be refused")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected a verification failure, got: %v", err)
	}
}

func TestOIDCRejectsExpiredToken(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) {
		c["exp"] = time.Now().Add(-time.Hour).Unix()
	}
	p, ctx := newTestProvider(t, m, nil)

	if _, err := p.Callback(ctx, mockLogin(t, m, p, "/")); err == nil {
		t.Fatal("an expired token must be refused")
	}
}

// TestOIDCRejectsWrongAudience stops a token minted for a different
// application being presented to this one.
func TestOIDCRejectsWrongAudience(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) { c["aud"] = "some-other-application" }
	p, ctx := newTestProvider(t, m, nil)

	if _, err := p.Callback(ctx, mockLogin(t, m, p, "/")); err == nil {
		t.Fatal("a token for another audience must be refused")
	}
}

func TestOIDCRejectsWrongIssuer(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) { c["iss"] = "https://evil.example.com" }
	p, ctx := newTestProvider(t, m, nil)

	if _, err := p.Callback(ctx, mockLogin(t, m, p, "/")); err == nil {
		t.Fatal("a token from another issuer must be refused")
	}
}

// TestOIDCRejectsReplayedCode confirms an authorization code cannot be
// redeemed twice, which is what limits the damage if one leaks via a referrer
// header or a proxy log.
func TestOIDCRejectsReplayedCode(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	authURL, cookie, err := p.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}

	client := m.httpClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	location := resp.Header.Get("Location")

	build := func() *http.Request {
		u, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
		r.AddCookie(cookie)
		return r
	}

	if _, err := p.Callback(ctx, build()); err != nil {
		t.Fatalf("first redemption must succeed: %v", err)
	}
	if _, err := p.Callback(ctx, build()); err == nil {
		t.Fatal("redeeming the same authorization code twice must fail")
	}
}

// TestOIDCSendsPKCE proves the challenge is actually sent. Without it, an
// intercepted authorization code could be redeemed by an attacker.
func TestOIDCSendsPKCE(t *testing.T) {
	m := newMockIssuer(t)
	p, _ := newTestProvider(t, m, nil)

	authURL, _, err := p.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()

	if q.Get("code_challenge") == "" {
		t.Error("no PKCE code_challenge was sent")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256 (plain offers no protection)", got)
	}
	if q.Get("nonce") == "" {
		t.Error("no nonce was sent")
	}
	if q.Get("state") == "" {
		t.Error("no state was sent")
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
}

// TestOIDCRejectsWrongPKCEVerifier proves the mock enforces PKCE, so the
// happy-path test above is meaningful.
func TestOIDCRejectsWrongPKCEVerifier(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	req := mockLogin(t, m, p, "/")

	// Re-sign a state cookie carrying a different PKCE verifier while keeping
	// the state value the callback will present.
	ls, err := p.openState(mustCookie(t, req, OIDCStateCookieName).Value)
	if err != nil {
		t.Fatal(err)
	}
	ls.PKCEVerifier = "a-completely-different-verifier-value-padding-padding"

	cookie, err := p.sealState(ls)
	if err != nil {
		t.Fatal(err)
	}

	swapped := &http.Request{Method: http.MethodGet, URL: req.URL, Header: http.Header{}}
	swapped.AddCookie(cookie)

	if _, err := p.Callback(ctx, swapped); err == nil {
		t.Fatal("a mismatched PKCE verifier must fail the exchange")
	}
}

func mustCookie(t *testing.T, r *http.Request, name string) *http.Cookie {
	t.Helper()
	c, err := r.Cookie(name)
	if err != nil {
		t.Fatalf("cookie %s: %v", name, err)
	}
	return c
}

// TestOIDCSurfacesProviderError covers consent being declined or a conditional
// access policy blocking sign-in. Entra reports these as query parameters, not
// HTTP errors, so they must not be mistaken for a missing code.
func TestOIDCSurfacesProviderError(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	_, cookie, err := p.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}

	req := callbackRequest(t, cookie, map[string]string{
		"error":             "access_denied",
		"error_description": "AADSTS53003%3A+Blocked+by+conditional+access",
	})

	_, err = p.Callback(ctx, req)
	if err == nil {
		t.Fatal("a provider error must be surfaced")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("the error should name the provider's code, got: %v", err)
	}
	if !strings.Contains(err.Error(), "conditional access") {
		t.Errorf("the error should carry the provider's description, got: %v", err)
	}
}

func TestOIDCRejectsMissingIDToken(t *testing.T) {
	m := newMockIssuer(t)
	m.omitIDToken = true
	p, ctx := newTestProvider(t, m, nil)

	_, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if err == nil || !strings.Contains(err.Error(), "id_token") {
		t.Fatalf("want an id_token error, got %v", err)
	}
}

func TestOIDCRejectsTokenWithoutSubject(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) {
		delete(c, "oid")
		delete(c, "sub")
	}
	p, ctx := newTestProvider(t, m, nil)

	// go-oidc requires a sub for verification, so this fails at verification
	// rather than reaching our own check. Either way it must be refused.
	if _, err := p.Callback(ctx, mockLogin(t, m, p, "/")); err == nil {
		t.Fatal("a token with no subject must be refused")
	}
}

// TestOIDCFallsBackToPreferredUsername covers Entra tenants where the email
// attribute is not populated but the UPN is an address.
func TestOIDCFallsBackToPreferredUsername(t *testing.T) {
	m := newMockIssuer(t)
	m.overrideClaims = func(c map[string]any) {
		delete(c, "email")
		c["preferred_username"] = "alice@contoso.onmicrosoft.com"
	}
	p, ctx := newTestProvider(t, m, nil)

	res, err := p.Callback(ctx, mockLogin(t, m, p, "/"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Claims.Email != "alice@contoso.onmicrosoft.com" {
		t.Errorf("email = %q; should fall back to preferred_username", res.Claims.Email)
	}
}

// TestSanitizeReturnTo closes the open-redirect hole. A login endpoint that
// forwards to an arbitrary URL is a standard phishing aid.
func TestSanitizeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/sessions":                    "/sessions",
		"/credentials?tab=keys":        "/credentials?tab=keys",
		"":                             "/",
		"https://evil.example.com":     "/",
		"//evil.example.com":           "/",
		"http://evil.example.com/path": "/",
		"javascript:alert(1)":          "/",
		"/path\\..\\evil":              "/",
		"/path\r\nSet-Cookie: x=y":     "/",
		"relative/path":                "/",
	}

	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			if got := sanitizeReturnTo(input); got != want {
				t.Errorf("sanitizeReturnTo(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

// TestOIDCReturnToIsSanitizedEndToEnd confirms the check survives the round
// trip, not just the helper.
func TestOIDCReturnToIsSanitizedEndToEnd(t *testing.T) {
	m := newMockIssuer(t)
	p, ctx := newTestProvider(t, m, nil)

	res, err := p.Callback(ctx, mockLogin(t, m, p, "https://evil.example.com/steal"))
	if err != nil {
		t.Fatal(err)
	}
	if res.ReturnTo != "/" {
		t.Fatalf("returnTo = %q; an absolute URL must not survive the round trip", res.ReturnTo)
	}
}

func TestOIDCStateCookieFlags(t *testing.T) {
	m := newMockIssuer(t)
	p, _ := newTestProvider(t, m, nil)

	_, cookie, err := p.AuthURL("/")
	if err != nil {
		t.Fatal(err)
	}

	if !cookie.HttpOnly {
		t.Error("the state cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("the state cookie must be Secure")
	}
	// Lax rather than Strict is required here: the browser reaches the
	// callback by a top-level redirect from Microsoft, and Strict would
	// withhold the cookie on that navigation, breaking every sign-in.
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v; must be Lax or the redirect back from Entra drops the cookie", cookie.SameSite)
	}
	if cookie.MaxAge <= 0 || cookie.MaxAge > int(OIDCStateTTL.Seconds()) {
		t.Errorf("MaxAge = %d, want a positive value no greater than the state TTL", cookie.MaxAge)
	}

	cleared := ClearStateCookie()
	if cleared.MaxAge != -1 || cleared.Value != "" {
		t.Error("the clearing cookie is malformed")
	}
}

func TestOIDCStateAndNonceAreUnique(t *testing.T) {
	m := newMockIssuer(t)
	p, _ := newTestProvider(t, m, nil)

	states := make(map[string]struct{}, 100)
	nonces := make(map[string]struct{}, 100)

	for i := 0; i < 100; i++ {
		_, cookie, err := p.AuthURL("/")
		if err != nil {
			t.Fatal(err)
		}
		ls, err := p.openState(cookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := states[ls.State]; dup {
			t.Fatalf("state repeated after %d logins", i)
		}
		if _, dup := nonces[ls.Nonce]; dup {
			t.Fatalf("nonce repeated after %d logins", i)
		}
		states[ls.State] = struct{}{}
		nonces[ls.Nonce] = struct{}{}
	}
}

func TestOIDCConfigValidate(t *testing.T) {
	valid := OIDCConfig{
		Enabled:        true,
		Issuer:         "https://login.microsoftonline.com/tenant-id/v2.0",
		ClientID:       "client",
		ClientSecret:   "secret",
		RedirectURL:    testRedirectURL,
		AllowedTenants: []string{"tenant-id"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid config was rejected: %v", err)
	}

	t.Run("disabled config needs nothing", func(t *testing.T) {
		if err := (OIDCConfig{Enabled: false}).Validate(); err != nil {
			t.Fatalf("a disabled config must validate: %v", err)
		}
	})

	missing := map[string]func(*OIDCConfig){
		"issuer":            func(c *OIDCConfig) { c.Issuer = "" },
		"http issuer":       func(c *OIDCConfig) { c.Issuer = "http://insecure.example.com" },
		"client id":         func(c *OIDCConfig) { c.ClientID = "" },
		"client secret":     func(c *OIDCConfig) { c.ClientSecret = "" },
		"redirect":          func(c *OIDCConfig) { c.RedirectURL = "" },
		"relative redirect": func(c *OIDCConfig) { c.RedirectURL = "/auth/callback" },
	}
	for name, mutate := range missing {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// TestOIDCConfigRefusesUncheckedMultiTenant is the configuration guard that
// matters most. Pointing at /common without listing tenants means any
// Microsoft account on earth can sign in.
func TestOIDCConfigRefusesUncheckedMultiTenant(t *testing.T) {
	for _, issuer := range []string{
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/organizations/v2.0",
		"https://login.microsoftonline.com/consumers/v2.0",
	} {
		t.Run(issuer, func(t *testing.T) {
			c := OIDCConfig{
				Enabled:      true,
				Issuer:       issuer,
				ClientID:     "client",
				ClientSecret: "secret",
				RedirectURL:  testRedirectURL,
			}
			err := c.Validate()
			if err == nil {
				t.Fatal("a multi-tenant issuer with no tenant allowlist must be refused")
			}
			if !strings.Contains(err.Error(), "allowed_tenants") {
				t.Errorf("the error should name the missing setting, got: %v", err)
			}

			// Naming the tenants makes it acceptable.
			c.AllowedTenants = []string{"tenant-a"}
			if err := c.Validate(); err != nil {
				t.Fatalf("listing tenants should make it valid: %v", err)
			}
		})
	}

	// A single-tenant issuer is safe without the allowlist, because the
	// endpoint itself only mints tokens for that tenant.
	t.Run("single tenant needs no allowlist", func(t *testing.T) {
		c := OIDCConfig{
			Enabled:      true,
			Issuer:       "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
			ClientID:     "client",
			ClientSecret: "secret",
			RedirectURL:  testRedirectURL,
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("a single-tenant issuer should validate without an allowlist: %v", err)
		}
	})
}

func TestNewOIDCProviderRejectsDisabled(t *testing.T) {
	_, err := NewOIDCProvider(context.Background(), OIDCConfig{Enabled: false}, testMasterKey(t))
	if !errors.Is(err, ErrOIDCDisabled) {
		t.Fatalf("want ErrOIDCDisabled, got %v", err)
	}
}

func TestNewOIDCProviderFailsOnBadIssuer(t *testing.T) {
	cfg := OIDCConfig{
		Enabled:      true,
		Issuer:       "https://127.0.0.1:1/nonexistent",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  testRedirectURL,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Discovery is a live call precisely so this fails at startup rather than
	// on a user's first sign-in.
	if _, err := NewOIDCProvider(ctx, cfg, testMasterKey(t)); err == nil {
		t.Fatal("an unreachable issuer must fail at construction")
	}
}
