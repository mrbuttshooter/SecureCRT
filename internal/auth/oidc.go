package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"golang.org/x/oauth2"
)

// OIDC errors. Every one of these means the sign-in is refused.
var (
	// ErrOIDCStateMismatch means the state returned by the identity provider
	// did not match the one we issued. This is the cross-site request forgery
	// defence for the login flow itself: without it an attacker could feed a
	// victim's browser their own authorization code and silently log the
	// victim into the attacker's account.
	ErrOIDCStateMismatch = errors.New("auth: OIDC state mismatch")

	// ErrOIDCNonceMismatch means the nonce inside the ID token was not the
	// one we asked for, which indicates a replayed or substituted token.
	ErrOIDCNonceMismatch = errors.New("auth: OIDC nonce mismatch")

	// ErrOIDCWrongTenant means the token came from a Microsoft tenant this
	// deployment does not accept. Without this check, any Entra tenant in the
	// world could mint tokens for a multi-tenant app registration.
	ErrOIDCWrongTenant = errors.New("auth: token issued by an unaccepted tenant")

	// ErrOIDCStateExpired means the login took longer than the state cookie's
	// lifetime, usually because the user left the Microsoft page open.
	ErrOIDCStateExpired = errors.New("auth: login attempt expired; please start again")

	// ErrOIDCNoSubject means the token lacked the claim identifying the user.
	ErrOIDCNoSubject = errors.New("auth: token has no usable subject claim")

	// ErrOIDCDisabled means single sign-on is not configured.
	ErrOIDCDisabled = errors.New("auth: single sign-on is not configured")
)

// OIDCStateTTL bounds how long a login may take between leaving for Microsoft
// and coming back. Long enough for a password, an MFA prompt and a moment of
// hesitation; short enough that a leaked state parameter is useless.
const OIDCStateTTL = 15 * time.Minute

// OIDCStateCookieName holds the signed state, nonce and PKCE verifier.
const OIDCStateCookieName = "bkd_oidc_state"

// OIDCConfig configures single sign-on.
type OIDCConfig struct {
	Enabled bool

	// Issuer is the discovery base, e.g.
	// https://login.microsoftonline.com/<tenant-id>/v2.0
	Issuer string

	ClientID     string
	ClientSecret string

	// RedirectURL must match the app registration exactly, including scheme
	// and trailing path. Entra compares it as an opaque string.
	RedirectURL string

	// AllowedTenants lists acceptable Entra `tid` values.
	//
	// Leaving this empty is refused when the issuer is a multi-tenant
	// endpoint (/common, /organizations, /consumers): such an endpoint will
	// happily validate a token from any tenant on earth, so accepting one
	// without checking `tid` means anyone with a Microsoft account can sign
	// in to your system.
	AllowedTenants []string

	// AutoProvision creates an account on first successful sign-in.
	AutoProvision bool

	// Scopes requested. Defaults to openid, profile, email.
	Scopes []string
}

// Validate checks the configuration is usable and not dangerously permissive.
func (c OIDCConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	var errs []error
	if c.Issuer == "" {
		errs = append(errs, errors.New("auth: oidc.issuer must be set"))
	} else if u, err := url.Parse(c.Issuer); err != nil || u.Scheme != "https" {
		errs = append(errs, fmt.Errorf("auth: oidc.issuer %q must be an https URL", c.Issuer))
	}
	if c.ClientID == "" {
		errs = append(errs, errors.New("auth: oidc.client_id must be set"))
	}
	if c.ClientSecret == "" {
		errs = append(errs, errors.New("auth: oidc.client_secret must be set (use BKD_OIDC_CLIENT_SECRET)"))
	}
	if c.RedirectURL == "" {
		errs = append(errs, errors.New("auth: oidc.redirect_url must be set"))
	} else if u, err := url.Parse(c.RedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("auth: oidc.redirect_url %q must be absolute", c.RedirectURL))
	}

	if len(c.AllowedTenants) == 0 && isMultiTenantIssuer(c.Issuer) {
		errs = append(errs, fmt.Errorf(
			"auth: oidc.issuer %q is a multi-tenant endpoint, so oidc.allowed_tenants must list "+
				"the tenant IDs you accept; without it any Microsoft account in the world can sign in",
			c.Issuer))
	}

	return errors.Join(errs...)
}

// isMultiTenantIssuer reports whether the issuer accepts tokens from tenants
// other than a single named one.
func isMultiTenantIssuer(issuer string) bool {
	for _, shared := range []string{"/common", "/organizations", "/consumers"} {
		if strings.Contains(issuer, shared+"/") || strings.HasSuffix(issuer, shared) {
			return true
		}
	}
	return false
}

// Claims is what we read out of an Entra ID token.
type Claims struct {
	// Subject is the stable per-tenant user identifier: Entra's `oid`.
	//
	// Deliberately not `sub`. Entra's `sub` is pairwise — unique per
	// application — so it changes if the app registration is ever deleted and
	// recreated, which would orphan every account and their credentials.
	// `oid` is the directory object ID and survives that.
	Subject string

	// TenantID is Entra's `tid`.
	TenantID string

	Email             string
	Name              string
	PreferredUsername string

	// MFASatisfied is true when Entra reports having performed multi-factor
	// authentication, via `amr` containing "mfa". Honouring it avoids asking
	// for a second factor the identity provider already collected.
	MFASatisfied bool

	// AuthTime is when the identity provider authenticated the user, which
	// can be well before now if it reused an existing session.
	AuthTime time.Time
}

// rawClaims mirrors the ID token payload.
type rawClaims struct {
	Subject           string   `json:"sub"`
	ObjectID          string   `json:"oid"`
	TenantID          string   `json:"tid"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	AMR               []string `json:"amr"`
	AuthTime          int64    `json:"auth_time"`
}

// OIDCProvider performs sign-in against an OpenID Connect identity provider.
type OIDCProvider struct {
	cfg      OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config

	// stateKey signs the state cookie. Derived from the master key, so the
	// service needs no additional secret on disk.
	stateKey vault.Key

	now func() time.Time
}

// NewOIDCProvider performs discovery against the issuer and builds a provider.
//
// Discovery is a live network call, so this fails fast at startup on a
// misconfigured issuer rather than on a user's first sign-in attempt.
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig, masterKey vault.Key) (*OIDCProvider, error) {
	if !cfg.Enabled {
		return nil, ErrOIDCDisabled
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC discovery against %s failed: %w", cfg.Issuer, err)
	}

	stateKey, err := vault.DeriveSubkey(masterKey, vault.SubkeyOIDCState)
	if err != nil {
		return nil, err
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	return &OIDCProvider{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		stateKey: stateKey,
		now:      time.Now,
	}, nil
}

// loginState is what rides in the signed cookie across the redirect.
//
// Keeping it in a cookie rather than a database table means the login flow
// holds no server-side state, so it survives a restart mid-login and works
// unchanged behind a load balancer with several nodes.
type loginState struct {
	State        string `json:"s"`
	Nonce        string `json:"n"`
	PKCEVerifier string `json:"v"`
	ReturnTo     string `json:"r,omitempty"`
	IssuedAt     int64  `json:"t"`
}

// AuthURL begins a sign-in. It returns the URL to redirect the browser to and
// the cookie that must accompany it.
//
// returnTo is where to land after a successful login. It is validated as a
// same-site relative path: accepting an absolute URL here would turn the
// login endpoint into an open redirect, which is a standard phishing aid.
func (p *OIDCProvider) AuthURL(returnTo string) (string, *http.Cookie, error) {
	state, err := randomToken()
	if err != nil {
		return "", nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", nil, err
	}
	verifier := oauth2.GenerateVerifier()

	ls := loginState{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     sanitizeReturnTo(returnTo),
		IssuedAt:     p.now().Unix(),
	}

	cookie, err := p.sealState(ls)
	if err != nil {
		return "", nil, err
	}

	authURL := p.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return authURL, cookie, nil
}

// sanitizeReturnTo keeps only same-site relative paths.
//
// "//evil.example.com" is deliberately rejected: browsers treat a
// protocol-relative path as an absolute URL, so allowing it would be an open
// redirect despite the leading slash.
func sanitizeReturnTo(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	if strings.Contains(raw, "\\") || strings.ContainsAny(raw, "\r\n") {
		return "/"
	}
	return raw
}

// CallbackResult is a completed sign-in.
type CallbackResult struct {
	Claims   Claims
	ReturnTo string
}

// Callback completes a sign-in: it validates the state cookie, exchanges the
// authorization code, verifies the ID token, and checks the nonce and tenant.
//
// The order matters. State is checked before the code is exchanged, so a
// forged callback costs nothing and never reaches the identity provider.
func (p *OIDCProvider) Callback(ctx context.Context, r *http.Request) (CallbackResult, error) {
	// An error returned by the identity provider — consent declined, a
	// conditional access policy blocking the sign-in — arrives as a query
	// parameter rather than an HTTP error, so it must be surfaced rather than
	// mistaken for a missing code.
	if provErr := r.URL.Query().Get("error"); provErr != "" {
		desc := r.URL.Query().Get("error_description")
		if desc == "" {
			desc = "no description supplied"
		}
		return CallbackResult{}, fmt.Errorf("auth: identity provider refused the sign-in: %s (%s)", provErr, desc)
	}

	cookie, err := r.Cookie(OIDCStateCookieName)
	if err != nil {
		return CallbackResult{}, ErrOIDCStateExpired
	}

	ls, err := p.openState(cookie.Value)
	if err != nil {
		return CallbackResult{}, err
	}

	if p.now().Unix()-ls.IssuedAt > int64(OIDCStateTTL.Seconds()) {
		return CallbackResult{}, ErrOIDCStateExpired
	}

	// Constant-time, though the state is single-use and short-lived.
	returned := r.URL.Query().Get("state")
	if returned == "" || !hmac.Equal([]byte(returned), []byte(ls.State)) {
		return CallbackResult{}, ErrOIDCStateMismatch
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return CallbackResult{}, errors.New("auth: callback carried no authorization code")
	}

	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(ls.PKCEVerifier))
	if err != nil {
		return CallbackResult{}, fmt.Errorf("auth: exchanging the authorization code failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return CallbackResult{}, errors.New("auth: token response contained no id_token")
	}

	// Verifies signature against the provider's JWKS, plus issuer, audience
	// and expiry. This is the step that must never be hand-rolled.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return CallbackResult{}, fmt.Errorf("auth: ID token verification failed: %w", err)
	}

	if !hmac.Equal([]byte(idToken.Nonce), []byte(ls.Nonce)) {
		return CallbackResult{}, ErrOIDCNonceMismatch
	}

	var raw rawClaims
	if err := idToken.Claims(&raw); err != nil {
		return CallbackResult{}, fmt.Errorf("auth: reading token claims: %w", err)
	}

	claims, err := p.buildClaims(raw)
	if err != nil {
		return CallbackResult{}, err
	}

	return CallbackResult{Claims: claims, ReturnTo: sanitizeReturnTo(ls.ReturnTo)}, nil
}

func (p *OIDCProvider) buildClaims(raw rawClaims) (Claims, error) {
	// Prefer oid; fall back to sub for providers that do not issue one, so
	// this stays usable against a non-Entra issuer.
	subject := raw.ObjectID
	if subject == "" {
		subject = raw.Subject
	}
	if subject == "" {
		return Claims{}, ErrOIDCNoSubject
	}

	if len(p.cfg.AllowedTenants) > 0 {
		if raw.TenantID == "" {
			return Claims{}, fmt.Errorf("%w: token carries no tid claim", ErrOIDCWrongTenant)
		}
		allowed := false
		for _, t := range p.cfg.AllowedTenants {
			if hmac.Equal([]byte(t), []byte(raw.TenantID)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Claims{}, fmt.Errorf("%w: %s", ErrOIDCWrongTenant, raw.TenantID)
		}
	}

	email := raw.Email
	// Entra frequently omits `email` unless the attribute is populated, but
	// preferred_username carries the UPN, which is an address in practice.
	if email == "" && strings.Contains(raw.PreferredUsername, "@") {
		email = raw.PreferredUsername
	}

	claims := Claims{
		Subject:           subject,
		TenantID:          raw.TenantID,
		Email:             strings.TrimSpace(email),
		Name:              raw.Name,
		PreferredUsername: raw.PreferredUsername,
		MFASatisfied:      hasAMR(raw.AMR, "mfa"),
	}
	if raw.AuthTime > 0 {
		claims.AuthTime = time.Unix(raw.AuthTime, 0).UTC()
	}
	return claims, nil
}

// hasAMR reports whether an authentication method reference is present.
//
// Entra reports multi-factor as "mfa". Some tenants additionally report the
// specific method used; matching those too avoids demanding a second factor
// from a user who has already provided a strong one.
func hasAMR(amr []string, want string) bool {
	strong := map[string]bool{
		want:     true,
		"mfa":    true,
		"fido":   true,
		"hwk":    true, // hardware key
		"otp":    true,
		"phr":    true, // phishing-resistant
		"phrmfa": true,
	}
	for _, v := range amr {
		if strong[strings.ToLower(v)] {
			return true
		}
	}
	return false
}

// sealState signs and encodes the login state into a cookie.
//
// Signed rather than encrypted: nothing in it is secret. The state and nonce
// are random values whose only purpose is to be matched later, and the PKCE
// verifier is meaningless without the authorization code. What matters is
// that an attacker cannot forge one, which a MAC provides.
func (p *OIDCProvider) sealState(ls loginState) (*http.Cookie, error) {
	payload, err := json.Marshal(ls)
	if err != nil {
		return nil, fmt.Errorf("auth: encode login state: %w", err)
	}

	mac := hmac.New(sha256.New, p.stateKey)
	mac.Write(payload)

	value := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return &http.Cookie{
		Name:     OIDCStateCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		// Lax, not Strict: the browser arrives at the callback via a
		// top-level redirect from Microsoft, and Strict would withhold the
		// cookie on that navigation, breaking every sign-in.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(OIDCStateTTL.Seconds()),
	}, nil
}

// ClearStateCookie removes the login state cookie once it has been consumed.
func ClearStateCookie() *http.Cookie {
	return &http.Cookie{
		Name:     OIDCStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func (p *OIDCProvider) openState(value string) (loginState, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return loginState{}, ErrOIDCStateMismatch
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return loginState{}, ErrOIDCStateMismatch
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return loginState{}, ErrOIDCStateMismatch
	}

	mac := hmac.New(sha256.New, p.stateKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return loginState{}, ErrOIDCStateMismatch
	}

	var ls loginState
	if err := json.Unmarshal(payload, &ls); err != nil {
		return loginState{}, ErrOIDCStateMismatch
	}
	if ls.State == "" || ls.Nonce == "" || ls.PKCEVerifier == "" {
		return loginState{}, ErrOIDCStateMismatch
	}
	return ls, nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("auth: generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
