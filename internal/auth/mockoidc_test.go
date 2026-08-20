package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// mockIssuer is an in-process OpenID Connect provider.
//
// It exists so the sign-in flow is exercised end to end — discovery, JWKS,
// authorization code exchange, PKCE, and a genuinely signed ID token — rather
// than against stubs that would agree with whatever we implemented. It also
// lets the tests mint deliberately bad tokens, which is the only way to prove
// the checks that matter actually reject them.
//
// It is not a complete provider. It implements exactly what go-oidc requests.
type mockIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	mu sync.Mutex
	// codes maps an issued authorization code to the request that produced
	// it, so the token endpoint can verify PKCE and echo the nonce.
	codes map[string]*mockAuthRequest
	// used records codes already redeemed, so replay can be rejected the way
	// a real provider does.
	used map[string]bool

	// Knobs the tests turn to produce malformed tokens.
	tenantID         string
	overrideClaims   func(map[string]any)
	signWithWrongKey bool
	omitIDToken      bool
}

type mockAuthRequest struct {
	clientID      string
	nonce         string
	codeChallenge string
	redirectURI   string
	subject       string
	email         string
	name          string
	amr           []string
}

const mockTenantID = "11111111-2222-3333-4444-555555555555"

func newMockIssuer(t *testing.T) *mockIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	m := &mockIssuer{
		key:      key,
		keyID:    "test-key-1",
		codes:    make(map[string]*mockAuthRequest),
		used:     make(map[string]bool),
		tenantID: mockTenantID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/keys", m.handleJWKS)
	mux.HandleFunc("/authorize", m.handleAuthorize)
	mux.HandleFunc("/token", m.handleToken)

	m.server = httptest.NewTLSServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// issuerURL is what goes into OIDCConfig.Issuer.
func (m *mockIssuer) issuerURL() string { return m.server.URL }

// httpClient returns a client trusting the mock's self-signed certificate.
func (m *mockIssuer) httpClient() *http.Client { return m.server.Client() }

func (m *mockIssuer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                m.server.URL,
		"authorization_endpoint":                m.server.URL + "/authorize",
		"token_endpoint":                        m.server.URL + "/token",
		"jwks_uri":                              m.server.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (m *mockIssuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := m.key.Public().(*rsa.PublicKey)
	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": m.keyID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// handleAuthorize stands in for the Microsoft sign-in page. A real one shows a
// form; this one immediately issues a code for a canned user.
func (m *mockIssuer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	m.mu.Lock()
	m.codes[code] = &mockAuthRequest{
		clientID:      q.Get("client_id"),
		nonce:         q.Get("nonce"),
		codeChallenge: q.Get("code_challenge"),
		redirectURI:   q.Get("redirect_uri"),
		subject:       "user-object-id-0001",
		email:         "alice@example.com",
		name:          "Alice Example",
		amr:           []string{"pwd"},
	}
	m.mu.Unlock()

	redirect := q.Get("redirect_uri") + "?code=" + code + "&state=" + q.Get("state")
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (m *mockIssuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")

	m.mu.Lock()
	req, ok := m.codes[code]
	alreadyUsed := m.used[code]
	if ok && !alreadyUsed {
		m.used[code] = true
	}
	m.mu.Unlock()

	if !ok {
		writeTokenError(w, "invalid_grant", "unknown authorization code")
		return
	}
	// A real provider refuses a second redemption; so does this one, which is
	// what makes the code-replay test meaningful.
	if alreadyUsed {
		writeTokenError(w, "invalid_grant", "authorization code already redeemed")
		return
	}

	// PKCE: the verifier must hash to the challenge sent at /authorize.
	if req.codeChallenge != "" {
		verifier := r.Form.Get("code_verifier")
		if verifier == "" {
			writeTokenError(w, "invalid_request", "code_verifier missing")
			return
		}
		if s256(verifier) != req.codeChallenge {
			writeTokenError(w, "invalid_grant", "code_verifier does not match code_challenge")
			return
		}
	}

	if m.omitIDToken {
		writeJSON(w, map[string]any{"access_token": "opaque", "token_type": "Bearer"})
		return
	}

	idToken, err := m.mintIDToken(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"access_token": "opaque-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// mintIDToken builds a signed ID token, applying whatever distortion the test
// has configured.
func (m *mockIssuer) mintIDToken(req *mockAuthRequest) (string, error) {
	now := time.Now()

	claims := map[string]any{
		"iss":                m.server.URL,
		"aud":                req.clientID,
		"sub":                "pairwise-subject-value",
		"oid":                req.subject,
		"tid":                m.tenantID,
		"email":              req.email,
		"name":               req.name,
		"preferred_username": req.email,
		"amr":                req.amr,
		"nonce":              req.nonce,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"auth_time":          now.Unix(),
	}
	if m.overrideClaims != nil {
		m.overrideClaims(claims)
	}

	signingKey := m.key
	if m.signWithWrongKey {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		signingKey = other
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeTokenError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// mockLogin drives a full browser round trip against the mock issuer and
// returns the callback request the application would receive.
//
// It follows the redirect by hand rather than using a cookie jar, because the
// point is to produce exactly the request the callback handler sees, with the
// state cookie attached.
func mockLogin(t *testing.T, m *mockIssuer, p *OIDCProvider, returnTo string) *http.Request {
	t.Helper()

	authURL, stateCookie, err := p.AuthURL(returnTo)
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}

	client := m.httpClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatalf("authorize did not redirect; status %d", resp.StatusCode)
	}

	req := httptest.NewRequest(http.MethodGet, location, nil)
	req.AddCookie(stateCookie)
	return req
}

// callbackRequest builds a callback request with arbitrary query parameters,
// for the cases that never reach the identity provider.
func callbackRequest(t *testing.T, cookie *http.Cookie, params map[string]string) *http.Request {
	t.Helper()

	q := make([]string, 0, len(params))
	for k, v := range params {
		q = append(q, k+"="+v)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+strings.Join(q, "&"), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}
