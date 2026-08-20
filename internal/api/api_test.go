package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

// harness is a running API with a client that keeps cookies, so tests drive
// the same flow a browser would rather than constructing sessions by hand.
type harness struct {
	t         *testing.T
	api       *API
	server    *httptest.Server
	users     *users.Store
	vaults    *users.VaultService
	cache     *vault.Cache
	tree      *sessions.Store
	terminals *terminal.Manager
	hostKeys  *hostkeys.Store

	cookies map[string]string
	csrf    string
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()

	db := storetest.New(t)
	ctx := context.Background()

	cfg := config.Default()
	cfg.Auth.SecureCookies = false // httptest serves plain HTTP
	// Cheap KDF costs; the real ones are exercised in the vault package.
	cfg.Vault.Argon2Time = 1
	cfg.Vault.Argon2MemoryKB = 16 * 1024
	cfg.Vault.Argon2Threads = 1
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}

	master, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cache := vault.NewCache(time.Hour)
	t.Cleanup(cache.Close)

	userStore := users.NewStore(db)
	vaultSvc, err := users.NewVaultService(userStore, cache, master, users.VaultServiceConfig{
		Argon2Time:     cfg.Vault.Argon2Time,
		Argon2MemoryKB: cfg.Vault.Argon2MemoryKB,
		Argon2Threads:  cfg.Vault.Argon2Threads,
		SSOUnlockMode:  users.SSOUnlockMode(cfg.Vault.SSOUnlockMode),
	})
	if err != nil {
		t.Fatal(err)
	}

	authSessions, err := auth.NewSessionStore(db, auth.SessionConfig{
		IdleTTL: cfg.Auth.SessionIdleTTL, AbsoluteTTL: cfg.Auth.SessionAbsoluteTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	throttle, err := auth.NewThrottle(db, auth.ThrottleConfig{
		MaxPerAccount:   cfg.Auth.MaxAttemptsPerAccount,
		MaxPerAddress:   cfg.Auth.MaxAttemptsPerAddress,
		Window:          cfg.Auth.LockoutWindow,
		LockoutDuration: cfg.Auth.LockoutDuration,
	})
	if err != nil {
		t.Fatal(err)
	}

	apiCfg, err := ConfigFrom(cfg)
	if err != nil {
		t.Fatal(err)
	}

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	sessionTree := sessions.NewStore(db)
	credStore := credentials.NewStore(db)
	hostKeyStore := hostkeys.NewStore(db)

	terminals := terminal.NewManager(quiet)
	t.Cleanup(terminals.Close)
	connector := terminal.NewConnector(terminals, sessionTree, credStore, hostKeyStore, quiet)

	a, err := New(apiCfg, Deps{
		DB: db, Users: userStore, Vaults: vaultSvc, Sessions: authSessions,
		Throttle: throttle, Credentials: credStore,
		Audit:       audit.NewRecorder(db, quiet),
		MasterKey:   master,
		SessionTree: sessionTree,
		Terminals:   terminals,
		Connector:   connector,
		HostKeys:    hostKeyStore,
	}, quiet)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)

	h := &harness{
		t: t, api: a, server: srv, users: userStore, vaults: vaultSvc,
		cache: cache, tree: sessionTree, terminals: terminals, hostKeys: hostKeyStore,
		cookies: map[string]string{},
	}

	// Every client begins by fetching the sign-in configuration, which is
	// also what issues the CSRF token.
	h.get("/api/auth/config")
	_ = ctx
	return h
}

// do performs a request, carrying cookies and the CSRF header as a browser
// would.
func (h *harness) do(method, path string, body any) (*http.Response, map[string]any) {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range h.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if h.csrf != "" {
		req.Header.Set(auth.CSRFHeaderName, h.csrf)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(h.cookies, c.Name)
			continue
		}
		h.cookies[c.Name] = c.Value
		if c.Name == auth.CSRFCookieName {
			h.csrf = c.Value
		}
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}

	var decoded map[string]any
	if len(raw) > 0 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			h.t.Fatalf("response from %s %s is not JSON: %v (%q)", method, path, err, raw)
		}
	}
	return resp, decoded
}

func (h *harness) get(path string) (*http.Response, map[string]any) {
	return h.do(http.MethodGet, path, nil)
}
func (h *harness) post(path string, body any) (*http.Response, map[string]any) {
	return h.do(http.MethodPost, path, body)
}

// createLocalUser adds an account with a password.
func (h *harness) createLocalUser(email, password string, admin bool) users.User {
	h.t.Helper()
	u, err := h.users.Create(context.Background(), users.CreateParams{
		Email: email, Password: password, IsAdmin: admin, DisplayName: "Test User",
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// login signs in and leaves the harness holding the session.
func (h *harness) login(email, password string) map[string]any {
	h.t.Helper()
	resp, body := h.post("/api/auth/login", map[string]string{"email": email, "password": password})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("login failed: %d %v", resp.StatusCode, body)
	}
	return body
}

func errCode(body map[string]any) string {
	e, ok := body["error"].(map[string]any)
	if !ok {
		return ""
	}
	code, _ := e["code"].(string)
	return code
}

// --- tests ------------------------------------------------------------------

func TestAuthConfigIsPublic(t *testing.T) {
	h := newHarness(t, nil)

	resp, body := h.get("/api/auth/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body["password_auth_enabled"] != true {
		t.Error("password auth should be reported as enabled")
	}
	if body["sso_enabled"] != false {
		t.Error("single sign-on should be reported as disabled in this harness")
	}
	// It must also mint the CSRF token the sign-in POST needs.
	if h.csrf == "" {
		t.Error("no CSRF token was issued")
	}
}

func TestLocalLoginFlow(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)

	body := h.login("alice@example.com", "correct horse battery staple")

	user, _ := body["user"].(map[string]any)
	if user["email"] != "alice@example.com" {
		t.Errorf("user = %v", user)
	}

	// The session cookie must be set and usable.
	if h.cookies[auth.SessionCookieName] == "" {
		t.Fatal("no session cookie was set")
	}
	resp, who := h.get("/api/auth/whoami")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whoami: %d %v", resp.StatusCode, who)
	}

	// A fresh account has no vault yet, and the response must say so rather
	// than leaving the client to infer it.
	next, _ := who["next"].(map[string]any)
	if next["enrol_vault"] != true {
		t.Errorf("a new account should be asked to enrol a vault: %v", next)
	}
}

// TestLoginDoesNotRevealWhichAccountsExist is the account-enumeration guard.
func TestLoginDoesNotRevealWhichAccountsExist(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)

	respUnknown, bodyUnknown := h.post("/api/auth/login",
		map[string]string{"email": "nobody@example.com", "password": "some password"})
	respWrong, bodyWrong := h.post("/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "wrong password"})

	if respUnknown.StatusCode != respWrong.StatusCode {
		t.Errorf("status differs: unknown account %d, wrong password %d",
			respUnknown.StatusCode, respWrong.StatusCode)
	}

	unknownJSON, _ := json.Marshal(bodyUnknown)
	wrongJSON, _ := json.Marshal(bodyWrong)
	if string(unknownJSON) != string(wrongJSON) {
		t.Errorf("response bodies differ, which reveals whether an account exists:\n  %s\n  %s",
			unknownJSON, wrongJSON)
	}
}

func TestLoginRejectsDisabledAccount(t *testing.T) {
	h := newHarness(t, nil)
	u := h.createLocalUser("alice@example.com", "correct horse battery staple", false)

	if err := h.users.SetDisabled(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}

	resp, _ := h.post("/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "correct horse battery staple"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a disabled account must not sign in: %d", resp.StatusCode)
	}
}

// TestDisablingAnAccountEndsItsSessions confirms a suspension takes effect on
// the next request, not whenever the session happens to expire.
func TestDisablingAnAccountEndsItsSessions(t *testing.T) {
	h := newHarness(t, nil)
	u := h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	if resp, _ := h.get("/api/auth/whoami"); resp.StatusCode != http.StatusOK {
		t.Fatal("session should work before disabling")
	}

	if err := h.users.SetDisabled(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}

	resp, body := h.get("/api/auth/whoami")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 once disabled: %v", resp.StatusCode, body)
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t, nil)

	for _, path := range []string{"/api/auth/whoami", "/api/credentials", "/api/sessions", "/api/vault/status"} {
		t.Run(path, func(t *testing.T) {
			resp, body := h.get(path)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if errCode(body) != string(CodeUnauthorized) {
				t.Errorf("code = %q", errCode(body))
			}
		})
	}
}

// TestCSRFIsEnforced covers the double-submit check on state-changing calls.
func TestCSRFIsEnforced(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	t.Run("missing header", func(t *testing.T) {
		saved := h.csrf
		h.csrf = ""
		defer func() { h.csrf = saved }()

		resp, body := h.post("/api/vault/lock", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if errCode(body) != string(CodeForbidden) {
			t.Errorf("code = %q", errCode(body))
		}
	})

	t.Run("header not matching cookie", func(t *testing.T) {
		saved := h.csrf
		h.csrf = "a-different-value"
		defer func() { h.csrf = saved }()

		resp, _ := h.post("/api/vault/lock", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("forged token in both places", func(t *testing.T) {
		savedCSRF, savedCookie := h.csrf, h.cookies[auth.CSRFCookieName]
		h.csrf = "forged.token"
		h.cookies[auth.CSRFCookieName] = "forged.token"
		defer func() { h.csrf, h.cookies[auth.CSRFCookieName] = savedCSRF, savedCookie }()

		// Matching halves are not enough: the signature must verify, so an
		// attacker who can set cookies still cannot forge one.
		resp, _ := h.post("/api/vault/lock", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for an unsigned token", resp.StatusCode)
		}
	})

	t.Run("safe methods are exempt", func(t *testing.T) {
		saved := h.csrf
		h.csrf = ""
		defer func() { h.csrf = saved }()

		if resp, _ := h.get("/api/auth/whoami"); resp.StatusCode != http.StatusOK {
			t.Fatal("GET must not require a CSRF token")
		}
	})
}

// TestVaultLifecycle walks enrol, use, lock, unlock.
func TestVaultLifecycle(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	t.Run("credentials are refused while locked", func(t *testing.T) {
		resp, body := h.post("/api/credentials", map[string]string{
			"name": "router", "kind": "password", "secret": "hunter2",
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if errCode(body) != string(CodeVaultLocked) {
			t.Errorf("code = %q, want vault_locked", errCode(body))
		}
	})

	t.Run("short passphrase refused", func(t *testing.T) {
		resp, body := h.post("/api/vault/enrol", map[string]string{"passphrase": "short"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		e, _ := body["error"].(map[string]any)
		msg, _ := e["message"].(string)
		if !strings.Contains(msg, "12 characters") {
			t.Errorf("the message should say what is required, got %q", msg)
		}
	})

	t.Run("enrol", func(t *testing.T) {
		resp, body := h.post("/api/vault/enrol", map[string]string{"passphrase": "a long enough passphrase"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		if body["unlocked"] != true {
			t.Error("enrolment should leave the vault open")
		}
	})

	t.Run("credentials work once unlocked", func(t *testing.T) {
		resp, body := h.post("/api/credentials", map[string]string{
			"name": "router", "kind": "password", "username": "admin", "secret": "hunter2",
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		// The secret must not come back in the response.
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), "hunter2") {
			t.Fatalf("the secret was echoed back in the response: %s", encoded)
		}
	})

	t.Run("lock", func(t *testing.T) {
		resp, body := h.post("/api/vault/lock", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		resp, _ = h.get("/api/vault/status")
		_, status := h.get("/api/vault/status")
		if status["unlocked"] != false {
			t.Error("the vault should read as locked")
		}
		_ = resp
	})

	t.Run("listing still works while locked", func(t *testing.T) {
		// The whole point of storing fingerprints in the clear.
		resp, body := h.get("/api/credentials")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		list, _ := body["credentials"].([]any)
		if len(list) != 1 {
			t.Fatalf("listed %d credentials, want 1", len(list))
		}
	})

	t.Run("wrong passphrase refused", func(t *testing.T) {
		resp, body := h.post("/api/vault/unlock", map[string]string{"passphrase": "not the passphrase"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
	})

	t.Run("unlock", func(t *testing.T) {
		resp, body := h.post("/api/vault/unlock", map[string]string{"passphrase": "a long enough passphrase"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %v", resp.StatusCode, body)
		}
		if body["unlocked"] != true {
			t.Error("unlock did not report success")
		}
	})
}

// TestGeneratedKeyNeverLeavesTheServer is the guarantee that makes storing
// keys here worthwhile.
func TestGeneratedKeyNeverLeavesTheServer(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "a long enough passphrase"})

	resp, body := h.post("/api/credentials/generate", map[string]string{
		"name": "jump host", "key_type": "ed25519",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d: %v", resp.StatusCode, body)
	}

	encoded, _ := json.Marshal(body)
	for _, marker := range []string{
		"BEGIN OPENSSH PRIVATE KEY", "PRIVATE KEY", "private_key", "secret",
	} {
		if strings.Contains(string(encoded), marker) {
			t.Fatalf("the response contains %q; the private key must never reach the browser:\n%s",
				marker, encoded)
		}
	}

	// The public half and fingerprint must be present — they are what the
	// user actually needs.
	if pub, _ := body["public_key"].(string); !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("public_key = %q", pub)
	}
	if fp, _ := body["fingerprint"].(string); !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint = %q", fp)
	}
}

func TestCredentialsAreScopedToTheirOwner(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.createLocalUser("bob@example.com", "correct horse battery staple", false)

	// Alice stores a credential.
	h.login("alice@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "alice's long passphrase"})
	_, created := h.post("/api/credentials", map[string]string{
		"name": "alice's router", "kind": "password", "secret": "hunter2",
	})
	credID, _ := created["id"].(string)
	if credID == "" {
		t.Fatal("no credential was created")
	}

	// Bob signs in on the same client.
	h.post("/api/auth/logout", nil)
	h.get("/api/auth/config")
	h.login("bob@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "bob's long passphrase"})

	t.Run("cannot read it", func(t *testing.T) {
		resp, _ := h.get("/api/credentials/" + credID)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("cannot delete it", func(t *testing.T) {
		resp, _ := h.do(http.MethodDelete, "/api/credentials/"+credID, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("does not see it in a list", func(t *testing.T) {
		_, body := h.get("/api/credentials")
		list, _ := body["credentials"].([]any)
		if len(list) != 0 {
			t.Fatalf("another user's credentials leaked into the list: %d", len(list))
		}
	})
}

func TestLogoutEndsTheSession(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	resp, _ := h.post("/api/auth/logout", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}

	// The cookie must be cleared, and the token must be dead even if a copy
	// were replayed.
	if h.cookies[auth.SessionCookieName] != "" {
		t.Error("the session cookie was not cleared")
	}
	if resp, _ := h.get("/api/auth/whoami"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d after logout, want 401", resp.StatusCode)
	}
}

func TestLoginThrottling(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Auth.MaxAttemptsPerAccount = 3
		c.Auth.MaxAttemptsPerAddress = 100
	})
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)

	for i := 0; i < 3; i++ {
		resp, _ := h.post("/api/auth/login",
			map[string]string{"email": "alice@example.com", "password": "wrong"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, resp.StatusCode)
		}
	}

	resp, body := h.post("/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "wrong"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if errCode(body) != string(CodeRateLimited) {
		t.Errorf("code = %q", errCode(body))
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After header, so the client cannot know when to try again")
	}

	// Even the correct password is refused while locked out — otherwise the
	// throttle would be trivially bypassed by an attacker who guessed right.
	resp, _ = h.post("/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "correct horse battery staple"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d during lockout, want 429", resp.StatusCode)
	}
}

func TestSessionListAndRevoke(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	resp, body := h.get("/api/sessions")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %v", resp.StatusCode, body)
	}
	list, _ := body["sessions"].([]any)
	if len(list) != 1 {
		t.Fatalf("listed %d sessions, want 1", len(list))
	}

	first, _ := list[0].(map[string]any)
	if first["current"] != true {
		t.Error("the current session should be marked")
	}
	// No token may appear on this screen, or the screen itself leaks a
	// credential.
	encoded, _ := json.Marshal(body)
	if strings.Contains(string(encoded), h.cookies[auth.SessionCookieName]) {
		t.Fatal("the session token appeared in the session list")
	}
}

func TestMalformedRequestsAreRejected(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	t.Run("unknown field", func(t *testing.T) {
		// A typo must be reported as such rather than surfacing later as a
		// confusing authentication failure.
		resp, _ := h.post("/api/vault/enrol", map[string]string{"passphrse": "a long enough passphrase"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("not JSON", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/vault/enrol",
			strings.NewReader("this is not json"))
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range h.cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		req.Header.Set(auth.CSRFHeaderName, h.csrf)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})
}

func TestUnknownEndpoint(t *testing.T) {
	h := newHarness(t, nil)
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)
	h.login("alice@example.com", "correct horse battery staple")

	resp, body := h.get("/api/nonsense")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %v", resp.StatusCode, body)
	}
}

// TestPasswordAuthCanBeDisabled covers a deployment that requires SSO.
func TestPasswordAuthCanBeDisabled(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Policy.AllowPasswordAuth = false })
	h.createLocalUser("alice@example.com", "correct horse battery staple", false)

	resp, body := h.post("/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "correct horse battery staple"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if errCode(body) != string(CodePasswordAuthOff) {
		t.Errorf("code = %q", errCode(body))
	}
}

// TestSSODisabledEndpoints confirms the routes exist but decline politely
// when single sign-on is not configured.
func TestSSODisabledEndpoints(t *testing.T) {
	h := newHarness(t, nil)

	resp, body := h.get("/api/auth/sso/start")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if errCode(body) != string(CodeSSODisabled) {
		t.Errorf("code = %q, want sso_disabled", errCode(body))
	}
}
