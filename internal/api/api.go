package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/files"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/portability"
	"github.com/mrbuttshooter/securecrt/internal/proto/tunnel"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/snippets"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Config holds the settings the API needs, resolved from config.Config.
type Config struct {
	Session auth.SessionConfig

	MFAPolicy           string
	RequireMFAForAdmins bool

	AllowPasswordAuth bool
	SecureCookies     bool

	OIDCEnabled       bool
	OIDCProviderName  string
	OIDCAutoProvision bool

	SSOUnlockMode users.SSOUnlockMode

	TrustedProxies []*net.IPNet

	ExternalURL string

	// AllowPlaintextExport gates every export format except the encrypted
	// bundle. Off by default: an export in the clear takes everything out of
	// the vault and writes it somewhere nothing is protecting.
	AllowPlaintextExport bool

	// MaxUploadBytes and MaxImportBytes cap the two endpoints that accept a
	// large body. Zero means the built-in default, so a caller that has not
	// heard of these fields still gets a bounded server.
	MaxUploadBytes int64
	MaxImportBytes int64
}

// uploadLimit and importLimit resolve the configured caps, falling back to the
// defaults when a caller left them unset.
func (c Config) uploadLimit() int64 {
	if c.MaxUploadBytes > 0 {
		return c.MaxUploadBytes
	}
	return defaultMaxUploadBytes
}

func (c Config) importLimit() int64 {
	if c.MaxImportBytes > 0 {
		return c.MaxImportBytes
	}
	return defaultMaxImportBytes
}

// API wires the HTTP handlers to the services behind them.
type API struct {
	cfg Config
	log *slog.Logger

	// db is used only for the few tables that have no repository of their
	// own — TOTP enrolment and recovery codes. Everything else goes through
	// the package that owns its invariants.
	db *store.DB

	users       *users.Store
	vaults      *users.VaultService
	sessions    *auth.SessionStore
	throttle    *auth.Throttle
	oidc        *auth.OIDCProvider
	credentials *credentials.Store
	audit       *audit.Recorder

	// The terminal side: the saved-connection tree, the live terminals, and
	// the connector that joins them to SSH.
	sessionTree *sessions.Store
	terminals   *terminal.Manager
	connector   *terminal.Connector
	hostKeys    *hostkeys.Store

	// The file side: open SFTP sessions and the server-side transfer queue.
	fileSessions *files.Manager
	transfers    *files.Transfers

	// Tunnels: port forwarding and the device web proxy.
	tunnels  *tunnel.Manager
	snippets *snippets.Store

	// Import and export, plus the previews waiting to be committed.
	portability *portability.Service
	staging     *staging

	// csrfKey signs CSRF tokens. An HKDF subkey of the master key, so the
	// service needs no additional secret on disk.
	csrfKey vault.Key
}

// Deps are the collaborators the API needs.
type Deps struct {
	DB          *store.DB
	Users       *users.Store
	Vaults      *users.VaultService
	Sessions    *auth.SessionStore
	Throttle    *auth.Throttle
	OIDC        *auth.OIDCProvider // nil when single sign-on is disabled
	Credentials *credentials.Store
	Audit       *audit.Recorder
	MasterKey   vault.Key

	SessionTree *sessions.Store
	Terminals   *terminal.Manager
	Connector   *terminal.Connector
	HostKeys    *hostkeys.Store

	FileSessions *files.Manager
	Transfers    *files.Transfers
	Portability  *portability.Service
	Tunnels      *tunnel.Manager
	Snippets     *snippets.Store
}

// New builds an API.
func New(cfg Config, deps Deps, log *slog.Logger) (*API, error) {
	if log == nil {
		log = slog.Default()
	}

	csrfKey, err := vault.DeriveSubkey(deps.MasterKey, vault.SubkeyCSRF)
	if err != nil {
		return nil, err
	}

	return &API{
		cfg:         cfg,
		log:         log,
		db:          deps.DB,
		users:       deps.Users,
		vaults:      deps.Vaults,
		sessions:    deps.Sessions,
		throttle:    deps.Throttle,
		oidc:        deps.OIDC,
		credentials: deps.Credentials,
		audit:       deps.Audit,
		sessionTree: deps.SessionTree,
		terminals:   deps.Terminals,
		connector:   deps.Connector,
		hostKeys:    deps.HostKeys,

		fileSessions: deps.FileSessions,
		transfers:    deps.Transfers,

		tunnels:  deps.Tunnels,
		snippets: deps.Snippets,

		portability: deps.Portability,
		staging:     newStaging(),

		csrfKey: csrfKey,
	}, nil
}

// ConfigFrom translates the file configuration into the API's own.
func ConfigFrom(c config.Config) (Config, error) {
	var proxies []*net.IPNet
	for _, cidr := range c.Server.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return Config{}, err
		}
		proxies = append(proxies, network)
	}

	providerName := c.Auth.OIDC.ProviderName
	if providerName == "" {
		providerName = "single sign-on"
	}

	return Config{
		Session: auth.SessionConfig{
			IdleTTL:       c.Auth.SessionIdleTTL,
			AbsoluteTTL:   c.Auth.SessionAbsoluteTTL,
			SecureCookies: c.Auth.SecureCookies,
		},
		MFAPolicy:           c.Auth.MFAPolicy,
		RequireMFAForAdmins: c.Auth.RequireMFAForAdmins,
		AllowPasswordAuth:   c.Policy.AllowPasswordAuth,
		SecureCookies:       c.Auth.SecureCookies,
		OIDCEnabled:         c.Auth.OIDC.Enabled,
		OIDCProviderName:    providerName,
		OIDCAutoProvision:   c.Auth.OIDC.AutoProvision,
		SSOUnlockMode:       users.SSOUnlockMode(c.Vault.SSOUnlockMode),
		TrustedProxies:      proxies,
		ExternalURL:         c.Server.ExternalURL,

		AllowPlaintextExport: c.Policy.AllowPlaintextExport,
		MaxUploadBytes:       c.Policy.MaxUploadBytes,
		MaxImportBytes:       c.Policy.MaxImportBytes,
	}, nil
}

// TunnelProxy returns the handler for a device's own web interface, and
// whether this server serves them at all.
//
// Mounted by the server rather than under /api, because it answers every path
// on a hostname of its own — a device's pages are served at the root or their
// absolute links break. It carries the same authentication and MFA as
// everything else, and deliberately not the CSRF middleware: a device has
// never heard of this application's token, and it is on a separate origin,
// which is where the protection comes from. See handleTunnelProxy.
func (a *API) TunnelProxy() (http.Handler, bool) {
	if a.tunnels == nil || !a.tunnels.WebTunnelsEnabled() {
		return nil, false
	}
	return chain(http.HandlerFunc(a.handleTunnelProxy), a.withAuth, a.withMFA), true
}

// IsTunnelHost reports whether a request addresses a tunnel's hostname rather
// than the application.
func (a *API) IsTunnelHost(r *http.Request) bool { return a.tunnelHostRequest(r) }

// mfaRequiredFor reports whether this user must complete a second factor.
func (a *API) mfaRequiredFor(u users.User) bool {
	switch a.cfg.MFAPolicy {
	case config.MFARequired:
		return true
	case config.MFAOff:
		return false
	}
	// Optional for most people, but an administrator can lock out everyone
	// else, so the policy can be tightened for them alone.
	return a.cfg.RequireMFAForAdmins && u.IsAdmin
}

// clientIP returns the caller's address, honouring X-Forwarded-For only from
// a configured trusted proxy.
func (a *API) clientIP(r *http.Request) string {
	return clientIP(r, a.cfg.TrustedProxies)
}

// Routes returns the API handler, mounted under /api.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()

	// --- Unauthenticated ---------------------------------------------------
	// These describe how to sign in and start a sign-in. Everything else
	// requires a session.
	mux.HandleFunc("GET /api/auth/config", a.handleAuthConfig)
	mux.HandleFunc("POST /api/auth/login", a.handleLocalLogin)
	mux.HandleFunc("GET /api/auth/sso/start", a.handleSSOStart)
	mux.HandleFunc("GET /api/auth/sso/callback", a.handleSSOCallback)

	// --- Authenticated, before MFA -----------------------------------------
	// Reachable with a session that has not yet completed a second factor,
	// because these are how it gets completed.
	preMFA := chain(http.HandlerFunc(a.routePreMFA), a.withAuth)
	mux.Handle("POST /api/auth/logout", preMFA)
	mux.Handle("GET /api/auth/whoami", preMFA)
	mux.Handle("POST /api/mfa/verify", preMFA)
	mux.Handle("POST /api/mfa/recovery", preMFA)

	// --- Authenticated, after MFA ------------------------------------------
	full := chain(http.HandlerFunc(a.routeAuthenticated), a.withAuth, a.withMFA)
	for _, route := range []string{
		"GET /api/sessions", "DELETE /api/sessions/{id}", "POST /api/sessions/revoke-others",
		"POST /api/vault/enrol", "POST /api/vault/unlock", "POST /api/vault/lock",
		"POST /api/vault/passphrase", "GET /api/vault/status",
		"POST /api/mfa/enrol", "POST /api/mfa/confirm", "DELETE /api/mfa",
		"GET /api/credentials", "POST /api/credentials", "GET /api/credentials/{id}",
		"PATCH /api/credentials/{id}", "DELETE /api/credentials/{id}",
		"POST /api/credentials/generate", "POST /api/credentials/import",
		"GET /api/tree", "POST /api/tree/folders", "PATCH /api/tree/folders/{id}",
		"DELETE /api/tree/folders/{id}", "POST /api/tree/sessions",
		"PATCH /api/tree/sessions/{id}", "DELETE /api/tree/sessions/{id}",
		"GET /api/tree/sessions/{id}/resolved",
		"GET /api/terminals", "DELETE /api/terminals/{id}",
		"POST /api/terminals/{id}/recording",
		"GET /api/transcripts", "GET /api/transcripts/{name}",
		"GET /api/known-hosts", "DELETE /api/known-hosts/{id}",

		"GET /api/files/sessions", "POST /api/files/sessions",
		"DELETE /api/files/sessions/{id}",
		"GET /api/files/list", "GET /api/files/stat",
		"POST /api/files/mkdir", "POST /api/files/rename",
		"POST /api/files/chmod", "POST /api/files/chown",
		"DELETE /api/files/entry",
		"POST /api/files/copy",
		"GET /api/files/transfers", "DELETE /api/files/transfers/{id}",

		"GET /api/tunnels", "POST /api/tunnels", "DELETE /api/tunnels/{id}",
		"GET /api/tunnels/config",
		"GET /api/consoles/profiles", "POST /api/consoles/plan",
		"POST /api/consoles/apply",
		"GET /api/snippets", "POST /api/snippets",
		"PATCH /api/snippets/{id}", "DELETE /api/snippets/{id}",
		"POST /api/snippets/send",

		"GET /api/portability/config", "POST /api/portability/import",
		"DELETE /api/portability/staged/{id}", "POST /api/portability/export",
	} {
		mux.Handle(route, full)
	}

	// The terminal socket carries its own protocol and cannot go through the
	// JSON error paths, so it is mounted separately — but behind the same
	// authentication, MFA and vault requirements.
	mux.Handle("GET /api/terminals/socket", chain(
		http.HandlerFunc(a.handleTerminalSocket), a.withAuth, a.withMFA))

	// Downloads and uploads stream raw bytes with their own headers — Range,
	// Content-Disposition, Content-Length — so they are mounted directly
	// rather than through the JSON dispatcher, behind the same chain.
	mux.Handle("GET /api/files/content", chain(
		http.HandlerFunc(a.handleDownload), a.withAuth, a.withMFA))
	mux.Handle("PUT /api/files/content", chain(
		http.HandlerFunc(a.handleUpload), a.withAuth, a.withMFA))

	// The import preview is a multipart upload rather than JSON, so it is
	// mounted directly rather than through the JSON dispatcher — behind the
	// same chain.
	mux.Handle("POST /api/portability/preview", chain(
		http.HandlerFunc(a.handlePreviewImport), a.withAuth, a.withMFA))

	// CSRF wraps everything: a state-changing request must carry a valid
	// token whether or not it is authenticated, so an unauthenticated login
	// attempt cannot be forged either.
	return chain(mux,
		withRequestID,
		withRecovery(a.log),
		withLogging(a.log),
		withCSRF(a.csrfKey, a.log),
	)
}

// routePreMFA dispatches the routes reachable before a second factor.
//
// Go's ServeMux matches patterns but cannot express "these paths share this
// middleware chain", so the chain is built once and dispatch happens here.
func (a *API) routePreMFA(w http.ResponseWriter, r *http.Request) {
	switch r.Method + " " + r.URL.Path {
	case "POST /api/auth/logout":
		a.handleLogout(w, r)
	case "GET /api/auth/whoami":
		a.handleWhoami(w, r)
	case "POST /api/mfa/verify":
		a.handleMFAVerify(w, r)
	case "POST /api/mfa/recovery":
		a.handleMFARecovery(w, r)
	default:
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such endpoint.")
	}
}

// routeAuthenticated dispatches the fully authenticated routes.
func (a *API) routeAuthenticated(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case r.Method == http.MethodGet && path == "/api/sessions":
		a.handleListSessions(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/sessions/"):
		a.handleRevokeSession(w, r)
	case r.Method == http.MethodPost && path == "/api/sessions/revoke-others":
		a.handleRevokeOtherSessions(w, r)

	case r.Method == http.MethodGet && path == "/api/vault/status":
		a.handleVaultStatus(w, r)
	case r.Method == http.MethodPost && path == "/api/vault/enrol":
		a.handleVaultEnrol(w, r)
	case r.Method == http.MethodPost && path == "/api/vault/unlock":
		a.handleVaultUnlock(w, r)
	case r.Method == http.MethodPost && path == "/api/vault/lock":
		a.handleVaultLock(w, r)
	case r.Method == http.MethodPost && path == "/api/vault/passphrase":
		a.handleVaultChangePassphrase(w, r)

	case r.Method == http.MethodPost && path == "/api/mfa/enrol":
		a.handleMFAEnrol(w, r)
	case r.Method == http.MethodPost && path == "/api/mfa/confirm":
		a.handleMFAConfirm(w, r)
	case r.Method == http.MethodDelete && path == "/api/mfa":
		a.handleMFADisable(w, r)

	case r.Method == http.MethodGet && path == "/api/tree":
		a.handleGetTree(w, r)
	case r.Method == http.MethodPost && path == "/api/tree/folders":
		a.handleCreateFolder(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/tree/folders/"):
		a.handleUpdateFolder(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/tree/folders/"):
		a.handleDeleteFolder(w, r)
	case r.Method == http.MethodPost && path == "/api/tree/sessions":
		a.handleCreateSavedSession(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/resolved"):
		a.handleResolveSession(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/tree/sessions/"):
		a.handleUpdateSavedSession(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/tree/sessions/"):
		a.handleDeleteSavedSession(w, r)

	case r.Method == http.MethodGet && path == "/api/terminals":
		a.handleListTerminals(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/terminals/") &&
		strings.HasSuffix(path, "/recording"):
		a.handleToggleRecording(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/terminals/"):
		a.handleCloseTerminal(w, r)

	case r.Method == http.MethodGet && path == "/api/transcripts":
		a.handleListTranscripts(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/transcripts/"):
		a.handleDownloadTranscript(w, r)

	case r.Method == http.MethodGet && path == "/api/known-hosts":
		a.handleListKnownHosts(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/known-hosts/"):
		a.handleForgetKnownHost(w, r)

	case r.Method == http.MethodGet && path == "/api/portability/config":
		a.handlePortabilityConfig(w, r)
	case r.Method == http.MethodPost && path == "/api/portability/import":
		a.handleCommitImport(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/portability/staged/"):
		a.handleDiscardImport(w, r)
	case r.Method == http.MethodPost && path == "/api/portability/export":
		a.handleExport(w, r)

	case r.Method == http.MethodGet && path == "/api/files/sessions":
		a.handleListFileSessions(w, r)
	case r.Method == http.MethodPost && path == "/api/files/sessions":
		a.handleOpenFileSession(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/files/sessions/"):
		a.handleCloseFileSession(w, r)
	case r.Method == http.MethodGet && path == "/api/files/list":
		a.handleListDirectory(w, r)
	case r.Method == http.MethodGet && path == "/api/files/stat":
		a.handleStatPath(w, r)
	case r.Method == http.MethodPost && path == "/api/files/mkdir":
		a.handleMkdir(w, r)
	case r.Method == http.MethodPost && path == "/api/files/rename":
		a.handleRename(w, r)
	case r.Method == http.MethodPost && path == "/api/files/chmod":
		a.handleChmod(w, r)
	case r.Method == http.MethodPost && path == "/api/files/chown":
		a.handleChown(w, r)
	case r.Method == http.MethodDelete && path == "/api/files/entry":
		a.handleDeletePath(w, r)
	case r.Method == http.MethodPost && path == "/api/files/copy":
		a.handleStartCopy(w, r)
	case r.Method == http.MethodGet && path == "/api/files/transfers":
		a.handleListTransfers(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/files/transfers/"):
		a.handleCancelTransfer(w, r)

	case r.Method == http.MethodGet && path == "/api/snippets":
		a.handleListSnippets(w, r)
	case r.Method == http.MethodPost && path == "/api/snippets":
		a.handleCreateSnippet(w, r)
	case r.Method == http.MethodPost && path == "/api/snippets/send":
		a.handleSendSnippet(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/snippets/"):
		a.handleUpdateSnippet(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/snippets/"):
		a.handleDeleteSnippet(w, r)

	case r.Method == http.MethodGet && path == "/api/consoles/profiles":
		a.handleConsoleProfiles(w, r)
	case r.Method == http.MethodPost && path == "/api/consoles/plan":
		a.handleConsolePlan(w, r)
	case r.Method == http.MethodPost && path == "/api/consoles/apply":
		a.handleConsoleApply(w, r)

	case r.Method == http.MethodGet && path == "/api/tunnels/config":
		a.handleTunnelConfig(w, r)
	case r.Method == http.MethodGet && path == "/api/tunnels":
		a.handleListTunnels(w, r)
	case r.Method == http.MethodPost && path == "/api/tunnels":
		a.handleOpenTunnel(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/tunnels/"):
		a.handleCloseTunnel(w, r)

	case r.Method == http.MethodGet && path == "/api/credentials":
		a.handleListCredentials(w, r)
	case r.Method == http.MethodPost && path == "/api/credentials":
		a.handleCreateCredential(w, r)
	case r.Method == http.MethodPost && path == "/api/credentials/generate":
		a.handleGenerateKey(w, r)
	case r.Method == http.MethodPost && path == "/api/credentials/import":
		a.handleImportKey(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/credentials/"):
		a.handleGetCredential(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/credentials/"):
		a.handleUpdateCredential(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/credentials/"):
		a.handleDeleteCredential(w, r)

	default:
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such endpoint.")
	}
}

// issueSession creates a session, sets both cookies, and returns the session.
//
// The CSRF cookie is reissued alongside the session cookie so the two always
// belong to the same login: a stale CSRF token from a previous session would
// otherwise cause a confusing rejection on the first state-changing request.
func (a *API) issueSession(ctx context.Context, w http.ResponseWriter, p auth.CreateSessionParams) (auth.Session, error) {
	sess, token, err := a.sessions.Create(ctx, p)
	if err != nil {
		return auth.Session{}, err
	}

	csrf, err := newCSRFToken(a.csrfKey)
	if err != nil {
		return auth.Session{}, err
	}

	http.SetCookie(w, a.cfg.Session.SessionCookie(token))
	http.SetCookie(w, csrfCookie(csrf, a.cfg.SecureCookies))
	return sess, nil
}
