// Package server wires configuration, storage, the vault and the HTTP
// listener into a runnable service, and owns startup and shutdown ordering.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/api"
	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/files"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"github.com/mrbuttshooter/securecrt/internal/web"
)

// Server holds the long-lived components of a running bkd process.
type Server struct {
	cfg   config.Config
	log   *slog.Logger
	db    *store.DB
	cache *vault.Cache

	// master is the server master key, held for the life of the process. It
	// opens only team keys and credentials explicitly marked for unattended
	// use — never an ordinary user's vault.
	master vault.Key

	api  *api.API
	http *http.Server

	// terminals holds every live SSH session. It outlives individual
	// WebSocket connections, which is what lets a browser reconnect to a
	// shell it left running.
	terminals *terminal.Manager

	// connections holds the shared SSH connections underneath the terminals
	// and the file browser.
	connections *remote.Pool

	// fileSessions holds open SFTP sessions; transfers runs the server-side
	// jobs — host-to-host copies and recursive deletes.
	fileSessions *files.Manager
	transfers    *files.Transfers
}

// New builds a Server: it opens the database, applies migrations if
// configured to, loads the master key and prepares the state directories.
//
// Everything that can fail does so here, before the listener opens, so a
// misconfigured deployment fails at startup rather than on a user's first
// connection.
func New(ctx context.Context, cfg config.Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}

	if err := ensureDirs(cfg); err != nil {
		return nil, err
	}

	db, err := openAndMigrate(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	master, err := vault.LoadMasterKey(cfg.Vault.MasterKeyPath)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("server: %w (run \"bkd gen-master-key\" first)", err)
	}

	s := &Server{
		cfg:    cfg,
		log:    log,
		db:     db,
		cache:  vault.NewCache(cfg.Vault.UnlockTTL),
		master: master,
	}

	if err := s.buildAPI(ctx); err != nil {
		s.closeResources()
		return nil, err
	}

	s.http = &http.Server{
		Addr:         cfg.Server.Bind,
		Handler:      s.routes(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	return s, nil
}

// buildAPI wires the service layer and mounts the HTTP API.
//
// Single sign-on discovery happens here, so a misconfigured issuer stops the
// server starting rather than failing on a user's first sign-in attempt.
func (s *Server) buildAPI(ctx context.Context) error {
	userStore := users.NewStore(s.db)

	vaultService, err := users.NewVaultService(userStore, s.cache, s.master, users.VaultServiceConfig{
		Argon2Time:     s.cfg.Vault.Argon2Time,
		Argon2MemoryKB: s.cfg.Vault.Argon2MemoryKB,
		Argon2Threads:  s.cfg.Vault.Argon2Threads,
		SSOUnlockMode:  users.SSOUnlockMode(s.cfg.Vault.SSOUnlockMode),
	})
	if err != nil {
		return err
	}

	authSessions, err := auth.NewSessionStore(s.db, auth.SessionConfig{
		IdleTTL:       s.cfg.Auth.SessionIdleTTL,
		AbsoluteTTL:   s.cfg.Auth.SessionAbsoluteTTL,
		SecureCookies: s.cfg.Auth.SecureCookies,
	})
	if err != nil {
		return err
	}

	throttle, err := auth.NewThrottle(s.db, auth.ThrottleConfig{
		MaxPerAccount:   s.cfg.Auth.MaxAttemptsPerAccount,
		MaxPerAddress:   s.cfg.Auth.MaxAttemptsPerAddress,
		Window:          s.cfg.Auth.LockoutWindow,
		LockoutDuration: s.cfg.Auth.LockoutDuration,
	})
	if err != nil {
		return err
	}

	var oidcProvider *auth.OIDCProvider
	if s.cfg.Auth.OIDC.Enabled {
		oidcProvider, err = auth.NewOIDCProvider(ctx, auth.OIDCConfig{
			Enabled:        true,
			Issuer:         s.cfg.Auth.OIDC.Issuer,
			ClientID:       s.cfg.Auth.OIDC.ClientID,
			ClientSecret:   s.cfg.Auth.OIDC.ClientSecret,
			RedirectURL:    strings.TrimRight(s.cfg.Server.ExternalURL, "/") + "/api/auth/sso/callback",
			AllowedTenants: s.cfg.Auth.OIDC.AllowedTenants,
			AutoProvision:  s.cfg.Auth.OIDC.AutoProvision,
		}, s.master)
		if err != nil {
			return fmt.Errorf("server: single sign-on: %w", err)
		}
		s.log.Info("single sign-on enabled", "issuer", s.cfg.Auth.OIDC.Issuer)
	}

	apiCfg, err := api.ConfigFrom(s.cfg)
	if err != nil {
		return err
	}

	sessionTree := sessions.NewStore(s.db)
	credentialStore := credentials.NewStore(s.db)
	hostKeyStore := hostkeys.NewStore(s.db)

	// One pool of SSH connections, shared by terminals and the file browser.
	// A user with a shell open on a host who then browses its filesystem gets
	// the connection they already have.
	s.connections = remote.NewPool(s.log)
	dialer := remote.NewDialer(s.connections, sessionTree, credentialStore, hostKeyStore, s.log)

	s.terminals = terminal.NewManager(s.log)
	connector := terminal.NewConnector(s.terminals, dialer, s.log)

	s.fileSessions = files.NewManager(dialer, s.log)
	s.transfers = files.NewTransfers(s.fileSessions, s.log)

	s.api, err = api.New(apiCfg, api.Deps{
		DB:           s.db,
		Users:        userStore,
		Vaults:       vaultService,
		Sessions:     authSessions,
		Throttle:     throttle,
		OIDC:         oidcProvider,
		Credentials:  credentialStore,
		Audit:        audit.NewRecorder(s.db, s.log),
		MasterKey:    s.master,
		SessionTree:  sessionTree,
		Terminals:    s.terminals,
		FileSessions: s.fileSessions,
		Transfers:    s.transfers,
		Connector:    connector,
		HostKeys:     hostKeyStore,
	}, s.log)
	return err
}

// ensureDirs creates the writable state directories with restrictive modes.
//
// 0700 rather than 0755: session transcripts and recordings contain whatever
// scrolled past on a production console, which is frequently as sensitive as
// the credentials themselves.
func ensureDirs(cfg config.Config) error {
	for _, dir := range []string{
		cfg.Paths.DataDir,
		cfg.Paths.SessionLogDir,
		cfg.Paths.RecordingDir,
		filepath.Dir(cfg.Vault.MasterKeyPath),
	} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("server: create %s: %w", dir, err)
		}
	}
	return nil
}

func openDB(ctx context.Context, cfg config.Config) (*store.DB, error) {
	return store.Open(ctx, store.Options{
		Driver:          cfg.Database.Driver,
		DSN:             cfg.Database.DSN,
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
	})
}

func openAndMigrate(ctx context.Context, cfg config.Config, log *slog.Logger) (*store.DB, error) {
	db, err := openDB(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Database.AutoMigrate {
		if err := store.Migrate(ctx, db, log); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	version, err := store.CurrentVersion(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	log.Info("database ready", "driver", cfg.Database.Driver, "schema_version", version)

	return db, nil
}

// Run starts the HTTP listener and blocks until ctx is cancelled, then shuts
// down gracefully.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Server.Bind)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", s.cfg.Server.Bind, err)
	}

	s.log.Info("bkd listening",
		"addr", ln.Addr().String(),
		"external_url", s.cfg.Server.ExternalURL,
		"version", config.Version,
	)
	s.warnOnRiskyPolicy()

	errCh := make(chan error, 1)
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		s.closeResources()
		return err
	case <-ctx.Done():
		s.log.Info("shutting down", "grace", s.cfg.Server.ShutdownGrace)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownGrace)
	defer cancel()

	shutdownErr := s.http.Shutdown(shutdownCtx)
	s.closeResources()

	if shutdownErr != nil {
		return fmt.Errorf("server: graceful shutdown: %w", shutdownErr)
	}
	s.log.Info("stopped cleanly")
	return nil
}

// warnOnRiskyPolicy surfaces settings that weaken the security model, so a
// deliberate relaxation is visible in the logs rather than forgotten.
func (s *Server) warnOnRiskyPolicy() {
	if s.cfg.Policy.AllowPlaintextExport {
		s.log.Warn("policy allows plaintext credential export; this is the most direct exfiltration path in a shared deployment")
	}
	if !s.cfg.Policy.RequireHostKeyVerify {
		s.log.Warn("policy does not require host key verification; connections are exposed to man-in-the-middle")
	}
	if s.cfg.Vault.SSOUnlockMode == config.SSOUnlockServerManaged {
		s.log.Warn("vault.sso_unlock_mode is server_managed: single-sign-on users' credentials are " +
			"wrapped under the server master key, so a stolen database together with that key would " +
			"expose them. Set it to passphrase to restore that protection.")
	}
	if !s.cfg.Auth.SecureCookies {
		s.log.Warn("auth.secure_cookies is disabled; session cookies will be sent over plain HTTP")
	}
	if !s.cfg.Auth.OIDC.Enabled {
		s.log.Warn("single sign-on is not configured; only local password accounts can sign in")
	}
}

// closeResources ends live sessions, zeroes key material and closes the
// database.
//
// The order is deliberate:
//
//  1. Transfers and file sessions, so a copy in flight is cancelled rather
//     than left writing into a connection about to disappear.
//  2. Terminals, so every remote shell gets an orderly exit rather than a
//     dropped TCP connection some host has to time out.
//  3. The connection pool, which sends each host a clean SSH disconnect and
//     catches anything no terminal owned.
//  4. Key material, before the database, so a crash while closing the
//     database still leaves no key in a core dump.
func (s *Server) closeResources() {
	if s.transfers != nil {
		s.transfers.Shutdown()
	}
	if s.fileSessions != nil {
		s.fileSessions.Shutdown()
	}
	if s.terminals != nil {
		s.terminals.Close()
	}
	if s.connections != nil {
		s.connections.Close()
	}

	s.cache.Close()
	s.master.Zero()

	if err := s.db.Close(); err != nil {
		s.log.Error("closing database", "error", err)
	}
}

// routes builds the HTTP handler.
//
// Phase 0 exposes only liveness and readiness. The REST API and the WebSocket
// terminal multiplexer land in later phases.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Liveness: the process is up. Never touches the database, so a database
	// outage does not cause an orchestrator to kill an otherwise healthy
	// process that would recover on its own.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`+"\n", config.Version)
	})

	// The API mounts itself under /api and brings its own middleware chain.
	if s.api != nil {
		mux.Handle("/api/", s.api.Routes())
	}

	// Readiness: the process can serve traffic, which requires the database.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		w.Header().Set("Content-Type", "application/json")
		if err := s.db.PingContext(ctx); err != nil {
			s.log.Warn("readiness check failed", "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"status":"unavailable","reason":"database"}`+"\n")
			return
		}
		fmt.Fprint(w, `{"status":"ready"}`+"\n")
	})

	// The frontend is the fallback for everything not claimed above, so a
	// browser reload on a client-side route serves the app rather than 404ing.
	if handler, err := web.Handler(); err == nil {
		mux.Handle("/", handler)
	} else {
		s.log.Warn("no frontend embedded in this binary; only the API is served",
			"reason", err)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "bkd is running, but no frontend was built into this binary.")
			fmt.Fprintln(w, "Run 'make web' before 'make build', or use the API directly.")
		})
	}

	return securityHeaders(mux)
}

// securityHeaders applies the baseline response headers.
//
// The CSP is deliberately strict now, while the app is small, rather than
// retrofitted later once inline scripts have crept in. HSTS is omitted here
// because TLS terminates upstream in nginx or Caddy, which owns that header.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// img-src includes data: because the authenticator QR code is rendered
		// in the browser to a data URI rather than fetched from the server —
		// the TOTP secret should not need a second round trip just to become
		// an image.
		//
		// style-src allows 'unsafe-inline' because the terminal needs it.
		// xterm.js builds its colour scheme and cell metrics into <style>
		// elements it writes at runtime, and its DOM renderer — the fallback
		// on machines without a usable GPU, which is exactly where it must
		// keep working — sets style attributes per cell. It offers no nonce
		// hook, and the content is generated, so hashes cannot be enumerated.
		//
		// What that costs is bounded, and worth stating rather than waving
		// past. A CSS injection needs somewhere to inject: this app renders
		// no user-supplied markup, and holds no dangerouslySetInnerHTML. If
		// one were found, the classic CSS exfiltration trick — a selector
		// matching a secret paired with an external url() — still cannot
		// reach anywhere, because default-src, img-src and font-src permit
		// this origin only. And script-src stays strict, which is the
		// directive that actually stops an attacker executing code.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// MigrateOnly applies pending migrations and exits. Used by the installer and
// by deployments that prefer migrations as an explicit step.
func MigrateOnly(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck

	// On a fresh database the bookkeeping table does not exist yet, so it has
	// to be created before the "before" version can be read.
	if err := store.EnsureMigrationsTable(ctx, db); err != nil {
		return err
	}

	before, err := store.CurrentVersion(ctx, db)
	if err != nil {
		return err
	}
	if err := store.Migrate(ctx, db, log); err != nil {
		return err
	}
	after, err := store.CurrentVersion(ctx, db)
	if err != nil {
		return err
	}

	if before == after {
		log.Info("database already up to date", "schema_version", after)
	} else {
		log.Info("migration complete", "from", before, "to", after)
	}
	return nil
}

// RollbackOnly reverts the most recent migration and exits.
func RollbackOnly(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck

	return store.Rollback(ctx, db, log)
}

// GenerateMasterKey creates the server master key file.
//
// Run once at install time. It refuses to overwrite an existing key, because
// doing so would permanently orphan every shared team credential.
func GenerateMasterKey(path string) error {
	if err := vault.GenerateMasterKeyFile(path); err != nil {
		return err
	}
	fmt.Printf("Master key written to %s (mode 0400).\n", path)
	fmt.Println("Back this file up separately from the database.")
	fmt.Println("Losing it means losing every shared team credential.")
	return nil
}
