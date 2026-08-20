package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Admin performs account administration from the command line.
//
// It deliberately opens the database without the HTTP listener or a master
// key: the operations below manage accounts, not secrets, and requiring the
// master key would mean an operator could not create the first account until
// the vault was already set up.
type Admin struct {
	db       *store.DB
	users    *users.Store
	sessions *auth.SessionStore
	log      *slog.Logger
}

// NewAdmin opens the database and applies migrations if configured to.
func NewAdmin(ctx context.Context, cfg config.Config, log *slog.Logger) (*Admin, error) {
	if log == nil {
		log = slog.Default()
	}

	db, err := openAndMigrate(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	sessions, err := auth.NewSessionStore(db, auth.SessionConfig{
		IdleTTL:     cfg.Auth.SessionIdleTTL,
		AbsoluteTTL: cfg.Auth.SessionAbsoluteTTL,
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Admin{db: db, users: users.NewStore(db), sessions: sessions, log: log}, nil
}

// Close releases the database.
func (a *Admin) Close() {
	if err := a.db.Close(); err != nil {
		a.log.Error("closing database", "error", err)
	}
}

// CreateUser adds a local account.
func (a *Admin) CreateUser(ctx context.Context, email, name, password string, admin bool) (users.User, error) {
	if password == "" {
		return users.User{}, errors.New("a password is required for a local account")
	}

	u, err := a.users.Create(ctx, users.CreateParams{
		Email: email, DisplayName: name, Password: password, IsAdmin: admin,
	})
	if err != nil {
		if errors.Is(err, users.ErrEmailInUse) {
			return users.User{}, fmt.Errorf("an account already exists for %s", email)
		}
		return users.User{}, err
	}
	return u, nil
}

// ListUsers returns all accounts.
func (a *Admin) ListUsers(ctx context.Context) ([]users.User, error) {
	return a.users.List(ctx, 0)
}

// FindUser resolves an account by email.
func (a *Admin) FindUser(ctx context.Context, email string) (users.User, error) {
	u, err := a.users.ByEmail(ctx, email)
	if errors.Is(err, users.ErrNotFound) {
		return users.User{}, fmt.Errorf("no account found for %s", email)
	}
	return u, err
}

// SetAdmin grants or revokes administrator rights.
//
// Refuses to remove the last administrator: an installation with none cannot
// be administered through the interface at all, and recovering from that
// needs database surgery.
func (a *Admin) SetAdmin(ctx context.Context, email string, admin bool) error {
	u, err := a.FindUser(ctx, email)
	if err != nil {
		return err
	}

	if !admin && u.IsAdmin {
		count, err := a.users.CountAdmins(ctx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return errors.New(
				"this is the only administrator; grant the role to someone else first, " +
					"or the system would be left with nobody able to administer it")
		}
	}

	return a.users.SetAdmin(ctx, u.ID, admin)
}

// SetDisabled disables or re-enables an account, returning how many sessions
// were ended.
func (a *Admin) SetDisabled(ctx context.Context, email string, disabled bool) (int, error) {
	u, err := a.FindUser(ctx, email)
	if err != nil {
		return 0, err
	}

	if disabled && u.IsAdmin {
		count, err := a.users.CountAdmins(ctx)
		if err != nil {
			return 0, err
		}
		if count <= 1 {
			return 0, errors.New(
				"this is the only enabled administrator; grant the role to someone else first")
		}
	}

	if err := a.users.SetDisabled(ctx, u.ID, disabled); err != nil {
		return 0, err
	}

	if !disabled {
		return 0, nil
	}

	// Sessions are revoked here rather than left to expire, so a suspension
	// takes effect immediately even for someone already signed in.
	revoked, err := a.sessions.RevokeAllForUser(ctx, u.ID)
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

// CountCredentials reports how many credentials a user owns, so the operator
// can see what a vault reset would destroy before confirming it.
func (a *Admin) CountCredentials(ctx context.Context, userID string) (int, error) {
	var n int
	err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM credentials WHERE user_id = ?`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting credentials: %w", err)
	}
	return n, nil
}

// ResetVault destroys a user's vault and everything it protected.
//
// Irreversible. There is no key escrow — the server genuinely cannot decrypt
// these credentials, which is the property that makes a stolen database
// useless, and the same property that makes a forgotten passphrase final.
func (a *Admin) ResetVault(ctx context.Context, u users.User) error {
	if err := a.users.ResetVault(ctx, u.ID); err != nil {
		return err
	}
	// Any live session still holds the old key in the running server's
	// memory; ending them forces a clean re-enrolment.
	if _, err := a.sessions.RevokeAllForUser(ctx, u.ID); err != nil {
		return err
	}
	return nil
}

// TestOIDC validates the single-sign-on configuration against the live
// identity provider.
//
// This exists because everything else about SSO can be verified locally
// except the part that actually matters: whether the app registration,
// redirect URI and tenant line up. Running it turns a blank sign-in page into
// a specific error before anyone tries to use the system.
func TestOIDC(ctx context.Context, cfg config.Config) error {
	if !cfg.Auth.OIDC.Enabled {
		return errors.New("single sign-on is not enabled in this configuration (auth.oidc.enabled)")
	}

	redirect := oidcRedirectURL(cfg)

	fmt.Println("Checking single sign-on configuration")
	fmt.Println()
	fmt.Printf("  issuer:        %s\n", cfg.Auth.OIDC.Issuer)
	fmt.Printf("  client id:     %s\n", cfg.Auth.OIDC.ClientID)
	fmt.Printf("  client secret: %s\n", maskSecret(cfg.Auth.OIDC.ClientSecret))
	fmt.Printf("  redirect URI:  %s\n", redirect)
	if len(cfg.Auth.OIDC.AllowedTenants) > 0 {
		fmt.Printf("  tenants:       %v\n", cfg.Auth.OIDC.AllowedTenants)
	} else {
		fmt.Printf("  tenants:       (any accepted by the issuer)\n")
	}
	fmt.Println()

	// A throwaway master key: discovery does not need the real one, and this
	// command must work before the vault exists.
	scratch, err := vault.NewKey()
	if err != nil {
		return err
	}
	defer scratch.Zero()

	provider, err := auth.NewOIDCProvider(ctx, auth.OIDCConfig{
		Enabled:        true,
		Issuer:         cfg.Auth.OIDC.Issuer,
		ClientID:       cfg.Auth.OIDC.ClientID,
		ClientSecret:   cfg.Auth.OIDC.ClientSecret,
		RedirectURL:    redirect,
		AllowedTenants: cfg.Auth.OIDC.AllowedTenants,
	}, scratch)
	if err != nil {
		fmt.Println("FAILED")
		fmt.Println()
		fmt.Printf("  %v\n\n", err)
		printOIDCHints(cfg)
		return errors.New("single sign-on configuration is not usable")
	}

	authURL, _, err := provider.AuthURL("/")
	if err != nil {
		return err
	}

	fmt.Println("Discovery succeeded. The provider's metadata and signing keys were fetched")
	fmt.Println("and the configuration is well formed.")
	fmt.Println()
	fmt.Println("Open this URL in a browser to test an actual sign-in:")
	fmt.Println()
	fmt.Printf("  %s\n", authURL)
	fmt.Println()
	fmt.Println("Note that this only proves the issuer is reachable and the settings parse.")
	fmt.Println("It cannot verify the client secret, the redirect URI registration, or any")
	fmt.Println("conditional access policy — those are only exercised by a real sign-in.")
	return nil
}

func oidcRedirectURL(cfg config.Config) string {
	base := cfg.Server.ExternalURL
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base + "/api/auth/sso/callback"
}

func maskSecret(s string) string {
	switch {
	case s == "":
		return "(not set)"
	case len(s) < 8:
		return "(set, suspiciously short)"
	default:
		return fmt.Sprintf("(set, %d characters)", len(s))
	}
}

// printOIDCHints lists the causes that actually occur, in the order they
// occur, so an operator has somewhere to start.
func printOIDCHints(cfg config.Config) {
	fmt.Println("Things to check, roughly in order of likelihood:")
	fmt.Println()
	fmt.Println("  1. The client secret has expired. This is the most common cause of")
	fmt.Println("     single sign-on breaking overnight — Entra secrets have a fixed")
	fmt.Println("     lifetime. Check Certificates & secrets in the app registration.")
	fmt.Println()
	fmt.Println("  2. The issuer URL is wrong. For Entra it should look like")
	fmt.Println("     https://login.microsoftonline.com/<tenant-id>/v2.0")
	fmt.Println("     including the /v2.0 suffix.")
	fmt.Println()
	fmt.Printf("  3. The redirect URI in the app registration must match exactly:\n")
	fmt.Printf("     %s\n", oidcRedirectURL(cfg))
	fmt.Println("     Entra compares it as an opaque string — scheme, host, path and any")
	fmt.Println("     trailing slash all matter.")
	fmt.Println()
	fmt.Println("  4. Outbound HTTPS to login.microsoftonline.com is blocked, or a proxy")
	fmt.Println("     is intercepting TLS without its certificate being trusted here.")
	fmt.Println()
	fmt.Println("  See docs/SSO-SETUP.md for the full app registration checklist.")
}
