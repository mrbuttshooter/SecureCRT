package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/portability"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Migrator runs imports and exports from the command line.
//
// The browser can only move one person's connections at a time, and only that
// person can drive it. Moving a team of eighty off SecureCRT that way means
// eighty people each remembering to do it. This runs the same code against
// the database directly, so it can be scripted.
//
// Unlike Admin it needs the master key: everything here touches the vault.
type Migrator struct {
	db     *store.DB
	cfg    config.Config
	cache  *vault.Cache
	users  *users.Store
	vaults *users.VaultService
	audit  *audit.Recorder
	svc    *portability.Service
	log    *slog.Logger
}

// cliSessionID names the vault-cache slot a command-line unlock occupies.
//
// The cache is keyed by (user, session), and a command-line run has no browser
// session. A fixed name keeps it out of the way of the real ones, and Close
// clears it, so the key does not outlive the command that needed it.
const cliSessionID = "cli"

// NewMigrator opens the database and the vault.
func NewMigrator(ctx context.Context, cfg config.Config, log *slog.Logger) (*Migrator, error) {
	if log == nil {
		log = slog.Default()
	}

	master, err := vault.LoadMasterKey(cfg.Vault.MasterKeyPath)
	if err != nil {
		return nil, err
	}

	db, err := openAndMigrate(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	userStore := users.NewStore(db)
	cache := vault.NewCache(cfg.Vault.UnlockTTL)

	vaultService, err := users.NewVaultService(userStore, cache, master, users.VaultServiceConfig{
		Argon2Time:     cfg.Vault.Argon2Time,
		Argon2MemoryKB: cfg.Vault.Argon2MemoryKB,
		Argon2Threads:  cfg.Vault.Argon2Threads,
		SSOUnlockMode:  users.SSOUnlockMode(cfg.Vault.SSOUnlockMode),
	})
	if err != nil {
		cache.Close()
		_ = db.Close()
		return nil, err
	}

	return &Migrator{
		db: db, cfg: cfg, cache: cache,
		users:  userStore,
		vaults: vaultService,
		audit:  audit.NewRecorder(db, log),
		svc: portability.NewService(
			sessions.NewStore(db), credentials.NewStore(db), hostkeys.NewStore(db), log),
		log: log,
	}, nil
}

// Close releases the vault key and the database, in that order.
func (m *Migrator) Close() {
	// The cache first: it holds decrypted key material, and there is no
	// reason for it to survive a moment longer than the database handle it
	// was opened alongside.
	m.cache.Close()
	if err := m.db.Close(); err != nil {
		m.log.Error("closing database", "error", err)
	}
}

// Config exposes the loaded configuration, so a command can honour the same
// policy switches the HTTP API does.
func (m *Migrator) Config() config.Config { return m.cfg }

// Open resolves an account and, if it has a vault, unlocks it.
//
// The key comes back nil when the account has never signed in and so has no
// vault. That is not an error here on purpose: a vault key can only be derived
// from a passphrase the user chose, so an administrator pre-loading the device
// tree for a team of eighty genuinely cannot have one. What such an import can
// carry is bounded instead — see Import — so the useful half of a bulk
// migration works on day one and the secrets follow each person's first login.
//
// The user and the key are returned together because every caller needs both,
// and separating them invites a call that fetches one user's record and
// another user's key.
func (m *Migrator) Open(ctx context.Context, email, passphrase string) (users.User, vault.Key, error) {
	u, err := m.Find(ctx, email)
	if err != nil {
		return users.User{}, nil, err
	}
	if !u.HasVault() {
		return u, nil, nil
	}

	key, err := m.Unlock(ctx, u, passphrase)
	if err != nil {
		return users.User{}, nil, err
	}
	return u, key, nil
}

// Find resolves an account without touching its vault.
//
// Separate from Unlock because a caller needs to know whether there is a vault
// at all before deciding to ask for a passphrase — prompting an administrator
// for a secret that does not exist yet is a confusing way to report that the
// user has never signed in.
func (m *Migrator) Find(ctx context.Context, email string) (users.User, error) {
	u, err := m.users.ByEmail(ctx, email)
	if errors.Is(err, users.ErrNotFound) {
		return users.User{}, fmt.Errorf("no account found for %s", email)
	}
	return u, err
}

// Unlock opens an account's vault.
func (m *Migrator) Unlock(ctx context.Context, u users.User, passphrase string) (vault.Key, error) {
	if !u.HasVault() {
		return nil, fmt.Errorf(
			"%s has no vault yet; they must sign in and set a vault passphrase "+
				"before anything encrypted can be read or written for them", u.Email)
	}
	if passphrase == "" {
		return nil, fmt.Errorf("%s has a vault and no passphrase was given for it", u.Email)
	}

	if err := m.vaults.Unlock(ctx, u, cliSessionID, passphrase); err != nil {
		if errors.Is(err, vault.ErrWrongPassphrase) {
			return nil, fmt.Errorf("that passphrase did not open %s's vault", u.Email)
		}
		return nil, err
	}
	return m.vaults.Key(u.ID, cliSessionID)
}

// Preview reports what importing a payload would do, writing nothing.
func (m *Migrator) Preview(ctx context.Context, u users.User, payload portability.Payload,
	opts portability.ImportOptions) (portability.Plan, error) {
	opts.UserID = u.ID
	return m.svc.Preview(ctx, payload, opts)
}

// Import writes a payload into a user's tree.
func (m *Migrator) Import(ctx context.Context, u users.User, key vault.Key,
	payload portability.Payload, opts portability.ImportOptions, source portability.Source,
) (portability.Result, error) {
	opts.UserID = u.ID

	// A locked or absent vault has nowhere to put key material. The
	// connections could still be written, but silently dropping the passwords
	// out of an import that was asked to carry them is how somebody discovers
	// six weeks later that half their credentials never arrived.
	if key == nil && len(payload.Credentials) > 0 {
		return portability.Result{}, fmt.Errorf(
			"this import carries %d credential(s) and %s has no open vault to put "+
				"them in. They must sign in and set a vault passphrase first, or "+
				"import the connections alone with -no-secrets",
			len(payload.Credentials), u.Email)
	}

	result, err := m.svc.Import(ctx, key, payload, opts)
	if err != nil {
		return portability.Result{}, err
	}

	// Recorded as the account it happened to, with the actor named as the
	// command line: someone reading the log later needs to see that these
	// connections did not appear through the interface.
	m.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: "cli",
		Action: audit.ActionImported, Severity: audit.SeverityNotice,
		TargetType: "import", TargetLabel: string(source),
		Detail: map[string]any{
			"source": string(source), "via": "command line",
			"sessions": result.Sessions, "credentials": result.Credentials,
			"folders": result.Folders, "skipped": result.Skipped,
		},
	})
	return result, nil
}

// ExportRequest is one export from the command line.
type ExportRequest struct {
	Format portability.Format

	// BundlePassphrase encrypts a .bkbundle. Ignored by every other format,
	// none of which has anywhere to put it.
	BundlePassphrase string

	IncludeSecrets    bool
	IncludeKnownHosts bool

	// Confirm is the deliberate acknowledgement a plaintext export needs.
	Confirm bool

	// Note is recorded in a bundle's clear header, so whoever finds the file
	// later knows what it is without its passphrase.
	Note string
}

// Export writes a user's connections to w.
//
// The plaintext gate is the same one the HTTP API applies, deliberately: an
// admin with shell access can read the database anyway, but "the policy said
// no" should not depend on which door the request came through, and the audit
// record should exist either way.
func (m *Migrator) Export(ctx context.Context, u users.User, key vault.Key,
	req ExportRequest, w io.Writer) ([]string, error) {
	// The gate is about credentials leaving the vault in the clear, so it is
	// the combination that trips it. A device list with no secrets in it is
	// how somebody goes back to plain OpenSSH, and refusing that would be
	// refusing the exit this system promises to leave open.
	if req.Format.Plaintext() && req.IncludeSecrets {
		if !m.cfg.Policy.AllowPlaintextExport {
			return nil, fmt.Errorf(
				"exporting %s with secrets writes credentials in the clear, and "+
					"policy.allow_plaintext_export is off in this deployment; "+
					"export a bundle, or pass -include-secrets=false", req.Format)
		}
		if !req.Confirm {
			return nil, fmt.Errorf(
				"exporting %s with secrets writes private keys and passwords to a "+
					"file nothing protects; pass -confirm if that is what you mean", req.Format)
		}
	}

	if req.Format == portability.FormatBundle &&
		len(req.BundlePassphrase) < portability.MinPassphraseLength {
		return nil, fmt.Errorf(
			"a bundle passphrase must be at least %d characters; nothing but this "+
				"passphrase protects the file", portability.MinPassphraseLength)
	}

	if req.IncludeSecrets && key == nil {
		return nil, fmt.Errorf(
			"%s has no open vault, so the keys and passwords cannot be read; "+
				"export without secrets, or supply their vault passphrase", u.Email)
	}

	payload, err := m.svc.Gather(ctx, key, portability.GatherOptions{
		UserID:            u.ID,
		IncludeSecrets:    req.IncludeSecrets,
		IncludeKnownHosts: req.IncludeKnownHosts,
	})
	if err != nil {
		return nil, err
	}

	// Built in memory first. Writing straight to the destination would leave
	// a half-finished file behind on a failure partway through, and half an
	// export looks exactly like a whole one to whoever picks it up later.
	var buf bytes.Buffer
	var warnings []string

	if req.Format == portability.FormatBundle {
		if err := portability.Write(&buf, payload, portability.WriteOptions{
			Passphrase: []byte(req.BundlePassphrase),
			CreatedBy:  u.Email,
			Note:       req.Note,
		}); err != nil {
			return nil, err
		}
	} else {
		result, err := portability.Export(&buf, payload, req.Format,
			portability.ExportOptions{IncludeSecrets: req.IncludeSecrets})
		if err != nil {
			return nil, err
		}
		warnings = result.Warnings
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("writing the export: %w", err)
	}

	event := audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: "cli",
		Action: audit.ActionExported, TargetType: "export",
		TargetLabel: string(req.Format),
		Detail: map[string]any{
			"format": string(req.Format), "via": "command line",
			"includes_key_material": req.IncludeSecrets,
			"encrypted":             !req.Format.Plaintext(),
			"sessions":              len(payload.Sessions),
			"credentials":           len(payload.Credentials),
			"bytes":                 buf.Len(),
		},
	}

	// A plaintext export carrying secrets is the one action here that must not
	// happen unrecorded — so if the audit write fails, say so rather than
	// letting the file stand as the only evidence.
	if req.Format.Plaintext() && req.IncludeSecrets {
		event.Action = audit.ActionExportedPlaintext
		event.Severity = audit.SeverityCritical
		if err := m.audit.RecordErr(ctx, event); err != nil {
			return warnings, fmt.Errorf(
				"the export was written but could not be recorded in the audit log: %w", err)
		}
		return warnings, nil
	}

	m.audit.Record(ctx, event)
	return warnings, nil
}
