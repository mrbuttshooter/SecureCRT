// Package config loads and validates runtime configuration for bkd.
//
// Configuration comes from three sources, applied in increasing order of
// precedence: built-in defaults, a YAML file, then environment variables
// prefixed with BKD_. This lets an operator keep a readable config file under
// /etc/bkd/config.yaml while injecting secrets (database passwords, the master
// key path) through systemd credentials or the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

// MFA policy values.
const (
	MFAOff      = "off"
	MFAOptional = "optional"
	MFARequired = "required"
)

// Vault unlock modes for single-sign-on users. See VaultConfig.SSOUnlockMode.
const (
	SSOUnlockPassphrase    = "passphrase"
	SSOUnlockServerManaged = "server_managed"
)

// EnvPrefix is prepended to every environment variable override.
const EnvPrefix = "BKD_"

// Config is the fully resolved runtime configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Vault    VaultConfig    `yaml:"vault"`
	Auth     AuthConfig     `yaml:"auth"`
	Paths    PathsConfig    `yaml:"paths"`
	Log      LogConfig      `yaml:"log"`
	Policy   PolicyConfig   `yaml:"policy"`
}

// ServerConfig controls the HTTP listener.
//
// The default bind address is loopback on purpose: bkd is designed to sit
// behind nginx or Caddy, which terminates TLS. Binding it to a public
// interface without a reverse proxy would serve terminal traffic in cleartext.
type ServerConfig struct {
	Bind              string        `yaml:"bind"`
	ExternalURL       string        `yaml:"external_url"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ShutdownGrace     time.Duration `yaml:"shutdown_grace"`
	TrustedProxyCIDRs []string      `yaml:"trusted_proxy_cidrs"`
}

// DatabaseConfig selects and configures the backing store.
//
// Driver is "postgres" for a company deployment or "sqlite" for a single-user
// or lab install. The schema and all queries are identical across both.
type DatabaseConfig struct {
	Driver          string        `yaml:"driver"`
	DSN             string        `yaml:"dsn"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	AutoMigrate     bool          `yaml:"auto_migrate"`
}

// VaultConfig tunes the envelope-encryption parameters.
//
// The Argon2id costs apply to deriving a user's key-encryption key from their
// vault passphrase. Raising them strengthens offline resistance against a
// stolen database at the cost of login latency and server memory. They are
// recorded per-credential at write time, so increasing them later does not
// invalidate existing data.
type VaultConfig struct {
	MasterKeyPath  string        `yaml:"master_key_path"`
	Argon2Time     uint32        `yaml:"argon2_time"`
	Argon2MemoryKB uint32        `yaml:"argon2_memory_kb"`
	Argon2Threads  uint8         `yaml:"argon2_threads"`
	UnlockTTL      time.Duration `yaml:"unlock_ttl"`

	// SSOUnlockMode decides how a single-sign-on user's vault is protected.
	// This is the most consequential setting in the file.
	//
	//   passphrase      the user types a vault passphrase after signing in
	//                   with Microsoft. A stolen database, even together
	//                   with the master key, yields nothing.
	//   server_managed  signing in with Microsoft opens everything. What
	//                   most commercial web-SSH products do, and defensible
	//                   — but it discards the guarantee above entirely.
	SSOUnlockMode string `yaml:"sso_unlock_mode"`
}

// AuthConfig controls authentication, sessions and single sign-on.
type AuthConfig struct {
	// SessionIdleTTL is how long a session survives without activity; each
	// authenticated request pushes the deadline out.
	SessionIdleTTL time.Duration `yaml:"session_idle_ttl"`

	// SessionAbsoluteTTL is the hard ceiling. Activity never extends a
	// session past this, so a stolen cookie cannot be kept alive forever
	// simply by using it.
	SessionAbsoluteTTL time.Duration `yaml:"session_absolute_ttl"`

	// MFAPolicy is off, optional or required.
	MFAPolicy string `yaml:"mfa_policy"`

	// RequireMFAForAdmins applies the required policy to administrators even
	// when it is optional for everyone else.
	RequireMFAForAdmins bool `yaml:"require_mfa_for_admins"`

	MaxAttemptsPerAccount int           `yaml:"max_attempts_per_account"`
	MaxAttemptsPerAddress int           `yaml:"max_attempts_per_address"`
	LockoutWindow         time.Duration `yaml:"lockout_window"`
	LockoutDuration       time.Duration `yaml:"lockout_duration"`

	// SecureCookies should be false only for local HTTP development.
	SecureCookies bool `yaml:"secure_cookies"`

	OIDC OIDCConfig `yaml:"oidc"`
}

// OIDCConfig configures single sign-on against an OpenID Connect provider,
// in practice Microsoft Entra.
type OIDCConfig struct {
	Enabled bool `yaml:"enabled"`

	// Issuer is the discovery base, e.g.
	// https://login.microsoftonline.com/<tenant-id>/v2.0
	Issuer string `yaml:"issuer"`

	ClientID string `yaml:"client_id"`

	// ClientSecret should come from BKD_OIDC_CLIENT_SECRET rather than this
	// file, which is world-readable on many systems.
	ClientSecret string `yaml:"client_secret"`

	// AllowedTenants lists acceptable Entra tid values. Required when the
	// issuer is a multi-tenant endpoint, because such an endpoint validates
	// tokens from any tenant in existence.
	AllowedTenants []string `yaml:"allowed_tenants"`

	// AutoProvision creates an account on first successful sign-in.
	AutoProvision bool `yaml:"auto_provision"`

	// ProviderName is shown on the sign-in button.
	ProviderName string `yaml:"provider_name"`
}

// PathsConfig names the writable state directories.
type PathsConfig struct {
	DataDir       string `yaml:"data_dir"`
	SessionLogDir string `yaml:"session_log_dir"`
	RecordingDir  string `yaml:"recording_dir"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// PolicyConfig holds org-wide rules an admin can enforce.
//
// AllowPlaintextExport is the single most security-relevant switch here: with
// it disabled, credentials can only leave the system inside a passphrase-
// encrypted bundle, closing the most obvious exfiltration path in a
// company-wide deployment.
type PolicyConfig struct {
	AllowPlaintextExport bool `yaml:"allow_plaintext_export"`
	AllowPasswordAuth    bool `yaml:"allow_password_auth"`
	RequireHostKeyVerify bool `yaml:"require_host_key_verify"`
	RecordAllSessions    bool `yaml:"record_all_sessions"`
}

// Default returns the built-in configuration.
//
// The defaults are chosen to be safe rather than convenient: loopback bind,
// host key verification required, plaintext export disabled.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Bind:          "127.0.0.1:8443",
			ExternalURL:   "https://localhost",
			ReadTimeout:   30 * time.Second,
			WriteTimeout:  30 * time.Second,
			IdleTimeout:   120 * time.Second,
			ShutdownGrace: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Driver:          "postgres",
			DSN:             "postgres:///bkd?host=/var/run/postgresql&sslmode=disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: time.Hour,
			AutoMigrate:     true,
		},
		Vault: VaultConfig{
			MasterKeyPath:  "/var/lib/bkd/master.key",
			Argon2Time:     3,
			Argon2MemoryKB: 64 * 1024,
			Argon2Threads:  4,
			UnlockTTL:      12 * time.Hour,
			SSOUnlockMode:  SSOUnlockPassphrase,
		},
		Auth: AuthConfig{
			SessionIdleTTL:        8 * time.Hour,
			SessionAbsoluteTTL:    7 * 24 * time.Hour,
			MFAPolicy:             MFAOptional,
			RequireMFAForAdmins:   false,
			MaxAttemptsPerAccount: 5,
			MaxAttemptsPerAddress: 30,
			LockoutWindow:         15 * time.Minute,
			LockoutDuration:       15 * time.Minute,
			SecureCookies:         true,
			OIDC: OIDCConfig{
				AutoProvision: true,
				ProviderName:  "Microsoft",
			},
		},
		Paths: PathsConfig{
			DataDir:       "/var/lib/bkd",
			SessionLogDir: "/var/lib/bkd/logs",
			RecordingDir:  "/var/lib/bkd/recordings",
		},
		Log: LogConfig{Level: "info", Format: "json"},
		Policy: PolicyConfig{
			AllowPlaintextExport: false,
			AllowPasswordAuth:    true,
			RequireHostKeyVerify: true,
			RecordAllSessions:    false,
		},
	}
}

// Load reads configuration from path (if non-empty), applies BKD_*
// environment overrides, and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
		if err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	applyEnv(&cfg)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyEnv overlays environment variables onto cfg.
//
// Only the settings an operator realistically needs to inject at runtime are
// exposed — chiefly the database DSN and master key path, which typically
// arrive from a systemd credential rather than a world-readable file.
func applyEnv(cfg *Config) {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(EnvPrefix + key); ok {
			*dst = v
		}
	}
	bl := func(key string, dst *bool) {
		if v, ok := os.LookupEnv(EnvPrefix + key); ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(EnvPrefix + key); ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}

	str("BIND", &cfg.Server.Bind)
	str("EXTERNAL_URL", &cfg.Server.ExternalURL)
	str("DB_DRIVER", &cfg.Database.Driver)
	str("DB_DSN", &cfg.Database.DSN)
	bl("DB_AUTO_MIGRATE", &cfg.Database.AutoMigrate)
	str("MASTER_KEY_PATH", &cfg.Vault.MasterKeyPath)
	str("DATA_DIR", &cfg.Paths.DataDir)
	str("LOG_LEVEL", &cfg.Log.Level)
	str("LOG_FORMAT", &cfg.Log.Format)
	dur("UNLOCK_TTL", &cfg.Vault.UnlockTTL)
	str("MFA_POLICY", &cfg.Auth.MFAPolicy)
	bl("SECURE_COOKIES", &cfg.Auth.SecureCookies)
	str("SSO_UNLOCK_MODE", &cfg.Vault.SSOUnlockMode)
	bl("OIDC_ENABLED", &cfg.Auth.OIDC.Enabled)
	str("OIDC_ISSUER", &cfg.Auth.OIDC.Issuer)
	str("OIDC_CLIENT_ID", &cfg.Auth.OIDC.ClientID)
	str("OIDC_CLIENT_SECRET", &cfg.Auth.OIDC.ClientSecret)
	bl("OIDC_AUTO_PROVISION", &cfg.Auth.OIDC.AutoProvision)
	bl("ALLOW_PLAINTEXT_EXPORT", &cfg.Policy.AllowPlaintextExport)
	bl("ALLOW_PASSWORD_AUTH", &cfg.Policy.AllowPasswordAuth)
	bl("REQUIRE_HOST_KEY_VERIFY", &cfg.Policy.RequireHostKeyVerify)
	bl("RECORD_ALL_SESSIONS", &cfg.Policy.RecordAllSessions)
}

// isMultiTenantIssuer reports whether an issuer mints tokens for tenants other
// than a single named one.
func isMultiTenantIssuer(issuer string) bool {
	for _, shared := range []string{"/common", "/organizations", "/consumers"} {
		if strings.Contains(issuer, shared+"/") || strings.HasSuffix(issuer, shared) {
			return true
		}
	}
	return false
}

// Validate rejects configurations that would produce an insecure or
// non-functional server. It is deliberately strict about the Argon2id
// parameters: silently accepting weak costs would undermine the whole
// at-rest encryption story.
func (c Config) Validate() error {
	var errs []error

	if c.Server.Bind == "" {
		errs = append(errs, errors.New("server.bind must not be empty"))
	}
	if c.Server.ExternalURL == "" {
		errs = append(errs, errors.New("server.external_url must not be empty"))
	} else if u, err := url.Parse(c.Server.ExternalURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("server.external_url %q is not an absolute URL", c.Server.ExternalURL))
	}

	switch c.Database.Driver {
	case "postgres", "sqlite":
	default:
		errs = append(errs, fmt.Errorf("database.driver %q must be \"postgres\" or \"sqlite\"", c.Database.Driver))
	}
	if c.Database.DSN == "" {
		errs = append(errs, errors.New("database.dsn must not be empty"))
	}

	if c.Vault.MasterKeyPath == "" {
		errs = append(errs, errors.New("vault.master_key_path must not be empty"))
	} else if !filepath.IsAbs(c.Vault.MasterKeyPath) {
		errs = append(errs, fmt.Errorf("vault.master_key_path %q must be absolute", c.Vault.MasterKeyPath))
	}
	// Bounded at both ends. The floors keep a derivation strong enough to
	// resist offline cracking; the ceilings stop a typo in a config file
	// producing a server that allocates gigabytes on every unlock and appears
	// to hang. They are the same limits the vault enforces on parameters
	// arriving from anywhere else.
	if c.Vault.Argon2Time < 1 {
		errs = append(errs, errors.New("vault.argon2_time must be at least 1"))
	}
	if c.Vault.Argon2Time > vault.MaxKDFTime {
		errs = append(errs, fmt.Errorf("vault.argon2_time is %d; the maximum is %d",
			c.Vault.Argon2Time, vault.MaxKDFTime))
	}
	if c.Vault.Argon2MemoryKB < 16*1024 {
		errs = append(errs, fmt.Errorf("vault.argon2_memory_kb is %d; must be at least 16384 (16 MiB) to resist offline cracking", c.Vault.Argon2MemoryKB))
	}
	if c.Vault.Argon2MemoryKB > vault.MaxKDFMemoryKB {
		errs = append(errs, fmt.Errorf("vault.argon2_memory_kb is %d; the maximum is %d (%d MiB)",
			c.Vault.Argon2MemoryKB, vault.MaxKDFMemoryKB, vault.MaxKDFMemoryKB/1024))
	}
	if c.Vault.Argon2Threads < 1 {
		errs = append(errs, errors.New("vault.argon2_threads must be at least 1"))
	}
	if c.Vault.Argon2Threads > vault.MaxKDFThreads {
		errs = append(errs, fmt.Errorf("vault.argon2_threads is %d; the maximum is %d",
			c.Vault.Argon2Threads, vault.MaxKDFThreads))
	}
	if c.Vault.UnlockTTL <= 0 {
		errs = append(errs, errors.New("vault.unlock_ttl must be positive"))
	}

	if c.Vault.SSOUnlockMode != SSOUnlockPassphrase && c.Vault.SSOUnlockMode != SSOUnlockServerManaged {
		errs = append(errs, fmt.Errorf(
			"vault.sso_unlock_mode %q must be %q or %q",
			c.Vault.SSOUnlockMode, SSOUnlockPassphrase, SSOUnlockServerManaged))
	}

	if c.Auth.SessionIdleTTL <= 0 {
		errs = append(errs, errors.New("auth.session_idle_ttl must be positive"))
	}
	if c.Auth.SessionAbsoluteTTL < c.Auth.SessionIdleTTL {
		errs = append(errs, errors.New("auth.session_absolute_ttl must be at least auth.session_idle_ttl"))
	}
	switch c.Auth.MFAPolicy {
	case MFAOff, MFAOptional, MFARequired:
	default:
		errs = append(errs, fmt.Errorf("auth.mfa_policy %q must be off, optional or required", c.Auth.MFAPolicy))
	}
	if c.Auth.MaxAttemptsPerAccount < 1 {
		errs = append(errs, errors.New("auth.max_attempts_per_account must be at least 1"))
	}
	if c.Auth.MaxAttemptsPerAddress < c.Auth.MaxAttemptsPerAccount {
		errs = append(errs, errors.New(
			"auth.max_attempts_per_address must be at least auth.max_attempts_per_account, "+
				"or one user's own retries would lock out everyone behind their office NAT"))
	}

	if c.Auth.OIDC.Enabled {
		if c.Auth.OIDC.Issuer == "" {
			errs = append(errs, errors.New("auth.oidc.issuer must be set when single sign-on is enabled"))
		}
		if c.Auth.OIDC.ClientID == "" {
			errs = append(errs, errors.New("auth.oidc.client_id must be set when single sign-on is enabled"))
		}
		if c.Auth.OIDC.ClientSecret == "" {
			errs = append(errs, errors.New(
				"auth.oidc.client_secret must be set when single sign-on is enabled "+
					"(prefer the BKD_OIDC_CLIENT_SECRET environment variable over this file)"))
		}
		if len(c.Auth.OIDC.AllowedTenants) == 0 && isMultiTenantIssuer(c.Auth.OIDC.Issuer) {
			errs = append(errs, fmt.Errorf(
				"auth.oidc.issuer %q is a multi-tenant endpoint, so auth.oidc.allowed_tenants must list "+
					"the tenant IDs you accept; without it any Microsoft account in the world can sign in",
				c.Auth.OIDC.Issuer))
		}
	}

	if !filepath.IsAbs(c.Paths.DataDir) {
		errs = append(errs, fmt.Errorf("paths.data_dir %q must be absolute", c.Paths.DataDir))
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q must be debug, info, warn or error", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format %q must be json or text", c.Log.Format))
	}

	return errors.Join(errs...)
}
