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
	"net"
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
	Tunnels  TunnelsConfig  `yaml:"tunnels"`
	Serial   SerialConfig   `yaml:"serial"`
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
//
// It gates secrets, not formats. An ssh_config or a CSV of hostnames with no
// keys or passwords in it is unaffected — that is how somebody leaves for
// plain OpenSSH, and this system does not hold anyone by making the exit
// difficult.
type PolicyConfig struct {
	AllowPlaintextExport bool `yaml:"allow_plaintext_export"`
	AllowPasswordAuth    bool `yaml:"allow_password_auth"`
	RequireHostKeyVerify bool `yaml:"require_host_key_verify"`
	RecordAllSessions    bool `yaml:"record_all_sessions"`

	// MaxUploadBytes caps one file-upload request. It is not a cap on file
	// size — the browser splits a large file into chunks and resumes each at
	// an offset — so raising it changes how much a single request may carry,
	// not what can be transferred. A request over the cap is refused rather
	// than truncated.
	MaxUploadBytes int64 `yaml:"max_upload_bytes"`

	// MaxImportBytes caps an uploaded configuration awaiting preview. A
	// SecureCRT tree for a large team is a few megabytes; the default leaves
	// room for an unusually large one without letting an upload fill the disk.
	MaxImportBytes int64 `yaml:"max_import_bytes"`

	// AllowTCPTunnels lets users open listening ports on this server, so a
	// database client or an RDP client on their own machine can reach a host
	// only this server can see.
	//
	// Off by default, and the reason is the word "listening". Everything else
	// here reaches outward; this accepts inbound connections on a shared
	// machine, and whoever can reach that port gets whatever is behind it
	// without authenticating to bkd at all. The bind address below is the
	// other half of that decision.
	AllowTCPTunnels bool `yaml:"allow_tcp_tunnels"`

	// AllowRemoteForwards lets users ask a remote host to listen on bkd's
	// behalf — `ssh -R`. A connection arriving at that port on the device is
	// carried back here and dialled *from this server*.
	//
	// Off by default, and for a different reason than the setting above.
	// A local tunnel lets someone who can reach this machine reach a device;
	// a remote forward lets someone who can reach the *device* reach whatever
	// this machine's network can, which on a shared server is a much larger
	// set than the person who opened it intended. bkd refuses loopback and
	// link-local destinations outright for that reason — see
	// internal/proto/tunnel — but the rest of the network is still reachable,
	// so the feature is a decision rather than a default.
	AllowRemoteForwards bool `yaml:"allow_remote_forwards"`

	// AllowTelnet permits telnet connections.
	//
	// On by default, which is a deliberate choice and not an oversight.
	// Telnet is plaintext — the password crosses the network in the clear,
	// and so does everything typed after it — but the equipment that needs it
	// is equipment that cannot do anything else: console servers, older
	// switches, PDUs, anything whose management plane predates its owner's
	// security policy. Refusing it does not make those devices go away; it
	// makes people reach them with a tool that has no audit log.
	//
	// So the cost is made visible instead: the tab is marked, and every
	// connection is recorded with encrypted=false. An organisation that has
	// finished retiring its telnet estate turns this off and finds out
	// immediately who had not noticed.
	AllowTelnet bool `yaml:"allow_telnet"`

	// AllowSerial permits opening serial ports on this machine.
	//
	// Off by default, and it should stay off almost everywhere. It only does
	// anything where this server is physically cabled to the equipment, which
	// for a central install serving a company is essentially never — a lab
	// box on somebody's bench is the case it exists for. The remote case is
	// what console servers are for, and those speak SSH or telnet.
	//
	// The device path comes from a saved connection, which is to say from a
	// user, so this switch is only half the guard: serial.allowed_devices is
	// the other half and has no default.
	AllowSerial bool `yaml:"allow_serial"`
}

// SerialConfig bounds what serial ports may be opened.
type SerialConfig struct {
	// AllowedDevices is a list of globs naming the ports that exist.
	//
	// Empty opens nothing, which is the safe default rather than an
	// oversight. Without this list, "open this path and stream it to my
	// browser" is an arbitrary-file-read primitive on a server holding every
	// engineer's encrypted credentials — and refusing anything that is not a
	// character device does not save it, because /dev/mem is one.
	//
	// Matched against the path after symbolic links are resolved, so a link
	// cannot be used to reach something these globs do not name.
	AllowedDevices []string `yaml:"allowed_devices"`
}

// TunnelsConfig holds the operational settings for port forwarding. The
// permission to use it at all lives in PolicyConfig; this is where it lands.
type TunnelsConfig struct {
	// Bind is the address TCP and SOCKS tunnels listen on.
	//
	// Loopback by default, which on its own makes the feature useless from
	// anywhere but this machine — deliberately. Widening it is a decision an
	// operator should make once, knowingly, rather than inherit.
	Bind string `yaml:"bind"`

	// PortRange bounds the ports allocated to tunnels, as "low-high", so a
	// firewall rule can be written once and stay true.
	PortRange string `yaml:"port_range"`

	// Domain is the wildcard base under which a device's web interface is
	// served, e.g. "tunnels.bkd.example.com" — each tunnel gets its own
	// hostname beneath it.
	//
	// Empty disables web tunnels entirely, and that is the safe default
	// rather than an oversight. A device's own pages cannot be served from
	// bkd's origin: the CSRF cookie is readable by JavaScript by design, so
	// a script on a compromised switch would inherit the whole session. A
	// separate origin is what makes the feature possible at all, and without
	// one configured there is nowhere safe to put it.
	Domain string `yaml:"domain"`

	// MaxPerUser caps concurrent tunnels per person.
	MaxPerUser int `yaml:"max_per_user"`

	// IdleTimeout closes a tunnel nothing has used. The cost being reclaimed
	// is the SSH connection underneath it, which on network equipment is a
	// vty line.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
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
			MaxUploadBytes:       1 << 30,  // 1 GiB per request
			MaxImportBytes:       64 << 20, // 64 MiB
			AllowTCPTunnels:      false,
			AllowRemoteForwards:  false,
			AllowTelnet:          true,
			AllowSerial:          false,
		},
		Serial: SerialConfig{AllowedDevices: nil},
		Tunnels: TunnelsConfig{
			Bind:        "127.0.0.1",
			PortRange:   "34000-34999",
			Domain:      "",
			MaxPerUser:  8,
			IdleTimeout: time.Hour,
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
	bl("ALLOW_TELNET", &cfg.Policy.AllowTelnet)
	bl("ALLOW_SERIAL", &cfg.Policy.AllowSerial)
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

	// Both ceilings are bounded at the top as well as the bottom. A limit
	// large enough to be meaningless is the same as no limit at all, and the
	// point of these two is that something eventually says no.
	if c.Policy.MaxUploadBytes < 1<<20 || c.Policy.MaxUploadBytes > 64<<30 {
		errs = append(errs, fmt.Errorf(
			"policy.max_upload_bytes %d must be between 1 MiB and 64 GiB",
			c.Policy.MaxUploadBytes))
	}
	if c.Policy.MaxImportBytes < 1<<10 || c.Policy.MaxImportBytes > 1<<30 {
		errs = append(errs, fmt.Errorf(
			"policy.max_import_bytes %d must be between 1 KiB and 1 GiB",
			c.Policy.MaxImportBytes))
	}

	errs = append(errs, c.Tunnels.validate(c.Policy.AllowTCPTunnels)...)

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

// validate checks the tunnel settings.
//
// The port range and bind address are only enforced when listeners are
// actually allowed: an operator who leaves them at nonsense values with the
// feature switched off has not made a mistake worth refusing to start over.
func (t TunnelsConfig) validate(listenersAllowed bool) []error {
	var errs []error

	if t.MaxPerUser < 1 || t.MaxPerUser > 128 {
		errs = append(errs, fmt.Errorf(
			"tunnels.max_per_user %d must be between 1 and 128", t.MaxPerUser))
	}
	if t.IdleTimeout < time.Minute || t.IdleTimeout > 24*time.Hour {
		errs = append(errs, fmt.Errorf(
			"tunnels.idle_timeout %s must be between a minute and a day", t.IdleTimeout))
	}

	if t.Domain != "" {
		if strings.ContainsAny(t.Domain, "/: ") || strings.HasPrefix(t.Domain, ".") {
			errs = append(errs, fmt.Errorf(
				"tunnels.domain %q must be a bare hostname such as tunnels.example.com", t.Domain))
		}
	}

	if !listenersAllowed {
		return errs
	}

	if net.ParseIP(t.Bind) == nil {
		errs = append(errs, fmt.Errorf(
			"tunnels.bind %q must be an IP address; it is what decides who can reach a "+
				"forwarded port, so a hostname that resolves differently later is not "+
				"a safe way to express it", t.Bind))
	}
	if _, _, err := ParsePortRange(t.PortRange); err != nil {
		errs = append(errs, fmt.Errorf("tunnels.port_range: %w", err))
	}

	return errs
}

// ParsePortRange reads a "low-high" range.
func ParsePortRange(spec string) (low, high int, err error) {
	before, after, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, fmt.Errorf("%q must be written low-high, such as 34000-34999", spec)
	}

	low, err = strconv.Atoi(strings.TrimSpace(before))
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a port number", before)
	}
	high, err = strconv.Atoi(strings.TrimSpace(after))
	if err != nil {
		return 0, 0, fmt.Errorf("%q is not a port number", after)
	}

	// Privileged ports are excluded outright. bkd runs unprivileged and could
	// not bind them anyway, so allowing them here would only produce a
	// confusing failure much later.
	if low < 1024 || high > 65535 || low > high {
		return 0, 0, fmt.Errorf(
			"%q must be an ascending range within 1024-65535", spec)
	}
	return low, high, nil
}
