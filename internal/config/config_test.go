package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config must validate, got: %v", err)
	}
}

func TestDefaultsAreSafe(t *testing.T) {
	c := Default()
	if c.Policy.AllowPlaintextExport {
		t.Error("plaintext credential export must be off by default")
	}
	if !c.Policy.RequireHostKeyVerify {
		t.Error("host key verification must be required by default")
	}
	if !strings.HasPrefix(c.Server.Bind, "127.0.0.1:") {
		t.Errorf("default bind must be loopback, got %q", c.Server.Bind)
	}
	// The default must be the mode where a stolen database is useless, not
	// the more convenient one that gives that guarantee up.
	if c.Vault.SSOUnlockMode != SSOUnlockPassphrase {
		t.Errorf("default sso_unlock_mode = %q, want %q", c.Vault.SSOUnlockMode, SSOUnlockPassphrase)
	}
	if !c.Auth.SecureCookies {
		t.Error("cookies must be marked Secure by default")
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
server:
  bind: "127.0.0.1:9000"
  external_url: "https://term.example.com"
database:
  driver: sqlite
  dsn: "/var/lib/bkd/bkd.db"
policy:
  allow_plaintext_export: true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Bind != "127.0.0.1:9000" {
		t.Errorf("bind = %q", cfg.Server.Bind)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("driver = %q", cfg.Database.Driver)
	}
	if !cfg.Policy.AllowPlaintextExport {
		t.Error("policy override not applied")
	}
	// Untouched keys must keep their defaults.
	if cfg.Vault.Argon2MemoryKB != 64*1024 {
		t.Errorf("argon2_memory_kb = %d, want default", cfg.Vault.Argon2MemoryKB)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  bnid: oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a typo'd key must be rejected, not silently ignored")
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n  dsn: \"from-file\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPrefix+"DB_DSN", "from-env")
	t.Setenv(EnvPrefix+"MFA_POLICY", "required")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.DSN != "from-env" {
		t.Errorf("dsn = %q, want env value to win", cfg.Database.DSN)
	}
	if cfg.Auth.MFAPolicy != MFARequired {
		t.Errorf("BKD_MFA_POLICY not applied: %q", cfg.Auth.MFAPolicy)
	}
}

func TestValidateRejectsWeakArgon2(t *testing.T) {
	c := Default()
	c.Vault.Argon2MemoryKB = 1024 // 1 MiB — far too low
	err := c.Validate()
	if err == nil {
		t.Fatal("weak argon2 memory must be rejected")
	}
	if !strings.Contains(err.Error(), "argon2_memory_kb") {
		t.Errorf("error should name the offending field, got: %v", err)
	}
}

func TestValidateCollectsAllErrors(t *testing.T) {
	c := Default()
	c.Server.Bind = ""
	c.Database.Driver = "mongodb"
	c.Log.Level = "verbose"

	err := c.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"server.bind", "database.driver", "log.level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error missing %q; got: %v", want, err)
		}
	}
}

func TestValidateRejectsAbsoluteTTLShorterThanIdle(t *testing.T) {
	c := Default()
	c.Auth.SessionIdleTTL = 8 * time.Hour
	c.Auth.SessionAbsoluteTTL = time.Hour
	if err := c.Validate(); err == nil {
		t.Fatal("an absolute session TTL below the idle TTL must be rejected")
	}
}

// TestValidateRefusesUncheckedMultiTenantSSO is the configuration guard that
// matters most for a company deployment: pointing at Entra's /common endpoint
// without naming the tenants means any Microsoft account in the world can sign
// in.
func TestValidateRefusesUncheckedMultiTenantSSO(t *testing.T) {
	c := Default()
	c.Auth.OIDC = OIDCConfig{
		Enabled:      true,
		Issuer:       "https://login.microsoftonline.com/common/v2.0",
		ClientID:     "client",
		ClientSecret: "secret",
	}

	err := c.Validate()
	if err == nil {
		t.Fatal("a multi-tenant issuer with no tenant allowlist must be refused")
	}
	if !strings.Contains(err.Error(), "allowed_tenants") {
		t.Errorf("the error should name the missing setting, got: %v", err)
	}

	c.Auth.OIDC.AllowedTenants = []string{"11111111-2222-3333-4444-555555555555"}
	if err := c.Validate(); err != nil {
		t.Fatalf("naming the tenants should make it valid: %v", err)
	}
}

// TestValidateRequiresSSOSecrets keeps a half-configured provider from
// starting and failing at a user's first sign-in instead.
func TestValidateRequiresSSOSecrets(t *testing.T) {
	base := OIDCConfig{
		Enabled:      true,
		Issuer:       "https://login.microsoftonline.com/tenant-id/v2.0",
		ClientID:     "client",
		ClientSecret: "secret",
	}

	for name, mutate := range map[string]func(*OIDCConfig){
		"no issuer":        func(o *OIDCConfig) { o.Issuer = "" },
		"no client id":     func(o *OIDCConfig) { o.ClientID = "" },
		"no client secret": func(o *OIDCConfig) { o.ClientSecret = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := Default()
			c.Auth.OIDC = base
			mutate(&c.Auth.OIDC)
			if err := c.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	// Disabled single sign-on needs none of it.
	c := Default()
	c.Auth.OIDC = OIDCConfig{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("a disabled provider must not require configuration: %v", err)
	}
}

func TestValidateSSOUnlockMode(t *testing.T) {
	for _, mode := range []string{SSOUnlockPassphrase, SSOUnlockServerManaged} {
		c := Default()
		c.Vault.SSOUnlockMode = mode
		if err := c.Validate(); err != nil {
			t.Errorf("%q should be valid: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "yes", "server", "managed"} {
		c := Default()
		c.Vault.SSOUnlockMode = mode
		if err := c.Validate(); err == nil {
			t.Errorf("%q should be refused", mode)
		}
	}
}

// TestValidateRefusesAddressLimitBelowAccountLimit guards a combination that
// would let one user's own retries lock out their whole office.
func TestValidateRefusesAddressLimitBelowAccountLimit(t *testing.T) {
	c := Default()
	c.Auth.MaxAttemptsPerAccount = 10
	c.Auth.MaxAttemptsPerAddress = 3
	if err := c.Validate(); err == nil {
		t.Fatal("a per-address limit below the per-account limit must be refused")
	}
}

func TestValidateRejectsRelativeMasterKeyPath(t *testing.T) {
	c := Default()
	c.Vault.MasterKeyPath = "master.key"
	if err := c.Validate(); err == nil {
		t.Fatal("relative master key path must be rejected")
	}
}
