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
	t.Setenv(EnvPrefix+"REQUIRE_MFA", "true")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.DSN != "from-env" {
		t.Errorf("dsn = %q, want env value to win", cfg.Database.DSN)
	}
	if !cfg.Auth.RequireMFA {
		t.Error("BKD_REQUIRE_MFA not applied")
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

func TestValidateRejectsRefreshShorterThanAccess(t *testing.T) {
	c := Default()
	c.Auth.AccessTokenTTL = time.Hour
	c.Auth.RefreshTokenTTL = time.Minute
	if err := c.Validate(); err == nil {
		t.Fatal("refresh TTL shorter than access TTL must be rejected")
	}
}

func TestValidateRejectsRelativeMasterKeyPath(t *testing.T) {
	c := Default()
	c.Vault.MasterKeyPath = "master.key"
	if err := c.Validate(); err == nil {
		t.Fatal("relative master key path must be rejected")
	}
}
