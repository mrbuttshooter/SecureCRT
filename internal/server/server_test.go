package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testConfig returns a configuration pointing entirely at a temp directory,
// backed by SQLite so the suite needs no external database.
func testConfig(t *testing.T) config.Config {
	t.Helper()

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.Bind = "127.0.0.1:0"
	cfg.Server.ExternalURL = "https://bkd.test"
	cfg.Database.Driver = "sqlite"
	cfg.Database.DSN = filepath.Join(dir, "bkd.db")
	cfg.Vault.MasterKeyPath = filepath.Join(dir, "master.key")
	cfg.Paths.DataDir = filepath.Join(dir, "data")
	cfg.Paths.SessionLogDir = filepath.Join(dir, "data", "logs")
	cfg.Paths.RecordingDir = filepath.Join(dir, "data", "recordings")
	cfg.Log.Format = "text"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config is invalid: %v", err)
	}
	return cfg
}

func newTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := testConfig(t)
	if err := vault.GenerateMasterKeyFile(cfg.Vault.MasterKeyPath); err != nil {
		t.Fatal(err)
	}

	s, err := New(context.Background(), cfg, quietLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.closeResources)
	return s
}

// TestNewRequiresMasterKey confirms the server refuses to start without one,
// rather than silently generating a key nobody has backed up.
func TestNewRequiresMasterKey(t *testing.T) {
	cfg := testConfig(t)

	_, err := New(context.Background(), cfg, quietLogger())
	if err == nil {
		t.Fatal("New must fail when the master key is absent")
	}
	if !strings.Contains(err.Error(), "gen-master-key") {
		t.Errorf("the error should tell the operator how to fix it, got: %v", err)
	}
}

// TestNewRejectsLooseMasterKeyPermissions covers the case of an operator
// copying the key between hosts and losing its mode along the way.
func TestNewRejectsLooseMasterKeyPermissions(t *testing.T) {
	cfg := testConfig(t)
	if err := vault.GenerateMasterKeyFile(cfg.Vault.MasterKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.Vault.MasterKeyPath, 0o444); err != nil {
		t.Fatal(err)
	}

	if _, err := New(context.Background(), cfg, quietLogger()); err == nil {
		t.Fatal("a world-readable master key must prevent startup")
	}
}

// TestNewCreatesStateDirectories checks both that the directories appear and
// that they are not world-readable: session logs contain whatever scrolled
// past on a production console.
func TestNewCreatesStateDirectories(t *testing.T) {
	cfg := testConfig(t)
	if err := vault.GenerateMasterKeyFile(cfg.Vault.MasterKeyPath); err != nil {
		t.Fatal(err)
	}

	s, err := New(context.Background(), cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeResources()

	for _, dir := range []string{cfg.Paths.DataDir, cfg.Paths.SessionLogDir, cfg.Paths.RecordingDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("%s was not created: %v", dir, err)
			continue
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %04o; session data must not be readable by other accounts", dir, perm)
		}
	}
}

// TestNewAppliesMigrations confirms auto_migrate reaches the database.
func TestNewAppliesMigrations(t *testing.T) {
	s := newTestServer(t)

	var n int
	if err := s.db.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("schema was not applied at startup: %v", err)
	}
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var body struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v (%q)", err, rec.Body.String())
	}
	if body.Status != "ok" {
		t.Errorf("status = %q", body.Status)
	}
	if body.Version == "" {
		t.Error("version should be reported")
	}
}

// TestHealthzSurvivesDatabaseOutage is the reason liveness does not touch the
// database: an orchestrator must not kill a process that would recover once
// the database comes back.
func TestHealthzSurvivesDatabaseOutage(t *testing.T) {
	s := newTestServer(t)

	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("liveness must stay green during a database outage, got %d", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ready") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// TestReadyzFailsWhenDatabaseIsDown is the counterpart: readiness must go red
// so a load balancer stops sending traffic.
func TestReadyzFailsWhenDatabaseIsDown(t *testing.T) {
	s := newTestServer(t)

	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestSecurityHeaders asserts the baseline headers are present on every
// response, including errors — the usual place they get forgotten.
func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	handler := s.routes()

	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}

	for _, path := range []string{"/healthz", "/readyz", "/does-not-exist"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			for header, expected := range want {
				if got := rec.Header().Get(header); got != expected {
					t.Errorf("%s = %q, want %q", header, got, expected)
				}
			}

			csp := rec.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Fatal("Content-Security-Policy is missing")
			}
			for _, directive := range []string{
				"default-src 'self'",
				"frame-ancestors 'none'",
				"base-uri 'none'",
				// Named explicitly rather than inherited from script-src, so
				// keyword highlighting's worker cannot be switched off by a
				// later tightening of script-src that nobody connected to it.
				"worker-src 'self'",
			} {
				if !strings.Contains(csp, directive) {
					t.Errorf("CSP is missing %q; full value: %s", directive, csp)
				}
			}
			// script-src must stay strict: an inline-script escape hatch is
			// what turns a markup injection into code execution, and would
			// defeat the policy entirely.
			if strings.Contains(csp, "unsafe-eval") {
				t.Errorf("CSP must never permit unsafe-eval: %s", csp)
			}
			for _, directive := range strings.Split(csp, ";") {
				directive = strings.TrimSpace(directive)
				if !strings.Contains(directive, "unsafe-inline") {
					continue
				}
				// style-src carries it deliberately, for the terminal
				// renderer; see securityHeaders. Anywhere else is a mistake.
				if !strings.HasPrefix(directive, "style-src ") {
					t.Errorf("unsafe-inline outside style-src: %q", directive)
				}
			}
		})
	}
}

// TestRunShutsDownGracefully covers the SIGTERM path: the listener closes and
// every key held in memory is zeroed.
func TestRunShutsDownGracefully(t *testing.T) {
	cfg := testConfig(t)
	if err := vault.GenerateMasterKeyFile(cfg.Vault.MasterKeyPath); err != nil {
		t.Fatal(err)
	}
	cfg.Server.ShutdownGrace = 5 * time.Second

	s, err := New(context.Background(), cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Park a key in the cache so shutdown has something to clear.
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s.cache.Put("session-1", key)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Give Run time to reach its listener before asking it to stop.
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	if !key.IsZero() {
		t.Error("shutdown left a cached key un-zeroed")
	}
	if !s.master.IsZero() {
		t.Error("shutdown left the master key un-zeroed")
	}
}

// TestRunFailsOnBusyPort checks that a port clash is reported rather than
// silently swallowed, which would leave systemd believing the unit is healthy.
func TestRunFailsOnBusyPort(t *testing.T) {
	first := newTestServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	first.cfg.Server.Bind = ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := first.Run(ctx); err == nil {
		t.Fatal("binding an occupied port must be an error")
	}
}

func TestMigrateOnlyFromScratch(t *testing.T) {
	cfg := testConfig(t)
	cfg.Database.AutoMigrate = false
	ctx := context.Background()

	// The bug this guards: reading the schema version before the bookkeeping
	// table exists.
	if err := MigrateOnly(ctx, cfg, quietLogger()); err != nil {
		t.Fatalf("MigrateOnly on a fresh database: %v", err)
	}
	// And it must be safe to run again.
	if err := MigrateOnly(ctx, cfg, quietLogger()); err != nil {
		t.Fatalf("MigrateOnly second run: %v", err)
	}
}

func TestGenerateMasterKeyRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	if err := GenerateMasterKey(path); err != nil {
		t.Fatal(err)
	}
	if err := GenerateMasterKey(path); err == nil {
		t.Fatal("regenerating a master key would orphan every team credential; it must be refused")
	}
}

// TestAnOverlappingTunnelRangeIsReported.
//
// The shipped default was 34000-34999, which sits inside Linux's ephemeral
// range of 32768-60999 — so the kernel hands those ports out as outbound
// source ports and a tunnel listener intermittently fails to bind against a
// socket bkd cannot see. The symptom is a feature that works nineteen times
// out of twenty, which reads as flakiness rather than as the configuration
// mistake it is.
//
// Found by a test flake in Phase 7, three phases after it shipped.
func TestAnOverlappingTunnelRangeIsReported(t *testing.T) {
	low, high, ok := ephemeralRange()
	if !ok {
		t.Skip("this kernel does not report an ephemeral port range")
	}

	// A range squarely inside it must be reported.
	if warning := describeEphemeralOverlap(low+100, low+200); warning == "" {
		t.Errorf("a range inside %d-%d drew no warning", low, high)
	}

	// One below it must not.
	if low > 2000 {
		if warning := describeEphemeralOverlap(low-1000, low-1); warning != "" {
			t.Errorf("a range below the ephemeral one was reported: %s", warning)
		}
	}

	// And the shipped default must be one of the quiet ones, which is the
	// whole point of having changed it.
	shipped := config.Default()
	shippedLow, shippedHigh, err := config.ParsePortRange(shipped.Tunnels.PortRange)
	if err != nil {
		t.Fatal(err)
	}
	if warning := describeEphemeralOverlap(shippedLow, shippedHigh); warning != "" {
		t.Errorf("the shipped default overlaps the ephemeral range: %s", warning)
	}
}
