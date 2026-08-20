package server

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/portability"
	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"golang.org/x/crypto/ssh"
)

// The bulk-migration path, driven the way an administrator drives it: a real
// database, a real vault, a real configuration file read off disk. Every
// assertion about what was imported is made by reading it back out through
// the same service the interface uses, not by inspecting what was passed in.

const testVaultPassphrase = "a long enough passphrase"

func newTestMigrator(t *testing.T, mutate func(*config.Config)) (*Migrator, config.Config) {
	t.Helper()

	cfg := testConfig(t)
	// Cheap KDF costs: the vault package proves the real ones.
	cfg.Vault.Argon2Time = 1
	cfg.Vault.Argon2MemoryKB = 16 * 1024
	cfg.Vault.Argon2Threads = 1
	if mutate != nil {
		mutate(&cfg)
	}
	if err := vault.GenerateMasterKeyFile(cfg.Vault.MasterKeyPath); err != nil {
		t.Fatal(err)
	}

	mig, err := NewMigrator(context.Background(), cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	t.Cleanup(mig.Close)
	return mig, cfg
}

// enrolledUser creates an account with an open vault, which is the state every
// import needs: the user has signed in once and chosen a passphrase.
func enrolledUser(t *testing.T, mig *Migrator, email string) users.User {
	t.Helper()
	ctx := context.Background()

	u, err := mig.users.Create(ctx, users.CreateParams{
		Email: email, DisplayName: "Test", Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mig.vaults.Enrol(ctx, u, "setup", testVaultPassphrase); err != nil {
		t.Fatal(err)
	}
	mig.vaults.Lock(u.ID, "setup")

	// Re-read: Enrol writes the wrapped key, and a stale copy would make the
	// unlock below look like it worked on a vault that does not exist.
	u, err = mig.users.ByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestTheCommandLineImportsWhatTheBrowserWould runs a SecureCRT configuration
// through the same reader the upload endpoint uses and checks the connections
// land, complete with the password SecureCRT had saved.
func TestTheCommandLineImportsWhatTheBrowserWould(t *testing.T) {
	mig, _ := newTestMigrator(t, nil)
	ctx := context.Background()
	enrolledUser(t, mig, "alice@example.com")

	u, key, err := mig.Open(ctx, "alice@example.com", testVaultPassphrase)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}

	imported, err := portability.ReadUpload(portability.SourceSecureCRT, "securecrt.zip",
		secureCRTArchive(t), portability.UploadOptions{})
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}

	// The plan first, and nothing written by it.
	plan, err := mig.Preview(ctx, u, imported.Payload, portability.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Counts.Sessions != 2 {
		t.Fatalf("the plan lists %d connections, want 2", plan.Counts.Sessions)
	}
	if !plan.HasSecrets {
		t.Error("the plan does not report that a password came across")
	}

	if got := storedSessions(t, mig, u.ID); got != 0 {
		t.Fatalf("previewing wrote %d connections", got)
	}

	result, err := mig.Import(ctx, u, key, imported.Payload,
		portability.ImportOptions{}, imported.Source)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Sessions != 2 {
		t.Errorf("imported %d connections, want 2", result.Sessions)
	}

	if got := storedSessions(t, mig, u.ID); got != 2 {
		t.Fatalf("the database holds %d connections, want 2", got)
	}
}

// TestTheRoundTripThroughTheCommandLine is the migration this whole phase is
// for, done the way an administrator would do it for eighty people: export
// one account to an encrypted bundle, import it into a second account on a
// second instance, and check the connections and the key material survived.
func TestTheRoundTripThroughTheCommandLine(t *testing.T) {
	ctx := context.Background()

	source, _ := newTestMigrator(t, nil)
	sourceUser := enrolledUser(t, source, "alice@example.com")

	u, key, err := source.Open(ctx, sourceUser.Email, testVaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := portability.ReadUpload(portability.SourceSecureCRT, "securecrt.zip",
		secureCRTArchive(t), portability.UploadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Import(ctx, u, key, imported.Payload,
		portability.ImportOptions{}, imported.Source); err != nil {
		t.Fatal(err)
	}

	var bundle bytes.Buffer
	if _, err := source.Export(ctx, u, key, ExportRequest{
		Format:            portability.FormatBundle,
		BundlePassphrase:  "a bundle passphrase",
		IncludeSecrets:    true,
		IncludeKnownHosts: true,
	}, &bundle); err != nil {
		t.Fatalf("export: %v", err)
	}

	// A second instance: its own database, its own master key. Nothing but
	// the bundle and its passphrase crosses between them.
	destination, _ := newTestMigrator(t, nil)
	destinationUser := enrolledUser(t, destination, "bob@example.com")

	bob, bobKey, err := destination.Open(ctx, destinationUser.Email, testVaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	arrived, err := portability.ReadUpload(portability.SourceBundle, "export.bkbundle",
		bundle.Bytes(), portability.UploadOptions{BundlePassphrase: "a bundle passphrase"})
	if err != nil {
		t.Fatalf("reading the bundle on the second instance: %v", err)
	}

	result, err := destination.Import(ctx, bob, bobKey, arrived.Payload,
		portability.ImportOptions{}, arrived.Source)
	if err != nil {
		t.Fatalf("import on the second instance: %v", err)
	}
	if result.Sessions != 2 {
		t.Errorf("arrived with %d connections, want 2", result.Sessions)
	}
	if result.Credentials < 1 {
		t.Errorf("arrived with %d credentials, want at least 1", result.Credentials)
	}

	// The password SecureCRT had saved must still be the password, on a
	// machine that has never seen the first instance's master key.
	secrets := storedSecrets(t, destination, bobKey, bob.ID)
	if !containsValue(secrets, "hunter2") {
		t.Errorf("the saved password did not survive the round trip; got %d secrets",
			len(secrets))
	}
}

// TestAWrongVaultPassphraseIsRefused, and says so rather than failing later
// with something about a decryption error.
func TestAWrongVaultPassphraseIsRefused(t *testing.T) {
	mig, _ := newTestMigrator(t, nil)
	enrolledUser(t, mig, "alice@example.com")

	_, _, err := mig.Open(context.Background(), "alice@example.com", "not the passphrase")
	if err == nil {
		t.Fatal("a wrong passphrase opened the vault")
	}
	if !strings.Contains(err.Error(), "did not open") {
		t.Errorf("error = %v, want it to name the problem", err)
	}
}

// TestAnAccountWithNoVaultTakesConnectionsButNotSecrets is the shape a bulk
// pre-load actually has: an administrator can push the device tree for a team
// of eighty on day one, because a vault key can only come from a passphrase
// each of those eighty people has not chosen yet. What must not happen is the
// secrets being dropped quietly — an import asked to carry them and unable to
// is refused, not silently thinned out.
func TestAnAccountWithNoVaultTakesConnectionsButNotSecrets(t *testing.T) {
	ctx := context.Background()
	mig, _ := newTestMigrator(t, nil)

	if _, err := mig.users.Create(ctx, users.CreateParams{
		Email: "new@example.com", Password: "correct horse battery staple",
	}); err != nil {
		t.Fatal(err)
	}

	u, key, err := mig.Open(ctx, "new@example.com", "")
	if err != nil {
		t.Fatalf("opening an account with no vault: %v", err)
	}
	if key != nil {
		t.Fatal("an account with no vault produced a key")
	}

	imported, err := portability.ReadUpload(portability.SourceSecureCRT, "securecrt.zip",
		secureCRTArchive(t), portability.UploadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// As read, this carries a password — so it is refused.
	if _, err := mig.Import(ctx, u, key, imported.Payload,
		portability.ImportOptions{}, imported.Source); err == nil {
		t.Fatal("credentials were imported into an account with no vault")
	} else if !strings.Contains(err.Error(), "no open vault") {
		t.Errorf("error = %v, want it to explain what is missing", err)
	}
	if got := storedSessions(t, mig, u.ID); got != 0 {
		t.Fatalf("the refused import still wrote %d connections", got)
	}

	// Without the secrets, the connections land.
	imported.Payload.Credentials = nil
	for i := range imported.Payload.Sessions {
		imported.Payload.Sessions[i].CredentialID = ""
	}

	result, err := mig.Import(ctx, u, key, imported.Payload,
		portability.ImportOptions{}, imported.Source)
	if err != nil {
		t.Fatalf("importing connections alone: %v", err)
	}
	if result.Sessions != 2 {
		t.Errorf("imported %d connections, want 2", result.Sessions)
	}
	if got := storedSessions(t, mig, u.ID); got != 2 {
		t.Errorf("the database holds %d connections, want 2", got)
	}
}

func TestAnUnknownAccountIsNamed(t *testing.T) {
	mig, _ := newTestMigrator(t, nil)

	_, _, err := mig.Open(context.Background(), "nobody@example.com", testVaultPassphrase)
	if err == nil || !strings.Contains(err.Error(), "nobody@example.com") {
		t.Fatalf("error = %v, want it to name the account", err)
	}
}

// TestPlaintextExportObeysThePolicySwitch. An administrator with shell access
// can read the database anyway — but "the policy said no" must not depend on
// which door the request came through, or the switch means nothing.
func TestPlaintextExportObeysThePolicySwitch(t *testing.T) {
	ctx := context.Background()

	mig, _ := newTestMigrator(t, func(c *config.Config) {
		c.Policy.AllowPlaintextExport = false
	})
	enrolledUser(t, mig, "alice@example.com")
	u, key, err := mig.Open(ctx, "alice@example.com", testVaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	_, err = mig.Export(ctx, u, key, ExportRequest{
		Format: portability.FormatJSON, IncludeSecrets: true, Confirm: true,
	}, &out)
	if err == nil {
		t.Fatal("a plaintext export was written with the policy switch off")
	}
	if !strings.Contains(err.Error(), "allow_plaintext_export") {
		t.Errorf("error = %v, want it to name the setting", err)
	}
	if out.Len() > 0 {
		t.Errorf("%d bytes were written despite the refusal", out.Len())
	}
}

// TestPlaintextExportNeedsAnExplicitConfirmation even when policy allows it.
func TestPlaintextExportNeedsAnExplicitConfirmation(t *testing.T) {
	ctx := context.Background()

	mig, _ := newTestMigrator(t, func(c *config.Config) {
		c.Policy.AllowPlaintextExport = true
	})
	enrolledUser(t, mig, "alice@example.com")
	u, key, err := mig.Open(ctx, "alice@example.com", testVaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if _, err := mig.Export(ctx, u, key, ExportRequest{
		Format: portability.FormatJSON, IncludeSecrets: true,
	}, &out); err == nil {
		t.Fatal("a plaintext export went ahead without confirmation")
	}

	// And with it, the same call succeeds — otherwise this test would pass
	// against a build where plaintext export simply never worked.
	out.Reset()
	if _, err := mig.Export(ctx, u, key, ExportRequest{
		Format: portability.FormatJSON, IncludeSecrets: true, Confirm: true,
	}, &out); err != nil {
		t.Fatalf("a confirmed plaintext export was refused: %v", err)
	}
	if out.Len() == 0 {
		t.Error("the confirmed export wrote nothing")
	}
}

// TestABundleNeedsALongPassphrase. Nothing but that passphrase protects the
// file, so a short one is refused before the file exists rather than after.
func TestABundleNeedsALongPassphrase(t *testing.T) {
	ctx := context.Background()

	mig, _ := newTestMigrator(t, nil)
	enrolledUser(t, mig, "alice@example.com")
	u, key, err := mig.Open(ctx, "alice@example.com", testVaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if _, err := mig.Export(ctx, u, key, ExportRequest{
		Format: portability.FormatBundle, BundlePassphrase: "short",
		IncludeSecrets: true,
	}, &out); err == nil {
		t.Fatal("a bundle was written under a five-character passphrase")
	}
	if out.Len() > 0 {
		t.Errorf("%d bytes were written despite the refusal", out.Len())
	}
}

// TestPuTTYKeysArriveThroughTheCommandLine: the migration that used to need
// PuTTYgen and a lot of clicking.
func TestPuTTYKeysArriveThroughTheCommandLine(t *testing.T) {
	ctx := context.Background()

	mig, _ := newTestMigrator(t, nil)
	enrolledUser(t, mig, "alice@example.com")
	u, key, err := mig.Open(ctx, "alice@example.com", testVaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := portability.ReadUpload(portability.SourcePuTTY, "putty.zip",
		puttyArchive(t), portability.UploadOptions{})
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}

	result, err := mig.Import(ctx, u, key, imported.Payload,
		portability.ImportOptions{}, imported.Source)
	if err != nil {
		t.Fatal(err)
	}
	if result.Credentials != 1 {
		t.Fatalf("imported %d credentials, want the one key: %v",
			result.Credentials, imported.Warnings)
	}

	secrets := storedSecrets(t, mig, key, u.ID)

	var found bool
	for _, secret := range secrets {
		if signer, err := ssh.ParsePrivateKey([]byte(secret)); err == nil {
			found = true
			if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
				t.Errorf("stored key is %s", signer.PublicKey().Type())
			}
		}
	}
	if !found {
		t.Error("no usable OpenSSH private key was stored")
	}
}

// storedSessions counts what is actually in the database, rather than what
// the import reported putting there.
func storedSessions(t *testing.T, mig *Migrator, ownerID string) int {
	t.Helper()

	tree, err := sessions.NewStore(mig.db).LoadTree(context.Background(), ownerID, false)
	if err != nil {
		t.Fatal(err)
	}
	return len(tree.Sessions)
}

// storedSecrets decrypts every credential the account owns, which is the only
// way to prove key material survived rather than merely a row.
func storedSecrets(t *testing.T, mig *Migrator, key vault.Key, ownerID string) []string {
	t.Helper()
	ctx := context.Background()

	store := credentials.NewStore(mig.db)
	list, err := store.List(ctx, ownerID, false)
	if err != nil {
		t.Fatal(err)
	}

	var out []string
	for _, credential := range list {
		secret, err := store.Reveal(ctx, key, ownerID, credential.ID)
		if err != nil {
			t.Fatalf("revealing %s: %v", credential.Name, err)
		}
		out = append(out, secret.Value)
	}
	return out
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// --- fixtures ----------------------------------------------------------------

// secureCRTArchive builds the zip a migrating user would upload: a SecureCRT
// configuration folder with two sessions, one of them carrying a password
// encrypted the way SecureCRT encrypts them.
func secureCRTArchive(t *testing.T) []byte {
	t.Helper()

	encoded, err := securecrt.EncryptV2("hunter2", "")
	if err != nil {
		t.Fatal(err)
	}

	return zipOf(t, map[string][]byte{
		"Config/Sessions/core-sw-01.ini": []byte(
			`S:"Protocol Name"=SSH2` + "\n" +
				`S:"Hostname"=10.0.0.1` + "\n" +
				`S:"Username"=netops` + "\n" +
				`D:"[SSH2] Port"=00000016` + "\n" +
				`S:"Password V2"=` + encoded + "\n"),
		"Config/Sessions/Edge routers/edge-01.ini": []byte(
			`S:"Hostname"=10.0.1.1` + "\n" + `S:"Username"=admin` + "\n"),
	})
}

// puttyArchive builds a zip of a .putty directory carrying a real .ppk, the
// one produced by puttygen for the ppk package's own tests.
func puttyArchive(t *testing.T) []byte {
	t.Helper()

	key, err := os.ReadFile(filepath.Join("..", "portability", "ppk", "testdata", "v3-ed25519.ppk"))
	if err != nil {
		t.Fatal(err)
	}

	return zipOf(t, map[string][]byte{
		"putty/sessions/core%20switch": []byte(
			"HostName=10.0.0.1\nPortNumber=22\nUserName=netops\nProtocol=ssh\n" +
				`PublicKeyFile=C:\Users\netops\core.ppk` + "\n"),
		"putty/core.ppk": key,
	})
}

func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)

	// Sorted, so a fixture is byte-identical between runs and a failure is
	// never about map iteration order.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
