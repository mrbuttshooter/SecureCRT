package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/mrbuttshooter/securecrt/internal/portability"
	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"

	"github.com/mrbuttshooter/securecrt/internal/config"
)

// The import and export surface, driven the way a browser drives it: a
// multipart upload, a preview, then a commit — through the whole stack.

// --- helpers -----------------------------------------------------------------

// previewUpload performs the multipart preview request.
func (h *harness) previewUpload(t *testing.T, filename string, contents []byte, fields map[string]string) (*http.Response, map[string]any) {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/portability/preview", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp := h.send(t, req)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("preview response is not JSON: %v (%q)", err, raw)
		}
	}
	return resp, decoded
}

// zipOf builds a zip archive from a map of paths to contents.
func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)

	for name, contents := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// secureCRTZip builds a configuration folder as a desktop would zip it: with
// everything under one top-level directory.
func secureCRTZip(t *testing.T, password string) []byte {
	t.Helper()

	encoded, err := securecrt.EncryptV2(password, "")
	if err != nil {
		t.Fatal(err)
	}

	return zipOf(t, map[string]string{
		"Config/Sessions/core-sw-01.ini": `S:"Protocol Name"=SSH2` + "\n" +
			`S:"Hostname"=10.0.0.1` + "\n" + `S:"Username"=netops` + "\n" +
			`D:"[SSH2] Port"=00000016` + "\n" + `S:"Password V2"=` + encoded + "\n",
		"Config/Sessions/Edge routers/edge-01.ini": `S:"Hostname"=10.0.1.1` + "\n" +
			`S:"Username"=admin` + "\n",
		"Config/Global.ini": `S:"Something"=global` + "\n",
	})
}

// exportFile performs an export and returns the body and headers.
func (h *harness) exportFile(t *testing.T, body map[string]any) (*http.Response, []byte) {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/api/portability/export",
		bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp := h.send(t, req)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

// --- import ------------------------------------------------------------------

// TestImportSecureCRTThroughTheAPI is the journey a migrating team takes:
// zip the configuration folder, upload it, read what would happen, commit.
func TestImportSecureCRTThroughTheAPI(t *testing.T) {
	h := signedInWithVault(t)

	resp, preview := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d: %v", resp.StatusCode, preview)
	}

	plan, _ := preview["plan"].(map[string]any)
	newSessions, _ := plan["new_sessions"].([]any)
	if len(newSessions) != 2 {
		t.Fatalf("the plan lists %d new connections, want 2: %v", len(newSessions), plan)
	}
	if hasSecrets, _ := plan["has_secrets"].(bool); !hasSecrets {
		t.Error("the plan does not report that a password came across")
	}

	// Previewing must not have written anything.
	_, tree := h.get("/api/tree")
	if sessions, _ := tree["sessions"].([]any); len(sessions) != 0 {
		t.Fatal("previewing an import created connections")
	}

	token, _ := preview["token"].(string)
	if token == "" {
		t.Fatalf("no staging token: %v", preview)
	}

	resp, committed := h.post("/api/portability/import", map[string]any{"token": token})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("commit = %d: %v", resp.StatusCode, committed)
	}

	result, _ := committed["result"].(map[string]any)
	if sessions, _ := result["sessions"].(float64); int(sessions) != 2 {
		t.Errorf("imported %v connections", result["sessions"])
	}
	if credentials, _ := result["credentials"].(float64); int(credentials) != 1 {
		t.Errorf("imported %v credentials", result["credentials"])
	}

	// And the connections are really there, with their folder.
	_, tree = h.get("/api/tree")
	sessions, _ := tree["sessions"].([]any)
	folders, _ := tree["folders"].([]any)
	if len(sessions) != 2 || len(folders) != 1 {
		t.Errorf("after importing: %d connections, %d folders", len(sessions), len(folders))
	}
}

// TestAPreviewCanOnlyBeCommittedOnce: a user pressing the button twice on a
// slow connection must not get two copies of their device list.
func TestAPreviewCanOnlyBeCommittedOnce(t *testing.T) {
	h := signedInWithVault(t)

	_, preview := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})
	token, _ := preview["token"].(string)

	if resp, _ := h.post("/api/portability/import", map[string]any{"token": token}); resp.StatusCode != http.StatusOK {
		t.Fatalf("first commit = %d", resp.StatusCode)
	}

	resp, body := h.post("/api/portability/import", map[string]any{"token": token})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second commit = %d, want 404: %v", resp.StatusCode, body)
	}

	_, tree := h.get("/api/tree")
	if sessions, _ := tree["sessions"].([]any); len(sessions) != 2 {
		t.Errorf("%d connections after committing twice, want 2", len(sessions))
	}
}

// TestAPreviewBelongsToItsOwner: a staging token is a handle on somebody's
// decrypted passwords.
func TestAPreviewBelongsToItsOwner(t *testing.T) {
	h := signedInWithVault(t)

	_, preview := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})
	token, _ := preview["token"].(string)

	h.createLocalUser("mallory@example.com", "correct horse battery staple", false)
	h.cookies = map[string]string{}
	h.csrf = ""
	h.get("/api/auth/config")
	h.login("mallory@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "another long passphrase"})

	resp, body := h.post("/api/portability/import", map[string]any{"token": token})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another user committed the preview: %d %v", resp.StatusCode, body)
	}

	_, tree := h.get("/api/tree")
	if sessions, _ := tree["sessions"].([]any); len(sessions) != 0 {
		t.Errorf("another user's tree gained %d connections", len(sessions))
	}
}

func TestDiscardingAPreview(t *testing.T) {
	h := signedInWithVault(t)

	_, preview := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})
	token, _ := preview["token"].(string)

	if resp, _ := h.do(http.MethodDelete, "/api/portability/staged/"+token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("discard = %d", resp.StatusCode)
	}
	if resp, _ := h.post("/api/portability/import", map[string]any{"token": token}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a discarded preview was still committable: %d", resp.StatusCode)
	}
}

// TestZipsFromADesktopAreUnderstood: zipping a folder puts everything under
// one directory, so without stripping it the readers would look one level too
// high and find nothing.
func TestZipsFromADesktopAreUnderstood(t *testing.T) {
	h := signedInWithVault(t)

	// With the wrapping directory, as a desktop produces.
	resp, preview := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d: %v", resp.StatusCode, preview)
	}
	plan, _ := preview["plan"].(map[string]any)
	if sessions, _ := plan["new_sessions"].([]any); len(sessions) != 2 {
		t.Errorf("a zipped folder yielded %d connections", len(sessions))
	}

	// And without it, as zipping the contents produces.
	flat := zipOf(t, map[string]string{
		"Sessions/core-sw-01.ini": `S:"Hostname"=10.0.0.1` + "\n",
	})
	resp, preview = h.previewUpload(t, "flat.zip", flat, map[string]string{"source": "securecrt"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d: %v", resp.StatusCode, preview)
	}
	plan, _ = preview["plan"].(map[string]any)
	if sessions, _ := plan["new_sessions"].([]any); len(sessions) != 1 {
		t.Errorf("a flat zip yielded %d connections", len(sessions))
	}
}

func TestUploadingSomethingThatIsNotAnArchive(t *testing.T) {
	h := signedInWithVault(t)

	resp, body := h.previewUpload(t, "holiday.jpg", []byte("\xff\xd8\xff\xe0not a zip"),
		map[string]string{"source": "securecrt"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("= %d, want 400: %v", resp.StatusCode, body)
	}
	if message := errorMessage(body); !strings.Contains(message, "zip") {
		t.Errorf("the message does not say what to upload: %q", message)
	}
}

func TestUploadingABundleThroughTheAPI(t *testing.T) {
	h := signedInWithVault(t)

	payload := portability.Payload{
		Sessions: []portability.Session{
			{ID: "s1", Name: "restored", Protocol: "ssh", Hostname: "10.0.0.9", Port: 22},
		},
		Credentials: []portability.Credential{
			{ID: "c1", Name: "restored password", Kind: "password", Secret: "hunter2"},
		},
	}

	var bundle bytes.Buffer
	if err := portability.Write(&bundle, payload, portability.WriteOptions{
		Passphrase: []byte("a long enough bundle passphrase"),
	}); err != nil {
		t.Fatal(err)
	}

	// The wrong passphrase is refused, and says so rather than blaming the
	// file.
	resp, body := h.previewUpload(t, "connections.bkbundle", bundle.Bytes(), map[string]string{
		"source": "bundle", "passphrase": "not the right one",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong passphrase = %d, want 403: %v", resp.StatusCode, body)
	}
	if message := errorMessage(body); !strings.Contains(message, "passphrase") {
		t.Errorf("the message does not name the problem: %q", message)
	}

	// And the right one opens it.
	resp, preview := h.previewUpload(t, "connections.bkbundle", bundle.Bytes(), map[string]string{
		"source": "bundle", "passphrase": "a long enough bundle passphrase",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d: %v", resp.StatusCode, preview)
	}

	token, _ := preview["token"].(string)
	if resp, body := h.post("/api/portability/import", map[string]any{"token": token}); resp.StatusCode != http.StatusOK {
		t.Fatalf("commit = %d: %v", resp.StatusCode, body)
	}

	_, tree := h.get("/api/tree")
	if sessions, _ := tree["sessions"].([]any); len(sessions) != 1 {
		t.Errorf("restored %d connections", len(sessions))
	}
}

// TestLockingTheVaultDiscardsStagedImports: a staged payload holds decrypted
// passwords, so locking has to take those with it — otherwise "lock" would
// leave the most sensitive thing the process is holding exactly where it was.
func TestLockingTheVaultDiscardsStagedImports(t *testing.T) {
	h := signedInWithVault(t)

	_, preview := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})
	token, _ := preview["token"].(string)

	h.post("/api/vault/lock", nil)

	// Reported as gone rather than as blocked by the lock: it really is gone,
	// and saying "unlock and try again" would be a lie the user would follow.
	resp, body := h.post("/api/portability/import", map[string]any{"token": token})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("= %d, want 404: %v", resp.StatusCode, body)
	}
	if message := errorMessage(body); !strings.Contains(message, "again") {
		t.Errorf("the message does not say what to do: %q", message)
	}

	// And after unlocking, it is still gone: the payload was dropped, not
	// merely hidden.
	h.post("/api/vault/unlock", map[string]string{"passphrase": "a long enough passphrase"})
	if resp, _ := h.post("/api/portability/import", map[string]any{"token": token}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("the staged payload survived the lock: %d", resp.StatusCode)
	}

	_, tree := h.get("/api/tree")
	if sessions, _ := tree["sessions"].([]any); len(sessions) != 0 {
		t.Errorf("%d connections were imported anyway", len(sessions))
	}
}

func TestImportEndpointsRequireAuthentication(t *testing.T) {
	h := newHarness(t, nil)

	resp, _ := h.post("/api/portability/import", map[string]any{"token": "anything"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("commit without a session = %d, want 401", resp.StatusCode)
	}
	resp, _ = h.get("/api/portability/config")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("config without a session = %d, want 401", resp.StatusCode)
	}
}

// --- export ------------------------------------------------------------------

// TestExportBundleThroughTheAPI exports and then re-imports, so the file is
// proved by use rather than by inspection.
func TestExportBundleThroughTheAPI(t *testing.T) {
	h := signedInWithVault(t)

	// Something to export.
	_, cred := h.post("/api/credentials", map[string]string{
		"name": "console password", "kind": "password", "secret": "hunter2",
	})
	credID, _ := cred["id"].(string)
	h.post("/api/tree/sessions", map[string]any{
		"name": "core-sw-01", "hostname": "10.0.0.1", "port": 22,
		"username": "netops", "credential_id": credID,
	})

	resp, file := h.exportFile(t, map[string]any{
		"format": "bundle", "include_secrets": true,
		"passphrase": "a long enough bundle passphrase",
		"note":       "before the migration",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d: %s", resp.StatusCode, file)
	}

	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(got, "connections.bkbundle") {
		t.Errorf("Content-Disposition = %q", got)
	}
	// This response is the user's entire credential store; a copy in a proxy
	// or a disk cache is exactly what the encryption was for.
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q", got)
	}

	// Nothing readable in the file.
	if bytes.Contains(file, []byte("hunter2")) || bytes.Contains(file, []byte("10.0.0.1")) {
		t.Error("the bundle contains readable secrets")
	}

	// It opens, and it carries what it should.
	bundle, err := portability.Read(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("the exported bundle does not read: %v", err)
	}
	if bundle.Header.Note != "before the migration" {
		t.Errorf("note = %q", bundle.Header.Note)
	}
	if bundle.Header.CreatedBy == "" {
		t.Error("the bundle does not say who made it")
	}

	payload, err := bundle.Open([]byte("a long enough bundle passphrase"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(payload.Sessions) != 1 || payload.Credentials[0].Secret != "hunter2" {
		t.Errorf("payload = %+v", payload)
	}
}

func TestExportBundleNeedsALongPassphrase(t *testing.T) {
	h := signedInWithVault(t)

	resp, body := h.exportFile(t, map[string]any{
		"format": "bundle", "passphrase": "short",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("= %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(string(body), "at least") {
		t.Errorf("the message does not say what is required: %s", body)
	}
}

// TestPlaintextExportIsRefusedWhenDisabled is the gate the policy switch
// exists for.
func TestPlaintextExportIsRefusedWhenDisabled(t *testing.T) {
	h := signedInWithVault(t) // the default configuration disables it

	for _, format := range []string{"ssh_config", "json", "csv", "securecrt", "putty_reg"} {
		resp, body := h.exportFile(t, map[string]any{
			"format": format, "confirm": true,
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s = %d, want 403: %s", format, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "disabled") {
			t.Errorf("%s: the message does not say why: %s", format, body)
		}
	}

	// The encrypted bundle is unaffected — it is not plaintext, and refusing
	// it would leave a user with no way out at all.
	resp, _ := h.exportFile(t, map[string]any{
		"format": "bundle", "passphrase": "a long enough bundle passphrase",
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the encrypted bundle was refused too: %d", resp.StatusCode)
	}
}

// TestPlaintextExportNeedsAnExplicitConfirmation.
func TestPlaintextExportNeedsAnExplicitConfirmation(t *testing.T) {
	h := signedInWithVault(t, allowPlaintextExport)

	resp, body := h.exportFile(t, map[string]any{"format": "json"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("without confirmation = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "not encrypted") {
		t.Errorf("the message does not say what is at stake: %s", body)
	}

	resp, _ = h.exportFile(t, map[string]any{"format": "json", "confirm": true})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with confirmation = %d", resp.StatusCode)
	}
}

// TestPlaintextExportIsAudited: the most security-relevant action in the
// system, and the one an investigation starts from.
func TestPlaintextExportIsAudited(t *testing.T) {
	h := signedInWithVault(t, allowPlaintextExport)

	h.post("/api/credentials", map[string]string{
		"name": "console password", "kind": "password", "secret": "hunter2",
	})

	resp, _ := h.exportFile(t, map[string]any{
		"format": "json", "include_secrets": true, "confirm": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d", resp.StatusCode)
	}

	var action, severity string
	row := h.db.QueryRow(t.Context(),
		`SELECT action, severity FROM audit_events WHERE action = ? ORDER BY occurred_at DESC LIMIT 1`,
		"portability.exported_plaintext")
	if err := row.Scan(&action, &severity); err != nil {
		t.Fatalf("no plaintext-export event was recorded: %v", err)
	}
	if severity != "critical" {
		t.Errorf("severity = %q, want critical", severity)
	}
}

func TestExportWithSecretsNeedsAnUnlockedVault(t *testing.T) {
	h := signedInWithVault(t)
	h.post("/api/vault/lock", nil)

	resp, body := h.exportFile(t, map[string]any{
		"format": "bundle", "include_secrets": true,
		"passphrase": "a long enough bundle passphrase",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("= %d, want 403: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "locked") {
		t.Errorf("the message does not explain what to do: %s", body)
	}
}

// TestExportReportsWhatAFormatCouldNotExpress.
func TestExportReportsWhatAFormatCouldNotExpress(t *testing.T) {
	h := signedInWithVault(t, allowPlaintextExport)

	_, cred := h.post("/api/credentials", map[string]string{
		"name": "console password", "kind": "password", "secret": "hunter2",
	})
	credID, _ := cred["id"].(string)
	h.post("/api/tree/sessions", map[string]any{
		"name": "console", "hostname": "10.1.0.1", "protocol": "telnet", "port": 23,
		"credential_id": credID,
	})

	resp, _ := h.exportFile(t, map[string]any{"format": "ssh_config", "confirm": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("= %d", resp.StatusCode)
	}

	warnings := resp.Header.Get("X-Export-Warnings")
	if !strings.Contains(warnings, "not SSH") {
		t.Errorf("the Telnet connection was dropped without saying so: %q", warnings)
	}
	if !strings.Contains(warnings, "Passwords cannot be expressed") {
		t.Errorf("the password was dropped without saying so: %q", warnings)
	}
}

func TestPortabilityConfigDescribesWhatIsAvailable(t *testing.T) {
	h := signedInWithVault(t)

	_, body := h.get("/api/portability/config")
	if allowed, _ := body["allow_plaintext_export"].(bool); allowed {
		t.Error("the default configuration reports plaintext export as allowed")
	}
	if length, _ := body["min_passphrase_length"].(float64); int(length) != portability.MinPassphraseLength {
		t.Errorf("min passphrase length = %v", body["min_passphrase_length"])
	}
	if sources, _ := body["sources"].([]any); len(sources) < 5 {
		t.Errorf("sources = %v", body["sources"])
	}
}

// TestAnOversizedImportIsRefusedBeforeItReachesTheDisk covers the gap that
// ParseMultipartForm leaves open on its own.
//
// Its argument bounds only what is held in memory; everything beyond that
// spills to the server's temporary directory. So the in-memory limit turned
// "too big to buffer" into "written to disk anyway", and a long enough upload
// filled the filesystem before any handler had looked at a single byte.
func TestAnOversizedImportIsRefusedBeforeItReachesTheDisk(t *testing.T) {
	const limit = 1 << 10 // the smallest the configuration allows

	h := signedInWithVault(t, func(c *config.Config) {
		c.Policy.MaxImportBytes = limit
	})

	// Comfortably past the framing headroom as well as the limit itself, so
	// this is refused by MaxBytesReader rather than by the later per-file
	// check — the whole point is that nothing is spooled first.
	oversized := bytes.Repeat([]byte("S:\"Hostname\"=host\r\n"), 200_000)

	resp, body := h.previewUpload(t, "Session.ini", oversized,
		map[string]string{"source": "securecrt"})

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("preview of %d bytes against a %d byte limit = %d, want 413",
			len(oversized), limit, resp.StatusCode)
	}

	// Pinned to the size message rather than just the status: the contents
	// are deliberately not a valid archive, so a run without the cap would
	// reject them for the wrong reason and the failure should say so.
	failure, _ := body["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "larger than") {
		t.Fatalf("refused with %q, want the message about size", message)
	}
}

// TestAnImportInsideTheLimitStillWorks: the cap must refuse what is over it
// without breaking what is under it.
func TestAnImportInsideTheLimitStillWorks(t *testing.T) {
	h := signedInWithVault(t, func(c *config.Config) {
		c.Policy.MaxImportBytes = 64 << 10
	})

	resp, body := h.previewUpload(t, "securecrt.zip", secureCRTZip(t, "hunter2"),
		map[string]string{"source": "securecrt"})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d: %v", resp.StatusCode, body)
	}
	if body["token"] == "" || body["token"] == nil {
		t.Fatalf("no staging token was issued: %v", body)
	}
}
