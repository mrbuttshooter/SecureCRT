package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"github.com/mrbuttshooter/securecrt/internal/config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The file browser, driven through the whole stack: HTTP, authentication,
// MFA, the vault, the shared connection pool, SSH and a real SFTP server
// serving a real directory. Every assertion about a file ends at a syscall
// against a temporary directory the test can look at directly.

// --- a real SFTP host --------------------------------------------------------

type sftpTestServer struct {
	Host string
	Port int
	Root string
}

func startSFTP(t *testing.T, password string) *sftpTestServer {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	srv := &gssh.Server{
		HostSigners:     []gssh.Signer{signer},
		PasswordHandler: func(_ gssh.Context, given string) bool { return given == password },
		SubsystemHandlers: map[string]gssh.SubsystemHandler{
			"sftp": func(s gssh.Session) {
				server, err := sftp.NewServer(s)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				_ = server.Serve()
			},
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	return &sftpTestServer{Host: host, Port: port, Root: t.TempDir()}
}

// savedSFTPConnection stores a credential and a saved connection for a host.
func (h *harness) savedSFTPConnection(t *testing.T, srv *sftpTestServer, name, password string) string {
	t.Helper()

	_, cred := h.post("/api/credentials", map[string]string{
		"name": name + " password", "kind": "password", "secret": password,
	})
	credID, _ := cred["id"].(string)
	if credID == "" {
		t.Fatalf("no credential was created: %v", cred)
	}

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": name, "hostname": srv.Host, "port": srv.Port,
		"username": "alice", "credential_id": credID,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the saved connection failed: %d %v", resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// openFiles opens a file session, answering the host key prompt on first
// contact the way the interface does.
func (h *harness) openFiles(t *testing.T, sessionID string) map[string]any {
	t.Helper()

	resp, body := h.post("/api/files/sessions?session="+sessionID, nil)

	if resp.StatusCode == http.StatusConflict {
		errBody, _ := body["error"].(map[string]any)
		hostKey, _ := errBody["host_key"].(map[string]any)
		fingerprint, _ := hostKey["fingerprint"].(string)
		if fingerprint == "" {
			t.Fatalf("the prompt carried no fingerprint to confirm: %v", body)
		}
		resp, body = h.post("/api/files/sessions?session="+sessionID+
			"&accept_host_key="+url.QueryEscape(fingerprint), nil)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("opening a file session failed: %d %v", resp.StatusCode, body)
	}
	return body
}

// --- tests -------------------------------------------------------------------

func TestFileSessionOpensAndReportsHome(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")

	body := h.openFiles(t, sessionID)

	if home, _ := body["home"].(string); home == "" || !strings.HasPrefix(home, "/") {
		t.Errorf("home = %v, want an absolute path", body["home"])
	}
	if label, _ := body["label"].(string); label != "files host" {
		t.Errorf("label = %v", body["label"])
	}

	_, list := h.get("/api/files/sessions")
	sessions, _ := list["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("%d file sessions are open, want 1", len(sessions))
	}
}

func TestListingADirectory(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	writeAt(t, srv, "notes.txt", "some notes")
	mkdirAt(t, srv, "subdir")

	resp, body := h.get("/api/files/list?session=" + sessionID + "&path=" + srv.Root)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list failed: %d %v", resp.StatusCode, body)
	}

	entries, _ := body["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("listed %d entries, want 2", len(entries))
	}

	// Directories first, so the interface does not have to re-sort.
	first, _ := entries[0].(map[string]any)
	if name, _ := first["name"].(string); name != "subdir" {
		t.Errorf("first entry = %v, want subdir", first["name"])
	}
	if isDir, _ := first["is_dir"].(bool); !isDir {
		t.Error("subdir was not reported as a directory")
	}

	second, _ := entries[1].(map[string]any)
	if size, _ := second["size"].(float64); int(size) != len("some notes") {
		t.Errorf("size = %v, want %d", second["size"], len("some notes"))
	}
	if mode, _ := second["mode"].(string); mode == "" {
		t.Error("no mode was reported")
	}
}

func TestListingAMissingDirectoryIsNotFound(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	resp, _ := h.get("/api/files/list?session=" + sessionID + "&path=" + srv.Root + "/absent")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("listing a missing directory = %d, want 404", resp.StatusCode)
	}
}

func TestUploadThenDownloadRoundTrips(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	// Larger than one SFTP packet, so the transfer spans many requests and
	// any offset mistake shows up as corruption.
	payload := make([]byte, 200*1024)
	for i := range payload {
		payload[i] = byte(i * 31 % 251)
	}

	target := path.Join(srv.Root, "payload.bin")
	resp := h.upload(t, sessionID, target, 0, payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload failed: %d", resp.StatusCode)
	}

	// It landed on disk, byte for byte.
	if got := readAtBytes(t, srv, "payload.bin"); !bytes.Equal(got, payload) {
		t.Fatalf("the file on disk is %d bytes, %d were sent", len(got), len(payload))
	}

	// And comes back the same way.
	body, headers := h.download(t, sessionID, target, "")
	if !bytes.Equal(body, payload) {
		t.Errorf("the download is %d bytes, %d were uploaded", len(body), len(payload))
	}
	if got := headers.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
		t.Errorf("Content-Length = %q, want %d", got, len(payload))
	}
}

// TestDownloadIsAlwaysAnAttachment: a file fetched from a managed host must
// never render in this origin. An HTML or SVG payload displayed inline would
// execute as though this application had served it.
func TestDownloadIsAlwaysAnAttachment(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	writeAt(t, srv, "evil.html", "<script>alert(document.cookie)</script>")

	_, headers := h.download(t, sessionID, path.Join(srv.Root, "evil.html"), "")

	disposition := headers.Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", disposition)
	}
	if !strings.Contains(disposition, "evil.html") {
		t.Errorf("Content-Disposition does not name the file: %q", disposition)
	}
	if got := headers.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	if got := headers.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
}

// TestResumingAnInterruptedUpload is the whole point of the offset parameter:
// a partial file must be continued, not started again.
func TestResumingAnInterruptedUpload(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	target := path.Join(srv.Root, "resumed.bin")

	first := []byte("the first half of the file, ")
	if resp := h.upload(t, sessionID, target, 0, first); resp.StatusCode != http.StatusOK {
		t.Fatalf("first chunk: %d", resp.StatusCode)
	}

	second := []byte("and the second half.")
	resp := h.upload(t, sessionID, target, int64(len(first)), second)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resumed chunk: %d", resp.StatusCode)
	}

	want := string(first) + string(second)
	if got := readAt(t, srv, "resumed.bin"); got != want {
		t.Errorf("resumed file = %q, want %q", got, want)
	}
}

// TestUploadingAtZeroTruncates: an overwrite that left the tail of a longer
// previous version would silently produce a corrupt file.
func TestUploadingAtZeroTruncates(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	writeAt(t, srv, "replaced.txt", "a considerably longer previous version")

	target := path.Join(srv.Root, "replaced.txt")
	if resp := h.upload(t, sessionID, target, 0, []byte("short")); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: %d", resp.StatusCode)
	}

	if got := readAt(t, srv, "replaced.txt"); got != "short" {
		t.Errorf("overwritten file = %q, want short", got)
	}
}

// TestDownloadHonoursRange is what makes a resumed download possible.
func TestDownloadHonoursRange(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	writeAt(t, srv, "ranged.txt", "0123456789")
	target := path.Join(srv.Root, "ranged.txt")

	body, headers := h.download(t, sessionID, target, "bytes=4-")
	if string(body) != "456789" {
		t.Errorf("ranged download = %q, want 456789", body)
	}
	if got := headers.Get("Content-Range"); got != "bytes 4-9/10" {
		t.Errorf("Content-Range = %q", got)
	}
	if got := headers.Get("Content-Length"); got != "6" {
		t.Errorf("Content-Length = %q, want 6", got)
	}

	// A range past the end is refused rather than answered with nothing,
	// which a client would read as an empty file.
	resp := h.rawDownload(t, sessionID, target, "bytes=99-")
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("a range past the end = %d, want 416", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestMkdirRenameChmodAndDelete(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	t.Run("mkdir creates missing parents", func(t *testing.T) {
		resp, body := h.post("/api/files/mkdir", map[string]string{
			"session": sessionID, "path": path.Join(srv.Root, "a", "b"),
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("mkdir: %d %v", resp.StatusCode, body)
		}
		if info, err := os.Stat(filepath.Join(srv.Root, "a", "b")); err != nil || !info.IsDir() {
			t.Fatalf("the directory was not created: %v", err)
		}
	})

	t.Run("rename moves a file", func(t *testing.T) {
		writeAt(t, srv, "before.txt", "contents")

		resp, body := h.post("/api/files/rename", map[string]string{
			"session": sessionID,
			"from":    path.Join(srv.Root, "before.txt"),
			"to":      path.Join(srv.Root, "a", "after.txt"),
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rename: %d %v", resp.StatusCode, body)
		}
		if got := readAt(t, srv, "a/after.txt"); got != "contents" {
			t.Errorf("after the rename = %q", got)
		}
	})

	t.Run("chmod changes the mode on disk", func(t *testing.T) {
		writeAt(t, srv, "script.sh", "#!/bin/sh\n")

		resp, body := h.post("/api/files/chmod", map[string]string{
			"session": sessionID, "path": path.Join(srv.Root, "script.sh"), "mode": "0750",
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("chmod: %d %v", resp.StatusCode, body)
		}

		info, err := os.Stat(filepath.Join(srv.Root, "script.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Errorf("mode on disk = %04o, want 0750", info.Mode().Perm())
		}
	})

	t.Run("a bad mode is refused with an explanation", func(t *testing.T) {
		resp, body := h.post("/api/files/chmod", map[string]string{
			"session": sessionID, "path": path.Join(srv.Root, "script.sh"), "mode": "rwxr-xr-x",
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("a symbolic mode = %d, want 400", resp.StatusCode)
		}
		if message := errorMessage(body); !strings.Contains(message, "octal") {
			t.Errorf("the message does not say what to type instead: %q", message)
		}
	})

	t.Run("deleting a file answers immediately", func(t *testing.T) {
		writeAt(t, srv, "doomed.txt", "x")

		resp, body := h.do(http.MethodDelete,
			"/api/files/entry?session="+sessionID+"&path="+path.Join(srv.Root, "doomed.txt"), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("delete: %d %v", resp.StatusCode, body)
		}
		if _, err := os.Stat(filepath.Join(srv.Root, "doomed.txt")); !os.IsNotExist(err) {
			t.Error("the file survived")
		}
	})

	t.Run("deleting a directory becomes a job", func(t *testing.T) {
		mkdirAt(t, srv, "tree/inner")
		writeAt(t, srv, "tree/inner/deep.txt", "x")

		resp, body := h.do(http.MethodDelete,
			"/api/files/entry?session="+sessionID+"&path="+path.Join(srv.Root, "tree"), nil)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("recursive delete: %d %v", resp.StatusCode, body)
		}

		id, _ := body["id"].(string)
		if id == "" {
			t.Fatalf("no job was returned: %v", body)
		}
		if final := h.awaitJob(t, id); final["state"] != "done" {
			t.Fatalf("the delete ended %v: %v", final["state"], final["error"])
		}
		if _, err := os.Stat(filepath.Join(srv.Root, "tree")); !os.IsNotExist(err) {
			t.Error("the tree survived")
		}
	})
}

// TestCopyBetweenTwoHosts is the thing SecureCRT cannot do: move a directory
// straight from one managed host to another, without it passing through
// anybody's laptop.
func TestCopyBetweenTwoHosts(t *testing.T) {
	h := signedInWithVault(t)

	source := startSFTP(t, "hunter2")
	dest := startSFTP(t, "hunter2")
	sourceID := h.savedSFTPConnection(t, source, "source host", "hunter2")
	destID := h.savedSFTPConnection(t, dest, "dest host", "hunter2")
	h.openFiles(t, sourceID)
	h.openFiles(t, destID)

	writeAt(t, source, "bundle/app.bin", "the binary")
	writeAt(t, source, "bundle/conf/settings.yaml", "key: value")

	resp, body := h.post("/api/files/copy", map[string]any{
		"source_session": sourceID,
		"source_path":    path.Join(source.Root, "bundle"),
		"dest_session":   destID,
		"dest_directory": dest.Root,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("copy: %d %v", resp.StatusCode, body)
	}

	id, _ := body["id"].(string)
	final := h.awaitJob(t, id)
	if final["state"] != "done" {
		t.Fatalf("the copy ended %v: %v", final["state"], final["error"])
	}

	if got := readAt(t, dest, "bundle/app.bin"); got != "the binary" {
		t.Errorf("app.bin at the destination = %q", got)
	}
	if got := readAt(t, dest, "bundle/conf/settings.yaml"); got != "key: value" {
		t.Errorf("settings.yaml at the destination = %q", got)
	}

	// The source is untouched: this is a copy, not a move.
	if got := readAt(t, source, "bundle/app.bin"); got != "the binary" {
		t.Errorf("the source was disturbed: %q", got)
	}
}

// TestFilesAreScopedToTheirOwner: one user's file session must be invisible
// and unusable to another, even knowing its identifier.
func TestFilesAreScopedToTheirOwner(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)
	writeAt(t, srv, "secret.txt", "not yours")

	// A second account in the same instance.
	h.createLocalUser("mallory@example.com", "correct horse battery staple", false)
	h.cookies = map[string]string{}
	h.csrf = ""
	// Fetching the sign-in configuration is what issues a CSRF token, exactly
	// as it is in the browser.
	h.get("/api/auth/config")
	h.login("mallory@example.com", "correct horse battery staple")
	h.post("/api/vault/enrol", map[string]string{"passphrase": "another long passphrase"})

	if _, body := h.get("/api/files/sessions"); len(body["sessions"].([]any)) != 0 {
		t.Errorf("another user saw file sessions: %v", body)
	}

	// Listing through the other user's connection must fail. It fails at the
	// saved connection, which mallory does not own, so it never reaches SFTP.
	resp, _ := h.get("/api/files/list?session=" + sessionID + "&path=" + srv.Root)
	if resp.StatusCode == http.StatusOK {
		t.Error("another user listed a directory through a session they do not own")
	}

	resp = h.rawDownload(t, sessionID, path.Join(srv.Root, "secret.txt"), "")
	if resp.StatusCode == http.StatusOK {
		t.Error("another user downloaded a file through a session they do not own")
	}
	_ = resp.Body.Close()
}

func TestFileEndpointsRequireAuthentication(t *testing.T) {
	h := newHarness(t, nil)

	for _, path := range []string{
		"/api/files/sessions",
		"/api/files/list?session=x",
		"/api/files/transfers",
	} {
		resp, _ := h.get(path)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a session = %d, want 401", path, resp.StatusCode)
		}
	}
}

// TestUnknownHostKeyIsPromptedThenConfirmed covers the two-step approval a
// plain HTTP request forces.
//
// A browser cannot be asked mid-handshake the way the terminal's WebSocket
// can, so the first attempt refuses and reports the fingerprint, and the
// user's answer arrives on a second attempt. Without this, a host nobody had
// opened a terminal on could never be browsed at all.
func TestUnknownHostKeyIsPromptedThenConfirmed(t *testing.T) {
	h := signedInWithVault(t)
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")

	resp, body := h.post("/api/files/sessions?session="+sessionID, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("opening against an unknown host key = %d, want 409: %v", resp.StatusCode, body)
	}

	errBody, _ := body["error"].(map[string]any)
	if code, _ := errBody["code"].(string); code != "host_key_prompt" {
		t.Fatalf("code = %v, want host_key_prompt", errBody["code"])
	}

	hostKey, _ := errBody["host_key"].(map[string]any)
	fingerprint, _ := hostKey["fingerprint"].(string)
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("the prompt carried no usable fingerprint: %v", hostKey)
	}

	// Nothing may have been recorded yet: an unanswered prompt must not skip
	// the question next time.
	_, known := h.get("/api/known-hosts")
	if hosts, _ := known["known_hosts"].([]any); len(hosts) != 0 {
		t.Fatalf("%d host keys were recorded before the user answered", len(hosts))
	}

	// A confirmation for the wrong fingerprint is refused. This is the case
	// that matters: answering "yes" about one key must not accept a
	// different one presented a moment later.
	resp, body = h.post("/api/files/sessions?session="+sessionID+
		"&accept_host_key=SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("confirming the wrong fingerprint = %d, want 409: %v", resp.StatusCode, body)
	}

	// The right one opens the session.
	resp, body = h.post("/api/files/sessions?session="+sessionID+
		"&accept_host_key="+url.QueryEscape(fingerprint), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirming the right fingerprint = %d: %v", resp.StatusCode, body)
	}

	// And it was recorded, so the question is not asked again.
	_, known = h.get("/api/known-hosts")
	hosts, _ := known["known_hosts"].([]any)
	if len(hosts) != 1 {
		t.Errorf("%d host keys recorded after acceptance, want 1", len(hosts))
	}
}

// TestDownloadHeaderSurvivesAHostileFilename.
//
// Remote filenames are not under this service's control. A name containing a
// quote, a semicolon or a newline would either break the header or let a
// crafted name inject another one, and a non-ASCII name has to survive
// intact for the person downloading it.
func TestDownloadHeaderSurvivesAHostileFilename(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wantsPlain string
	}{
		{name: `plain.txt`, wantsPlain: `plain.txt`},
		{name: `"quoted".txt`, wantsPlain: `_quoted_.txt`},
		{name: "line\r\nX-Injected: yes", wantsPlain: "line__X-Injected: yes"},
		{name: `semi;colon,comma`, wantsPlain: `semi_colon_comma`},
		{name: `réponse.txt`, wantsPlain: `r_ponse.txt`},
		{name: `配置.conf`, wantsPlain: `__.conf`},
	} {
		got := contentDisposition(tc.name)

		if !strings.HasPrefix(got, "attachment; ") {
			t.Errorf("contentDisposition(%q) = %q, want an attachment", tc.name, got)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("contentDisposition(%q) contains a line break: %q", tc.name, got)
		}
		if want := `filename="` + tc.wantsPlain + `"`; !strings.Contains(got, want) {
			t.Errorf("contentDisposition(%q) = %q, want it to contain %q", tc.name, got, want)
		}
		// The real name still travels, so a browser that understands RFC 5987
		// saves the file under the name it actually has.
		if !strings.Contains(got, "filename*=UTF-8''"+url.PathEscape(tc.name)) {
			t.Errorf("contentDisposition(%q) does not carry the exact name: %q", tc.name, got)
		}
	}

	// A name that sanitises away entirely still needs something to save as.
	if got := contentDisposition("\x01\x02"); !strings.Contains(got, `filename="__"`) {
		t.Errorf("contentDisposition of control characters = %q", got)
	}
	if got := contentDisposition(""); !strings.Contains(got, `filename="download"`) {
		t.Errorf("contentDisposition of an empty name = %q", got)
	}
}

// --- helpers -----------------------------------------------------------------

func (h *harness) upload(t *testing.T, sessionID, target string, offset int64, body []byte) *http.Response {
	t.Helper()

	url := "/api/files/content?session=" + sessionID + "&path=" + target +
		"&offset=" + strconv.FormatInt(offset, 10)

	req, err := http.NewRequest(http.MethodPut, h.server.URL+url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp := h.send(t, req)
	_ = resp.Body.Close()
	return resp
}

func (h *harness) rawDownload(t *testing.T, sessionID, target, rangeHeader string) *http.Response {
	t.Helper()

	url := "/api/files/content?session=" + sessionID + "&path=" + target
	req, err := http.NewRequest(http.MethodGet, h.server.URL+url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	return h.send(t, req)
}

func (h *harness) download(t *testing.T, sessionID, target, rangeHeader string) ([]byte, http.Header) {
	t.Helper()

	resp := h.rawDownload(t, sessionID, target, rangeHeader)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("download = %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body, resp.Header
}

// send performs a raw request with the harness's cookies and CSRF token.
func (h *harness) send(t *testing.T, req *http.Request) *http.Response {
	t.Helper()

	for name, value := range h.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if h.csrf != "" {
		req.Header.Set("X-CSRF-Token", h.csrf)
	}

	resp, err := (&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// awaitJob blocks until a server-side transfer stops running.
func (h *harness) awaitJob(t *testing.T, id string) map[string]any {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, body := h.get("/api/files/transfers")
		jobs, _ := body["transfers"].([]any)

		for _, raw := range jobs {
			job, _ := raw.(map[string]any)
			if job["id"] != id {
				continue
			}
			if job["state"] != "running" {
				return job
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the transfer %s never finished", id)
	return nil
}

func errorMessage(body map[string]any) string {
	errBody, _ := body["error"].(map[string]any)
	message, _ := errBody["message"].(string)
	return message
}

func writeAt(t *testing.T, srv *sftpTestServer, rel, contents string) {
	t.Helper()

	full := filepath.Join(srv.Root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readAt(t *testing.T, srv *sftpTestServer, rel string) string {
	t.Helper()
	return string(readAtBytes(t, srv, rel))
}

func readAtBytes(t *testing.T, srv *sftpTestServer, rel string) []byte {
	t.Helper()

	// #nosec G304 -- a path the test itself built under its own temp dir
	data, err := os.ReadFile(filepath.Join(srv.Root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return data
}

func mkdirAt(t *testing.T, srv *sftpTestServer, rel string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(srv.Root, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestAnOversizedUploadIsRefusedNotTruncated guards a failure mode that is
// worse than a rejection: the handler used to read the body through an
// io.LimitReader, which stops at the cap and reports a clean end of input. A
// file over the limit was therefore cut in half, written to the host, and
// answered with 200 and a byte count — the user was told their file arrived.
func TestAnOversizedUploadIsRefusedNotTruncated(t *testing.T) {
	const limit = 1 << 20 // the smallest the configuration allows

	h := signedInWithVault(t, func(c *config.Config) {
		c.Policy.MaxUploadBytes = limit
	})
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	target := path.Join(srv.Root, "oversized.bin")
	body := bytes.Repeat([]byte("x"), limit+4096)

	resp := h.upload(t, sessionID, target, 0, body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload of %d bytes against a %d byte limit = %d, want 413",
			len(body), limit, resp.StatusCode)
	}

	// The partial write that got as far as the host before the cap tripped is
	// expected — resuming from an offset is how this interface works. What
	// must not happen is a whole-looking file: the caller was told no, so
	// nothing here may claim the upload completed.
	info, err := os.Stat(target)
	if err == nil && info.Size() >= int64(len(body)) {
		t.Fatalf("the file on the host is %d bytes: the oversized upload was accepted after all",
			info.Size())
	}
}

// TestAnUploadInsideTheLimitStillSucceeds is the other half of the pair: the
// cap must refuse what is over it without breaking what is under it. Sized
// just below the limit so it exercises the same code path as the refusal.
func TestAnUploadInsideTheLimitStillSucceeds(t *testing.T) {
	const limit = 1 << 20

	h := signedInWithVault(t, func(c *config.Config) {
		c.Policy.MaxUploadBytes = limit
	})
	srv := startSFTP(t, "hunter2")
	sessionID := h.savedSFTPConnection(t, srv, "files host", "hunter2")
	h.openFiles(t, sessionID)

	target := path.Join(srv.Root, "just-under.bin")
	body := bytes.Repeat([]byte("y"), limit-1)

	if resp := h.upload(t, sessionID, target, 0, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload of %d bytes against a %d byte limit = %d, want 200",
			len(body), limit, resp.StatusCode)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len(body)) {
		t.Errorf("file on the host is %d bytes, want %d", info.Size(), len(body))
	}
}
