package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/files"
	"github.com/mrbuttshooter/securecrt/internal/proto/sftpx"
	"github.com/mrbuttshooter/securecrt/internal/remote"
)

// The file browser's HTTP surface.
//
// Browsing and metadata are JSON. The two that move bytes are not: a download
// is a plain streaming GET and an upload is a plain streaming PUT, so the
// browser's own transfer machinery — progress events, Range requests, the
// download manager — does the work rather than being reimplemented on top of
// JSON and base64, which would inflate every byte by a third.
//
// Nothing is spooled to this server's disk in either direction.

// maxUploadBytes bounds a single upload request.
//
// Not a limit on file size: the interface splits a large upload into chunks
// and resumes each at an offset, so this bounds one request rather than one
// file. It exists so a runaway client cannot hold an unbounded read open.
const maxUploadBytes = 1 << 30 // 1 GiB per request

// fileSession resolves an already-open file session from the "session" query
// parameter.
//
// Opening is deliberately not implicit here. A dial can need a host key
// decision from the user, and burying that inside an incidental directory
// listing would mean any request could suddenly demand one. Opening happens
// in exactly one place, where the prompt belongs.
func (a *API) fileSession(w http.ResponseWriter, r *http.Request) (*files.Session, bool) {
	return a.sessionFor(w, r, r.URL.Query().Get("session"))
}

// fingerprintPrompter answers the host key question for a file session.
//
// The browser cannot be asked mid-handshake over a plain HTTP request the way
// it can over the terminal's WebSocket, so the decision is split in two: the
// first attempt records the fingerprint and refuses, the interface shows it,
// and the user's answer comes back as accept_host_key on a second attempt.
//
// The accepted fingerprint must match what the host presents on that second
// attempt, so a host that swaps keys between the two — which is exactly what
// a machine-in-the-middle would have to do — is refused rather than
// rubber-stamped by an answer given about a different key.
type fingerprintPrompter struct {
	accept string
	seen   *remote.HostKeyInfo
}

func (p *fingerprintPrompter) PromptHostKey(_ context.Context, info remote.HostKeyInfo) (bool, error) {
	copied := info
	p.seen = &copied
	return p.accept != "" && p.accept == info.Fingerprint, nil
}

// handleOpenFileSession opens a file session and reports where it starts.
func (a *API) handleOpenFileSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())

	query := r.URL.Query()
	sessionID := query.Get("session")
	if sessionID == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return
	}

	if existing, err := a.fileSessions.Get(u.ID, sessionID); err == nil {
		a.writeFileSession(w, existing)
		return
	}

	// The vault is only needed when the SSH connection has to be dialled. A
	// host that already has a terminal on it opens instantly, and keeps
	// working after the vault has been locked for the night.
	vaultKey, _ := a.vaults.Key(u.ID, sess.ID)
	prompter := &fingerprintPrompter{accept: query.Get("accept_host_key")}

	session, err := a.fileSessions.Open(r.Context(), files.OpenParams{
		UserID:    u.ID,
		SessionID: sessionID,
		VaultKey:  vaultKey,
		Prompter:  prompter,
	})
	if err != nil {
		a.writeOpenError(w, r, err, prompter)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionFileSessionOpened, TargetType: "session", TargetID: sessionID,
		TargetLabel: session.Label,
		Detail:      map[string]any{"host": session.Host, "port": session.Port},
	})

	a.writeFileSession(w, session)
}

func (a *API) writeFileSession(w http.ResponseWriter, session *files.Session) {
	client := session.Client()
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"session_id":  session.SessionID,
		"label":       session.Label,
		"host":        session.Host,
		"port":        session.Port,
		"username":    session.Username,
		"home":        session.Home,
		"owner_names": client.OwnerNamesAvailable(),
	})
}

// writeOpenError maps a failed open onto a response.
//
// An unknown host key becomes a prompt carrying the fingerprint rather than a
// flat refusal, because otherwise a host nobody has opened a terminal on
// could never be browsed at all.
func (a *API) writeOpenError(w http.ResponseWriter, r *http.Request, err error, prompter *fingerprintPrompter) {
	u, _ := UserFrom(r.Context())

	var remoteErr *remote.Error
	if !errors.As(err, &remoteErr) {
		writeInternal(w, a.log, "opening a file session", err)
		return
	}

	if remoteErr.Code == remote.CodeHostKeyRejected && prompter.seen != nil {
		writeJSON(w, a.log, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code": "host_key_prompt",
				"message": "You have not connected to this host before. Check the " +
					"fingerprint against the host itself, then confirm. Nothing has " +
					"been sent to it.",
				"host_key": prompter.seen,
			},
		})
		return
	}

	status := http.StatusBadGateway
	switch remoteErr.Code {
	case remote.CodeNotFound:
		status = http.StatusNotFound
	case remote.CodeVaultLocked:
		status = http.StatusForbidden
	case remote.CodeNoCredential:
		status = http.StatusBadRequest
	case remote.CodeHostKeyChanged, remote.CodeHostKeyRejected:
		// Not a server error and not the client's fault: the host failed to
		// prove who it is. 409 says "the state on the other side conflicts
		// with what you asked for", which is exactly the situation.
		status = http.StatusConflict
	}

	if remoteErr.Code == remote.CodeHostKeyChanged {
		// The most serious thing this system reports: either a host was
		// rebuilt, or something is impersonating it.
		a.audit.Record(r.Context(), audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: audit.ActionFileSessionOpened, Outcome: audit.OutcomeFailure,
			Severity: audit.SeverityCritical, TargetType: "session",
			TargetID: r.URL.Query().Get("session"),
			Detail:   map[string]any{"reason": remoteErr.Code},
		})
	}

	body := map[string]any{
		"code":    remoteErr.Code,
		"message": remoteErr.Message,
	}
	if remoteErr.HostKey != nil {
		body["host_key"] = remoteErr.HostKey
	}
	writeJSON(w, a.log, status, map[string]any{"error": body})
}

// handleListFileSessions returns the user's open file sessions.
func (a *API) handleListFileSessions(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"sessions": a.fileSessions.ListForUser(u.ID),
	})
}

// handleCloseFileSession ends a file session. The SSH connection survives if
// a terminal still holds it.
func (a *API) handleCloseFileSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/files/sessions/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return
	}

	if err := a.fileSessions.Close(u.ID, id); err != nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No file session for that connection.")
		return
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"closed": true})
}

// handleListDirectory reads a directory.
func (a *API) handleListDirectory(w http.ResponseWriter, r *http.Request) {
	session, ok := a.fileSession(w, r)
	if !ok {
		return
	}

	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = session.Home
	}

	entries, err := session.Client().List(r.Context(), dir)
	if err != nil {
		a.writeFileError(w, err, "listing a directory")
		return
	}

	// The resolved path goes back so the interface can show where it actually
	// landed after "..", a symlink or a relative path.
	resolved, err := session.Client().RealPath(dir)
	if err != nil {
		resolved = dir
	}

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"path":    resolved,
		"parent":  path.Dir(resolved),
		"entries": entries,
	})
}

// handleStatPath describes one path.
func (a *API) handleStatPath(w http.ResponseWriter, r *http.Request) {
	session, ok := a.fileSession(w, r)
	if !ok {
		return
	}

	target := r.URL.Query().Get("path")
	if target == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No path was specified.")
		return
	}

	entry, err := session.Client().Stat(r.Context(), target)
	if err != nil {
		a.writeFileError(w, err, "reading a path")
		return
	}
	writeJSON(w, a.log, http.StatusOK, entry)
}

type mkdirRequest struct {
	Session string `json:"session"`
	Path    string `json:"path"`
}

func (a *API) handleMkdir(w http.ResponseWriter, r *http.Request) {
	var req mkdirRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	session, ok := a.sessionFor(w, r, req.Session)
	if !ok {
		return
	}
	if req.Path == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No path was specified.")
		return
	}

	if err := session.Client().Mkdir(req.Path); err != nil {
		a.writeFileError(w, err, "creating a directory")
		return
	}
	a.recordFileChange(r, session, audit.ActionDirectoryCreated, req.Path)

	writeJSON(w, a.log, http.StatusCreated, map[string]any{"path": req.Path})
}

type renameRequest struct {
	Session string `json:"session"`
	From    string `json:"from"`
	To      string `json:"to"`
}

func (a *API) handleRename(w http.ResponseWriter, r *http.Request) {
	var req renameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	session, ok := a.sessionFor(w, r, req.Session)
	if !ok {
		return
	}
	if req.From == "" || req.To == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "Both a source and a destination are required.")
		return
	}

	if err := session.Client().Rename(req.From, req.To); err != nil {
		a.writeFileError(w, err, "renaming")
		return
	}
	a.recordFileChange(r, session, audit.ActionFileRenamed, req.From+" → "+req.To)

	writeJSON(w, a.log, http.StatusOK, map[string]any{"path": req.To})
}

type chmodRequest struct {
	Session string `json:"session"`
	Path    string `json:"path"`
	Mode    string `json:"mode"`
}

func (a *API) handleChmod(w http.ResponseWriter, r *http.Request) {
	var req chmodRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	session, ok := a.sessionFor(w, r, req.Session)
	if !ok {
		return
	}

	mode, err := sftpx.ParseMode(req.Mode)
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That is not a permission mode. Use octal, as chmod takes it — 0644, 0755.")
		return
	}

	if err := session.Client().Chmod(req.Path, mode); err != nil {
		a.writeFileError(w, err, "changing permissions")
		return
	}
	a.recordFileChange(r, session, audit.ActionFileChmod, fmt.Sprintf("%s to %s", req.Path, req.Mode))

	writeJSON(w, a.log, http.StatusOK, map[string]any{"path": req.Path, "mode": req.Mode})
}

type chownRequest struct {
	Session string `json:"session"`
	Path    string `json:"path"`

	// Owner and Group accept a name or a numeric ID. Empty means leave it
	// alone, which is what chown(2) means by -1 — the interface needs to set
	// a group without knowing or disturbing the owner.
	Owner string `json:"owner"`
	Group string `json:"group"`
}

func (a *API) handleChown(w http.ResponseWriter, r *http.Request) {
	var req chownRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	session, ok := a.sessionFor(w, r, req.Session)
	if !ok {
		return
	}
	client := session.Client()

	uid, err := resolveOwner(req.Owner, client.LookupUser)
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			fmt.Sprintf("The host does not know a user called %q.", req.Owner))
		return
	}
	gid, err := resolveOwner(req.Group, client.LookupGroup)
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			fmt.Sprintf("The host does not know a group called %q.", req.Group))
		return
	}

	if err := client.Chown(r.Context(), req.Path, uid, gid); err != nil {
		a.writeFileError(w, err, "changing ownership")
		return
	}
	a.recordFileChange(r, session, audit.ActionFileChown,
		fmt.Sprintf("%s to %s:%s", req.Path, req.Owner, req.Group))

	writeJSON(w, a.log, http.StatusOK, map[string]any{"path": req.Path})
}

// resolveOwner turns a name or numeric ID into an ID, or -1 for "leave it".
func resolveOwner(value string, lookup func(string) (int, bool)) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return -1, nil
	}
	if id, err := strconv.Atoi(value); err == nil {
		return id, nil
	}
	if id, ok := lookup(value); ok {
		return id, nil
	}
	return 0, fmt.Errorf("api: unknown owner %q", value)
}

// handleDeletePath removes a file, or starts a job for a directory.
//
// A single file is one round trip and answers immediately. A tree is one
// round trip per entry, which on a slow link runs past any sensible request
// timeout, so it becomes a job the interface can watch.
func (a *API) handleDeletePath(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	session, ok := a.fileSession(w, r)
	if !ok {
		return
	}

	target := r.URL.Query().Get("path")
	if target == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No path was specified.")
		return
	}

	entry, err := session.Client().Stat(r.Context(), target)
	if err != nil {
		a.writeFileError(w, err, "reading a path")
		return
	}

	// A symlink is removed as a link even when it points at a directory.
	// Following it would delete the target's contents, which is never what
	// "delete this shortcut" was meant to do.
	if !entry.IsDir || entry.IsSymlink {
		if err := session.Client().Remove(target); err != nil {
			a.writeFileError(w, err, "deleting")
			return
		}
		a.recordFileChange(r, session, audit.ActionFileDeleted, target)
		writeJSON(w, a.log, http.StatusOK, map[string]any{"deleted": true})
		return
	}

	job, err := a.transfers.StartDelete(files.DeleteParams{
		UserID:    u.ID,
		SessionID: session.SessionID,
		Path:      target,
	})
	if err != nil {
		a.writeJobError(w, err, "starting a delete")
		return
	}
	a.recordFileChange(r, session, audit.ActionFileTreeDeleted, target)

	writeJSON(w, a.log, http.StatusAccepted, job)
}

// handleDownload streams a file to the browser.
//
// Range is honoured so a large download can be resumed, and so the browser
// can seek in media without fetching everything before it.
func (a *API) handleDownload(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	session, ok := a.fileSession(w, r)
	if !ok {
		return
	}

	target := r.URL.Query().Get("path")
	if target == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No path was specified.")
		return
	}

	size, err := session.Client().Size(target)
	if err != nil {
		a.writeFileError(w, err, "opening a file")
		return
	}

	offset, ok := parseRange(r.Header.Get("Range"), size)
	if !ok {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		writeError(w, a.log, http.StatusRequestedRangeNotSatisfiable, CodeBadRequest,
			"That range is outside the file.")
		return
	}

	reader, err := session.Client().Reader(target, offset)
	if err != nil {
		a.writeFileError(w, err, "opening a file")
		return
	}
	defer func() { _ = reader.Close() }()

	name := path.Base(target)
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(size-offset, 10))
	h.Set("Accept-Ranges", "bytes")
	// attachment, always: a file fetched from a managed host must never be
	// rendered in this origin, where an HTML or SVG payload would run as
	// though this application had served it.
	h.Set("Content-Disposition", contentDisposition(name))
	h.Set("X-Content-Type-Options", "nosniff")

	status := http.StatusOK
	if offset > 0 {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, size-1, size))
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)

	if _, err := io.Copy(w, reader); err != nil {
		// The status is long since written, so this can only be logged. A
		// truncated body is what the client sees, and Content-Length tells
		// it the transfer was short.
		a.log.Debug("download interrupted", "path", target, "error", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionFileDownloaded, TargetType: "file", TargetID: target,
		TargetLabel: session.Label,
		Detail:      map[string]any{"host": session.Host, "bytes": size - offset},
	})
}

// contentDisposition builds an attachment header for a remote filename.
//
// Remote filenames are not under this service's control: they can contain
// quotes, semicolons, newlines or non-ASCII, any of which would either break
// the header or let a crafted name inject another one. So the plain filename
// parameter is sanitised down to something safe and ASCII, and the real name
// is carried in the RFC 5987 form every current browser prefers.
func contentDisposition(name string) string {
	safe := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f: // control characters, including CR and LF
			safe = append(safe, '_')
		case r > 0x7e: // non-ASCII travels in the filename* parameter instead
			safe = append(safe, '_')
		case r == '"' || r == '\\' || r == ';' || r == ',':
			safe = append(safe, '_')
		default:
			safe = append(safe, r)
		}
	}

	fallback := strings.TrimSpace(string(safe))
	if fallback == "" {
		fallback = "download"
	}

	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`,
		fallback, url.PathEscape(name))
}

// parseRange reads a single-range "bytes=N-" header.
//
// Only the open-ended form, which is the one a resumed download sends. A
// multi-range request is refused rather than answered wrongly.
func parseRange(header string, size int64) (offset int64, ok bool) {
	if header == "" {
		return 0, true
	}
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") {
		return 0, false
	}

	spec := strings.TrimPrefix(header, "bytes=")
	dash := strings.Index(spec, "-")
	if dash < 0 {
		return 0, false
	}

	start, err := strconv.ParseInt(spec[:dash], 10, 64)
	if err != nil || start < 0 || start > size {
		return 0, false
	}
	return start, true
}

// handleUpload writes a request body to a file on the host.
//
// The offset query parameter is what makes an interrupted upload resumable:
// at zero the file is truncated, at anything else the write continues a
// partial file rather than starting again.
func (a *API) handleUpload(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	session, ok := a.fileSession(w, r)
	if !ok {
		return
	}

	target := r.URL.Query().Get("path")
	if target == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No path was specified.")
		return
	}

	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 {
		offset = 0
	}

	writer, err := session.Client().Writer(target, offset)
	if err != nil {
		a.writeFileError(w, err, "opening a file for writing")
		return
	}

	written, copyErr := io.Copy(writer, io.LimitReader(r.Body, maxUploadBytes))
	closeErr := writer.Close()

	if copyErr != nil {
		a.log.Debug("upload interrupted", "path", target, "error", copyErr)
		writeError(w, a.log, http.StatusBadGateway, CodeInternal,
			"The upload stopped partway. It can be resumed from where it stopped.")
		return
	}
	if closeErr != nil {
		a.writeFileError(w, closeErr, "finishing an upload")
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionFileUploaded, TargetType: "file", TargetID: target,
		TargetLabel: session.Label,
		Detail: map[string]any{
			"host": session.Host, "bytes": written, "offset": offset,
		},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"path":  target,
		"bytes": written,
		"size":  offset + written,
	})
}

type copyRequest struct {
	SourceSession string `json:"source_session"`
	SourcePath    string `json:"source_path"`
	DestSession   string `json:"dest_session"`
	DestDirectory string `json:"dest_directory"`
	Overwrite     bool   `json:"overwrite"`
}

// handleStartCopy begins a host-to-host copy.
func (a *API) handleStartCopy(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req copyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	if req.SourcePath == "" || req.DestDirectory == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"A source path and a destination directory are required.")
		return
	}

	// Both ends must already be open, which they are whenever the copy came
	// from dragging between two panes.
	for _, id := range []string{req.SourceSession, req.DestSession} {
		if _, ok := a.sessionFor(w, r, id); !ok {
			return
		}
	}

	job, err := a.transfers.StartCopy(files.CopyParams{
		UserID:        u.ID,
		SourceSession: req.SourceSession,
		SourcePath:    req.SourcePath,
		DestSession:   req.DestSession,
		DestDirectory: req.DestDirectory,
		Overwrite:     req.Overwrite,
	})
	if err != nil {
		a.writeJobError(w, err, "starting a copy")
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionFileCopied, TargetType: "file", TargetID: req.SourcePath,
		Detail: map[string]any{
			"from_session": req.SourceSession,
			"to_session":   req.DestSession,
			"to":           req.DestDirectory,
		},
	})

	writeJSON(w, a.log, http.StatusAccepted, job)
}

// handleListTransfers returns a user's server-side jobs.
func (a *API) handleListTransfers(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"transfers": a.transfers.ListForUser(u.ID),
	})
}

// handleCancelTransfer stops a running job.
func (a *API) handleCancelTransfer(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/files/transfers/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No transfer was specified.")
		return
	}

	if err := a.transfers.Cancel(u.ID, id); err != nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such transfer.")
		return
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"cancelled": true})
}

// sessionFor looks up an already-open file session by saved-connection ID.
func (a *API) sessionFor(w http.ResponseWriter, r *http.Request, sessionID string) (*files.Session, bool) {
	u, _ := UserFrom(r.Context())

	if sessionID == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return nil, false
	}

	session, err := a.fileSessions.Get(u.ID, sessionID)
	if err != nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound,
			"No file session for that connection. Open it first.")
		return nil, false
	}
	return session, true
}

// writeFileError maps an SFTP failure onto a response.
func (a *API) writeFileError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, sftpx.ErrNotFound):
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "That path does not exist.")

	case errors.Is(err, sftpx.ErrPermission):
		writeError(w, a.log, http.StatusForbidden, CodeForbidden,
			"The remote host refused: permission denied.")

	case errors.Is(err, sftpx.ErrExists):
		writeError(w, a.log, http.StatusConflict, CodeConflict, "Something is already there.")

	case errors.Is(err, sftpx.ErrIsDirectory):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "That is a directory.")

	case errors.Is(err, sftpx.ErrNotSupported):
		writeError(w, a.log, http.StatusNotImplemented, CodeBadRequest,
			"The remote host does not support that operation.")

	default:
		// Reported as a gateway failure rather than an internal one: the
		// thing that went wrong is on the far side, and saying so is the
		// difference between someone checking the host and someone opening a
		// ticket against this service.
		a.log.Warn(what, "error", err)
		writeError(w, a.log, http.StatusBadGateway, CodeInternal,
			"The remote host reported an error.")
	}
}

// writeJobError maps a transfer-queue failure onto a response.
func (a *API) writeJobError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, files.ErrSessionNotFound):
		writeError(w, a.log, http.StatusNotFound, CodeNotFound,
			"No file session for that connection. Open it first.")

	case errors.Is(err, files.ErrTooManyJobs):
		writeError(w, a.log, http.StatusTooManyRequests, CodeRateLimited,
			fmt.Sprintf("You already have %d transfers running. Wait for one to finish.",
				files.MaxJobsPerUser))

	default:
		writeInternal(w, a.log, what, err)
	}
}

// recordFileChange writes an audit event for a mutation.
func (a *API) recordFileChange(r *http.Request, session *files.Session, action audit.Action, target string) {
	u, _ := UserFrom(r.Context())

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: action, TargetType: "file", TargetID: target,
		TargetLabel: session.Label,
		Detail:      map[string]any{"host": session.Host, "at": time.Now().UTC().Format(time.RFC3339)},
	})
}
