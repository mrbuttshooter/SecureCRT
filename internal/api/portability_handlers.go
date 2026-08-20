package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/portability"
)

// Importing and exporting.
//
// The shape here is preview-then-commit, and the preview is not advisory: it
// stages the exact payload it described, and committing applies that staged
// copy. Re-parsing the upload at commit time would mean the user approved one
// thing and the server applied another — which, for an operation that writes
// to somebody's working device list, is the difference between a preview and
// a suggestion.

// defaultMaxImportBytes bounds an uploaded configuration when the operator has
// not chosen a limit of their own.
//
// A SecureCRT configuration for a large team is a few megabytes of small text
// files. The limit is what a hostile upload cannot exceed before anything has
// looked at it.
const defaultMaxImportBytes int64 = 64 << 20 // 64 MiB

// previewBodyHeadroom is added to the import limit to bound the whole
// multipart request rather than just the file inside it.
//
// ParseMultipartForm's argument only caps how much is held in memory; the rest
// spills to the server's temporary directory, so on its own it turns "too big
// to buffer" into "written to disk anyway" and a long enough upload fills the
// filesystem. MaxBytesReader is the cap that actually refuses. The headroom
// covers the multipart framing — boundaries, part headers and the source
// field — so a file at exactly the documented limit still gets the message
// about the file rather than one about the request.
const previewBodyHeadroom int64 = 1 << 20

// stagingTTL is how long a previewed import waits to be committed.
//
// Long enough to read a plan of three hundred connections and think about it;
// short enough that an abandoned preview does not hold a copy of somebody's
// passwords in memory for the afternoon.
const stagingTTL = 15 * time.Minute

// maxStagedPerUser bounds how many previews one user can hold at once.
const maxStagedPerUser = 4

// staged is a previewed import waiting to be committed.
type staged struct {
	userID    string
	source    portability.Source
	payload   portability.Payload
	plan      portability.Plan
	expiresAt time.Time
}

// staging holds previewed imports in memory.
//
// In memory rather than in the database: a staged payload holds decrypted
// passwords, and writing them to a table — even briefly — would put them
// somewhere a backup could pick them up.
type staging struct {
	mu    sync.Mutex
	items map[string]*staged
}

func newStaging() *staging {
	return &staging{items: map[string]*staged{}}
}

func (s *staging) put(entry *staged) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(time.Now())

	held := 0
	for _, item := range s.items {
		if item.userID == entry.userID {
			held++
		}
	}
	if held >= maxStagedPerUser {
		return "", fmt.Errorf("too many previews are already waiting")
	}

	token := uuid.Must(uuid.NewV7()).String()
	entry.expiresAt = time.Now().Add(stagingTTL)
	s.items[token] = entry
	return token, nil
}

// take returns a staged import and removes it.
//
// Removed on collection, so committing the same preview twice imports once.
// A user who presses the button twice on a slow connection should not get two
// copies of their device list.
func (s *staging) take(userID, token string) (*staged, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(time.Now())

	entry, ok := s.items[token]
	if !ok || entry.userID != userID {
		return nil, false
	}
	delete(s.items, token)
	return entry, true
}

func (s *staging) sweepLocked(now time.Time) {
	for token, item := range s.items {
		if now.After(item.expiresAt) {
			delete(s.items, token)
		}
	}
}

// forget drops everything staged for a user, called when they lock the vault.
func (s *staging) forget(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, item := range s.items {
		if item.userID == userID {
			delete(s.items, token)
		}
	}
}

// handlePreviewImport reads an uploaded configuration and says what importing
// it would do.
func (a *API) handlePreviewImport(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	limit := a.cfg.importLimit()

	r.Body = http.MaxBytesReader(w, r.Body, limit+previewBodyHeadroom)

	// #nosec G120 -- the body is bounded by the MaxBytesReader on the line
	// above, which gosec's pattern does not look for. The 8 MiB argument here
	// is only the in-memory/on-disk split, and the cap that actually refuses
	// is covered by TestAnOversizedImportIsRefusedBeforeItReachesTheDisk.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, a.log, http.StatusRequestEntityTooLarge, CodeBadRequest,
				fmt.Sprintf("That upload is larger than %d bytes.", limit))
			return
		}
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That upload could not be read.")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No file was uploaded.")
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "That upload could not be read.")
		return
	}
	if int64(len(data)) > limit {
		writeError(w, a.log, http.StatusRequestEntityTooLarge, CodeBadRequest,
			fmt.Sprintf("That file is larger than %d bytes.", limit))
		return
	}

	source := portability.Source(r.FormValue("source"))
	imported, err := a.readUpload(source, header.Filename, data, r)
	if err != nil {
		a.writeImportError(w, err)
		return
	}

	plan, err := a.portability.Preview(r.Context(), imported.Payload,
		portability.ImportOptions{UserID: u.ID})
	if err != nil {
		writeInternal(w, a.log, "previewing an import", err)
		return
	}

	token, err := a.staging.put(&staged{
		userID:  u.ID,
		source:  imported.Source,
		payload: imported.Payload,
		plan:    plan,
	})
	if err != nil {
		writeError(w, a.log, http.StatusTooManyRequests, CodeRateLimited,
			"You have several previews waiting. Finish or discard one first.")
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionImportPreviewed, TargetType: "import",
		TargetLabel: string(imported.Source),
		Detail: map[string]any{
			"source": string(imported.Source), "file": header.Filename,
			"sessions": plan.Counts.Sessions, "credentials": plan.Counts.Credentials,
		},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"token":    token,
		"source":   imported.Source,
		"plan":     plan,
		"warnings": imported.Warnings,
		"notes":    imported.Notes,
		"expires":  time.Now().Add(stagingTTL).UTC().Format(time.RFC3339),
	})
}

// readUpload turns an uploaded file into a payload.
//
// The conversion itself lives in the portability package, because the command
// line drives the same one. This is only the translation from form fields.
func (a *API) readUpload(
	source portability.Source,
	filename string,
	data []byte,
	r *http.Request,
) (portability.Import, error) {
	return portability.ReadUpload(source, filename, data, portability.UploadOptions{
		BundlePassphrase: r.FormValue("passphrase"),
		ConfigPassphrase: r.FormValue("config_passphrase"),
		SkipPasswords:    r.FormValue("skip_passwords") == "true",
		KeyPassphrase:    r.FormValue("key_passphrase"),
		ImportKeys:       r.FormValue("import_keys") == "true",
		ImportKnownHosts: r.FormValue("import_known_hosts") == "true",
		FolderName:       r.FormValue("folder"),
	})
}

type commitImportRequest struct {
	Token          string `json:"token"`
	OnConflict     string `json:"on_conflict"`
	IntoFolder     string `json:"into_folder"`
	SkipKnownHosts bool   `json:"skip_known_hosts"`
}

// handleCommitImport applies a previously previewed import.
func (a *API) handleCommitImport(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())

	var req commitImportRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	entry, ok := a.staging.take(u.ID, req.Token)
	if !ok {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound,
			"That preview has expired or was already used. Upload the file again.")
		return
	}

	key, err := a.vaults.Key(u.ID, sess.ID)
	if err != nil {
		writeError(w, a.log, http.StatusForbidden, CodeVaultLocked,
			"Your vault is locked. Unlock it, then import again.")
		return
	}

	result, err := a.portability.Import(r.Context(), key, entry.payload, portability.ImportOptions{
		UserID:         u.ID,
		IntoFolder:     req.IntoFolder,
		OnConflict:     portability.OnConflict(req.OnConflict),
		SkipKnownHosts: req.SkipKnownHosts,
	})
	if err != nil {
		// Partial results are reported rather than swallowed: an import that
		// stopped halfway has already written rows, and the user needs to
		// know which so they can decide whether to tidy up or carry on.
		a.log.Warn("import failed partway", "user", u.ID, "error", err)
		writeJSON(w, a.log, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{
				"code": CodeInternal,
				"message": "The import stopped partway. What had already been created " +
					"is listed below and was kept.",
			},
			"result": result,
		})
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionImported, TargetType: "import",
		TargetLabel: string(entry.source),
		Detail: map[string]any{
			"source": string(entry.source), "sessions": result.Sessions,
			"folders": result.Folders, "credentials": result.Credentials,
			"known_hosts": result.KnownHosts, "skipped": result.Skipped,
		},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"result": result})
}

// handleDiscardImport throws a preview away.
func (a *API) handleDiscardImport(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	token := pathID(r.URL.Path, "/api/portability/staged/")
	if token == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No preview was specified.")
		return
	}

	a.staging.take(u.ID, token) //nolint:errcheck // discarding: absent is the same outcome
	writeJSON(w, a.log, http.StatusOK, map[string]any{"discarded": true})
}

type exportRequest struct {
	Format         string `json:"format"`
	IncludeSecrets bool   `json:"include_secrets"`

	// Passphrase seals a bundle. Required for that format and ignored by the
	// others, which have nothing to seal with.
	Passphrase string `json:"passphrase"`

	Note              string `json:"note"`
	IncludeKnownHosts bool   `json:"include_known_hosts"`

	// Confirm is the explicit acknowledgement a plaintext export needs. The
	// interface asks in words; this is the answer.
	Confirm bool `json:"confirm"`
}

// handleExport writes the user's connections in the requested format.
func (a *API) handleExport(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())

	var req exportRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	format := portability.Format(req.Format)
	if format == "" {
		format = portability.FormatBundle
	}

	// The gate. A plaintext export is the most security-relevant thing this
	// system does: it takes everything out of the vault and writes it
	// somewhere nothing is protecting.
	// The gate is about credentials leaving the vault in the clear, so it is
	// the combination that trips it. A device list with no secrets in it is
	// how somebody goes back to plain OpenSSH, and refusing that would be
	// refusing the exit this system promises to leave open. It is also what
	// the audit recorder already assumes: only this combination is critical.
	if format.Plaintext() && req.IncludeSecrets {
		if !a.cfg.AllowPlaintextExport {
			writeError(w, a.log, http.StatusForbidden, CodeForbidden,
				"Exporting keys and passwords in the clear is disabled on this "+
					"server. Export an encrypted bundle instead, or export this "+
					"format without secrets.")
			return
		}
		if !req.Confirm {
			writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
				"This format is not encrypted, and you asked for the keys and "+
					"passwords. Confirm that you understand what the file will contain.")
			return
		}
	}

	if format == portability.FormatBundle && len(req.Passphrase) < portability.MinPassphraseLength {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			fmt.Sprintf("A bundle passphrase must be at least %d characters. "+
				"Nothing but this passphrase protects the file.",
				portability.MinPassphraseLength))
		return
	}

	var key = a.vaultKeyFor(u.ID, sess.ID)
	if req.IncludeSecrets && key == nil {
		writeError(w, a.log, http.StatusForbidden, CodeVaultLocked,
			"Your vault is locked, so the keys and passwords cannot be read. "+
				"Unlock it, or export without secrets.")
		return
	}

	payload, err := a.portability.Gather(r.Context(), key, portability.GatherOptions{
		UserID:            u.ID,
		IncludeSecrets:    req.IncludeSecrets,
		IncludeKnownHosts: req.IncludeKnownHosts,
	})
	if err != nil {
		writeInternal(w, a.log, "gathering an export", err)
		return
	}

	// Written to a buffer first: a failure partway through would otherwise
	// have already sent a 200 and half a file, which a browser would save as
	// a complete but truncated export.
	var buf bytes.Buffer
	var warnings []string

	if format == portability.FormatBundle {
		if err := portability.Write(&buf, payload, portability.WriteOptions{
			Passphrase: []byte(req.Passphrase),
			CreatedBy:  u.Email,
			Note:       req.Note,
		}); err != nil {
			writeInternal(w, a.log, "writing a bundle", err)
			return
		}
	} else {
		result, err := portability.Export(&buf, payload, format, portability.ExportOptions{
			IncludeSecrets: req.IncludeSecrets,
		})
		if err != nil {
			writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
			return
		}
		warnings = result.Warnings
	}

	severity := audit.SeverityInfo
	action := audit.ActionExported
	unauditedIsFatal := false
	if format.Plaintext() && req.IncludeSecrets {
		// The most security-relevant action in the system, and the audit
		// recorder raises this to critical whatever is passed here.
		action = audit.ActionExportedPlaintext
		severity = audit.SeverityCritical
		unauditedIsFatal = true
	}

	event := audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: action, Severity: severity, TargetType: "export",
		TargetLabel: string(format),
		Detail: map[string]any{
			"format": string(format), "includes_key_material": req.IncludeSecrets,
			"sessions": payload.Counts().Sessions, "credentials": payload.Counts().Credentials,
			"bytes": buf.Len(),
		},
	}

	if unauditedIsFatal {
		// Refused rather than logged. If this system cannot record that
		// somebody took every credential out of the vault in the clear, it
		// must not be the thing that hands them over — an unaudited
		// plaintext export is precisely the event an investigation would
		// start from and find missing.
		if err := a.audit.RecordErr(r.Context(), event); err != nil {
			a.log.Error("refusing a plaintext export that could not be audited",
				"user", u.ID, "format", format, "error", err)
			writeError(w, a.log, http.StatusServiceUnavailable, CodeInternal,
				"This export could not be recorded in the audit log, so it was "+
					"refused. Tell an administrator: the audit trail is not working.")
			return
		}
	} else {
		a.audit.Record(r.Context(), event)
	}

	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(format.Filename()))
	h.Set("X-Content-Type-Options", "nosniff")
	// Never cached, anywhere. This response is the user's entire credential
	// store; a copy in a proxy or a disk cache is the thing the encryption
	// was for.
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	h.Set("Pragma", "no-cache")

	if len(warnings) > 0 {
		// Sent as a header because the body is the file. The interface reads
		// it and shows what the format could not express.
		h.Set("X-Export-Warnings", strings.Join(warnings, " | "))
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		a.log.Debug("export interrupted", "error", err)
	}
}

// vaultKeyFor returns the user's vault key, or nil when it is locked.
func (a *API) vaultKeyFor(userID, sessionID string) []byte {
	key, err := a.vaults.Key(userID, sessionID)
	if err != nil {
		return nil
	}
	return key
}

// handlePortabilityConfig tells the interface what is available.
func (a *API) handlePortabilityConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"allow_plaintext_export":  a.cfg.AllowPlaintextExport,
		"min_passphrase_length":   portability.MinPassphraseLength,
		"max_upload_bytes":        a.cfg.importLimit(),
		"sources":                 []string{"bundle", "securecrt", "ssh_config", "putty", "csv"},
		"formats":                 []string{"bundle", "ssh_config", "securecrt", "putty_reg", "json", "csv"},
		"formats_carrying_secret": []string{"bundle", "securecrt", "json", "csv"},
	})
}

// writeImportError maps a failure to read an upload onto a response.
func (a *API) writeImportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, portability.ErrWrongPassphrase):
		writeError(w, a.log, http.StatusForbidden, CodeInvalidCode,
			"That passphrase did not open the bundle.")

	case errors.Is(err, portability.ErrNotABundle):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That file is not a bkd bundle.")

	case errors.Is(err, portability.ErrUnsupportedVersion):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())

	case errors.Is(err, portability.ErrBundleTooLarge):
		writeError(w, a.log, http.StatusRequestEntityTooLarge, CodeBadRequest,
			"That file is too large to read.")

	case errors.Is(err, portability.ErrNotAnArchive):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That is not a zip archive. Zip your configuration folder and upload that.")

	case errors.Is(err, portability.ErrUnknownSource):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That is not a format this can read.")

	default:
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			fmt.Sprintf("That file could not be read: %v", err))
	}
}
