package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Transcripts: the recordings a user's own sessions have written.
//
// Scoped to the requesting user's directory in every handler — an operator
// reviewing someone else's transcripts does it on the server, with the
// filesystem permissions that directory already enforces, not through this
// API. The web interface answers "what did I do on that switch last Tuesday",
// which is the question engineers actually have.

// handleListTranscripts lists the caller's transcripts, newest first.
func (a *API) handleListTranscripts(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	list, err := terminal.ListTranscripts(a.connector.SessionLogDir(), u.ID)
	if err != nil {
		writeInternal(w, a.log, "listing transcripts", err)
		return
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"transcripts": list})
}

// handleDownloadTranscript streams one transcript as plain text.
func (a *API) handleDownloadTranscript(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	name := pathID(r.URL.Path, "/api/transcripts/")
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No transcript was specified.")
		return
	}

	file, err := terminal.OpenTranscriptFile(a.connector.SessionLogDir(), u.ID, name)
	if err != nil {
		// Everything collapses to not-found: a traversal attempt and a
		// genuinely missing file should be indistinguishable from outside.
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such transcript.")
		return
	}
	defer func() { _ = file.Close() }()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if _, err := io.Copy(w, file); err != nil {
		// The response is already streaming; all that is left is to log.
		a.log.Debug("streaming a transcript", "error", err)
	}
}

// handleToggleRecording starts or stops a transcript on a live terminal.
func (a *API) handleToggleRecording(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := strings.TrimSuffix(pathID(r.URL.Path, "/api/terminals/"), "/recording")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No terminal was specified.")
		return
	}

	var body struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "The request body could not be read.")
		return
	}

	term, err := a.terminals.Get(u.ID, id)
	if err != nil {
		if errors.Is(err, terminal.ErrTerminalNotFound) {
			writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such terminal.")
			return
		}
		writeInternal(w, a.log, "finding a terminal", err)
		return
	}

	if body.On {
		if _, err := a.connector.StartRecording(term); err != nil {
			if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "session_log_dir") {
				writeError(w, a.log, http.StatusConflict, CodeConflict,
					"Recording is not available: no session log directory is configured on this server.")
				return
			}
			if strings.Contains(err.Error(), "already being recorded") {
				writeJSON(w, a.log, http.StatusOK, map[string]any{"recorded": true})
				return
			}
			writeInternal(w, a.log, "starting a recording", err)
			return
		}
		a.audit.Record(r.Context(), audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: audit.ActionRecordingStarted, TargetType: "terminal", TargetID: id,
			Detail: map[string]any{"transcript": term.TranscriptPath()},
		})
		writeJSON(w, a.log, http.StatusOK, map[string]any{"recorded": true})
		return
	}

	if err := term.StopRecording(); err != nil {
		writeError(w, a.log, http.StatusForbidden, CodeForbidden,
			"Recording is required by this server's policy and cannot be turned off.")
		return
	}
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionRecordingStopped, TargetType: "terminal", TargetID: id,
	})
	writeJSON(w, a.log, http.StatusOK, map[string]any{"recorded": false})
}
