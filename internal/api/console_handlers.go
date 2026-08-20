package api

import (
	"net/http"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/consoles"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// Console servers: one appliance becomes a folder of lines.
//
// Plan then apply, like every import here, and for the same reason stated at
// the top of MIGRATING.md: nothing is written until somebody has seen what
// would happen. Forty-eight connections generated from a base port that was
// right for the last rack is a mistake to catch on screen rather than in an
// outage six weeks later.

func (a *API) handleConsoleProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"profiles":             consoles.Profiles(),
		"default_name_pattern": consoles.DefaultNamePattern,
		"max_lines":            consoles.MaxLines,
	})
}

type consoleRequest struct {
	ProfileID   string `json:"profile_id"`
	Hostname    string `json:"hostname"`
	Protocol    string `json:"protocol"`
	BasePort    int    `json:"base_port"`
	FirstLine   int    `json:"first_line"`
	Lines       int    `json:"lines"`
	NamePattern string `json:"name_pattern"`

	Username     string `json:"username"`
	CredentialID string `json:"credential_id"`
	FolderID     string `json:"folder_id"`
}

func (r consoleRequest) params() consoles.Params {
	return consoles.Params{
		ProfileID:    r.ProfileID,
		Hostname:     r.Hostname,
		Protocol:     sessions.Protocol(r.Protocol),
		BasePort:     r.BasePort,
		FirstLine:    r.FirstLine,
		Lines:        r.Lines,
		NamePattern:  r.NamePattern,
		Username:     r.Username,
		CredentialID: r.CredentialID,
		FolderID:     r.FolderID,
	}
}

// handleConsolePlan shows what would be created.
func (a *API) handleConsolePlan(w http.ResponseWriter, r *http.Request) {
	var req consoleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	plan, err := consoles.Build(req.params())
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	writeJSON(w, a.log, http.StatusOK, plan)
}

// handleConsoleApply creates the connections.
func (a *API) handleConsoleApply(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req consoleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	plan, err := consoles.Build(req.params())
	if err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	// The credential is checked before anything is written rather than
	// after: half a rack created against a credential that turns out not to
	// exist is worse than none of it.
	if req.CredentialID != "" {
		if _, err := a.credentials.Get(r.Context(), u.ID, req.CredentialID); err != nil {
			writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
				"That credential does not exist.")
			return
		}
	}

	created := make([]map[string]any, 0, len(plan.Lines))
	for _, params := range plan.SessionParams(u.ID, req.FolderID, req.Username, req.CredentialID) {
		session, err := a.sessionTree.CreateSession(r.Context(), params)
		if err != nil {
			// Reported with what was already made rather than rolled back.
			// These are independent connections, not one transaction, and
			// the useful answer to "it stopped at line 31" is the list of
			// thirty that worked — not an empty tree and the same error.
			writeJSON(w, a.log, http.StatusMultiStatus, map[string]any{
				"created": created,
				"error": map[string]any{
					"code":    CodeBadRequest,
					"message": "Stopped part-way: " + err.Error(),
				},
			})
			return
		}
		created = append(created,
			savedSessionView(session, a.effectivePort(r, u.ID, session)))
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionConsoleGenerated, TargetType: "folder",
		TargetID: req.FolderID, TargetLabel: plan.Hostname,
		Detail: map[string]any{
			"profile": plan.Profile.ID, "protocol": string(plan.Protocol),
			"hostname": plan.Hostname, "lines": len(created),
		},
	})

	writeJSON(w, a.log, http.StatusCreated, map[string]any{"created": created})
}
