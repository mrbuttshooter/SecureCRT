package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
)

// handleListSessions shows where the user is signed in.
//
// The point of this screen is that someone can notice a session they do not
// recognise, so it shows enough to identify a device — and no session token,
// which would turn the screen itself into a credential leak.
func (a *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	current, _ := SessionFrom(r.Context())

	list, err := a.sessions.ListForUser(r.Context(), u.ID)
	if err != nil {
		writeInternal(w, a.log, "listing sessions", err)
		return
	}

	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		out = append(out, map[string]any{
			"id":            s.ID,
			"current":       s.ID == current.ID,
			"auth_method":   string(s.AuthMethod),
			"user_agent":    s.UserAgent,
			"ip_address":    s.IPAddress,
			"mfa_satisfied": s.MFASatisfied,
			"created_at":    s.CreatedAt.Format(time.RFC3339),
			"expires_at":    s.ExpiresAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, a.log, http.StatusOK, map[string]any{"sessions": out})
}

// handleRevokeSession ends one session.
func (a *API) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	current, _ := SessionFrom(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No session was specified.")
		return
	}

	// Confirm ownership before revoking: without this check any signed-in
	// user could end anyone else's session by guessing an ID.
	target, err := a.sessions.Get(r.Context(), id)
	if err != nil || target.UserID != u.ID {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such session.")
		return
	}

	a.vaults.Lock(u.ID, id)
	if err := a.sessions.Revoke(r.Context(), id); err != nil {
		writeInternal(w, a.log, "revoking session", err)
		return
	}

	// Revoking your own session is a sign-out, so clear the cookie too rather
	// than leaving the browser holding a dead one.
	if id == current.ID {
		http.SetCookie(w, a.cfg.Session.ClearSessionCookie())
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionSessionRevoked, TargetType: "session", TargetID: id,
		Detail: map[string]any{"self": id == current.ID},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"revoked": true})
}

// handleRevokeOtherSessions signs the user out everywhere except here.
//
// The action someone takes on noticing a session they do not recognise, so it
// must not also sign them out of the device they are using to react.
func (a *API) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	current, _ := SessionFrom(r.Context())

	list, err := a.sessions.ListForUser(r.Context(), u.ID)
	if err != nil {
		writeInternal(w, a.log, "listing sessions", err)
		return
	}
	for _, s := range list {
		if s.ID != current.ID {
			a.vaults.Lock(u.ID, s.ID)
		}
	}

	n, err := a.sessions.RevokeAllForUserExcept(r.Context(), u.ID, current.ID)
	if err != nil {
		writeInternal(w, a.log, "revoking other sessions", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionSessionRevoked, Severity: audit.SeverityNotice,
		Detail: map[string]any{"count": n, "scope": "all_other_sessions"},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"revoked": n})
}
