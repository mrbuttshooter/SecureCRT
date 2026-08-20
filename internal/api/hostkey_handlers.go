package api

import (
	"net/http"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
)

// handleListKnownHosts shows which host keys are trusted, and where each
// decision came from.
//
// Worth surfacing: a user who has accepted a fingerprint they now doubt needs
// somewhere to see and remove it, and an org-wide entry needs to be visibly
// distinct so they understand why they cannot.
func (a *API) handleListKnownHosts(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	entries, err := a.hostKeys.ListForUser(r.Context(), u.ID)
	if err != nil {
		writeInternal(w, a.log, "listing known hosts", err)
		return
	}

	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"id":          e.ID,
			"hostname":    e.Hostname,
			"port":        e.Port,
			"key_type":    e.KeyType,
			"fingerprint": e.Fingerprint,
			"org_wide":    e.IsOrgWide(),
			"created_at":  e.CreatedAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, a.log, http.StatusOK, map[string]any{"known_hosts": out})
}

// handleForgetKnownHost removes a user's trust decision for a host.
//
// Only their own: an org-wide entry is an administrator's decision, and
// letting a user delete it locally would defeat the point of publishing it.
func (a *API) handleForgetKnownHost(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/known-hosts/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No host was specified.")
		return
	}

	entries, err := a.hostKeys.ListForUser(r.Context(), u.ID)
	if err != nil {
		writeInternal(w, a.log, "listing known hosts", err)
		return
	}

	var target *hostkeys.Entry
	for i := range entries {
		if entries[i].ID == id {
			target = &entries[i]
			break
		}
	}
	if target == nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such host key.")
		return
	}
	if target.IsOrgWide() {
		writeError(w, a.log, http.StatusForbidden, CodeForbidden,
			"That host key was published by an administrator and cannot be removed here.")
		return
	}

	if _, err := a.hostKeys.Forget(r.Context(), u.ID, target.Hostname, target.Port); err != nil {
		writeInternal(w, a.log, "forgetting a host key", err)
		return
	}

	// Recorded at notice level: forgetting a host key means the next
	// connection will accept whatever is offered, which is worth being able
	// to look up afterwards.
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "hostkey.forgotten", Severity: audit.SeverityNotice,
		TargetType: "known_host", TargetID: id,
		TargetLabel: hostkeys.Describe(target.Hostname, target.Port),
		Detail:      map[string]any{"fingerprint": target.Fingerprint},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"forgotten": true})
}
