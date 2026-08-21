package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/teams"
	"github.com/mrbuttshooter/securecrt/internal/users"
)

// Teams and the administrator's view.
//
// Management — creating teams, membership, deleting — sits behind withAdmin
// at the routing layer. Reading is looser on purpose: any member may list
// their own teams, because the tree view needs names for its badges.

// handleListTeams returns all teams for an administrator, or the caller's
// own teams for anyone else.
func (a *API) handleListTeams(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var (
		list []teams.Team
		err  error
	)
	if u.IsAdmin {
		list, err = a.teams.List(r.Context())
	} else {
		list, err = a.teams.ListForUser(r.Context(), u.ID)
	}
	if err != nil {
		writeInternal(w, a.log, "listing teams", err)
		return
	}
	if list == nil {
		list = []teams.Team{}
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"teams": list})
}

func (a *API) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "A team needs a name.")
		return
	}

	team, err := a.teams.Create(r.Context(), req.Name, strings.TrimSpace(req.Description))
	if err != nil {
		if errors.Is(err, teams.ErrExists) {
			writeError(w, a.log, http.StatusConflict, CodeConflict,
				"A team with that name already exists.")
			return
		}
		writeInternal(w, a.log, "creating a team", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "team.created", TargetType: "team",
		TargetID: team.ID, TargetLabel: team.Name,
	})
	writeJSON(w, a.log, http.StatusCreated, team)
}

func (a *API) handleDeleteTeam(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/teams/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No team was specified.")
		return
	}

	team, err := a.teams.Get(r.Context(), id)
	if err != nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such team.")
		return
	}

	// Deleting a team cascades its shared folders and connections away. Say
	// what is at stake so the interface can confirm with real numbers.
	tree, err := a.sessionTree.LoadTree(r.Context(), id, true)
	if err != nil {
		writeInternal(w, a.log, "counting a team's tree", err)
		return
	}
	if r.URL.Query().Get("confirm") != "true" && (len(tree.Folders) > 0 || len(tree.Sessions) > 0) {
		writeError(w, a.log, http.StatusConflict, CodeConflict,
			"This team owns shared folders and connections that will be deleted with it. Repeat the request with ?confirm=true.")
		return
	}

	if err := a.teams.Delete(r.Context(), id); err != nil {
		writeInternal(w, a.log, "deleting a team", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "team.deleted", Severity: audit.SeverityNotice,
		TargetType: "team", TargetID: id, TargetLabel: team.Name,
		Detail: map[string]any{
			"shared_folders": len(tree.Folders), "shared_connections": len(tree.Sessions),
		},
	})
	writeJSON(w, a.log, http.StatusOK, map[string]any{"deleted": true})
}

func (a *API) handleListTeamMembers(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(pathID(strings.TrimSuffix(r.URL.Path, "/members"), "/api/teams/"), "/members")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No team was specified.")
		return
	}
	members, err := a.teams.ListMembers(r.Context(), id)
	if err != nil {
		writeInternal(w, a.log, "listing team members", err)
		return
	}
	if members == nil {
		members = []teams.Member{}
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"members": members})
}

func (a *API) handleAddTeamMember(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(strings.TrimSuffix(r.URL.Path, "/members"), "/api/teams/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No team was specified.")
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	member, err := a.users.ByEmail(r.Context(), strings.TrimSpace(req.Email))
	if err != nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound,
			"No account with that email address.")
		return
	}
	if _, err := a.teams.Get(r.Context(), id); err != nil {
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such team.")
		return
	}

	if err := a.teams.AddMember(r.Context(), id, member.ID); err != nil {
		writeInternal(w, a.log, "adding a team member", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "team.member.added", TargetType: "team", TargetID: id,
		Detail: map[string]any{"member": member.Email},
	})
	writeJSON(w, a.log, http.StatusOK, map[string]any{"added": true})
}

func (a *API) handleRemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	// /api/teams/{id}/members/{userID}
	rest := strings.TrimPrefix(r.URL.Path, "/api/teams/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "members" || parts[0] == "" || parts[2] == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No member was specified.")
		return
	}
	teamID, memberID := parts[0], parts[2]

	if err := a.teams.RemoveMember(r.Context(), teamID, memberID); err != nil {
		if errors.Is(err, teams.ErrNotFound) {
			writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such membership.")
			return
		}
		writeInternal(w, a.log, "removing a team member", err)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "team.member.removed", TargetType: "team", TargetID: teamID,
		Detail: map[string]any{"member_id": memberID},
	})
	writeJSON(w, a.log, http.StatusOK, map[string]any{"removed": true})
}

// handleListUsers gives administrators the roster, for membership pickers.
func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := a.users.List(r.Context(), 500)
	if err != nil {
		writeInternal(w, a.log, "listing users", err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, one := range list {
		out = append(out, map[string]any{
			"id":       one.ID,
			"email":    one.Email,
			"name":     one.DisplayName,
			"is_admin": one.IsAdmin,
			"disabled": one.IsDisabled,
		})
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"users": out})
}

// handleSetFolderCredential remembers the caller's credential for a shared
// folder — the member-side half of the shared tree.
func (a *API) handleSetFolderCredential(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(strings.TrimSuffix(r.URL.Path, "/credential"), "/api/tree/folders/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No folder was specified.")
		return
	}

	var req struct {
		CredentialID string `json:"credential_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	if err := a.sessionTree.SetFolderCredential(r.Context(), u.ID, id, req.CredentialID); err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			writeError(w, a.log, http.StatusNotFound, CodeNotFound,
				"No such folder, or the credential is not yours.")
			return
		}
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"saved": true})
}

// handleAdminTerminals is the operator's answer to "who is connected to what
// right now" — every user's live terminals, with the owner named.
func (a *API) handleAdminTerminals(w http.ResponseWriter, r *http.Request) {
	infos := a.terminals.ListAll()

	// One roster fetch rather than a lookup per terminal.
	roster, err := a.users.List(r.Context(), 500)
	if err != nil {
		writeInternal(w, a.log, "listing users", err)
		return
	}
	emails := make(map[string]string, len(roster))
	for _, one := range roster {
		emails[one.ID] = one.Email
	}

	out := make([]map[string]any, 0, len(infos))
	for _, t := range infos {
		out = append(out, map[string]any{
			"id":         t.ID,
			"user_id":    t.UserID,
			"user_email": emails[t.UserID],
			"label":      t.Label,
			"protocol":   t.Protocol,
			"host":       t.Host,
			"port":       t.Port,
			"device":     t.Device,
			"encrypted":  t.Encrypted,
			"recorded":   t.Recorded,
			"created_at": t.CreatedAt,
			"attached":   t.Attached,
			"closed":     t.Closed,
		})
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"terminals": out})
}

// handleAdminAudit searches the audit trail.
func (a *API) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := audit.Query{
		ActorID: q.Get("actor"),
		Action:  audit.Action(q.Get("action")),
		Limit:   atoiOr(q.Get("limit"), 100),
	}
	if query.Limit > 500 {
		query.Limit = 500
	}

	events, err := a.audit.List(r.Context(), query)
	if err != nil {
		writeInternal(w, a.log, "searching the audit log", err)
		return
	}

	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"id":           e.ID,
			"occurred_at":  e.OccurredAt,
			"actor_id":     e.ActorID,
			"actor_email":  e.ActorEmail,
			"ip":           e.IPAddress,
			"action":       string(e.Action),
			"severity":     string(e.Severity),
			"target_type":  e.TargetType,
			"target_id":    e.TargetID,
			"target_label": e.TargetLabel,
			"outcome":      string(e.Outcome),
			"detail":       e.Detail,
		})
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"events": out})
}

// Compile-time check that the user type this file leans on stays compatible.
var _ = users.User{}
