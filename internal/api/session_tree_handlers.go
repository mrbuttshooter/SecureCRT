package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// folderView renders a folder for the interface.
func folderView(f sessions.Folder) map[string]any {
	return map[string]any{
		"id":         f.ID,
		"parent_id":  f.ParentID,
		"name":       f.Name,
		"defaults":   f.Defaults,
		"sort_order": f.SortOrder,
		"created_at": f.CreatedAt.Format(time.RFC3339),
		"updated_at": f.UpdatedAt.Format(time.RFC3339),
	}
}

// savedSessionView renders a saved connection.
//
// Built by hand rather than serialising the domain type, for the same reason
// as credentials: adding a field internally must never silently start
// publishing it.
func savedSessionView(s sessions.Session) map[string]any {
	view := map[string]any{
		"id":            s.ID,
		"folder_id":     s.FolderID,
		"name":          s.Name,
		"protocol":      string(s.Protocol),
		"hostname":      s.Hostname,
		"port":          s.Port,
		"username":      s.Username,
		"credential_id": s.CredentialID,
		"jump_chain":    s.JumpChain,
		"settings":      s.Settings,
		"sort_order":    s.SortOrder,
		"created_at":    s.CreatedAt.Format(time.RFC3339),
		"updated_at":    s.UpdatedAt.Format(time.RFC3339),
	}
	if s.LastUsedAt != nil {
		view["last_used_at"] = s.LastUsedAt.Format(time.RFC3339)
	}
	return view
}

// handleGetTree returns the whole saved-connection tree in one response.
//
// The interface renders it all at once, so fetching folder by folder would
// mean a request per folder — noticeable with a few hundred devices.
func (a *API) handleGetTree(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	tree, err := a.sessionTree.LoadTree(r.Context(), u.ID, false)
	if err != nil {
		writeInternal(w, a.log, "loading the session tree", err)
		return
	}

	folders := make([]map[string]any, 0, len(tree.Folders))
	for _, f := range tree.Folders {
		folders = append(folders, folderView(f))
	}
	saved := make([]map[string]any, 0, len(tree.Sessions))
	for _, s := range tree.Sessions {
		saved = append(saved, savedSessionView(s))
	}

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"folders":  folders,
		"sessions": saved,
	})
}

type folderRequest struct {
	Name      string             `json:"name"`
	ParentID  string             `json:"parent_id"`
	SortOrder *int               `json:"sort_order"`
	Defaults  *sessions.Settings `json:"defaults"`
}

func (a *API) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req folderRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	var defaults sessions.Settings
	if req.Defaults != nil {
		defaults = *req.Defaults
	}

	folder, err := a.sessionTree.CreateFolder(r.Context(), sessions.CreateFolderParams{
		OwnerID: u.ID, ParentID: req.ParentID, Name: req.Name, Defaults: defaults,
	})
	if err != nil {
		a.writeTreeError(w, err, "creating a folder")
		return
	}

	writeJSON(w, a.log, http.StatusCreated, folderView(folder))
}

func (a *API) handleUpdateFolder(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/tree/folders/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No folder was specified.")
		return
	}

	// Pointer fields so an omitted key leaves the value alone rather than
	// clearing it.
	var req struct {
		Name      *string            `json:"name"`
		ParentID  *string            `json:"parent_id"`
		SortOrder *int               `json:"sort_order"`
		Defaults  *sessions.Settings `json:"defaults"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	folder, err := a.sessionTree.UpdateFolder(r.Context(), u.ID, id, sessions.UpdateFolderParams{
		Name: req.Name, ParentID: req.ParentID, SortOrder: req.SortOrder, Defaults: req.Defaults,
	})
	if err != nil {
		a.writeTreeError(w, err, "updating a folder")
		return
	}

	writeJSON(w, a.log, http.StatusOK, folderView(folder))
}

// handleDeleteFolder removes a folder, recursively only when asked.
func (a *API) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/tree/folders/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No folder was specified.")
		return
	}

	folder, err := a.sessionTree.GetFolder(r.Context(), u.ID, id)
	if err != nil {
		a.writeTreeError(w, err, "loading a folder")
		return
	}

	// Recursion is opt-in via a query parameter, so a mis-sent request cannot
	// destroy a subtree.
	if r.URL.Query().Get("recursive") != "true" {
		if err := a.sessionTree.DeleteFolder(r.Context(), u.ID, id); err != nil {
			a.writeTreeError(w, err, "deleting a folder")
			return
		}
		a.audit.Record(r.Context(), audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: "session.folder.deleted", TargetType: "folder",
			TargetID: id, TargetLabel: folder.Name,
		})
		writeJSON(w, a.log, http.StatusOK, map[string]any{"deleted": true})
		return
	}

	destroyed, err := a.sessionTree.DeleteFolderRecursive(r.Context(), u.ID, id)
	if err != nil {
		a.writeTreeError(w, err, "deleting a folder")
		return
	}

	// Recorded at notice level with the count, because this is the action
	// somebody regrets and then wants to look up.
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "session.folder.deleted", Severity: audit.SeverityNotice,
		TargetType: "folder", TargetID: id, TargetLabel: folder.Name,
		Detail: map[string]any{"recursive": true, "connections_deleted": destroyed},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"deleted":             true,
		"connections_deleted": destroyed,
	})
}

type savedSessionRequest struct {
	Name         string             `json:"name"`
	FolderID     string             `json:"folder_id"`
	Protocol     string             `json:"protocol"`
	Hostname     string             `json:"hostname"`
	Port         int                `json:"port"`
	Username     string             `json:"username"`
	CredentialID string             `json:"credential_id"`
	JumpChain    []string           `json:"jump_chain"`
	Settings     *sessions.Settings `json:"settings"`
}

func (a *API) handleCreateSavedSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req savedSessionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	var settings sessions.Settings
	if req.Settings != nil {
		settings = *req.Settings
	}

	created, err := a.sessionTree.CreateSession(r.Context(), sessions.CreateSessionParams{
		OwnerID:      u.ID,
		FolderID:     req.FolderID,
		Name:         req.Name,
		Protocol:     sessions.Protocol(req.Protocol),
		Hostname:     req.Hostname,
		Port:         req.Port,
		Username:     req.Username,
		CredentialID: req.CredentialID,
		JumpChain:    req.JumpChain,
		Settings:     settings,
	})
	if err != nil {
		a.writeTreeError(w, err, "creating a saved connection")
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "session.created", TargetType: "session",
		TargetID: created.ID, TargetLabel: created.Name,
		Detail: map[string]any{"hostname": created.Hostname, "port": created.Port},
	})

	writeJSON(w, a.log, http.StatusCreated, savedSessionView(created))
}

func (a *API) handleUpdateSavedSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/tree/sessions/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return
	}

	var req struct {
		Name         *string            `json:"name"`
		FolderID     *string            `json:"folder_id"`
		Protocol     *string            `json:"protocol"`
		Hostname     *string            `json:"hostname"`
		Port         *int               `json:"port"`
		Username     *string            `json:"username"`
		CredentialID *string            `json:"credential_id"`
		JumpChain    *[]string          `json:"jump_chain"`
		Settings     *sessions.Settings `json:"settings"`
		SortOrder    *int               `json:"sort_order"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	params := sessions.UpdateSessionParams{
		Name: req.Name, FolderID: req.FolderID, Hostname: req.Hostname,
		Port: req.Port, Username: req.Username, CredentialID: req.CredentialID,
		JumpChain: req.JumpChain, Settings: req.Settings, SortOrder: req.SortOrder,
	}
	if req.Protocol != nil {
		p := sessions.Protocol(*req.Protocol)
		params.Protocol = &p
	}

	updated, err := a.sessionTree.UpdateSession(r.Context(), u.ID, id, params)
	if err != nil {
		a.writeTreeError(w, err, "updating a saved connection")
		return
	}

	writeJSON(w, a.log, http.StatusOK, savedSessionView(updated))
}

func (a *API) handleDeleteSavedSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/tree/sessions/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return
	}

	// Read it first, so the audit record can name what went.
	existing, err := a.sessionTree.GetSession(r.Context(), u.ID, id)
	if err != nil {
		a.writeTreeError(w, err, "loading a saved connection")
		return
	}
	if err := a.sessionTree.DeleteSession(r.Context(), u.ID, id); err != nil {
		a.writeTreeError(w, err, "deleting a saved connection")
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: "session.deleted", TargetType: "session",
		TargetID: id, TargetLabel: existing.Name,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"deleted": true})
}

// handleResolveSession shows the effective settings after folder inheritance,
// so the interface can explain where a value came from before connecting.
func (a *API) handleResolveSession(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := strings.TrimSuffix(pathID(r.URL.Path, "/api/tree/sessions/"), "/resolved")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return
	}

	resolved, err := a.sessionTree.Resolve(r.Context(), u.ID, id)
	if err != nil {
		a.writeTreeError(w, err, "resolving a saved connection")
		return
	}

	view := savedSessionView(resolved.Session)
	view["effective"] = map[string]any{
		"username":      resolved.EffectiveUsername,
		"port":          resolved.EffectivePort,
		"credential_id": resolved.EffectiveCredentialID,
	}
	view["inherited_from"] = resolved.InheritedFrom

	writeJSON(w, a.log, http.StatusOK, view)
}

// pathID extracts a trailing identifier, rejecting anything with a further
// slash so a nested path cannot be read as an ID.
func pathID(path, prefix string) string {
	id := strings.TrimPrefix(path, prefix)
	id = strings.TrimSuffix(id, "/resolved")
	if id == "" || strings.Contains(id, "/") {
		return ""
	}
	return id
}

// writeTreeError maps store errors to responses.
func (a *API) writeTreeError(w http.ResponseWriter, err error, context string) {
	var (
		notEmpty  *sessions.ErrFolderNotEmpty
		jumpInUse *sessions.ErrJumpInUse
	)

	switch {
	case errors.Is(err, sessions.ErrNotFound):
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such folder or connection.")

	case errors.As(err, &notEmpty):
		// The counts go back so the interface can say exactly what would be
		// lost rather than asking a vague "are you sure?".
		var body errorBody
		body.Error.Code = "folder_not_empty"
		body.Error.Message = "That folder is not empty."
		writeJSON(w, a.log, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code":     "folder_not_empty",
				"message":  "That folder is not empty.",
				"folders":  notEmpty.Folders,
				"sessions": notEmpty.Sessions,
			},
		})

	case errors.As(err, &jumpInUse):
		// Named, not counted. "Three connections use this" leaves somebody
		// hunting; naming them means they can go and change those three.
		writeJSON(w, a.log, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code": "jump_host_in_use",
				"message": "Other connections are reached through this one. " +
					"Change their route first, or delete them.",
				"used_by": jumpInUse.Names,
			},
		})

	case errors.Is(err, sessions.ErrJumpNotFound):
		writeError(w, a.log, http.StatusBadRequest, "jump_host_not_found",
			"One of the jump hosts on that route no longer exists.")

	case errors.Is(err, sessions.ErrJumpSelf):
		writeError(w, a.log, http.StatusBadRequest, "jump_chain_invalid",
			"A connection cannot be reached through itself.")

	case errors.Is(err, sessions.ErrJumpCycle):
		writeError(w, a.log, http.StatusBadRequest, "jump_chain_invalid",
			"That route loops back on itself, so it would never arrive.")

	case errors.Is(err, sessions.ErrJumpTooLong):
		writeError(w, a.log, http.StatusBadRequest, "jump_chain_invalid",
			fmt.Sprintf("A route can pass through at most %d hosts.", sessions.MaxJumpChain))

	case errors.Is(err, sessions.ErrJumpProtocol):
		writeError(w, a.log, http.StatusBadRequest, "jump_chain_invalid",
			"Only SSH connections can be used as jump hosts.")

	case errors.Is(err, sessions.ErrCycle):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"A folder cannot be moved inside itself.")

	case errors.Is(err, sessions.ErrTooDeep):
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"Folders cannot be nested that deeply.")

	default:
		if isTreeValidationError(err) {
			writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, userFacing(err))
			return
		}
		writeInternal(w, a.log, context, err)
	}
}

// isTreeValidationError reports whether an error came from input validation.
func isTreeValidationError(err error) bool {
	msg := err.Error()
	for _, prefix := range []string{
		"sessions: a name is required",
		"sessions: a folder name is required",
		"sessions: a hostname is required",
		"sessions: an owner is required",
		"sessions: port ",
		"sessions: unknown protocol",
		"sessions: destination folder",
	} {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}
