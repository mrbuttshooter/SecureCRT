package api

import (
	"errors"
	"net/http"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/snippets"
)

// Snippets: the commands people paste for the hundredth time.
//
// Ordinary CRUD, with one endpoint that is not: sending one to a terminal.
// That is a write to a device, so it goes through the terminal the user
// already has open rather than opening anything, and it is audited.

func snippetView(s snippets.Snippet) map[string]any {
	return map[string]any{
		"id":          s.ID,
		"name":        s.Name,
		"description": s.Description,
		"body":        s.Body,
		"parameters":  s.Parameters,
		"sort_order":  s.SortOrder,
		"created_at":  s.CreatedAt,
		"updated_at":  s.UpdatedAt,
	}
}

func (a *API) handleListSnippets(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	stored, err := a.snippets.ListForOwner(r.Context(), u.ID, false)
	if err != nil {
		writeInternal(w, a.log, "listing snippets", err)
		return
	}

	out := make([]map[string]any, 0, len(stored))
	for _, snippet := range stored {
		out = append(out, snippetView(snippet))
	}
	writeJSON(w, a.log, http.StatusOK, map[string]any{"snippets": out})
}

type snippetRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Body        string `json:"body"`
	SortOrder   *int   `json:"sort_order"`
}

func (a *API) handleCreateSnippet(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req snippetRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	order := 0
	if req.SortOrder != nil {
		order = *req.SortOrder
	}

	created, err := a.snippets.Create(r.Context(), snippets.CreateParams{
		OwnerID: u.ID, Name: req.Name, Description: req.Description,
		Body: req.Body, SortOrder: order,
	})
	if err != nil {
		a.writeSnippetError(w, err, "creating a snippet")
		return
	}

	writeJSON(w, a.log, http.StatusCreated, snippetView(created))
}

func (a *API) handleUpdateSnippet(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/snippets/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No snippet was specified.")
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Body        *string `json:"body"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	updated, err := a.snippets.Update(r.Context(), u.ID, id, snippets.UpdateParams{
		Name: req.Name, Description: req.Description,
		Body: req.Body, SortOrder: req.SortOrder,
	})
	if err != nil {
		a.writeSnippetError(w, err, "updating a snippet")
		return
	}

	writeJSON(w, a.log, http.StatusOK, snippetView(updated))
}

func (a *API) handleDeleteSnippet(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/snippets/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No snippet was specified.")
		return
	}

	if err := a.snippets.Delete(r.Context(), u.ID, id); err != nil {
		a.writeSnippetError(w, err, "deleting a snippet")
		return
	}

	writeJSON(w, a.log, http.StatusOK, map[string]any{"deleted": true})
}

type sendSnippetRequest struct {
	SnippetID string `json:"snippet_id"`

	// Values fill the snippet's parameters. Not stored, here or anywhere:
	// remembering them would make a snippet the obvious place to keep a
	// password, which is a credential outside the vault in a table nobody
	// thinks of as holding secrets.
	Values map[string]string `json:"values"`

	// Terminals are the terminals to send it to. More than one is the
	// deliberate case — a snippet across a rack is the point — and is why
	// this is a list rather than a path parameter.
	Terminals []string `json:"terminals"`
}

// handleSendSnippet types a snippet at one or more open terminals.
//
// Goes through terminals the user already has open rather than opening
// anything: this is not a way to reach a device, it is a way to type at one
// that is already reached. Which also means it inherits everything those
// sessions already have — the transcript, the triggers, the audit trail.
func (a *API) handleSendSnippet(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	var req sendSnippetRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	if len(req.Terminals) == 0 {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"No terminals were named.")
		return
	}

	snippet, err := a.snippets.Get(r.Context(), u.ID, req.SnippetID)
	if err != nil {
		a.writeSnippetError(w, err, "reading a snippet")
		return
	}

	body := snippets.Render(snippet.Body, req.Values)

	// Every terminal is checked before anything is typed. Half a rack having
	// received a configuration command is worse than none of it, and the
	// failure people actually hit here is a stale terminal id in a tab that
	// was closed on another device.
	targets := make([]*terminalTarget, 0, len(req.Terminals))
	for _, id := range req.Terminals {
		term, err := a.terminals.Get(u.ID, id)
		if err != nil {
			writeError(w, a.log, http.StatusNotFound, CodeNotFound,
				"One of those terminals is no longer open. Nothing was sent.")
			return
		}
		targets = append(targets, &terminalTarget{id: id, label: term.Label, write: term.Write})
	}

	sent := make([]string, 0, len(targets))
	for _, target := range targets {
		if err := target.write([]byte(body)); err != nil {
			// Reported with what was already sent rather than pretending it
			// did not happen. These are independent devices, not one
			// transaction, and "it stopped at the fourth switch" needs the
			// list of the three that got it.
			writeJSON(w, a.log, http.StatusMultiStatus, map[string]any{
				"sent": sent,
				"error": map[string]any{
					"code": CodeInternal,
					"message": "Stopped part-way: " + target.label +
						" is no longer accepting input.",
				},
			})
			return
		}
		sent = append(sent, target.id)
	}

	// One record for the whole send, naming the snippet and how many devices
	// received it. Not the rendered body: a parameter value is whatever
	// somebody typed into a form, and an audit log forwarded to a SIEM is the
	// wrong place to find out.
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionSnippetSent, TargetType: "snippet",
		TargetID: snippet.ID, TargetLabel: snippet.Name,
		Detail: map[string]any{
			"terminals": len(sent),
			"broadcast": len(sent) > 1,
		},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"sent": sent})
}

// terminalTarget is one destination for a send.
type terminalTarget struct {
	id    string
	label string
	write func([]byte) error
}

func (a *API) writeSnippetError(w http.ResponseWriter, err error, _ string) {
	switch {
	case errors.Is(err, snippets.ErrNotFound):
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such snippet.")
	case errors.Is(err, snippets.ErrDuplicate):
		writeError(w, a.log, http.StatusConflict, CodeConflict,
			"You already have a snippet with that name.")
	default:
		// Everything else the store returns is a validation failure — a name
		// that is empty, a body that is too long, more parameters than one
		// snippet may ask for. Those are the request being wrong, not the
		// server, and the store's own message says which.
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
	}
}
