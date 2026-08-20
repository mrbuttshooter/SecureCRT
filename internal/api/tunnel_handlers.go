package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/proto/tunnel"
	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/users"
)

// Tunnels: forwarding traffic over a connection a user already has.
//
// The interesting handler here is the proxy, and what is interesting about it
// is where it is mounted. See handleTunnelProxy.

// tunnelView renders a tunnel for the interface.
func (a *API) tunnelView(t *tunnel.Tunnel) map[string]any {
	info := t.Info(a.tunnels.URLFor)
	return map[string]any{
		"id": info.ID, "kind": string(info.Kind), "state": string(info.State),
		"session_id": info.SessionID, "label": info.Label,
		"via":    info.Via,
		"listen": info.Listen, "remote": info.Remote, "url": info.URL,
		"connections": info.Connections, "active": info.Active,
		"bytes_up": info.BytesUp, "bytes_down": info.BytesDown,
		"opened_at": info.OpenedAt, "last_used_at": info.LastUsedAt,
		"error": info.Error,
	}
}

func (a *API) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"tunnels": a.tunnels.ListForUser(u.ID, a.tunnels.URLFor),
	})
}

type openTunnelRequest struct {
	SessionID string `json:"session_id"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Host      string `json:"host"`
	Port      int    `json:"port"`

	// AcceptHostKey answers a fingerprint prompt on a second attempt, the
	// same two-step the file browser uses: there is no socket here to ask
	// over, so the first attempt refuses and reports what it saw.
	AcceptHostKey string `json:"accept_host_key"`
}

func (a *API) handleOpenTunnel(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())

	var req openTunnelRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	if req.SessionID == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No connection was specified.")
		return
	}

	kind := tunnel.Kind(req.Kind)
	if err := kind.Validate(); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"That is not a kind of tunnel this server opens.")
		return
	}

	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	prompter := &fingerprintPrompter{accept: req.AcceptHostKey}

	t, err := a.tunnels.Open(r.Context(), tunnel.OpenParams{
		UserID:    u.ID,
		SessionID: req.SessionID,
		Kind:      kind,
		Label:     req.Label,
		Host:      req.Host,
		Port:      req.Port,
		VaultKey:  key,
		Prompter:  prompter,
	})
	if err != nil {
		a.recordTunnelRefusal(r, u, req, err)
		a.writeTunnelError(w, r, err, prompter)
		return
	}

	action := audit.ActionTunnelOpened
	if kind.NeedsListener() {
		// Raised because a listener is reachable by anyone who can reach this
		// host, with no account here at all.
		action = audit.ActionTunnelListener
	}

	info := t.Info(a.tunnels.URLFor)
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: action, TargetType: "tunnel", TargetID: t.ID, TargetLabel: t.Label,
		Detail: map[string]any{
			"kind": string(kind), "session": req.SessionID,
			"listen": info.Listen, "remote": info.Remote,
			"via_hops": len(info.Via),
		},
	})
	_ = sess

	writeJSON(w, a.log, http.StatusCreated, a.tunnelView(t))
}

func (a *API) handleCloseTunnel(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	id := pathID(r.URL.Path, "/api/tunnels/")
	if id == "" {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, "No tunnel was specified.")
		return
	}

	t, err := a.tunnels.Get(u.ID, id)
	if err != nil {
		a.writeTunnelError(w, r, err, nil)
		return
	}
	label, kind := t.Label, t.Kind

	if err := a.tunnels.Close(u.ID, id); err != nil {
		a.writeTunnelError(w, r, err, nil)
		return
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionTunnelClosed, TargetType: "tunnel",
		TargetID: id, TargetLabel: label,
		Detail: map[string]any{"kind": string(kind)},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"closed": true})
}

// handleTunnelConfig tells the interface what this server will do, so it can
// explain rather than offer something that will be refused.
func (a *API) handleTunnelConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"web_enabled":       a.tunnels.WebTunnelsEnabled(),
		"listeners_enabled": a.tunnels.ListenersEnabled(),
		"domain":            a.tunnels.Domain(),
	})
}

// recordTunnelRefusal logs a refusal that was the policy's doing rather than
// a mistake, so an operator can see the feature being asked for.
func (a *API) recordTunnelRefusal(r *http.Request, u users.User, req openTunnelRequest, err error) {
	if !errors.Is(err, tunnel.ErrListenersOff) && !errors.Is(err, tunnel.ErrWebTunnelsOff) {
		return
	}
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionTunnelRefused, Outcome: audit.OutcomeDenied,
		TargetType: "tunnel", TargetLabel: req.Label,
		Detail: map[string]any{"kind": req.Kind, "reason": err.Error()},
	})
}

// writeTunnelError maps this package's failures onto something a person can
// act on, following writeFileError's shape.
func (a *API) writeTunnelError(
	w http.ResponseWriter, r *http.Request, err error, prompter *fingerprintPrompter,
) {
	switch {
	case errors.Is(err, tunnel.ErrNotFound):
		writeError(w, a.log, http.StatusNotFound, CodeNotFound, "No such tunnel.")

	case errors.Is(err, tunnel.ErrTooManyTunnels):
		writeError(w, a.log, http.StatusTooManyRequests, CodeRateLimited,
			"You have as many tunnels open as this server allows. Close one first.")

	case errors.Is(err, tunnel.ErrListenersOff):
		writeError(w, a.log, http.StatusForbidden, CodeForbidden,
			"Opening a port on this server is disabled here. An administrator can "+
				"enable it with policy.allow_tcp_tunnels.")

	case errors.Is(err, tunnel.ErrWebTunnelsOff):
		writeError(w, a.log, http.StatusServiceUnavailable, CodeForbidden,
			"Reaching a device's web interface needs a separate domain configured "+
				"on this server, because a device's own pages cannot safely be "+
				"served from this address. See tunnels.domain.")

	case errors.Is(err, tunnel.ErrNoPortAvailable):
		writeError(w, a.log, http.StatusServiceUnavailable, CodeInternal,
			"Every port in this server's tunnel range is in use.")

	case errors.Is(err, tunnel.ErrManagerClosed):
		writeError(w, a.log, http.StatusServiceUnavailable, CodeInternal,
			"The server is shutting down.")

	default:
		// A dial failure comes back as a remote.Error, which already has a
		// host key prompt path the file browser established.
		var dialErr *remote.Error
		if errors.As(err, &dialErr) && prompter != nil {
			a.writeOpenError(w, r, err, prompter)
			return
		}
		writeInternal(w, a.log, "opening a tunnel", err)
	}
}

// handleTunnelProxy serves a device's own web interface.
//
// Mounted outside the CSRF middleware, deliberately and with a replacement.
// A device has never heard of this application's CSRF token, so every form it
// posts would be refused — and it is on a different origin, which is where
// the protection actually comes from. What replaces it:
//
//   - The request is authenticated as usual, and the tunnel must belong to
//     the signed-in user. A tunnel's hostname contains its identifier, which
//     is time-ordered and guessable from another, so the hostname is not
//     treated as a credential.
//   - Sec-Fetch-Site is checked: a cross-site request to a device's interface
//     is something another page initiated, and this origin exists to be
//     driven by a person looking at it.
func (a *API) handleTunnelProxy(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())

	t, ok := a.tunnels.TunnelForHost(r.Host)
	if !ok {
		http.Error(w, "No tunnel is served at this address.", http.StatusNotFound)
		return
	}

	if t.UserID != u.ID {
		// Not "forbidden": the same reasoning as everywhere else here.
		http.Error(w, "No tunnel is served at this address.", http.StatusNotFound)
		return
	}

	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		http.Error(w,
			"This address is reached from the tunnel list, not linked to from elsewhere.",
			http.StatusForbidden)
		return
	}

	a.tunnels.ProxyHandler(t).ServeHTTP(w, r)
}

// tunnelHostRequest reports whether a request addresses a tunnel's hostname
// rather than the application, so routing can send it to the proxy before any
// of the ordinary API matching runs.
func (a *API) tunnelHostRequest(r *http.Request) bool {
	if a.tunnels == nil || !a.tunnels.WebTunnelsEnabled() {
		return false
	}
	host := r.Host
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	return strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(a.tunnels.Domain()))
}
