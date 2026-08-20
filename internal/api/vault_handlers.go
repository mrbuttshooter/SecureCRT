package api

import (
	"errors"
	"net/http"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// minPassphraseLength is the floor for a vault passphrase.
//
// Higher than a typical password minimum on purpose. This one secret protects
// every credential the user owns, it is typed roughly once a day rather than
// constantly, and it is the only thing standing between a stolen database and
// their private keys. A composition rule (a symbol, a digit) is deliberately
// not imposed: length is what matters, and character classes mostly produce
// predictable substitutions.
const minPassphraseLength = 12

type passphraseRequest struct {
	Passphrase string `json:"passphrase"`
}

// handleVaultStatus reports whether the vault is enrolled and open.
func (a *API) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())

	_, err := a.vaults.Key(u.ID, sess.ID)

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"enrolled":            u.HasVault(),
		"unlocked":            err == nil,
		"unlock_kind":         string(u.UnlockKind),
		"requires_passphrase": a.vaults.RequiresPassphrase(u),
		"was_reset":           u.VaultResetAt != nil,
		"minimum_length":      minPassphraseLength,
	})
}

// handleVaultEnrol creates the vault on first use.
func (a *API) handleVaultEnrol(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())

	var req passphraseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	// A passphrase is required unless this deployment has been configured to
	// let the server hold the key for single-sign-on users.
	if a.vaults.RequiresPassphrase(u) {
		if msg, ok := checkPassphrase(req.Passphrase); !ok {
			writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, msg)
			return
		}
	}

	kind, err := a.vaults.Enrol(r.Context(), u, sess.ID, req.Passphrase)
	if err != nil {
		if errors.Is(err, users.ErrVaultAlreadySetUp) {
			writeError(w, a.log, http.StatusConflict, CodeConflict,
				"This account already has a vault. Use the change-passphrase option instead.")
			return
		}
		writeInternal(w, a.log, "enrolling vault", err)
		return
	}

	if err := a.sessions.SetVaultUnlocked(r.Context(), sess.ID, true); err != nil {
		a.log.Warn("recording vault state", "error", err)
	}

	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionVaultPassphraseSet, Severity: audit.SeverityNotice,
		Detail: map[string]any{"unlock_kind": string(kind)},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"enrolled":    true,
		"unlocked":    true,
		"unlock_kind": string(kind),
	})
}

// handleVaultUnlock opens the vault for this session.
func (a *API) handleVaultUnlock(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())
	ctx := r.Context()
	ip := a.clientIP(r)

	var req passphraseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	// Unlock attempts are throttled per account, exactly as sign-in is.
	// Otherwise an attacker holding a stolen session cookie could brute-force
	// the passphrase at full speed — the one secret the cookie does not
	// already give them.
	if err := a.throttle.Check(ctx, auth.AttemptAccount, "vault:"+u.ID); err != nil {
		var limited *auth.ErrRateLimited
		if errors.As(err, &limited) {
			writeRateLimited(w, a.log, int(limited.RetryAfter.Seconds())+1,
				"Too many unlock attempts. Please wait before trying again.")
			return
		}
		writeInternal(w, a.log, "checking unlock throttle", err)
		return
	}

	err := a.vaults.Unlock(ctx, u, sess.ID, req.Passphrase)
	switch {
	case errors.Is(err, users.ErrVaultNotSetUp):
		writeError(w, a.log, http.StatusConflict, CodeVaultNotSetUp,
			"This account has no vault yet. Set a passphrase to create one.")
		return

	case errors.Is(err, vault.ErrWrongPassphrase):
		_ = a.throttle.RecordFailure(ctx, auth.AttemptAccount, "vault:"+u.ID)
		a.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: ip,
			Action: audit.ActionVaultUnlockFailed, Outcome: audit.OutcomeFailure,
			Severity: audit.SeverityNotice,
		})
		writeError(w, a.log, http.StatusUnauthorized, CodeUnauthorized,
			"That passphrase did not open your vault.")
		return

	case err != nil:
		writeInternal(w, a.log, "unlocking vault", err)
		return
	}

	_ = a.throttle.RecordSuccess(ctx, auth.AttemptAccount, "vault:"+u.ID)
	if err := a.sessions.SetVaultUnlocked(ctx, sess.ID, true); err != nil {
		a.log.Warn("recording vault state", "error", err)
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: ip,
		Action: audit.ActionVaultUnlocked,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"unlocked": true})
}

// handleVaultLock closes the vault without ending the session.
//
// Useful for stepping away from a shared machine: the session survives, so
// there is no need to sign in again, but the key is gone from memory.
func (a *API) handleVaultLock(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())

	a.vaults.Lock(u.ID, sess.ID)

	// A staged import holds decrypted passwords in memory, so locking the
	// vault has to take those with it — otherwise "lock" would leave the most
	// sensitive thing the process is holding exactly where it was.
	a.staging.forget(u.ID)

	if err := a.sessions.SetVaultUnlocked(r.Context(), sess.ID, false); err != nil {
		a.log.Warn("recording vault state", "error", err)
	}
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionVaultLocked,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"unlocked": false})
}

type changePassphraseRequest struct {
	Current string `json:"current_passphrase"`
	New     string `json:"new_passphrase"`
}

// handleVaultChangePassphrase re-wraps the key under a new passphrase.
func (a *API) handleVaultChangePassphrase(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())
	ctx := r.Context()

	var req changePassphraseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	if msg, ok := checkPassphrase(req.New); !ok {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, msg)
		return
	}
	if req.New == req.Current {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest,
			"The new passphrase must be different from the current one.")
		return
	}

	// Throttled: this endpoint verifies the current passphrase, so without a
	// limit it is another brute-force oracle for a stolen session.
	if err := a.throttle.Check(ctx, auth.AttemptAccount, "vault:"+u.ID); err != nil {
		var limited *auth.ErrRateLimited
		if errors.As(err, &limited) {
			writeRateLimited(w, a.log, int(limited.RetryAfter.Seconds())+1,
				"Too many attempts. Please wait before trying again.")
			return
		}
		writeInternal(w, a.log, "checking throttle", err)
		return
	}

	err := a.vaults.ChangePassphrase(ctx, u, sess.ID, req.Current, req.New)
	switch {
	case errors.Is(err, vault.ErrWrongPassphrase):
		_ = a.throttle.RecordFailure(ctx, auth.AttemptAccount, "vault:"+u.ID)
		writeError(w, a.log, http.StatusUnauthorized, CodeUnauthorized,
			"Your current passphrase was not correct.")
		return
	case errors.Is(err, users.ErrVaultNotSetUp):
		writeError(w, a.log, http.StatusConflict, CodeVaultNotSetUp,
			"This account has no vault yet.")
		return
	case err != nil:
		writeInternal(w, a.log, "changing vault passphrase", err)
		return
	}

	_ = a.throttle.RecordSuccess(ctx, auth.AttemptAccount, "vault:"+u.ID)

	// Every other session keeps a key derived from the old passphrase. They
	// are cut off so a device the user no longer trusts cannot continue with
	// the credentials they just re-secured — while the device in their hand
	// stays signed in.
	revoked, err := a.sessions.RevokeAllForUserExcept(ctx, u.ID, sess.ID)
	if err != nil {
		a.log.Warn("revoking other sessions after passphrase change", "error", err)
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionVaultPassphraseChanged, Severity: audit.SeverityNotice,
		Detail: map[string]any{"other_sessions_revoked": revoked},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"changed":                true,
		"other_sessions_revoked": revoked,
	})
}

// checkPassphrase applies the passphrase policy, returning a message the user
// can act on rather than a bare rejection.
func checkPassphrase(p string) (string, bool) {
	switch {
	case p == "":
		return "A vault passphrase is required.", false
	case len([]rune(p)) < minPassphraseLength:
		return "Your vault passphrase must be at least 12 characters. " +
			"A few unrelated words is both stronger and easier to remember than a short complex one.", false
	case len(p) > 1024:
		return "That passphrase is too long.", false
	}
	return "", true
}

// requireVaultKey fetches the session's vault key, or writes the locked error.
//
// Every handler touching a secret goes through here, so "locked" is reported
// the same way everywhere and the client has one condition to handle.
func (a *API) requireVaultKey(w http.ResponseWriter, r *http.Request) (vault.Key, bool) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())

	key, err := a.vaults.Key(u.ID, sess.ID)
	if err != nil {
		writeError(w, a.log, http.StatusForbidden, CodeVaultLocked,
			"Your vault is locked. Enter your passphrase to continue.")
		return nil, false
	}
	return key, true
}
