package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/users"
)

// handleAuthConfig tells the sign-in page what this deployment offers.
//
// Unauthenticated on purpose: the browser needs it before it can sign in.
// It exposes only what is already visible from the login screen — nothing
// here reveals whether a given account exists.
func (a *API) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	// Issue a CSRF token so the sign-in POST that follows can carry one.
	token, err := newCSRFToken(a.csrfKey)
	if err != nil {
		writeInternal(w, a.log, "generating CSRF token", err)
		return
	}
	http.SetCookie(w, csrfCookie(token, a.cfg.SecureCookies))

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"password_auth_enabled": a.cfg.AllowPasswordAuth,
		"sso_enabled":           a.cfg.OIDCEnabled && a.oidc != nil,
		"sso_provider_name":     a.cfg.OIDCProviderName,
		"mfa_policy":            a.cfg.MFAPolicy,
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// handleLocalLogin signs in with an email and password.
//
// Local accounts exist for break-glass access when single sign-on is
// unavailable — an expired client secret, a conditional-access
// misconfiguration, a network fault reaching Microsoft. They are not the
// normal path.
func (a *API) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AllowPasswordAuth {
		writeError(w, a.log, http.StatusForbidden, CodePasswordAuthOff,
			"Password sign-in is disabled on this system. Use single sign-on.")
		return
	}

	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	ip := a.clientIP(r)
	normalized := users.NormalizeEmail(req.Email)

	// Throttle before verifying, so a locked-out attacker never reaches the
	// Argon2id work — otherwise the defence becomes an amplifier.
	for _, check := range []struct {
		kind       auth.AttemptKind
		identifier string
	}{
		{auth.AttemptAddress, ip},
		{auth.AttemptAccount, normalized},
	} {
		if err := a.throttle.Check(ctx, check.kind, check.identifier); err != nil {
			var limited *auth.ErrRateLimited
			if errors.As(err, &limited) {
				a.audit.Record(ctx, audit.Event{
					ActorEmail: normalized, IPAddress: ip,
					Action: audit.ActionLoginThrottled, Outcome: audit.OutcomeDenied,
					Detail: map[string]any{"scope": limited.Scope},
				})
				writeRateLimited(w, a.log, int(limited.RetryAfter.Seconds())+1,
					"Too many sign-in attempts. Please wait before trying again.")
				return
			}
			writeInternal(w, a.log, "checking login throttle", err)
			return
		}
	}

	u, err := a.users.ByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, users.ErrNotFound) {
		writeInternal(w, a.log, "looking up user", err)
		return
	}

	// A missing account and a wrong password must be indistinguishable, in
	// both the response and the time taken — otherwise this endpoint tells an
	// attacker which addresses are registered. When there is no account, a
	// verification is still performed against a dummy hash so the Argon2id
	// cost is paid either way.
	authenticated := false
	switch {
	case errors.Is(err, users.ErrNotFound):
		burnPasswordTime(req.Password)
	case u.IsDisabled:
		burnPasswordTime(req.Password)
	case !u.CanSignInLocally():
		burnPasswordTime(req.Password)
	default:
		authenticated = auth.VerifyPassword([]byte(req.Password), u.PasswordHash) == nil
	}

	if !authenticated {
		_ = a.throttle.RecordFailure(ctx, auth.AttemptAddress, ip)
		_ = a.throttle.RecordFailure(ctx, auth.AttemptAccount, normalized)
		a.audit.Record(ctx, audit.Event{
			ActorEmail: normalized, IPAddress: ip,
			Action: audit.ActionLoginFailed, Outcome: audit.OutcomeFailure,
			Severity: audit.SeverityNotice,
		})
		writeError(w, a.log, http.StatusUnauthorized, CodeUnauthorized,
			"That email address and password did not match.")
		return
	}

	_ = a.throttle.RecordSuccess(ctx, auth.AttemptAddress, ip)
	_ = a.throttle.RecordSuccess(ctx, auth.AttemptAccount, normalized)

	sess, err := a.issueSession(ctx, w, auth.CreateSessionParams{
		UserID:     u.ID,
		AuthMethod: auth.AuthMethodLocal,
		UserAgent:  r.UserAgent(),
		IPAddress:  ip,
	})
	if err != nil {
		writeInternal(w, a.log, "creating session", err)
		return
	}

	if err := a.users.UpdateLastLogin(ctx, u.ID); err != nil {
		a.log.Warn("recording last login", "error", err)
	}
	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: ip,
		Action: audit.ActionLoginSucceeded,
		Detail: map[string]any{"method": "local"},
	})

	a.writeWhoami(w, r, u, sess)
}

// burnPasswordTime performs a throwaway verification so a failed sign-in
// takes the same time whether or not the account exists.
//
// Without it, response timing distinguishes a real account from an unknown
// one just as reliably as a different error message would.
func burnPasswordTime(password string) {
	const dummy = "$argon2id$v=19$m=19456,t=3,p=4$" +
		"YWFhYWFhYWFhYWFhYWFhYQ$" +
		"Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M"
	_ = auth.VerifyPassword([]byte(password), dummy)
}

// handleSSOStart begins a single-sign-on redirect.
func (a *API) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil {
		writeError(w, a.log, http.StatusNotFound, CodeSSODisabled,
			"Single sign-on is not configured on this system.")
		return
	}

	authURL, cookie, err := a.oidc.AuthURL(r.URL.Query().Get("return_to"))
	if err != nil {
		writeInternal(w, a.log, "starting single sign-on", err)
		return
	}

	http.SetCookie(w, cookie)

	// #nosec G710 -- authURL is built by the OAuth2 library from the
	// discovered provider endpoint and this deployment's configured client
	// ID, not from request input. The one caller-supplied value, return_to,
	// is restricted to same-site relative paths by sanitizeReturnTo and
	// travels inside the signed state cookie rather than in this URL.
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSSOCallback completes a single-sign-on redirect.
//
// This is a browser navigation, not an API call, so failures render a page
// rather than JSON — the user arrives here by being redirected, and a raw
// JSON error would be baffling.
func (a *API) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil {
		a.ssoFailure(w, r, "Single sign-on is not configured on this system.", nil)
		return
	}

	ctx := r.Context()
	ip := a.clientIP(r)

	// The state cookie is single use whatever happens next.
	http.SetCookie(w, auth.ClearStateCookie())

	result, err := a.oidc.Callback(ctx, r)
	if err != nil {
		a.audit.Record(ctx, audit.Event{
			IPAddress: ip, Action: audit.ActionSSOFailed, Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"reason": err.Error()},
		})
		a.ssoFailure(w, r, "Sign-in could not be completed.", err)
		return
	}

	u, provisioned, err := a.resolveSSOUser(ctx, result.Claims)
	if err != nil {
		if errors.Is(err, errSSONotProvisioned) {
			a.ssoFailure(w, r,
				"Your account has not been set up on this system. Ask an administrator to add you.", nil)
			return
		}
		if errors.Is(err, users.ErrDisabled) {
			a.ssoFailure(w, r, "This account has been disabled. Contact an administrator.", nil)
			return
		}
		writeInternal(w, a.log, "resolving single sign-on user", err)
		return
	}

	sess, err := a.issueSession(ctx, w, auth.CreateSessionParams{
		UserID:     u.ID,
		AuthMethod: auth.AuthMethodOIDC,
		// Entra has already performed multi-factor authentication when it
		// says so, so the user is not asked for a second factor this system
		// would only be duplicating.
		MFASatisfied: result.Claims.MFASatisfied,
		UserAgent:    r.UserAgent(),
		IPAddress:    ip,
	})
	if err != nil {
		writeInternal(w, a.log, "creating session", err)
		return
	}

	if err := a.users.UpdateLastLogin(ctx, u.ID); err != nil {
		a.log.Warn("recording last login", "error", err)
	}

	action := audit.ActionSSOSignIn
	if provisioned {
		action = audit.ActionSSOProvisioned
	}
	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: ip, Action: action,
		Detail: map[string]any{
			"tenant":        result.Claims.TenantID,
			"mfa_satisfied": result.Claims.MFASatisfied,
			"provisioned":   provisioned,
		},
	})

	_ = sess
	http.Redirect(w, r, result.ReturnTo, http.StatusFound)
}

// errSSONotProvisioned means a valid directory user has no account here and
// automatic provisioning is off.
var errSSONotProvisioned = errors.New("api: no account for this single-sign-on identity")

// resolveSSOUser finds or creates the account behind a set of claims.
func (a *API) resolveSSOUser(ctx context.Context, claims auth.Claims) (users.User, bool, error) {
	const provider = "entra"

	u, err := a.users.BySSO(ctx, provider, claims.Subject)
	switch {
	case err == nil:
		if u.IsDisabled {
			return users.User{}, false, users.ErrDisabled
		}
		// Follow directory changes — a marriage, a department rename — so the
		// interface does not show a stale name indefinitely.
		if claims.Email != "" && (claims.Email != u.Email || claims.Name != u.DisplayName) {
			if err := a.users.UpdateProfile(ctx, u.ID, claims.Email, claims.Name); err != nil {
				// Not fatal: a colliding address should not block a sign-in.
				a.log.Warn("updating profile from single sign-on", "error", err, "user", u.ID)
			} else {
				u.Email, u.DisplayName = claims.Email, claims.Name
			}
		}
		return u, false, nil

	case !errors.Is(err, users.ErrNotFound):
		return users.User{}, false, err
	}

	if !a.ssoAutoProvision() {
		return users.User{}, false, errSSONotProvisioned
	}

	created, err := a.users.Create(ctx, users.CreateParams{
		Email:       claims.Email,
		DisplayName: claims.Name,
		SSOProvider: provider,
		SSOSubject:  claims.Subject,
		SSOTenant:   claims.TenantID,
	})
	if err != nil {
		return users.User{}, false, err
	}
	return created, true, nil
}

// handleLogout ends the current session.
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())

	// Zero the vault key first: revoking the session row closes the door, but
	// the decrypted key would otherwise sit in memory until its TTL expired.
	a.vaults.Lock(u.ID, sess.ID)

	if err := a.sessions.Revoke(r.Context(), sess.ID); err != nil {
		writeInternal(w, a.log, "revoking session", err)
		return
	}

	http.SetCookie(w, a.cfg.Session.ClearSessionCookie())
	a.audit.Record(r.Context(), audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionLogout, TargetType: "session", TargetID: sess.ID,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"signed_out": true})
}

// handleWhoami describes the current session.
func (a *API) handleWhoami(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	u, _ := UserFrom(r.Context())
	a.writeWhoami(w, r, u, sess)
}

// writeWhoami is the canonical description of who is signed in and what the
// client must do next.
//
// The client drives its whole flow from this: whether to prompt for a second
// factor, whether to ask for a vault passphrase, whether to offer enrolment.
// Keeping that in one response avoids the client inferring state from a
// sequence of error codes.
func (a *API) writeWhoami(w http.ResponseWriter, r *http.Request, u users.User, sess auth.Session) {
	_, unlocked := a.vaults.Key(u.ID, sess.ID)

	needsMFA := a.mfaRequiredFor(u) && !sess.MFASatisfied
	needsVaultEnrolment := !u.HasVault()
	needsPassphrase := !needsVaultEnrolment && unlocked != nil && a.vaults.RequiresPassphrase(u)

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           u.ID,
			"email":        u.Email,
			"display_name": u.DisplayName,
			"is_admin":     u.IsAdmin,
			"sso":          u.IsSSO(),
			"totp_enabled": u.TOTPEnabled,
		},
		"session": map[string]any{
			"id":            sess.ID,
			"auth_method":   string(sess.AuthMethod),
			"mfa_satisfied": sess.MFASatisfied,
			"expires_at":    sess.ExpiresAt.Format(time.RFC3339),
		},
		"vault": map[string]any{
			"enrolled":            u.HasVault(),
			"unlocked":            unlocked == nil,
			"unlock_kind":         string(u.UnlockKind),
			"requires_passphrase": a.vaults.RequiresPassphrase(u),
			"was_reset":           u.VaultResetAt != nil,
		},
		"next": map[string]any{
			"mfa":           needsMFA,
			"enrol_vault":   needsVaultEnrolment,
			"unlock_vault":  needsPassphrase,
			"mfa_available": a.cfg.MFAPolicy != "off",
		},
	})
}

// ssoFailure renders a browser-facing sign-in error.
func (a *API) ssoFailure(w http.ResponseWriter, r *http.Request, message string, cause error) {
	if cause != nil {
		a.log.Warn("single sign-on failed",
			"error", cause,
			"request_id", RequestIDFrom(r.Context()))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)

	// Deliberately plain and self-contained: this page must render even if
	// the application bundle is unavailable, and the strict CSP forbids
	// inline script, so there is nothing dynamic here.
	_, _ = w.Write([]byte(`<!doctype html>
<meta charset="utf-8">
<title>Sign-in failed</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 4rem auto; max-width: 34rem; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  a { color: inherit; }
</style>
<h1>Sign-in failed</h1>
<p>` + htmlEscape(message) + `</p>
<p><a href="/">Return to the sign-in page</a></p>
`))
}

// htmlEscape escapes the small set of characters that matter in element text.
func htmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(s)
}

// ssoAutoProvision reports whether unknown directory users get an account.
func (a *API) ssoAutoProvision() bool { return a.cfg.OIDCAutoProvision }
