package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/audit"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// TOTP secrets are encrypted under the user's vault key.
//
// The consequence is that enrolling and verifying both require an unlocked
// vault. That is the right trade: a plaintext TOTP secret in the database
// would let anyone with a dump mint valid codes indefinitely. Recovery codes
// are hashed rather than encrypted precisely so there is still a way in when
// the vault is locked and the authenticator is lost.

const totpIssuer = "Bridgekeeper"

// handleMFAEnrol begins TOTP setup and returns the provisioning URI.
func (a *API) handleMFAEnrol(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	ctx := r.Context()

	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	if u.TOTPEnabled {
		writeError(w, a.log, http.StatusConflict, CodeConflict,
			"Two-factor authentication is already set up. Remove it first if you want to re-enrol.")
		return
	}

	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeInternal(w, a.log, "generating TOTP secret", err)
		return
	}

	uri, err := auth.TOTPProvisioningURI(secret, u.Email, totpIssuer)
	if err != nil {
		writeInternal(w, a.log, "building provisioning URI", err)
		return
	}

	sealed, err := sealTOTPSecret(key, u.ID, secret)
	if err != nil {
		writeInternal(w, a.log, "encrypting TOTP secret", err)
		return
	}

	// Stored unconfirmed. Marking it enabled before the user has proved their
	// authenticator works would lock them out of their own account.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := a.db.Exec(ctx, `
		INSERT INTO mfa_totp (user_id, secret_enc, last_step, created_at, updated_at)
		VALUES (?, ?, 0, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET
			secret_enc = excluded.secret_enc,
			confirmed_at = NULL,
			last_step = 0,
			updated_at = excluded.updated_at`,
		u.ID, sealed, now, now); err != nil {
		writeInternal(w, a.log, "storing TOTP secret", err)
		return
	}

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"secret":           secret,
		"provisioning_uri": uri,
		"digits":           auth.TOTPDigits,
		"period_seconds":   int(auth.TOTPPeriod.Seconds()),
	})
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

// handleMFAConfirm completes enrolment and issues recovery codes.
func (a *API) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())
	ctx := r.Context()

	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	var req totpCodeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	secret, lastStep, err := a.loadTOTPSecret(ctx, key, u.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, a.log, http.StatusConflict, CodeConflict,
				"Start two-factor setup before confirming it.")
			return
		}
		writeInternal(w, a.log, "loading TOTP secret", err)
		return
	}

	result, err := auth.VerifyTOTP(secret, req.Code, time.Now(), lastStep)
	if err != nil {
		a.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: audit.ActionMFAFailed, Outcome: audit.OutcomeFailure,
		})
		writeError(w, a.log, http.StatusUnauthorized, CodeInvalidCode,
			"That code was not correct. Check your authenticator app and try again.")
		return
	}

	display, hashes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		writeInternal(w, a.log, "generating recovery codes", err)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	err = a.db.InTx(ctx, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE mfa_totp SET confirmed_at = ?, last_step = ?, updated_at = ? WHERE user_id = ?`,
			now, result.Step, now, u.ID); err != nil {
			return err
		}
		// Replace any codes from a previous enrolment: leaving them valid
		// would mean an old printout still opens the account.
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)`,
				uuid.Must(uuid.NewV7()).String(), u.ID, h, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?`, now, u.ID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		writeInternal(w, a.log, "confirming TOTP enrolment", err)
		return
	}

	if err := a.sessions.SetMFASatisfied(ctx, sess.ID); err != nil {
		a.log.Warn("recording MFA state", "error", err)
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionMFAEnrolled, Severity: audit.SeverityNotice,
	})

	// The only time these are ever shown.
	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"enabled":        true,
		"recovery_codes": display,
		"warning": "Save these recovery codes now. They are shown once and cannot be retrieved later. " +
			"Each one works a single time, and they are the only way back in if you lose your authenticator.",
	})
}

// handleMFAVerify completes a second factor for an existing session.
func (a *API) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())
	ctx := r.Context()

	// Verification needs the vault key, since the secret is encrypted under
	// it. For a local account the vault opens with the same password used to
	// sign in; an SSO user unlocks first. If the vault is locked, recovery
	// codes remain available — they are hashed, not encrypted, for this
	// reason.
	key, ok := a.requireVaultKey(w, r)
	if !ok {
		return
	}

	var req totpCodeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	if err := a.throttle.Check(ctx, auth.AttemptAccount, "mfa:"+u.ID); err != nil {
		var limited *auth.ErrRateLimited
		if errors.As(err, &limited) {
			writeRateLimited(w, a.log, int(limited.RetryAfter.Seconds())+1,
				"Too many codes tried. Please wait before trying again.")
			return
		}
		writeInternal(w, a.log, "checking MFA throttle", err)
		return
	}

	secret, lastStep, err := a.loadTOTPSecret(ctx, key, u.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, a.log, http.StatusConflict, CodeConflict,
				"Two-factor authentication is not set up on this account.")
			return
		}
		writeInternal(w, a.log, "loading TOTP secret", err)
		return
	}

	result, err := auth.VerifyTOTP(secret, req.Code, time.Now(), lastStep)
	if err != nil {
		_ = a.throttle.RecordFailure(ctx, auth.AttemptAccount, "mfa:"+u.ID)

		message := "That code was not correct."
		if errors.Is(err, auth.ErrTOTPReplayed) {
			// Worth saying plainly: the usual cause is an impatient double
			// submission, and the user would otherwise assume their
			// authenticator is broken.
			message = "That code has already been used. Wait for your authenticator to show the next one."
		}

		a.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: audit.ActionMFAFailed, Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"replayed": errors.Is(err, auth.ErrTOTPReplayed)},
		})
		writeError(w, a.log, http.StatusUnauthorized, CodeInvalidCode, message)
		return
	}

	// Record the accepted step before granting access, so the same code
	// cannot be replayed by a second request racing the first.
	if _, err := a.db.Exec(ctx,
		`UPDATE mfa_totp SET last_step = ?, updated_at = ? WHERE user_id = ?`,
		result.Step, time.Now().UTC().Format(time.RFC3339Nano), u.ID); err != nil {
		writeInternal(w, a.log, "recording TOTP step", err)
		return
	}

	_ = a.throttle.RecordSuccess(ctx, auth.AttemptAccount, "mfa:"+u.ID)
	if err := a.sessions.SetMFASatisfied(ctx, sess.ID); err != nil {
		writeInternal(w, a.log, "recording MFA state", err)
		return
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionMFAVerified,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"mfa_satisfied": true})
}

type recoveryRequest struct {
	Code string `json:"code"`
}

// handleMFARecovery accepts a recovery code in place of an authenticator.
//
// Works without an unlocked vault, deliberately: someone who has lost their
// phone needs a way in that does not depend on the phone.
func (a *API) handleMFARecovery(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	sess, _ := SessionFrom(r.Context())
	ctx := r.Context()

	var req recoveryRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, a.log, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	if err := a.throttle.Check(ctx, auth.AttemptAccount, "recovery:"+u.ID); err != nil {
		var limited *auth.ErrRateLimited
		if errors.As(err, &limited) {
			writeRateLimited(w, a.log, int(limited.RetryAfter.Seconds())+1,
				"Too many recovery codes tried. Please wait before trying again.")
			return
		}
		writeInternal(w, a.log, "checking recovery throttle", err)
		return
	}

	stored, err := a.loadRecoveryCodes(ctx, u.ID)
	if err != nil {
		writeInternal(w, a.log, "loading recovery codes", err)
		return
	}

	matchedID, err := auth.VerifyRecoveryCode(req.Code, stored)
	if err != nil {
		_ = a.throttle.RecordFailure(ctx, auth.AttemptAccount, "recovery:"+u.ID)
		a.audit.Record(ctx, audit.Event{
			ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
			Action: audit.ActionMFAFailed, Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"method": "recovery_code"},
		})
		writeError(w, a.log, http.StatusUnauthorized, CodeInvalidCode,
			"That recovery code was not valid, or has already been used.")
		return
	}

	// Marked used before access is granted, so two requests racing with the
	// same code cannot both succeed.
	if _, err := a.db.Exec(ctx,
		`UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), matchedID); err != nil {
		writeInternal(w, a.log, "marking recovery code used", err)
		return
	}

	_ = a.throttle.RecordSuccess(ctx, auth.AttemptAccount, "recovery:"+u.ID)
	if err := a.sessions.SetMFASatisfied(ctx, sess.ID); err != nil {
		writeInternal(w, a.log, "recording MFA state", err)
		return
	}

	remaining, err := a.countUnusedRecoveryCodes(ctx, u.ID)
	if err != nil {
		a.log.Warn("counting recovery codes", "error", err)
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionRecoveryCodeUsed,
		Detail: map[string]any{"remaining": remaining},
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{
		"mfa_satisfied":   true,
		"codes_remaining": remaining,
		"notice": "That recovery code has been used and will not work again. " +
			"Set up your authenticator again to get a fresh set.",
	})
}

// handleMFADisable removes two-factor authentication.
func (a *API) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	ctx := r.Context()

	if a.cfg.MFAPolicy == "required" || (a.cfg.RequireMFAForAdmins && u.IsAdmin) {
		writeError(w, a.log, http.StatusForbidden, CodeForbidden,
			"Two-factor authentication is required on this system and cannot be removed.")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	err := a.db.InTx(ctx, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_totp WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE users SET totp_enabled = 0, updated_at = ? WHERE id = ?`, now, u.ID)
		return err
	})
	if err != nil {
		writeInternal(w, a.log, "disabling MFA", err)
		return
	}

	a.audit.Record(ctx, audit.Event{
		ActorID: u.ID, ActorEmail: u.Email, IPAddress: a.clientIP(r),
		Action: audit.ActionMFADisabled, Severity: audit.SeverityNotice,
	})

	writeJSON(w, a.log, http.StatusOK, map[string]any{"enabled": false})
}

// --- storage helpers --------------------------------------------------------

func sealTOTPSecret(key vault.Key, userID, secret string) (string, error) {
	env, err := vault.Seal(key, vault.CredentialAAD(userID, "totp", "secret"), []byte(secret))
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func (a *API) loadTOTPSecret(ctx context.Context, key vault.Key, userID string) (string, uint64, error) {
	var (
		sealed   string
		lastStep int64
	)
	err := a.db.QueryRow(ctx,
		`SELECT secret_enc, last_step FROM mfa_totp WHERE user_id = ?`, userID).
		Scan(&sealed, &lastStep)
	if err != nil {
		return "", 0, err
	}

	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", 0, fmt.Errorf("api: decode TOTP secret: %w", err)
	}
	var env vault.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", 0, fmt.Errorf("api: parse TOTP secret: %w", err)
	}

	plaintext, err := vault.Open(key, vault.CredentialAAD(userID, "totp", "secret"), env)
	if err != nil {
		return "", 0, fmt.Errorf("api: decrypt TOTP secret: %w", err)
	}

	// A negative last_step means the row is corrupt. Converting it would wrap
	// to a value near the top of the unsigned range, and since a code is only
	// accepted when its step is strictly greater, that would reject every
	// future code and lock the user out permanently. Failing loudly is far
	// better than that.
	if lastStep < 0 {
		return "", 0, fmt.Errorf("api: TOTP record for user %s has a negative step (%d); the row is corrupt", userID, lastStep)
	}

	return string(plaintext), uint64(lastStep), nil
}

func (a *API) loadRecoveryCodes(ctx context.Context, userID string) ([]auth.StoredRecoveryCode, error) {
	rows, err := a.db.Query(ctx,
		`SELECT id, code_hash, used_at FROM mfa_recovery_codes WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []auth.StoredRecoveryCode
	for rows.Next() {
		var (
			c      auth.StoredRecoveryCode
			usedAt sql.NullString
		)
		if err := rows.Scan(&c.ID, &c.Hash, &usedAt); err != nil {
			return nil, err
		}
		c.Used = usedAt.Valid && usedAt.String != ""
		out = append(out, c)
	}
	return out, rows.Err()
}

func (a *API) countUnusedRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}
