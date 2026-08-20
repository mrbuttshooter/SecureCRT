// Package api exposes the HTTP surface: authentication, vault access,
// multi-factor enrolment and credential management.
//
// Two rules hold throughout, and both exist because the alternative fails
// quietly rather than loudly:
//
//   - Error responses carry a stable machine-readable code and a message
//     written for the person reading it. Nothing leaks internal detail: a
//     wrong password and an unknown account produce byte-identical replies,
//     because any difference is an account-enumeration oracle.
//   - No handler ever writes secret material into a response except the one
//     explicitly named for it, which is audited at every call site.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// ErrorCode is a stable identifier a client can branch on. The human-readable
// message may be reworded freely; these must not be.
type ErrorCode string

const (
	CodeBadRequest      ErrorCode = "bad_request"
	CodeUnauthorized    ErrorCode = "unauthorized"
	CodeForbidden       ErrorCode = "forbidden"
	CodeNotFound        ErrorCode = "not_found"
	CodeConflict        ErrorCode = "conflict"
	CodeRateLimited     ErrorCode = "rate_limited"
	CodeInternal        ErrorCode = "internal_error"
	CodeVaultLocked     ErrorCode = "vault_locked"
	CodeVaultNotSetUp   ErrorCode = "vault_not_set_up"
	CodeMFARequired     ErrorCode = "mfa_required"
	CodeInvalidCode     ErrorCode = "invalid_code"
	CodeSSODisabled     ErrorCode = "sso_disabled"
	CodePasswordAuthOff ErrorCode = "password_auth_disabled"

	// CodeRemoteRefused is the far end saying no, rather than this server.
	// Distinct from CodeForbidden because the two send a person to different
	// places: one to their administrator here, the other to the device's own
	// sshd configuration.
	CodeRemoteRefused ErrorCode = "remote_refused"
)

// errorBody is the shape of every error response.
type errorBody struct {
	Error struct {
		Code    ErrorCode `json:"code"`
		Message string    `json:"message"`
		// RetryAfterSeconds is set only on rate-limit responses.
		RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
	} `json:"error"`
}

// writeJSON sends a JSON body.
//
// The body is encoded before the status is written, so an encoding failure
// produces a clean 500 rather than a truncated 200 the client would parse as
// success.
func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		log.Error("encoding response body", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal_error","message":"The server could not produce a response."}}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(encoded); err != nil {
		// The client hung up mid-write. Not actionable, but worth knowing
		// about at debug level when investigating truncated responses.
		log.Debug("writing response body", "error", err)
	}
}

// writeError sends an error response.
func writeError(w http.ResponseWriter, log *slog.Logger, status int, code ErrorCode, message string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, log, status, body)
}

// writeRateLimited sends a 429 with a Retry-After header.
func writeRateLimited(w http.ResponseWriter, log *slog.Logger, retryAfterSeconds int, message string) {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	w.Header().Set("Retry-After", itoa(retryAfterSeconds))

	var body errorBody
	body.Error.Code = CodeRateLimited
	body.Error.Message = message
	body.Error.RetryAfterSeconds = retryAfterSeconds
	writeJSON(w, log, http.StatusTooManyRequests, body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// writeInternal logs the real cause and returns a generic message.
//
// The distinction matters: the operator needs the detail to diagnose the
// fault, and the client must not receive it, because internal errors leak
// table names, file paths and library versions.
func writeInternal(w http.ResponseWriter, log *slog.Logger, context string, err error) {
	log.Error(context, "error", err)
	writeError(w, log, http.StatusInternalServerError, CodeInternal,
		"Something went wrong on our side. The error has been logged.")
}

// maxRequestBody bounds a request body. Nothing this API accepts is large —
// an imported private key is a few kilobytes — so a generous cap still closes
// the memory-exhaustion path.
const maxRequestBody = 1 << 20 // 1 MiB

// decodeJSON reads and validates a JSON request body.
//
// DisallowUnknownFields is deliberate: a client sending "passphrase" where the
// field is "vault_passphrase" would otherwise get a confusing authentication
// failure instead of being told about the typo.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errors.New("the request body is too large")
		}
		return errors.New("the request body could not be read as JSON")
	}

	// Exactly one JSON value, so a trailing second object cannot smuggle
	// anything past the first decode.
	if dec.More() {
		return errors.New("the request body must contain a single JSON object")
	}
	return nil
}
