package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/auth"
	"github.com/mrbuttshooter/securecrt/internal/users"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Context keys. Unexported so nothing outside this package can plant one.
type contextKey int

const (
	ctxRequestID contextKey = iota
	ctxSession
	ctxUser
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// chain applies middleware so the first listed runs outermost.
//
// Order is not cosmetic here: recovery must be outside logging so a panic is
// still logged with its request ID, and the request ID must be assigned before
// either.
func chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// RequestIDFrom returns the request ID, or "" outside a request.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

// SessionFrom returns the authenticated session.
func SessionFrom(ctx context.Context) (auth.Session, bool) {
	s, ok := ctx.Value(ctxSession).(auth.Session)
	return s, ok
}

// UserFrom returns the authenticated user.
func UserFrom(ctx context.Context) (users.User, bool) {
	u, ok := ctx.Value(ctxUser).(users.User)
	return u, ok
}

// withRequestID assigns an identifier to each request and echoes it back.
//
// A client-supplied X-Request-ID is deliberately ignored. Trusting it would
// let a caller collide or forge identifiers in the log, which is exactly what
// an attacker would do to make their requests hard to trace.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.Must(uuid.NewV7()).String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

// statusRecorder captures the status code for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer, which the
// WebSocket upgrade in a later phase will need.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// withLogging records one line per request.
//
// The URL path is logged but never the query string or body: this API carries
// passphrases and private keys in request bodies, and a log line is exactly
// where one must not end up.
func withLogging(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}

			next.ServeHTTP(rec, r)

			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelWarn
			}

			log.Log(r.Context(), level, "request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFrom(r.Context()),
				"remote", clientIP(r, nil),
			)
		})
	}
}

// withRecovery turns a panic into a 500 instead of a dropped connection.
//
// Without this, a nil dereference in one handler would kill the whole process
// and disconnect every other user's session — unacceptable for a service
// holding long-lived terminal connections.
func withRecovery(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if p := recover(); p != nil {
					// http.ErrAbortHandler is the documented way to abandon a
					// response; it is not a fault and must propagate.
					if p == http.ErrAbortHandler {
						panic(p)
					}
					log.Error("panic in handler",
						"panic", fmt.Sprint(p),
						"path", r.URL.Path,
						"request_id", RequestIDFrom(r.Context()))
					writeError(w, log, http.StatusInternalServerError, CodeInternal,
						"Something went wrong on our side. The error has been logged.")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP determines the caller's address.
//
// X-Forwarded-For is honoured only from a configured trusted proxy. Trusting
// it unconditionally would let anyone spoof their address and walk straight
// past the per-address rate limit — which is precisely the header's most
// common misuse.
func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remote = r.RemoteAddr
	}

	if len(trustedProxies) == 0 {
		return remote
	}

	ip := net.ParseIP(remote)
	if ip == nil {
		return remote
	}
	trusted := false
	for _, cidr := range trustedProxies {
		if cidr.Contains(ip) {
			trusted = true
			break
		}
	}
	if !trusted {
		return remote
	}

	// Right-most entry the proxy appended is the one it actually observed;
	// everything to its left is client-supplied and forgeable.
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return remote
	}
	parts := strings.Split(forwarded, ",")
	candidate := strings.TrimSpace(parts[len(parts)-1])
	if net.ParseIP(candidate) == nil {
		return remote
	}
	return candidate
}

// --- CSRF -------------------------------------------------------------------

// CSRF tokens use the double-submit pattern: a value in a JavaScript-readable
// cookie that the client echoes in a header.
//
// SameSite=Strict on the session cookie already blocks the classic
// cross-site request forgery, so this is defence in depth — it covers a
// same-site scripting flaw and browsers that mishandle SameSite. The token is
// signed with an HKDF subkey of the master key, so it cannot be forged even
// by something that can set cookies.

const csrfTokenBytes = 32

// newCSRFToken mints a signed token.
func newCSRFToken(key vault.Key) (string, error) {
	raw := make([]byte, csrfTokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("api: generate CSRF token: %w", err)
	}

	value := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))

	return value + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyCSRFToken checks a token's signature.
func verifyCSRFToken(key vault.Key, token string) bool {
	value, sig, found := strings.Cut(token, ".")
	if !found || value == "" || sig == "" {
		return false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hmac.Equal(decoded, mac.Sum(nil))
}

// csrfCookie builds the JavaScript-readable CSRF cookie.
//
// HttpOnly is deliberately false: the SPA must read this value to echo it in
// a header, and that echo is the half of the check a cross-origin page cannot
// perform. The token is not a credential on its own.
func csrfCookie(token string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     auth.CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// safeMethods never change state, so they are exempt from the CSRF check.
var safeMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true,
}

// withCSRF rejects state-changing requests without a valid token.
func withCSRF(key vault.Key, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if safeMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get(auth.CSRFHeaderName)
			cookie, err := r.Cookie(auth.CSRFCookieName)

			switch {
			case header == "" || err != nil:
				writeError(w, log, http.StatusForbidden, CodeForbidden,
					"This request is missing its CSRF token. Reload the page and try again.")
				return
			// Both halves must match each other as well as verifying, which
			// is what makes the pattern work: a cross-origin page can cause
			// the cookie to be sent but cannot read it to set the header.
			case !hmac.Equal([]byte(header), []byte(cookie.Value)):
				writeError(w, log, http.StatusForbidden, CodeForbidden,
					"This request's CSRF token did not match. Reload the page and try again.")
				return
			case !verifyCSRFToken(key, header):
				writeError(w, log, http.StatusForbidden, CodeForbidden,
					"This request's CSRF token is not valid. Reload the page and try again.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// --- Authentication ---------------------------------------------------------

// withAuth resolves the session cookie and loads the user.
//
// A disabled account is rejected here rather than only at sign-in, so
// suspending someone takes effect on their next request instead of whenever
// their session happens to expire.
func (a *API) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(auth.SessionCookieName)
		if err != nil || cookie.Value == "" {
			a.unauthorized(w)
			return
		}

		sess, err := a.sessions.Lookup(r.Context(), cookie.Value)
		if err != nil {
			if !errors.Is(err, auth.ErrSessionNotFound) {
				writeInternal(w, a.log, "looking up session", err)
				return
			}
			// Clear the stale cookie so the browser stops sending it.
			http.SetCookie(w, a.cfg.Session.ClearSessionCookie())
			a.unauthorized(w)
			return
		}

		u, err := a.users.ByID(r.Context(), sess.UserID)
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				// The account was deleted while the session lived.
				_ = a.sessions.Revoke(r.Context(), sess.ID)
				http.SetCookie(w, a.cfg.Session.ClearSessionCookie())
				a.unauthorized(w)
				return
			}
			writeInternal(w, a.log, "loading user for session", err)
			return
		}

		if u.IsDisabled {
			_, _ = a.sessions.RevokeAllForUser(r.Context(), u.ID)
			a.vaults.LockAllForUser(u.ID)
			http.SetCookie(w, a.cfg.Session.ClearSessionCookie())
			writeError(w, a.log, http.StatusForbidden, CodeForbidden,
				"This account has been disabled. Contact an administrator.")
			return
		}

		ctx := context.WithValue(r.Context(), ctxSession, sess)
		ctx = context.WithValue(ctx, ctxUser, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withMFA rejects a session that has not satisfied the org's MFA policy.
//
// Applied after withAuth, so a user who has signed in but not yet completed a
// second factor can still reach the endpoints needed to do so.
func (a *API) withMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := SessionFrom(r.Context())
		if !ok {
			a.unauthorized(w)
			return
		}
		u, _ := UserFrom(r.Context())

		if a.mfaRequiredFor(u) && !sess.MFASatisfied {
			writeError(w, a.log, http.StatusForbidden, CodeMFARequired,
				"Two-factor authentication is required before you can continue.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withAdmin restricts a route to administrators.
func (a *API) withAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok || !u.IsAdmin {
			writeError(w, a.log, http.StatusForbidden, CodeForbidden,
				"This action requires administrator rights.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) unauthorized(w http.ResponseWriter) {
	writeError(w, a.log, http.StatusUnauthorized, CodeUnauthorized,
		"You are not signed in.")
}
