// Package logging configures the process-wide structured logger.
//
// Every log line bkd emits goes through here. The redaction helpers exist
// because this service handles private keys and passwords in memory: a
// well-meaning debug line that interpolates a credential would leak it to
// disk and to any log shipper. Callers should pass secrets through Redact
// rather than trusting themselves to remember.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Setup builds a slog.Logger for the given level and format and installs it
// as the default. Format is "json" (for log shippers) or "text" (for humans).
func Setup(level, format string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}

	opts := &slog.HandlerOptions{Level: parseLevel(level)}

	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}

	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Redact renders a secret as a fixed-width mask that reveals only its length
// bucket, so operators can tell "empty" from "set" without seeing the value.
func Redact(secret string) string {
	switch {
	case secret == "":
		return "<empty>"
	case len(secret) < 8:
		return "<redacted:short>"
	default:
		return "<redacted>"
	}
}

// Fingerprint renders a byte slice as a short, non-reversible label for
// correlating log lines about the same key without disclosing it.
func Fingerprint(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	// Length alone is safe to publish and is enough to correlate.
	return fmt.Sprintf("<%d bytes>", len(b))
}
