package users

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// encodeWrappedKey splits a vault.WrappedKey across the two database columns.
//
// The envelope goes into wrapped_dek_enc as base64 JSON; the KDF parameters
// go into kdf_params as plain JSON. Keeping the parameters separate and
// readable lets an operator find which accounts are still on old Argon2id
// costs without decrypting anything — the whole point of raising the cost is
// knowing who has yet to be migrated.
func encodeWrappedKey(wk vault.WrappedKey) (envelope string, params string, err error) {
	envJSON, err := json.Marshal(wk.Envelope)
	if err != nil {
		return "", "", fmt.Errorf("users: encode wrapped key: %w", err)
	}
	kdfJSON, err := json.Marshal(wk.KDF)
	if err != nil {
		return "", "", fmt.Errorf("users: encode KDF params: %w", err)
	}
	return base64.StdEncoding.EncodeToString(envJSON), string(kdfJSON), nil
}

// decodeWrappedKey is the inverse of encodeWrappedKey.
func decodeWrappedKey(envelope, params string) (vault.WrappedKey, error) {
	envJSON, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return vault.WrappedKey{}, fmt.Errorf("users: decode wrapped key: %w", err)
	}

	var wk vault.WrappedKey
	if err := json.Unmarshal(envJSON, &wk.Envelope); err != nil {
		return vault.WrappedKey{}, fmt.Errorf("users: parse wrapped key: %w", err)
	}
	if params != "" {
		if err := json.Unmarshal([]byte(params), &wk.KDF); err != nil {
			return vault.WrappedKey{}, fmt.Errorf("users: parse KDF params: %w", err)
		}
	}
	return wk, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("users: unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

func parseNullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
