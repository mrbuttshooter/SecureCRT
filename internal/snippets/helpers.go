package snippets

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Small helpers, kept beside the store that uses them.
//
// Duplicated from internal/sessions rather than shared, and that is a
// deliberate choice about what a package exports. These are four lines each,
// they are only meaningful next to a particular table's columns, and a shared
// "database helpers" package is how a project acquires a module that
// everything imports and nobody owns.

// ownerColumns turns an owner into the two nullable columns the schema uses.
//
// A user_id or a team_id, never both, never neither — the constraint the
// snippets table shares with folders and sessions.
func ownerColumns(ownerID string, isTeam bool) (userID, teamID any) {
	if isTeam {
		return nil, ownerID
	}
	return ownerID, nil
}

// ts renders a timestamp the way every table here stores one.
func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("snippets: unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// orEmpty makes a nil slice encode as [] rather than null, so the interface
// never has to distinguish "no parameters" from "field missing".
func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// isDuplicate reports a unique-constraint violation.
//
// Matched on the message rather than on a driver-specific error type, because
// the two backends disagree about everything else here: SQLite says "UNIQUE
// constraint failed" and PostgreSQL says "duplicate key value violates unique
// constraint" with SQLSTATE 23505. Both are checked, and a miss costs only a
// less specific error message rather than a wrong answer.
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "23505")
}

// scanner is the part of *sql.Row and *sql.Rows this needs.
type scanner interface {
	Scan(dest ...any) error
}

// scanSnippet reads one row.
func scanSnippet(row scanner) (Snippet, error) {
	var (
		snippet          Snippet
		userID, teamID   sql.NullString
		parameters       string
		created, updated string
	)

	err := row.Scan(&snippet.ID, &userID, &teamID, &snippet.Name,
		&snippet.Description, &snippet.Body, &parameters,
		&snippet.SortOrder, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Snippet{}, ErrNotFound
	}
	if err != nil {
		return Snippet{}, fmt.Errorf("snippets: scan: %w", err)
	}

	switch {
	case userID.Valid:
		snippet.OwnerID = userID.String
	case teamID.Valid:
		snippet.OwnerID, snippet.IsTeam = teamID.String, true
	}

	// Decoded rather than re-derived from the body: listing snippets should
	// not mean running a regular expression over every one of them.
	if err := decodeParameters(parameters, &snippet.Parameters); err != nil {
		return Snippet{}, err
	}

	if snippet.CreatedAt, err = parseTime(created); err != nil {
		return Snippet{}, err
	}
	if snippet.UpdatedAt, err = parseTime(updated); err != nil {
		return Snippet{}, err
	}
	return snippet, nil
}

// decodeParameters reads the stored JSON array.
func decodeParameters(encoded string, out *[]string) error {
	if strings.TrimSpace(encoded) == "" {
		*out = nil
		return nil
	}
	if err := json.Unmarshal([]byte(encoded), out); err != nil {
		return fmt.Errorf("snippets: decode parameters: %w", err)
	}
	return nil
}
