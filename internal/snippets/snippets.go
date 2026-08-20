// Package snippets stores the commands people paste for the hundredth time.
//
// A snippet is a name, a body, and however many parameters the body mentions.
// `show interface {{interface}}` asks which interface before it is sent;
// `write memory` asks nothing. The parameters are derived from the body when
// it is saved rather than declared separately, so the two cannot disagree.
//
// # Why parameter values are never stored
//
// It would be easy, and useful-looking, to remember the last value somebody
// used for each parameter. It would also make a snippet the obvious place to
// keep a password — `enable {{password}}`, filled in once and remembered —
// and that would be a credential stored outside the vault, unencrypted, in a
// table nobody thinks of as holding secrets.
//
// So the values live in the browser for as long as the dialog is open and
// nowhere else. Credentials belong in the vault, which is what the
// %PASSWORD% placeholder is for.
package snippets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

// Limits.
const (
	// MaxBodyBytes bounds one snippet.
	//
	// A snippet is something a person types at a device, not a file. Sixteen
	// kilobytes is a very long configuration block and small enough that a
	// thousand of them are still a small table.
	MaxBodyBytes = 16 << 10

	// MaxParameters bounds how many questions one snippet may ask. Beyond a
	// handful it is a form, and a form is a script somebody should be writing
	// somewhere else.
	MaxParameters = 12

	// MaxNameBytes bounds the name.
	MaxNameBytes = 100
)

// Errors callers distinguish.
var (
	ErrNotFound  = errors.New("snippets: no such snippet")
	ErrDuplicate = errors.New("snippets: a snippet with that name already exists")
)

// parameterPattern finds {{name}} in a body.
//
// Deliberately narrow: letters, digits, underscores and hyphens. A parameter
// name becomes a form label and a map key, and allowing arbitrary text would
// mean deciding what {{ }} or {{../etc}} mean rather than simply not matching
// them.
var parameterPattern = regexp.MustCompile(`\{\{([A-Za-z0-9_-]{1,40})\}\}`)

// Snippet is one stored command.
type Snippet struct {
	ID      string
	OwnerID string
	IsTeam  bool

	Name        string
	Description string
	Body        string

	// Parameters are the names the body mentions, in the order they first
	// appear — which is the order the form should ask them in, because a
	// dialog whose fields are alphabetical when the command is not is
	// needlessly confusing.
	Parameters []string

	SortOrder int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ParametersIn returns the parameter names a body mentions, deduplicated and
// in order of first appearance.
func ParametersIn(body string) []string {
	matches := parameterPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		name := match[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// Render fills a snippet's parameters in.
//
// A missing value leaves the placeholder as it was written rather than
// substituting an empty string. Sending `show interface ` to a switch because
// a field was blank produces an error message nobody can interpret; sending
// `show interface {{interface}}` produces one anybody can.
func Render(body string, values map[string]string) string {
	return parameterPattern.ReplaceAllStringFunc(body, func(match string) string {
		name := match[2 : len(match)-2]
		if value, ok := values[name]; ok {
			return value
		}
		return match
	})
}

// Validate checks a snippet before it is stored.
func Validate(name, body string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("snippets: a snippet needs a name")
	}
	if len(name) > MaxNameBytes {
		return fmt.Errorf("snippets: a name is limited to %d characters", MaxNameBytes)
	}
	if strings.TrimSpace(body) == "" {
		return errors.New("snippets: a snippet needs something to send")
	}
	if len(body) > MaxBodyBytes {
		return fmt.Errorf("snippets: a snippet is limited to %d bytes", MaxBodyBytes)
	}
	if count := len(ParametersIn(body)); count > MaxParameters {
		return fmt.Errorf(
			"snippets: %d parameters is more than the %d one snippet may ask for",
			count, MaxParameters)
	}
	return nil
}

// Store persists snippets.
type Store struct {
	db  *store.DB
	now func() time.Time
}

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db, now: time.Now} }

// CreateParams describes a snippet to store.
type CreateParams struct {
	OwnerID     string
	IsTeam      bool
	Name        string
	Description string
	Body        string
	SortOrder   int
}

// Create stores a snippet.
func (s *Store) Create(ctx context.Context, p CreateParams) (Snippet, error) {
	if p.OwnerID == "" {
		return Snippet{}, errors.New("snippets: an owner is required")
	}
	if err := Validate(p.Name, p.Body); err != nil {
		return Snippet{}, err
	}

	now := s.now().UTC()
	snippet := Snippet{
		ID:          uuid.Must(uuid.NewV7()).String(),
		OwnerID:     p.OwnerID,
		IsTeam:      p.IsTeam,
		Name:        strings.TrimSpace(p.Name),
		Description: p.Description,
		Body:        p.Body,
		Parameters:  ParametersIn(p.Body),
		SortOrder:   p.SortOrder,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	encoded, err := json.Marshal(orEmpty(snippet.Parameters))
	if err != nil {
		return Snippet{}, fmt.Errorf("snippets: encode parameters: %w", err)
	}

	userID, teamID := ownerColumns(p.OwnerID, p.IsTeam)
	_, err = s.db.Exec(ctx, `
		INSERT INTO snippets
			(id, user_id, team_id, name, description, body, parameters,
			 sort_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snippet.ID, userID, teamID, snippet.Name, snippet.Description,
		snippet.Body, string(encoded), snippet.SortOrder,
		ts(now), ts(now))
	if err != nil {
		if isDuplicate(err) {
			return Snippet{}, fmt.Errorf("%w: %s", ErrDuplicate, snippet.Name)
		}
		return Snippet{}, fmt.Errorf("snippets: create: %w", err)
	}

	return snippet, nil
}

// UpdateParams describes a change. Nil fields are left alone.
type UpdateParams struct {
	Name        *string
	Description *string
	Body        *string
	SortOrder   *int
}

// Update changes a snippet.
func (s *Store) Update(ctx context.Context, ownerID, id string, p UpdateParams) (Snippet, error) {
	snippet, err := s.Get(ctx, ownerID, id)
	if err != nil {
		return Snippet{}, err
	}

	if p.Name != nil {
		snippet.Name = strings.TrimSpace(*p.Name)
	}
	if p.Description != nil {
		snippet.Description = *p.Description
	}
	if p.Body != nil {
		snippet.Body = *p.Body
		// Re-derived rather than kept, so a body and its parameter list
		// cannot drift apart.
		snippet.Parameters = ParametersIn(snippet.Body)
	}
	if p.SortOrder != nil {
		snippet.SortOrder = *p.SortOrder
	}

	if err := Validate(snippet.Name, snippet.Body); err != nil {
		return Snippet{}, err
	}

	encoded, err := json.Marshal(orEmpty(snippet.Parameters))
	if err != nil {
		return Snippet{}, fmt.Errorf("snippets: encode parameters: %w", err)
	}

	snippet.UpdatedAt = s.now().UTC()
	_, err = s.db.Exec(ctx, `
		UPDATE snippets
		   SET name = ?, description = ?, body = ?, parameters = ?,
		       sort_order = ?, updated_at = ?
		 WHERE id = ?`,
		snippet.Name, snippet.Description, snippet.Body, string(encoded),
		snippet.SortOrder, ts(snippet.UpdatedAt), snippet.ID)
	if err != nil {
		if isDuplicate(err) {
			return Snippet{}, fmt.Errorf("%w: %s", ErrDuplicate, snippet.Name)
		}
		return Snippet{}, fmt.Errorf("snippets: update: %w", err)
	}

	return snippet, nil
}

// Get returns one snippet, refusing another owner's.
func (s *Store) Get(ctx context.Context, ownerID, id string) (Snippet, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id, user_id, team_id, name, description, body, parameters,
		       sort_order, created_at, updated_at
		  FROM snippets
		 WHERE id = ? AND COALESCE(user_id, team_id) = ?`, id, ownerID)

	snippet, err := scanSnippet(row)
	if err != nil {
		return Snippet{}, err
	}
	return snippet, nil
}

// ListForOwner returns an owner's snippets, in their chosen order.
func (s *Store) ListForOwner(ctx context.Context, ownerID string, isTeam bool) ([]Snippet, error) {
	column := "user_id"
	if isTeam {
		column = "team_id"
	}

	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT id, user_id, team_id, name, description, body, parameters,
		       sort_order, created_at, updated_at
		  FROM snippets
		 WHERE %s = ?
		 ORDER BY sort_order, name`, column), ownerID)
	if err != nil {
		return nil, fmt.Errorf("snippets: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	out := make([]Snippet, 0)
	for rows.Next() {
		snippet, err := scanSnippet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, snippet)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("snippets: list: %w", err)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SortOrder != out[j].SortOrder {
			return out[i].SortOrder < out[j].SortOrder
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Delete removes a snippet.
func (s *Store) Delete(ctx context.Context, ownerID, id string) error {
	result, err := s.db.Exec(ctx,
		`DELETE FROM snippets WHERE id = ? AND COALESCE(user_id, team_id) = ?`,
		id, ownerID)
	if err != nil {
		return fmt.Errorf("snippets: delete: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("snippets: delete: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
