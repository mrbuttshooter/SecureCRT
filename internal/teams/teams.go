// Package teams owns groups of users and their membership.
//
// The schema has carried teams since 0001; this is the code that finally
// uses it. A team here is a *visibility* group: folders and sessions owned
// by a team are seen by its members, and that is the whole mechanism behind
// the shared device tree. Credentials stay personal — a shared folder says
// where to connect, never with what — so the wrapped_team_dek_enc column
// stays empty until shared team credentials become a feature of their own.
package teams

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mrbuttshooter/securecrt/internal/store"
)

// ErrNotFound means no such team, or no such membership.
var ErrNotFound = errors.New("teams: not found")

// ErrExists means a team with that name already exists.
var ErrExists = errors.New("teams: a team with that name already exists")

// Team is a named group of users.
type Team struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	// Members is filled by ListWithMembers, zero elsewhere.
	Members int `json:"members,omitempty"`
}

// Member is one user's place in a team.
type Member struct {
	UserID  string    `json:"user_id"`
	Email   string    `json:"email"`
	Name    string    `json:"name"`
	AddedAt time.Time `json:"added_at"`
}

// Store reads and writes teams.
type Store struct {
	db *store.DB
}

// NewStore builds a team store.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Create makes a team.
func (s *Store) Create(ctx context.Context, name, description string) (Team, error) {
	t := Team{
		ID:          uuid.Must(uuid.NewV7()).String(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO teams (id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Description, ts(t.CreatedAt), ts(t.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return Team{}, ErrExists
		}
		return Team{}, fmt.Errorf("teams: create: %w", err)
	}
	return t, nil
}

// Get returns one team.
func (s *Store) Get(ctx context.Context, id string) (Team, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM teams WHERE id = ?`, id)
	return scanTeam(row)
}

// Delete removes a team.
//
// Folders, sessions and snippets owned by the team cascade away with it —
// the schema says so — which is exactly as destructive as it sounds. The
// interface confirms with the counts before calling this.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.Exec(ctx, `DELETE FROM teams WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("teams: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns every team, with member counts, name order.
func (s *Store) List(ctx context.Context) ([]Team, error) {
	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.name, t.description, t.created_at,
		       (SELECT COUNT(*) FROM team_members m WHERE m.team_id = t.id)
		FROM teams t ORDER BY t.name ASC`)
	if err != nil {
		return nil, fmt.Errorf("teams: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Team
	for rows.Next() {
		var t Team
		var created string
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &created, &t.Members); err != nil {
			return nil, fmt.Errorf("teams: scan: %w", err)
		}
		t.CreatedAt = parseTS(created)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListForUser returns the teams a user belongs to, name order.
func (s *Store) ListForUser(ctx context.Context, userID string) ([]Team, error) {
	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.name, t.description, t.created_at
		FROM teams t
		JOIN team_members m ON m.team_id = t.id
		WHERE m.user_id = ?
		ORDER BY t.name ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("teams: list for user: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Team
	for rows.Next() {
		t, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// IsMember reports whether a user belongs to a team.
func (s *Store) IsMember(ctx context.Context, userID, teamID string) (bool, error) {
	var one int
	err := s.db.QueryRow(ctx,
		`SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?`,
		teamID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("teams: membership check: %w", err)
	}
	return true, nil
}

// AddMember puts a user in a team. Adding twice is not an error.
//
// wrapped_team_dek_enc is stored empty: this membership grants visibility of
// the team's tree, not access to team credentials, which do not exist yet.
func (s *Store) AddMember(ctx context.Context, teamID, userID string) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO team_members (team_id, user_id, role, wrapped_team_dek_enc, created_at)
		VALUES (?, ?, 'member', '', ?)
		ON CONFLICT (team_id, user_id) DO NOTHING`,
		teamID, userID, ts(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("teams: add member: %w", err)
	}
	return nil
}

// RemoveMember takes a user out of a team.
func (s *Store) RemoveMember(ctx context.Context, teamID, userID string) error {
	res, err := s.db.Exec(ctx,
		`DELETE FROM team_members WHERE team_id = ? AND user_id = ?`, teamID, userID)
	if err != nil {
		return fmt.Errorf("teams: remove member: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListMembers returns a team's members with enough identity to render.
func (s *Store) ListMembers(ctx context.Context, teamID string) ([]Member, error) {
	rows, err := s.db.Query(ctx, `
		SELECT m.user_id, u.email, u.display_name, m.created_at
		FROM team_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.team_id = ?
		ORDER BY u.email ASC`, teamID)
	if err != nil {
		return nil, fmt.Errorf("teams: list members: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Member
	for rows.Next() {
		var m Member
		var added string
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name, &added); err != nil {
			return nil, fmt.Errorf("teams: scan member: %w", err)
		}
		m.AddedAt = parseTS(added)
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanTeam(row interface{ Scan(...any) error }) (Team, error) {
	var t Team
	var created string
	err := row.Scan(&t.ID, &t.Name, &t.Description, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	if err != nil {
		return Team{}, fmt.Errorf("teams: scan: %w", err)
	}
	t.CreatedAt = parseTS(created)
	return t, nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// isDuplicate reports a unique-constraint violation, matched on the message
// because SQLite and PostgreSQL agree on nothing else about it. The same
// idiom as internal/snippets, duplicated for the same reason it is there.
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "23505")
}
