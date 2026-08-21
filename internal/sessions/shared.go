package sessions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The shared tree: what Phase 8 adds to this package.
//
// A team-owned folder or session is visible to every member of that team.
// Visibility is decided here, in SQL, in one place — the interface hides
// what these queries do not return, and the dial path refuses what they do
// not return, so hiding and refusing can never disagree.
//
// Membership is read straight from team_members rather than through the
// teams package, for the same reason ListFolders does not call ListSessions:
// one round trip for the answer, and no import cycle between the two stores.

// memberClause matches rows owned by the user or by any team the user is in.
// Callers append it after a WHERE with two bind arguments, both the user id.
const memberClause = `(user_id = ? OR team_id IN
	(SELECT team_id FROM team_members WHERE user_id = ?))`

// LoadTreeForUser returns everything one person can see: their own tree and
// the tree of every team they belong to, in one pass.
func (s *Store) LoadTreeForUser(ctx context.Context, userID string) (Tree, error) {
	// #nosec G201 -- memberClause is a package constant, never input
	folderQuery := `SELECT id, user_id, team_id, parent_id, name, sort_order, defaults, created_at, updated_at
	          FROM folders WHERE ` + memberClause + ` ORDER BY sort_order ASC, name ASC`
	rows, err := s.db.Query(ctx, folderQuery, userID, userID)
	if err != nil {
		return Tree{}, fmt.Errorf("sessions: list visible folders: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var folders []Folder
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return Tree{}, err
		}
		folders = append(folders, f)
	}
	if err := rows.Err(); err != nil {
		return Tree{}, err
	}

	// #nosec G201 -- memberClause is a package constant, never input
	sessionQuery := `SELECT` + sessionColumns + ` FROM sessions WHERE ` + memberClause +
		` ORDER BY sort_order ASC, name ASC`
	srows, err := s.db.Query(ctx, sessionQuery, userID, userID)
	if err != nil {
		return Tree{}, fmt.Errorf("sessions: list visible sessions: %w", err)
	}
	defer srows.Close() //nolint:errcheck // read-only query

	var sess []Session
	for srows.Next() {
		one, err := scanSession(srows)
		if err != nil {
			return Tree{}, err
		}
		sess = append(sess, one)
	}
	return Tree{Folders: folders, Sessions: sess}, srows.Err()
}

// getSessionVisible returns a session the user owns or can see through a
// team. Anything else is ErrNotFound — never "forbidden", for the same
// disclosure reason GetSession gives.
func (s *Store) getSessionVisible(ctx context.Context, userID, id string) (Session, error) {
	// #nosec G201 -- memberClause is a package constant, never input
	query := `SELECT` + sessionColumns + ` FROM sessions WHERE id = ? AND ` + memberClause
	row := s.db.QueryRow(ctx, query, id, userID, userID)
	return scanSession(row)
}

// GetSessionAny returns a session by id with no access check at all.
//
// For administrators deciding what a mutation is allowed to touch — the
// handler that calls this is behind the admin gate, and everything else must
// keep using the access-checked paths.
func (s *Store) GetSessionAny(ctx context.Context, id string) (Session, error) {
	row := s.db.QueryRow(ctx, `SELECT`+sessionColumns+` FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

// GetFolderAny is GetSessionAny for folders, under the same admin-only rule.
func (s *Store) GetFolderAny(ctx context.Context, id string) (Folder, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, user_id, team_id, parent_id, name, sort_order, defaults, created_at, updated_at
		 FROM folders WHERE id = ?`, id)
	return scanFolder(row)
}

// SetFolderCredential remembers which of the user's own credentials opens
// the devices in a shared folder. One row per (user, folder); choosing again
// replaces the choice.
func (s *Store) SetFolderCredential(ctx context.Context, userID, folderID, credentialID string) error {
	// The folder must be one the user can actually see, and shared — a
	// personal folder inherits credentials the normal way and a row here
	// would just be a second, confusing mechanism.
	folder, err := s.GetFolderAny(ctx, folderID)
	if err != nil {
		return err
	}
	if !folder.IsTeam {
		return fmt.Errorf("sessions: only shared folders take a per-user credential")
	}
	var one int
	err = s.db.QueryRow(ctx,
		`SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?`,
		folder.OwnerID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("sessions: membership check: %w", err)
	}

	// The credential must belong to the user personally. AAD binding would
	// catch a foreign credential at decrypt time anyway; failing here fails
	// with a sentence instead of a cipher error.
	err = s.db.QueryRow(ctx,
		`SELECT 1 FROM credentials WHERE id = ? AND user_id = ?`,
		credentialID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("sessions: credential check: %w", err)
	}

	_, err = s.db.Exec(ctx, `
		INSERT INTO user_folder_credentials (user_id, folder_id, credential_id, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id, folder_id) DO UPDATE SET
			credential_id = excluded.credential_id, updated_at = excluded.updated_at`,
		userID, folderID, credentialID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("sessions: remember folder credential: %w", err)
	}
	return nil
}

// folderCredentialFor walks a folder chain from the inside out and returns
// the user's remembered credential for the nearest folder that has one.
func (s *Store) folderCredentialFor(ctx context.Context, userID, folderID string) string {
	current := folderID
	for depth := 0; current != "" && depth <= MaxDepth; depth++ {
		var credentialID string
		err := s.db.QueryRow(ctx,
			`SELECT credential_id FROM user_folder_credentials WHERE user_id = ? AND folder_id = ?`,
			userID, current).Scan(&credentialID)
		if err == nil && credentialID != "" {
			return credentialID
		}

		var parent sql.NullString
		if err := s.db.QueryRow(ctx,
			`SELECT parent_id FROM folders WHERE id = ?`, current).Scan(&parent); err != nil {
			return ""
		}
		current = parent.String
	}
	return ""
}
