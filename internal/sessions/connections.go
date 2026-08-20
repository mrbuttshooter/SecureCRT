package sessions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// CreateSessionParams describes a saved connection to create.
type CreateSessionParams struct {
	OwnerID  string
	IsTeam   bool
	FolderID string

	Name     string
	Protocol Protocol
	Hostname string
	Port     int
	Username string

	CredentialID string
	JumpChain    []string
	Settings     Settings
}

// CreateSession saves a connection.
func (s *Store) CreateSession(ctx context.Context, p CreateSessionParams) (Session, error) {
	if p.OwnerID == "" {
		return Session{}, errors.New("sessions: an owner is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return Session{}, errors.New("sessions: a name is required")
	}
	if p.Protocol == "" {
		p.Protocol = ProtocolSSH
	}
	if err := p.Protocol.Validate(); err != nil {
		return Session{}, err
	}
	// Serial connections address a device rather than a host, so an empty
	// hostname is legitimate only there.
	if strings.TrimSpace(p.Hostname) == "" && p.Protocol != ProtocolSerial {
		return Session{}, errors.New("sessions: a hostname is required")
	}
	// Zero is stored as zero, and means "inherit". Filling in the protocol's
	// default here is what made a folder's default port unreachable for three
	// phases: the column was never empty, so Resolve's fallback never ran and
	// a folder default nobody could see was silently ignored.
	if p.Port != 0 && (p.Port < 1 || p.Port > 65535) {
		return Session{}, fmt.Errorf("sessions: port %d is out of range", p.Port)
	}
	if p.FolderID != "" {
		if _, err := s.GetFolder(ctx, p.OwnerID, p.FolderID); err != nil {
			return Session{}, fmt.Errorf("sessions: destination folder: %w", err)
		}
	}

	// Validated before it is stored, not merely on the way out. The importer
	// and the bundle restore both write chains through here, so this is the
	// one place that catches a chain nobody typed.
	if err := s.ValidateJumpChain(ctx, p.OwnerID, "", p.JumpChain); err != nil {
		return Session{}, err
	}

	jumpJSON, err := json.Marshal(orEmpty(p.JumpChain))
	if err != nil {
		return Session{}, fmt.Errorf("sessions: encode jump chain: %w", err)
	}
	settingsJSON, err := json.Marshal(p.Settings)
	if err != nil {
		return Session{}, fmt.Errorf("sessions: encode settings: %w", err)
	}

	now := s.now().UTC()
	sess := Session{
		ID:           uuid.Must(uuid.NewV7()).String(),
		OwnerID:      p.OwnerID,
		IsTeam:       p.IsTeam,
		FolderID:     p.FolderID,
		Name:         strings.TrimSpace(p.Name),
		Protocol:     p.Protocol,
		Hostname:     strings.TrimSpace(p.Hostname),
		Port:         p.Port,
		Username:     strings.TrimSpace(p.Username),
		CredentialID: p.CredentialID,
		JumpChain:    orEmpty(p.JumpChain),
		Settings:     p.Settings,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	userID, teamID := ownerColumns(p.OwnerID, p.IsTeam)

	if _, err := s.db.Exec(ctx, `
		INSERT INTO sessions
			(id, user_id, team_id, folder_id, name, protocol, hostname, port, username,
			 credential_id, jump_chain, settings, sort_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, userID, teamID, nullable(sess.FolderID), sess.Name, string(sess.Protocol),
		sess.Hostname, sess.Port, sess.Username, nullable(sess.CredentialID),
		string(jumpJSON), string(settingsJSON), sess.SortOrder,
		ts(sess.CreatedAt), ts(sess.UpdatedAt)); err != nil {
		return Session{}, fmt.Errorf("sessions: create: %w", err)
	}
	return sess, nil
}

const sessionColumns = `
	id, user_id, team_id, folder_id, name, protocol, hostname, port, username,
	credential_id, jump_chain, settings, sort_order, created_at, updated_at, last_used_at`

// ListSessions returns an owner's saved connections.
func (s *Store) ListSessions(ctx context.Context, ownerID string, isTeam bool) ([]Session, error) {
	column := "user_id"
	if isTeam {
		column = "team_id"
	}
	// #nosec G201 -- column is one of two literals chosen above, never input
	query := `SELECT` + sessionColumns + ` FROM sessions WHERE ` + column +
		` = ? ORDER BY sort_order ASC, name ASC`

	rows, err := s.db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, fmt.Errorf("sessions: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// GetSession returns one saved connection.
func (s *Store) GetSession(ctx context.Context, ownerID, id string) (Session, error) {
	row := s.db.QueryRow(ctx, `SELECT`+sessionColumns+` FROM sessions WHERE id = ?`, id)
	sess, err := scanSession(row)
	if err != nil {
		return Session{}, err
	}
	if sess.OwnerID != ownerID {
		// Not-found rather than forbidden: confirming a session exists but
		// belongs to someone else discloses their infrastructure.
		return Session{}, ErrNotFound
	}
	return sess, nil
}

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var (
		sess             Session
		userID, teamID   sql.NullString
		folderID         sql.NullString
		protocol         string
		credentialID     sql.NullString
		jumpJSON         string
		settingsJSON     string
		created, updated string
		lastUsed         sql.NullString
	)

	err := row.Scan(&sess.ID, &userID, &teamID, &folderID, &sess.Name, &protocol,
		&sess.Hostname, &sess.Port, &sess.Username, &credentialID,
		&jumpJSON, &settingsJSON, &sess.SortOrder, &created, &updated, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("sessions: read: %w", err)
	}

	if teamID.Valid && teamID.String != "" {
		sess.OwnerID, sess.IsTeam = teamID.String, true
	} else {
		sess.OwnerID = userID.String
	}
	sess.FolderID = folderID.String
	sess.Protocol = Protocol(protocol)
	sess.CredentialID = credentialID.String

	if jumpJSON != "" {
		if err := json.Unmarshal([]byte(jumpJSON), &sess.JumpChain); err != nil {
			return Session{}, fmt.Errorf("sessions: parse jump chain: %w", err)
		}
	}
	if sess.JumpChain == nil {
		sess.JumpChain = []string{}
	}
	if settingsJSON != "" {
		if err := json.Unmarshal([]byte(settingsJSON), &sess.Settings); err != nil {
			return Session{}, fmt.Errorf("sessions: parse settings: %w", err)
		}
	}

	if sess.CreatedAt, err = parseTime(created); err != nil {
		return Session{}, err
	}
	if sess.UpdatedAt, err = parseTime(updated); err != nil {
		return Session{}, err
	}
	if lastUsed.Valid && lastUsed.String != "" {
		t, err := parseTime(lastUsed.String)
		if err != nil {
			return Session{}, err
		}
		sess.LastUsedAt = &t
	}
	return sess, nil
}

// UpdateSessionParams describes a change. Nil fields are left alone.
type UpdateSessionParams struct {
	Name         *string
	FolderID     *string
	Protocol     *Protocol
	Hostname     *string
	Port         *int
	Username     *string
	CredentialID *string
	JumpChain    *[]string
	Settings     *Settings
	SortOrder    *int
}

// UpdateSession changes a saved connection.
func (s *Store) UpdateSession(ctx context.Context, ownerID, id string, p UpdateSessionParams) (Session, error) {
	sess, err := s.GetSession(ctx, ownerID, id)
	if err != nil {
		return Session{}, err
	}

	if p.Name != nil {
		if strings.TrimSpace(*p.Name) == "" {
			return Session{}, errors.New("sessions: a name is required")
		}
		sess.Name = strings.TrimSpace(*p.Name)
	}
	if p.FolderID != nil {
		if *p.FolderID != "" {
			if _, err := s.GetFolder(ctx, ownerID, *p.FolderID); err != nil {
				return Session{}, fmt.Errorf("sessions: destination folder: %w", err)
			}
		}
		sess.FolderID = *p.FolderID
	}
	if p.Protocol != nil {
		if err := p.Protocol.Validate(); err != nil {
			return Session{}, err
		}
		sess.Protocol = *p.Protocol
	}
	if p.Hostname != nil {
		sess.Hostname = strings.TrimSpace(*p.Hostname)
	}
	if p.Port != nil {
		// Zero clears it back to inherited, the same as leaving the field
		// blank when the connection was created.
		if *p.Port != 0 && (*p.Port < 1 || *p.Port > 65535) {
			return Session{}, fmt.Errorf("sessions: port %d is out of range", *p.Port)
		}
		sess.Port = *p.Port
	}
	if p.Username != nil {
		sess.Username = strings.TrimSpace(*p.Username)
	}
	if p.CredentialID != nil {
		sess.CredentialID = *p.CredentialID
	}
	if p.JumpChain != nil {
		// Only when the chain itself is being set. Re-validating on every
		// unrelated edit would mean renaming a connection failing because a
		// hop somebody else owns was deleted last week.
		if err := s.ValidateJumpChain(ctx, ownerID, id, *p.JumpChain); err != nil {
			return Session{}, err
		}
		sess.JumpChain = orEmpty(*p.JumpChain)
	}
	if p.Settings != nil {
		sess.Settings = *p.Settings
	}
	if p.SortOrder != nil {
		sess.SortOrder = *p.SortOrder
	}

	jumpJSON, err := json.Marshal(sess.JumpChain)
	if err != nil {
		return Session{}, fmt.Errorf("sessions: encode jump chain: %w", err)
	}
	settingsJSON, err := json.Marshal(sess.Settings)
	if err != nil {
		return Session{}, fmt.Errorf("sessions: encode settings: %w", err)
	}
	sess.UpdatedAt = s.now().UTC()

	if _, err := s.db.Exec(ctx, `
		UPDATE sessions SET folder_id = ?, name = ?, protocol = ?, hostname = ?, port = ?,
		                    username = ?, credential_id = ?, jump_chain = ?, settings = ?,
		                    sort_order = ?, updated_at = ?
		WHERE id = ?`,
		nullable(sess.FolderID), sess.Name, string(sess.Protocol), sess.Hostname, sess.Port,
		sess.Username, nullable(sess.CredentialID), string(jumpJSON), string(settingsJSON),
		sess.SortOrder, ts(sess.UpdatedAt), id); err != nil {
		return Session{}, fmt.Errorf("sessions: update: %w", err)
	}
	return sess, nil
}

// DeleteSession removes a saved connection.
func (s *Store) DeleteSession(ctx context.Context, ownerID, id string) error {
	if _, err := s.GetSession(ctx, ownerID, id); err != nil {
		return err
	}

	// A jump chain is a JSON array of identifiers with no foreign key behind
	// it, so deleting a bastion would leave every connection behind it
	// pointing at nothing — and they would fail at dial time with an error
	// about a host the user did not know was involved. Refuse, and name them.
	dependents, err := s.jumpDependents(ctx, ownerID, id)
	if err != nil {
		return err
	}
	if len(dependents) > 0 {
		return &ErrJumpInUse{Names: dependents}
	}

	if _, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("sessions: delete: %w", err)
	}
	return nil
}

// MarkUsed records that a connection was opened, so the interface can offer
// recent hosts.
func (s *Store) MarkUsed(ctx context.Context, id string) error {
	if _, err := s.db.Exec(ctx, `UPDATE sessions SET last_used_at = ? WHERE id = ?`,
		ts(s.now().UTC()), id); err != nil {
		return fmt.Errorf("sessions: mark used: %w", err)
	}
	return nil
}

// Resolve applies folder inheritance to produce the settings a connection
// will actually use.
//
// Walks from the session's folder up to the root, merging each folder's
// defaults into whatever is still unset. Outer folders are weakest: a value
// set on the session beats its immediate folder, which beats that folder's
// parent, and so on.
func (s *Store) Resolve(ctx context.Context, ownerID, sessionID string) (Resolved, error) {
	sess, err := s.GetSession(ctx, ownerID, sessionID)
	if err != nil {
		return Resolved{}, err
	}

	return resolveWith(sess, func(id string) (Folder, bool) {
		folder, err := s.GetFolder(ctx, ownerID, id)
		if err != nil {
			// A folder that has vanished should not make the session
			// unusable; the inheritance chain simply stops here.
			return Folder{}, false
		}
		return folder, true
	})
}

// Resolve applies inheritance using folders already in hand.
//
// The same rules as Store.Resolve, and deliberately the same code beneath:
// export and the tree endpoint both need the effective values for every
// session at once, and doing that through the query-per-folder path would be
// a few thousand round trips for a large team. Two implementations of
// inheritance would drift, and the way they would drift is that one of them
// keeps working while the other quietly stops.
func (t Tree) Resolve(sess Session) (Resolved, error) {
	byID := make(map[string]Folder, len(t.Folders))
	for _, folder := range t.Folders {
		byID[folder.ID] = folder
	}
	return resolveWith(sess, func(id string) (Folder, bool) {
		folder, ok := byID[id]
		return folder, ok
	})
}

// resolveWith walks the folder chain and produces the effective settings.
func resolveWith(sess Session, lookup func(id string) (Folder, bool)) (Resolved, error) {
	effective := sess.Settings
	var inheritedFrom []string

	current := sess.FolderID
	for depth := 0; current != ""; depth++ {
		if depth > MaxDepth {
			return Resolved{}, ErrTooDeep
		}
		folder, ok := lookup(current)
		if !ok {
			break
		}
		effective = effective.merge(folder.Defaults)
		inheritedFrom = append([]string{folder.Name}, inheritedFrom...)
		current = folder.ParentID
	}

	resolved := Resolved{Session: sess, InheritedFrom: inheritedFrom}

	// The column wins over the setting when both are present: the column is
	// what the interface shows and edits, so a stale inherited value must not
	// silently override what the user can see. Empty means inherit — which
	// for the port means *zero*, and storing zero rather than pre-filling the
	// protocol default is what makes the folder default below reachable.
	resolved.EffectiveUsername = sess.Username
	if resolved.EffectiveUsername == "" && effective.Username != nil {
		resolved.EffectiveUsername = *effective.Username
	}

	resolved.EffectivePort = sess.Port
	if resolved.EffectivePort == 0 && effective.Port != nil {
		resolved.EffectivePort = *effective.Port
	}
	if resolved.EffectivePort == 0 {
		resolved.EffectivePort = sess.Protocol.DefaultPort()
	}

	resolved.EffectiveCredentialID = sess.CredentialID
	if resolved.EffectiveCredentialID == "" && effective.CredentialID != nil {
		resolved.EffectiveCredentialID = *effective.CredentialID
	}

	resolved.Settings = effective
	return resolved, nil
}

// Tree is the whole saved-connection tree for one owner.
type Tree struct {
	Folders  []Folder
	Sessions []Session
}

// LoadTree returns everything an owner has saved, in one round trip.
//
// The interface renders the entire tree at once, so fetching it piecemeal
// would mean a request per folder — noticeable with a few hundred devices.
func (s *Store) LoadTree(ctx context.Context, ownerID string, isTeam bool) (Tree, error) {
	folders, err := s.ListFolders(ctx, ownerID, isTeam)
	if err != nil {
		return Tree{}, err
	}
	sess, err := s.ListSessions(ctx, ownerID, isTeam)
	if err != nil {
		return Tree{}, err
	}
	return Tree{Folders: folders, Sessions: sess}, nil
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// Ptr is a convenience for building Settings, whose fields are pointers so
// that "unset" is distinguishable from "set to zero".
func Ptr[T any](v T) *T { return &v }

// Ensure Store satisfies the interface the API depends on, so a signature
// change here is a compile error there rather than at run time.
var _ interface {
	LoadTree(context.Context, string, bool) (Tree, error)
	Resolve(context.Context, string, string) (Resolved, error)
} = (*Store)(nil)
