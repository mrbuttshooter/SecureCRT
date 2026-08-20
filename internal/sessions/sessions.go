// Package sessions owns the saved connection tree: folders and the connection
// profiles inside them.
//
// This is the equivalent of SecureCRT's session list, and it is what people
// actually spend their day in — an engineer with three hundred devices needs
// the tree to be fast, orderable, and to inherit settings from folders rather
// than repeating a username and port on every entry.
//
// Folder inheritance is resolved here rather than in the interface, so the
// terminal, an export, and a future scripting API all agree about what a
// connection's effective settings are.
package sessions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/store"
)

// Errors returned by this package.
var (
	ErrNotFound = errors.New("sessions: no such item")

	// ErrCycle means a move would make a folder its own ancestor. Left
	// unchecked this produces a tree that cannot be walked, which manifests
	// much later as a hang rather than an error.
	ErrCycle = errors.New("sessions: that move would put a folder inside itself")

	// ErrTooDeep bounds nesting. The limit is generous; its purpose is to
	// stop a pathological import producing a tree nothing can render.
	ErrTooDeep = errors.New("sessions: folders are nested too deeply")
)

// MaxDepth bounds folder nesting.
const MaxDepth = 32

// Protocol identifies how to reach a host.
type Protocol string

const (
	ProtocolSSH    Protocol = "ssh"
	ProtocolTelnet Protocol = "telnet"
	ProtocolSerial Protocol = "serial"
)

// Validate rejects an unknown protocol.
func (p Protocol) Validate() error {
	switch p {
	case ProtocolSSH, ProtocolTelnet, ProtocolSerial:
		return nil
	default:
		return fmt.Errorf("sessions: unknown protocol %q", p)
	}
}

// DefaultPort returns the conventional port for a protocol.
func (p Protocol) DefaultPort() int {
	switch p {
	case ProtocolTelnet:
		return 23
	default:
		return 22
	}
}

// Settings are the per-connection options that vary.
//
// Held as a document rather than columns because they are numerous, mostly
// optional, and grow with every phase — appearance now, triggers and logging
// later. A column per setting would mean a migration for each one.
//
// Every field is a pointer so that "not set here" is distinguishable from
// "set to the zero value", which is what makes folder inheritance work: a
// session that does not specify a username inherits one, but a session that
// deliberately specifies an empty username does not.
type Settings struct {
	Username *string `json:"username,omitempty"`
	Port     *int    `json:"port,omitempty"`

	// CredentialID names the stored credential to authenticate with.
	CredentialID *string `json:"credential_id,omitempty"`

	// Appearance.
	ColourScheme *string `json:"colour_scheme,omitempty"`
	FontSize     *int    `json:"font_size,omitempty"`
	Scrollback   *int    `json:"scrollback,omitempty"`

	// KeepAliveSeconds overrides the default keepalive interval.
	KeepAliveSeconds *int `json:"keepalive_seconds,omitempty"`

	// LogSession records the transcript to disk when set.
	LogSession *bool `json:"log_session,omitempty"`

	// AgentForwardCredentials names the keys to offer through a forwarded
	// SSH agent on this connection. Nil or empty means no agent is forwarded,
	// which is the only sensible default.
	//
	// One field rather than a switch and a list: "forwarding is on but no
	// keys are named" is not a state worth being able to express, and having
	// two sources of truth for one decision is how a security setting ends up
	// half-applied.
	//
	// **Never inherited from a folder.** See merge, which skips it on
	// purpose. A folder default here would silently offer somebody's keys to
	// every host inside that folder, and the person who set the default would
	// be the last to know.
	AgentForwardCredentials *[]string `json:"agent_forward_credentials,omitempty"`
}

// ForwardsAgent reports whether this connection offers an agent.
func (s Settings) ForwardsAgent() bool {
	return s.AgentForwardCredentials != nil && len(*s.AgentForwardCredentials) > 0
}

// AgentCredentials returns the keys to offer, or nothing.
func (s Settings) AgentCredentials() []string {
	if !s.ForwardsAgent() {
		return nil
	}
	return append([]string(nil), (*s.AgentForwardCredentials)...)
}

// merge returns a copy of s with any unset field taken from parent.
//
// Child wins, always. Inheritance fills gaps; it never overrides a decision
// the user made on the session itself.
func (s Settings) merge(parent Settings) Settings {
	out := s
	if out.Username == nil {
		out.Username = parent.Username
	}
	if out.Port == nil {
		out.Port = parent.Port
	}
	if out.CredentialID == nil {
		out.CredentialID = parent.CredentialID
	}
	if out.ColourScheme == nil {
		out.ColourScheme = parent.ColourScheme
	}
	if out.FontSize == nil {
		out.FontSize = parent.FontSize
	}
	if out.Scrollback == nil {
		out.Scrollback = parent.Scrollback
	}
	if out.KeepAliveSeconds == nil {
		out.KeepAliveSeconds = parent.KeepAliveSeconds
	}
	if out.LogSession == nil {
		out.LogSession = parent.LogSession
	}

	// AgentForwardCredentials is absent from this list deliberately, and the
	// omission is the feature. Forwarding an agent means a host can use those
	// keys, for as long as the connection lives, to authenticate anywhere they
	// are accepted — so a compromised device in a folder of forty would have
	// the run of the other thirty-nine. Every other setting here is a
	// convenience; this one is an authority, and an authority granted by
	// inheritance is one nobody remembers granting.
	//
	// A test asserts this. Adding the field to merge would be a one-line
	// change that looks like tidying up.

	return out
}

// Folder groups connections.
type Folder struct {
	ID       string
	OwnerID  string
	IsTeam   bool
	ParentID string // empty at the top level
	Name     string

	// Defaults are inherited by everything inside, unless overridden.
	Defaults Settings

	SortOrder int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Session is a saved connection.
type Session struct {
	ID       string
	OwnerID  string
	IsTeam   bool
	FolderID string // empty at the top level

	Name     string
	Protocol Protocol
	Hostname string

	// Port and Username are stored as columns because they are queried and
	// displayed constantly; Settings may still override them, and Resolve
	// reconciles the two.
	Port     int
	Username string

	CredentialID string

	// JumpChain is an ordered list of session IDs to hop through. Stored as
	// a list rather than a single field so an arbitrary-depth ProxyJump
	// survives an import from ~/.ssh/config.
	JumpChain []string

	Settings Settings

	SortOrder  int
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
}

// Resolved is a session with folder inheritance applied.
//
// What the terminal actually connects with. Produced once, here, so that the
// interface, the connection code and any export agree.
type Resolved struct {
	Session

	// EffectiveUsername, EffectivePort and EffectiveCredentialID are the
	// values after inheritance.
	EffectiveUsername     string
	EffectivePort         int
	EffectiveCredentialID string

	// InheritedFrom names the folders the settings came from, outermost
	// first, so the interface can explain why a value is what it is.
	InheritedFrom []string
}

// Store persists the tree.
type Store struct {
	db  *store.DB
	now func() time.Time
}

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db, now: time.Now} }

// --- folders ---------------------------------------------------------------

// CreateFolderParams describes a folder to create.
type CreateFolderParams struct {
	OwnerID  string
	IsTeam   bool
	ParentID string
	Name     string
	Defaults Settings
}

// CreateFolder adds a folder.
func (s *Store) CreateFolder(ctx context.Context, p CreateFolderParams) (Folder, error) {
	if p.OwnerID == "" {
		return Folder{}, errors.New("sessions: an owner is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return Folder{}, errors.New("sessions: a folder name is required")
	}

	if p.ParentID != "" {
		depth, err := s.depthOf(ctx, p.OwnerID, p.ParentID)
		if err != nil {
			return Folder{}, err
		}
		if depth+1 >= MaxDepth {
			return Folder{}, ErrTooDeep
		}
	}

	defaults, err := json.Marshal(p.Defaults)
	if err != nil {
		return Folder{}, fmt.Errorf("sessions: encode folder defaults: %w", err)
	}

	now := s.now().UTC()
	f := Folder{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OwnerID:   p.OwnerID,
		IsTeam:    p.IsTeam,
		ParentID:  p.ParentID,
		Name:      strings.TrimSpace(p.Name),
		Defaults:  p.Defaults,
		CreatedAt: now,
		UpdatedAt: now,
	}

	userID, teamID := ownerColumns(p.OwnerID, p.IsTeam)

	if _, err := s.db.Exec(ctx, `
		INSERT INTO folders (id, user_id, team_id, parent_id, name, sort_order, defaults, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, userID, teamID, nullable(f.ParentID), f.Name, f.SortOrder,
		string(defaults), ts(f.CreatedAt), ts(f.UpdatedAt)); err != nil {
		return Folder{}, fmt.Errorf("sessions: create folder: %w", err)
	}
	return f, nil
}

// depthOf reports how many ancestors a folder has, and doubles as an
// existence check.
func (s *Store) depthOf(ctx context.Context, ownerID, folderID string) (int, error) {
	depth := 0
	current := folderID

	for current != "" {
		if depth > MaxDepth {
			return 0, ErrTooDeep
		}
		var parent sql.NullString
		var owner sql.NullString
		err := s.db.QueryRow(ctx,
			`SELECT parent_id, COALESCE(user_id, team_id) FROM folders WHERE id = ?`, current).
			Scan(&parent, &owner)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, fmt.Errorf("sessions: walk folder ancestry: %w", err)
		}
		if owner.String != ownerID {
			return 0, ErrNotFound
		}
		current = parent.String
		depth++
	}
	return depth, nil
}

// ListFolders returns an owner's folders.
func (s *Store) ListFolders(ctx context.Context, ownerID string, isTeam bool) ([]Folder, error) {
	column := "user_id"
	if isTeam {
		column = "team_id"
	}
	// #nosec G201 -- column is one of two literals chosen above, never input
	query := `SELECT id, user_id, team_id, parent_id, name, sort_order, defaults, created_at, updated_at
	          FROM folders WHERE ` + column + ` = ? ORDER BY sort_order ASC, name ASC`

	rows, err := s.db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, fmt.Errorf("sessions: list folders: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query

	var out []Folder
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func scanFolder(row interface{ Scan(...any) error }) (Folder, error) {
	var (
		f                Folder
		userID, teamID   sql.NullString
		parentID         sql.NullString
		defaults         string
		created, updated string
	)
	err := row.Scan(&f.ID, &userID, &teamID, &parentID, &f.Name, &f.SortOrder,
		&defaults, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Folder{}, ErrNotFound
	}
	if err != nil {
		return Folder{}, fmt.Errorf("sessions: read folder: %w", err)
	}

	if teamID.Valid && teamID.String != "" {
		f.OwnerID, f.IsTeam = teamID.String, true
	} else {
		f.OwnerID = userID.String
	}
	f.ParentID = parentID.String

	if defaults != "" {
		if err := json.Unmarshal([]byte(defaults), &f.Defaults); err != nil {
			return Folder{}, fmt.Errorf("sessions: parse folder defaults: %w", err)
		}
	}
	if f.CreatedAt, err = parseTime(created); err != nil {
		return Folder{}, err
	}
	if f.UpdatedAt, err = parseTime(updated); err != nil {
		return Folder{}, err
	}
	return f, nil
}

// GetFolder returns one folder.
func (s *Store) GetFolder(ctx context.Context, ownerID, id string) (Folder, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, user_id, team_id, parent_id, name, sort_order, defaults, created_at, updated_at
		 FROM folders WHERE id = ?`, id)
	f, err := scanFolder(row)
	if err != nil {
		return Folder{}, err
	}
	if f.OwnerID != ownerID {
		return Folder{}, ErrNotFound
	}
	return f, nil
}

// UpdateFolderParams describes a folder change. Nil fields are left alone.
type UpdateFolderParams struct {
	Name      *string
	ParentID  *string
	SortOrder *int
	Defaults  *Settings
}

// UpdateFolder changes a folder, refusing a move that would create a cycle.
func (s *Store) UpdateFolder(ctx context.Context, ownerID, id string, p UpdateFolderParams) (Folder, error) {
	existing, err := s.GetFolder(ctx, ownerID, id)
	if err != nil {
		return Folder{}, err
	}

	if p.ParentID != nil && *p.ParentID != existing.ParentID {
		if err := s.checkMove(ctx, ownerID, id, *p.ParentID); err != nil {
			return Folder{}, err
		}
		existing.ParentID = *p.ParentID
	}
	if p.Name != nil {
		if strings.TrimSpace(*p.Name) == "" {
			return Folder{}, errors.New("sessions: a folder name is required")
		}
		existing.Name = strings.TrimSpace(*p.Name)
	}
	if p.SortOrder != nil {
		existing.SortOrder = *p.SortOrder
	}
	if p.Defaults != nil {
		existing.Defaults = *p.Defaults
	}

	defaults, err := json.Marshal(existing.Defaults)
	if err != nil {
		return Folder{}, fmt.Errorf("sessions: encode folder defaults: %w", err)
	}
	existing.UpdatedAt = s.now().UTC()

	if _, err := s.db.Exec(ctx,
		`UPDATE folders SET name = ?, parent_id = ?, sort_order = ?, defaults = ?, updated_at = ?
		 WHERE id = ?`,
		existing.Name, nullable(existing.ParentID), existing.SortOrder,
		string(defaults), ts(existing.UpdatedAt), id); err != nil {
		return Folder{}, fmt.Errorf("sessions: update folder: %w", err)
	}
	return existing, nil
}

// checkMove refuses a move that would make a folder its own ancestor.
func (s *Store) checkMove(ctx context.Context, ownerID, folderID, newParentID string) error {
	if newParentID == "" {
		return nil // moving to the top level is always safe
	}
	if newParentID == folderID {
		return ErrCycle
	}

	// Walk up from the proposed parent. Meeting the folder being moved means
	// the move would detach that whole subtree from the tree and make it
	// unreachable — a bug that manifests much later as a hang.
	current := newParentID
	for depth := 0; current != ""; depth++ {
		if depth > MaxDepth {
			return ErrTooDeep
		}
		if current == folderID {
			return ErrCycle
		}

		var parent sql.NullString
		var owner sql.NullString
		err := s.db.QueryRow(ctx,
			`SELECT parent_id, COALESCE(user_id, team_id) FROM folders WHERE id = ?`, current).
			Scan(&parent, &owner)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("sessions: check move: %w", err)
		}
		if owner.String != ownerID {
			return ErrNotFound
		}
		current = parent.String
	}
	return nil
}

// ErrFolderNotEmpty means a folder still contains something.
//
// Deleting a folder full of saved connections is how somebody loses an
// afternoon's work, so it is refused unless the caller asks for a recursive
// delete explicitly. The error carries the counts so the interface can say
// what would be lost rather than asking a vague "are you sure?".
type ErrFolderNotEmpty struct {
	Folders  int
	Sessions int
}

func (e *ErrFolderNotEmpty) Error() string {
	return fmt.Sprintf("sessions: the folder still contains %d folder(s) and %d saved connection(s)",
		e.Folders, e.Sessions)
}

// IsNotEmpty reports whether err is a non-empty-folder refusal.
func IsNotEmpty(err error) bool {
	var e *ErrFolderNotEmpty
	return errors.As(err, &e)
}

// DeleteFolder removes an empty folder.
//
// Refuses when anything is inside. The schema sets a session's folder to NULL
// when its folder disappears while sub-folders cascade, which would mean
// deleting one folder silently vanishes its sub-folders and dumps their
// connections at the top level — a confusing outcome nobody asked for. Making
// the caller choose avoids it.
func (s *Store) DeleteFolder(ctx context.Context, ownerID, id string) error {
	if _, err := s.GetFolder(ctx, ownerID, id); err != nil {
		return err
	}

	folders, sess, err := s.countContents(ctx, id)
	if err != nil {
		return err
	}
	if folders > 0 || sess > 0 {
		return &ErrFolderNotEmpty{Folders: folders, Sessions: sess}
	}

	if _, err := s.db.Exec(ctx, `DELETE FROM folders WHERE id = ?`, id); err != nil {
		return fmt.Errorf("sessions: delete folder: %w", err)
	}
	return nil
}

// DeleteFolderRecursive removes a folder and everything inside it, returning
// how many saved connections were destroyed.
//
// The count is returned rather than discarded so the caller can record in the
// audit log what was actually lost.
func (s *Store) DeleteFolderRecursive(ctx context.Context, ownerID, id string) (int, error) {
	if _, err := s.GetFolder(ctx, ownerID, id); err != nil {
		return 0, err
	}

	ids, err := s.descendantFolderIDs(ctx, ownerID, id)
	if err != nil {
		return 0, err
	}

	deleted := 0
	err = s.db.InTx(ctx, func(tx *store.Tx) error {
		// Sessions are removed explicitly rather than relying on the schema,
		// which would set their folder to NULL and leave them at the top
		// level — the opposite of what a recursive delete means.
		for _, folderID := range ids {
			res, err := tx.Exec(ctx, `DELETE FROM sessions WHERE folder_id = ?`, folderID)
			if err != nil {
				return fmt.Errorf("sessions: delete folder contents: %w", err)
			}
			if n, err := res.RowsAffected(); err == nil {
				deleted += int(n)
			}
		}
		// Deleting the root cascades the sub-folders.
		if _, err := tx.Exec(ctx, `DELETE FROM folders WHERE id = ?`, id); err != nil {
			return fmt.Errorf("sessions: delete folder: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// countContents reports what is directly inside a folder.
func (s *Store) countContents(ctx context.Context, folderID string) (folders, sessions int, err error) {
	if err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM folders WHERE parent_id = ?`, folderID).Scan(&folders); err != nil {
		return 0, 0, fmt.Errorf("sessions: count sub-folders: %w", err)
	}
	if err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE folder_id = ?`, folderID).Scan(&sessions); err != nil {
		return 0, 0, fmt.Errorf("sessions: count contents: %w", err)
	}
	return folders, sessions, nil
}

// descendantFolderIDs returns a folder and every folder beneath it.
func (s *Store) descendantFolderIDs(ctx context.Context, ownerID, rootID string) ([]string, error) {
	all, err := s.ListFolders(ctx, ownerID, false)
	if err != nil {
		return nil, err
	}

	children := make(map[string][]string, len(all))
	for _, f := range all {
		children[f.ParentID] = append(children[f.ParentID], f.ID)
	}

	out := []string{rootID}
	queue := []string{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			out = append(out, child)
			queue = append(queue, child)
		}
		if len(out) > 10000 {
			// Defensive: a cycle should be impossible given checkMove, but a
			// runaway walk here would hang a request rather than fail it.
			return nil, ErrTooDeep
		}
	}
	return out, nil
}

func ownerColumns(ownerID string, isTeam bool) (userID, teamID any) {
	if isTeam {
		return nil, ownerID
	}
	return ownerID, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sessions: unparseable timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
