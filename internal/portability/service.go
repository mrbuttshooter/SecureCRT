package portability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// Service gathers a user's world into a payload and puts one back.
type Service struct {
	sessions    *sessions.Store
	credentials *credentials.Store
	hostKeys    *hostkeys.Store
	log         *slog.Logger
}

// NewService builds a Service.
func NewService(
	sess *sessions.Store,
	creds *credentials.Store,
	hostKeys *hostkeys.Store,
	log *slog.Logger,
) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{sessions: sess, credentials: creds, hostKeys: hostKeys, log: log}
}

// GatherOptions control what an export includes.
type GatherOptions struct {
	UserID string

	// IncludeSecrets carries private keys and passwords. Without it a bundle
	// describes the connections but cannot open any of them, which is right
	// for sharing a device list with a colleague and wrong for a migration.
	IncludeSecrets bool

	// IncludeKnownHosts carries accepted host keys.
	IncludeKnownHosts bool
}

// Gather reads everything a user has into a payload.
//
// vaultKey is needed only when IncludeSecrets is set; it is used to decrypt
// each credential and is not retained.
func (s *Service) Gather(ctx context.Context, key vault.Key, opts GatherOptions) (Payload, error) {
	tree, err := s.sessions.LoadTree(ctx, opts.UserID, false)
	if err != nil {
		return Payload{}, fmt.Errorf("portability: read the saved connections: %w", err)
	}

	payload := Payload{
		Folders:     make([]Folder, 0, len(tree.Folders)),
		Sessions:    make([]Session, 0, len(tree.Sessions)),
		Credentials: make([]Credential, 0),
		KnownHosts:  make([]KnownHost, 0),
	}

	for _, folder := range tree.Folders {
		defaults, err := marshalSettings(folder.Defaults)
		if err != nil {
			return Payload{}, err
		}
		payload.Folders = append(payload.Folders, Folder{
			ID:        folder.ID,
			ParentID:  folder.ParentID,
			Name:      folder.Name,
			Defaults:  defaults,
			SortOrder: folder.SortOrder,
		})
	}

	for _, session := range tree.Sessions {
		settings, err := marshalSettings(session.Settings)
		if err != nil {
			return Payload{}, err
		}
		payload.Sessions = append(payload.Sessions, Session{
			ID:           session.ID,
			FolderID:     session.FolderID,
			Name:         session.Name,
			Protocol:     string(session.Protocol),
			Hostname:     session.Hostname,
			Port:         session.Port,
			Username:     session.Username,
			CredentialID: session.CredentialID,
			JumpChain:    session.JumpChain,
			Settings:     settings,
			SortOrder:    session.SortOrder,
		})
	}

	stored, err := s.credentials.List(ctx, opts.UserID, false)
	if err != nil {
		return Payload{}, fmt.Errorf("portability: read the credentials: %w", err)
	}

	for _, cred := range stored {
		entry := Credential{
			ID:          cred.ID,
			Name:        cred.Name,
			Kind:        string(cred.Kind),
			Username:    cred.Username,
			PublicKey:   cred.PublicKey,
			Fingerprint: cred.Fingerprint,
			KeyType:     cred.KeyType,
		}

		if opts.IncludeSecrets {
			secret, err := s.credentials.Reveal(ctx, key, opts.UserID, cred.ID)
			if err != nil {
				if errors.Is(err, credentials.ErrNoSecret) {
					// A credential with nothing in it still belongs in the
					// bundle: the connections that name it must keep working.
					payload.Credentials = append(payload.Credentials, entry)
					continue
				}
				return Payload{}, fmt.Errorf("portability: read the secret for %q: %w", cred.Name, err)
			}
			entry.Secret = secret.Value
			entry.Extra = secret.Extra
			secret.Zero()
		}

		payload.Credentials = append(payload.Credentials, entry)
	}

	if opts.IncludeKnownHosts {
		entries, err := s.hostKeys.ListForUser(ctx, opts.UserID)
		if err != nil {
			return Payload{}, fmt.Errorf("portability: read the known hosts: %w", err)
		}
		for _, entry := range entries {
			// Org-wide entries belong to the administrator who published
			// them, not to the person exporting, and carrying them would let
			// a restored instance inherit trust decisions nobody made there.
			if entry.IsOrgWide() {
				continue
			}
			payload.KnownHosts = append(payload.KnownHosts, KnownHost{
				Hostname:    entry.Hostname,
				Port:        entry.Port,
				KeyType:     entry.KeyType,
				Fingerprint: entry.Fingerprint,
				PublicKey:   entry.PublicKey,
			})
		}
	}

	return payload, nil
}

// Plan is what an import would do, before it does any of it.
//
// Produced and shown first because an import writes to somebody's working
// device list, and "restore the wrong bundle" is a mistake that should be
// caught by reading rather than by undoing.
type Plan struct {
	Counts Counts `json:"counts"`

	// NewFolders and NewSessions are what would be created.
	NewFolders  []string `json:"new_folders"`
	NewSessions []string `json:"new_sessions"`

	// Conflicts are records whose name already exists here. Not an error:
	// the import policy decides what happens to them.
	Conflicts []Conflict `json:"conflicts"`

	// Warnings are things worth reading before committing — a session whose
	// credential is missing from the bundle, a bundle with no secrets in it.
	Warnings []string `json:"warnings"`

	// HasSecrets reports whether the credentials carry usable material.
	HasSecrets bool `json:"has_secrets"`
}

// Conflict is a record that collides with something already here.
type Conflict struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Existing string `json:"existing"`
}

// OnConflict says what to do when an imported record's name already exists.
type OnConflict string

const (
	// ConflictSkip leaves what is already here alone. The default, because
	// an import that silently replaces a working connection is worse than
	// one that quietly declines to.
	ConflictSkip OnConflict = "skip"

	// ConflictRename imports alongside, with a suffix.
	ConflictRename OnConflict = "rename"

	// ConflictReplace overwrites. Only ever on an explicit choice.
	ConflictReplace OnConflict = "replace"
)

// ImportOptions control applying a payload.
type ImportOptions struct {
	UserID string

	// IntoFolder puts everything under an existing folder, so an import can
	// be quarantined and inspected rather than mixed into a live tree.
	IntoFolder string

	OnConflict OnConflict

	// SkipKnownHosts leaves accepted host keys out, so a user can choose to
	// re-verify every fingerprint on the new instance.
	SkipKnownHosts bool
}

// Result reports what an import actually did.
type Result struct {
	Folders     int `json:"folders"`
	Sessions    int `json:"sessions"`
	Credentials int `json:"credentials"`
	KnownHosts  int `json:"known_hosts"`

	Skipped  int      `json:"skipped"`
	Warnings []string `json:"warnings"`
}

// Preview describes what importing a payload would do.
func (s *Service) Preview(ctx context.Context, payload Payload, opts ImportOptions) (Plan, error) {
	tree, err := s.sessions.LoadTree(ctx, opts.UserID, false)
	if err != nil {
		return Plan{}, fmt.Errorf("portability: read the saved connections: %w", err)
	}
	stored, err := s.credentials.List(ctx, opts.UserID, false)
	if err != nil {
		return Plan{}, fmt.Errorf("portability: read the credentials: %w", err)
	}

	existingFolders := map[string]string{}
	for _, folder := range tree.Folders {
		existingFolders[strings.ToLower(folder.Name)] = folder.ID
	}
	existingSessions := map[string]string{}
	for _, session := range tree.Sessions {
		existingSessions[strings.ToLower(session.Name)] = session.ID
	}
	existingCredentials := map[string]string{}
	for _, cred := range stored {
		existingCredentials[strings.ToLower(cred.Name)] = cred.ID
	}

	plan := Plan{
		Counts:      payload.Counts(),
		NewFolders:  make([]string, 0, len(payload.Folders)),
		NewSessions: make([]string, 0, len(payload.Sessions)),
		Conflicts:   make([]Conflict, 0),
		Warnings:    make([]string, 0),
	}

	for _, folder := range payload.Folders {
		if id, clash := existingFolders[strings.ToLower(folder.Name)]; clash {
			plan.Conflicts = append(plan.Conflicts,
				Conflict{Kind: "folder", Name: folder.Name, Existing: id})
			continue
		}
		plan.NewFolders = append(plan.NewFolders, folder.Name)
	}

	for _, session := range payload.Sessions {
		if id, clash := existingSessions[strings.ToLower(session.Name)]; clash {
			plan.Conflicts = append(plan.Conflicts,
				Conflict{Kind: "connection", Name: session.Name, Existing: id})
			continue
		}
		plan.NewSessions = append(plan.NewSessions, session.Name)
	}

	for _, cred := range payload.Credentials {
		if cred.Secret != "" {
			plan.HasSecrets = true
		}
		if id, clash := existingCredentials[strings.ToLower(cred.Name)]; clash {
			plan.Conflicts = append(plan.Conflicts,
				Conflict{Kind: "credential", Name: cred.Name, Existing: id})
		}
	}

	// The warning that matters most: a bundle exported without secrets
	// restores a device list nothing can connect with, and finding that out
	// after importing is a bad afternoon.
	if len(payload.Credentials) > 0 && !plan.HasSecrets {
		plan.Warnings = append(plan.Warnings,
			"This bundle carries no keys or passwords, so the connections in it "+
				"will not be able to authenticate until a credential is set on each.")
	}

	// A connection naming a credential the bundle does not contain will
	// import, and will fail the first time somebody tries to use it.
	inBundle := map[string]bool{}
	for _, cred := range payload.Credentials {
		inBundle[cred.ID] = true
	}
	var orphaned []string
	for _, session := range payload.Sessions {
		if session.CredentialID != "" && !inBundle[session.CredentialID] {
			orphaned = append(orphaned, session.Name)
		}
	}
	if len(orphaned) > 0 {
		sort.Strings(orphaned)
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"%d connections name a credential this bundle does not contain, "+
				"starting with %q. They will import without one.",
			len(orphaned), orphaned[0]))
	}

	return plan, nil
}

// Import applies a payload.
//
// Identifiers are remapped rather than reused. Two instances would otherwise
// collide the moment they had a record in common, and honouring the
// identifiers in a file somebody else wrote would let a crafted bundle
// address — and overwrite — rows it was never given.
func (s *Service) Import(ctx context.Context, key vault.Key, payload Payload, opts ImportOptions) (Result, error) {
	if opts.OnConflict == "" {
		opts.OnConflict = ConflictSkip
	}

	result := Result{Warnings: []string{}}

	tree, err := s.sessions.LoadTree(ctx, opts.UserID, false)
	if err != nil {
		return Result{}, fmt.Errorf("portability: read the saved connections: %w", err)
	}
	stored, err := s.credentials.List(ctx, opts.UserID, false)
	if err != nil {
		return Result{}, fmt.Errorf("portability: read the credentials: %w", err)
	}

	takenFolders := map[string]bool{}
	for _, folder := range tree.Folders {
		takenFolders[strings.ToLower(folder.Name)] = true
	}
	takenSessions := map[string]bool{}
	for _, session := range tree.Sessions {
		takenSessions[strings.ToLower(session.Name)] = true
	}
	takenCredentials := map[string]string{}
	for _, cred := range stored {
		takenCredentials[strings.ToLower(cred.Name)] = cred.ID
	}

	// Old identifier to new, so references between records survive remapping.
	folderIDs := map[string]string{}
	credentialIDs := map[string]string{}

	// Credentials first: sessions reference them.
	for _, cred := range payload.Credentials {
		if existing, clash := takenCredentials[strings.ToLower(cred.Name)]; clash {
			switch opts.OnConflict {
			case ConflictSkip, ConflictReplace:
				// Replace is not offered for credentials. Overwriting the
				// secret behind a name is how somebody loses the only copy
				// of a key, and the name is a label rather than an identity.
				credentialIDs[cred.ID] = existing
				result.Skipped++
				continue
			case ConflictRename:
				cred.Name = uniqueName(cred.Name, func(candidate string) bool {
					_, taken := takenCredentials[strings.ToLower(candidate)]
					return taken
				})
			}
		}

		created, err := s.credentials.Create(ctx, key, credentials.CreateParams{
			OwnerID:     opts.UserID,
			Name:        cred.Name,
			Kind:        credentials.Kind(cred.Kind),
			Username:    cred.Username,
			Secret:      cred.Secret,
			Extra:       cred.Extra,
			PublicKey:   cred.PublicKey,
			Fingerprint: cred.Fingerprint,
			KeyType:     cred.KeyType,
		})
		if err != nil {
			return result, fmt.Errorf("portability: import the credential %q: %w", cred.Name, err)
		}

		credentialIDs[cred.ID] = created.ID
		takenCredentials[strings.ToLower(cred.Name)] = created.ID
		result.Credentials++
	}

	// Folders next, outermost first, so a parent exists before its children.
	for _, folder := range inParentOrder(payload.Folders) {
		if takenFolders[strings.ToLower(folder.Name)] {
			switch opts.OnConflict {
			case ConflictSkip, ConflictReplace:
				result.Skipped++
				continue
			case ConflictRename:
				folder.Name = uniqueName(folder.Name, func(candidate string) bool {
					return takenFolders[strings.ToLower(candidate)]
				})
			}
		}

		parent := opts.IntoFolder
		if folder.ParentID != "" {
			if mapped, ok := folderIDs[folder.ParentID]; ok {
				parent = mapped
			}
			// A parent that is not in the bundle means the tree was cut
			// somewhere; the folder lands at the import root rather than
			// vanishing with everything under it.
		}

		defaults, err := unmarshalSettings(folder.Defaults)
		if err != nil {
			return result, fmt.Errorf("portability: the folder %q has unreadable defaults: %w", folder.Name, err)
		}

		created, err := s.sessions.CreateFolder(ctx, sessions.CreateFolderParams{
			OwnerID:  opts.UserID,
			ParentID: parent,
			Name:     folder.Name,
			Defaults: defaults,
		})
		if err != nil {
			return result, fmt.Errorf("portability: import the folder %q: %w", folder.Name, err)
		}

		folderIDs[folder.ID] = created.ID
		takenFolders[strings.ToLower(folder.Name)] = true
		result.Folders++
	}

	// Sessions last. Their identifiers are recorded as they are created, so
	// jump chains can be resolved once every session exists.
	sessionIDs := map[string]string{}

	for _, session := range payload.Sessions {
		if takenSessions[strings.ToLower(session.Name)] {
			switch opts.OnConflict {
			case ConflictSkip, ConflictReplace:
				result.Skipped++
				continue
			case ConflictRename:
				session.Name = uniqueName(session.Name, func(candidate string) bool {
					return takenSessions[strings.ToLower(candidate)]
				})
			}
		}

		folder := opts.IntoFolder
		if mapped, ok := folderIDs[session.FolderID]; ok {
			folder = mapped
		}

		settings, err := unmarshalSettings(session.Settings)
		if err != nil {
			return result, fmt.Errorf("portability: the connection %q has unreadable settings: %w", session.Name, err)
		}

		protocol := sessions.Protocol(session.Protocol)
		if protocol == "" {
			protocol = sessions.ProtocolSSH
		}

		// The jump chain is left for the second pass: it names other
		// sessions, and one of them may not exist yet.
		created, err := s.sessions.CreateSession(ctx, sessions.CreateSessionParams{
			OwnerID:      opts.UserID,
			FolderID:     folder,
			Name:         session.Name,
			Protocol:     protocol,
			Hostname:     session.Hostname,
			Port:         session.Port,
			Username:     session.Username,
			CredentialID: credentialIDs[session.CredentialID],
			Settings:     settings,
		})
		if err != nil {
			return result, fmt.Errorf("portability: import the connection %q: %w", session.Name, err)
		}

		sessionIDs[session.ID] = created.ID
		takenSessions[strings.ToLower(session.Name)] = true
		result.Sessions++
	}

	// Second pass: jump chains, now that every session has an identifier.
	//
	// A chain names other sessions, so it cannot be written as each is
	// created — the host to hop through may come later in the bundle. A hop
	// that is not in the bundle at all is dropped rather than guessed:
	// pointing a ProxyJump at whatever happens to hold that identifier here
	// would try to authenticate against an unrelated device.
	for _, session := range payload.Sessions {
		if len(session.JumpChain) == 0 {
			continue
		}
		newID, imported := sessionIDs[session.ID]
		if !imported {
			continue // skipped as a conflict
		}

		chain := make([]string, 0, len(session.JumpChain))
		dropped := 0
		for _, hop := range session.JumpChain {
			if mapped, ok := sessionIDs[hop]; ok {
				chain = append(chain, mapped)
				continue
			}
			dropped++
		}

		if dropped > 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"%q hops through %d connections that are not in this bundle; "+
					"those hops were left out.", session.Name, dropped))
		}
		if len(chain) == 0 {
			continue
		}

		if _, err := s.sessions.UpdateSession(ctx, opts.UserID, newID,
			sessions.UpdateSessionParams{JumpChain: &chain}); err != nil {
			// A refused chain must not abandon the import. Chains are now
			// validated on the way in, and a bundle can legitimately carry
			// one this instance will not accept — a loop, or a hop that
			// arrived as a conflict and was skipped. Losing eighty
			// connections because one of them had a bad route would be a far
			// worse outcome than losing the route.
			if isChainRefusal(err) {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"%q could not keep its jump chain: %v. The connection was "+
						"imported without it; set a route by hand.", session.Name, err))
				continue
			}
			return result, fmt.Errorf("portability: set the jump chain for %q: %w", session.Name, err)
		}
	}

	if !opts.SkipKnownHosts {
		for _, host := range payload.KnownHosts {
			if _, err := s.hostKeys.Trust(ctx, opts.UserID, host.Hostname, host.Port, hostkeys.Presented{
				KeyType:     host.KeyType,
				PublicKey:   host.PublicKey,
				Fingerprint: host.Fingerprint,
			}); err != nil {
				// A host key that conflicts with one already recorded here is
				// not a reason to abandon the import: it means this instance
				// has seen the host and disagrees, which the user needs to
				// know about but can settle afterwards.
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"The host key for %s:%d was not imported: %v", host.Hostname, host.Port, err))
				continue
			}
			result.KnownHosts++
		}
	}

	return result, nil
}

// inParentOrder returns folders with every parent before its children.
func inParentOrder(folders []Folder) []Folder {
	byID := make(map[string]Folder, len(folders))
	for _, folder := range folders {
		byID[folder.ID] = folder
	}

	var out []Folder
	placed := map[string]bool{}

	// Repeated passes rather than a recursive walk: a bundle can name a
	// parent it does not contain, and a cycle — which a hand-edited file can
	// certainly contain — must terminate rather than recurse forever.
	for len(out) < len(folders) {
		progress := false
		for _, folder := range folders {
			if placed[folder.ID] {
				continue
			}
			_, parentInBundle := byID[folder.ParentID]
			if folder.ParentID == "" || !parentInBundle || placed[folder.ParentID] {
				out = append(out, folder)
				placed[folder.ID] = true
				progress = true
			}
		}
		if !progress {
			// Everything left is in a cycle. Import them at the top level
			// rather than dropping them: a user would rather find their
			// folders flattened than missing.
			for _, folder := range folders {
				if !placed[folder.ID] {
					folder.ParentID = ""
					out = append(out, folder)
					placed[folder.ID] = true
				}
			}
		}
	}

	return out
}

// uniqueName appends a counter until the name is free.
func uniqueName(base string, taken func(string) bool) string {
	for i := 2; i < 1000; i++ {
		candidate := fmt.Sprintf("%s (%d)", base, i)
		if !taken(candidate) {
			return candidate
		}
	}
	return fmt.Sprintf("%s (imported)", base)
}

func marshalSettings(s sessions.Settings) (json.RawMessage, error) {
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("portability: encode settings: %w", err)
	}
	if string(encoded) == "{}" {
		return nil, nil
	}
	return encoded, nil
}

func unmarshalSettings(raw json.RawMessage) (sessions.Settings, error) {
	if len(raw) == 0 {
		return sessions.Settings{}, nil
	}
	var out sessions.Settings
	if err := json.Unmarshal(raw, &out); err != nil {
		return sessions.Settings{}, err
	}
	return out, nil
}

// isChainRefusal reports whether an error is the session store declining a
// jump chain, as opposed to something having gone wrong.
//
// The distinction matters because the two call for opposite responses: a
// refused chain is one connection's route and the import continues without
// it, while a database failure means nothing else is going to work either.
func isChainRefusal(err error) bool {
	return errors.Is(err, sessions.ErrJumpNotFound) ||
		errors.Is(err, sessions.ErrJumpSelf) ||
		errors.Is(err, sessions.ErrJumpCycle) ||
		errors.Is(err, sessions.ErrJumpTooLong) ||
		errors.Is(err, sessions.ErrJumpProtocol)
}
