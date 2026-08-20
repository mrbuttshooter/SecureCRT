package portability

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
)

// Turning a foreign configuration into a Payload.
//
// Everything imported becomes a Payload and then goes through the same code
// path a bundle does: the same preview, the same conflict policy, the same
// identifier remapping. A SecureCRT import that took its own route into the
// database would be a second place for those rules to be got wrong.

// Source names where an import came from, for the interface and the audit log.
type Source string

const (
	SourceBundle    Source = "bundle"
	SourceSecureCRT Source = "securecrt"
	SourceOpenSSH   Source = "ssh_config"
	SourcePuTTY     Source = "putty"
	SourceCSV       Source = "csv"
)

// Import is a payload plus what was learned while producing it.
type Import struct {
	Source  Source
	Payload Payload

	// Warnings are things the user needs to read: a password that did not
	// decode, a file that was not in the format, a setting with no equivalent.
	Warnings []string

	// Notes are per-source facts worth reporting even when nothing is wrong,
	// such as how many passwords were recovered out of how many stored.
	Notes []string
}

// SecureCRTOptions control a SecureCRT import.
type SecureCRTOptions struct {
	// ConfigPassphrase is SecureCRT's own "Configuration Passphrase", when
	// the user set one. Off by default there, so usually empty.
	ConfigPassphrase string

	// SkipPasswords reads the device list without the passwords.
	SkipPasswords bool

	// CredentialPrefix is prepended to the name of every credential created
	// from a session's saved password, so an imported credential is
	// recognisable in a list beside hand-made ones.
	CredentialPrefix string
}

// FromSecureCRT reads a SecureCRT configuration directory into a payload.
//
// One credential is created per session that had a password, named after the
// session. SecureCRT stores a password per session rather than a credential
// list, so there is nothing to deduplicate against — and merging two sessions
// that happen to share a password would be a guess with a bad failure mode:
// changing one later would silently change the other.
func FromSecureCRT(fsys fs.FS, opts SecureCRTOptions) (Import, error) {
	result, err := securecrt.ReadDirectory(fsys, securecrt.ReadOptions{
		ConfigPassphrase: opts.ConfigPassphrase,
		SkipPasswords:    opts.SkipPasswords,
	})
	if err != nil {
		return Import{}, fmt.Errorf("portability: read the SecureCRT configuration: %w", err)
	}

	out := Import{
		Source:   SourceSecureCRT,
		Warnings: append([]string{}, result.Warnings...),
		Notes:    []string{},
		Payload: Payload{
			Folders:     []Folder{},
			Sessions:    []Session{},
			Credentials: []Credential{},
			KnownHosts:  []KnownHost{},
		},
	}

	if len(result.Sessions) == 0 {
		out.Warnings = append(out.Warnings,
			"No sessions were found. Point this at your SecureCRT configuration "+
				"folder — the one containing a Sessions directory.")
		return out, nil
	}

	prefix := opts.CredentialPrefix
	if prefix == "" {
		prefix = "SecureCRT"
	}

	folders := newFolderTree()
	// Sessions in a stable order, so two runs over one configuration produce
	// identical output and a user comparing them sees no spurious churn.
	sorted := append([]securecrt.Session{}, result.Sessions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	// Session name to identifier, so a jump host named by another session can
	// be resolved once every session exists.
	byName := map[string]string{}
	type pendingJump struct{ sessionID, jumpName string }
	var jumps []pendingJump

	for _, source := range sorted {
		session := Session{
			ID:       uuid.Must(uuid.NewV7()).String(),
			FolderID: folders.ensure(source.Folders),
			Name:     source.Name,
			Protocol: source.Protocol,
			Hostname: source.Hostname,
			Port:     source.Port,
			Username: source.Username,
		}

		if source.Scrollback > 0 {
			session.Settings = settingsJSON(map[string]any{"scrollback": source.Scrollback})
		}

		if source.Password != "" {
			credential := Credential{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Name:     fmt.Sprintf("%s: %s", prefix, source.Name),
				Kind:     "password",
				Username: source.Username,
				Secret:   source.Password,
			}
			out.Payload.Credentials = append(out.Payload.Credentials, credential)
			session.CredentialID = credential.ID
		}

		if source.IdentityFile != "" {
			// The key itself lives outside the configuration, so it cannot
			// travel with the session. Saying which file it was is the most
			// useful thing available.
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%q used the key at %s. Import that key separately and set it on "+
					"the connection — SecureCRT stores the path, not the key.",
				source.Name, source.IdentityFile))
		}

		if jump := source.JumpSession(); jump != "" {
			jumps = append(jumps, pendingJump{sessionID: session.ID, jumpName: jump})
		} else if source.FirewallName != "" && !strings.EqualFold(source.FirewallName, "None") {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%q went through the firewall %q, which has no equivalent here. "+
					"Set a jump host on the connection if it needs one.",
				source.Name, source.FirewallName))
		}

		byName[source.Name] = session.ID
		out.Payload.Sessions = append(out.Payload.Sessions, session)
	}

	// Jump hosts, now that every session has an identifier.
	if len(jumps) > 0 {
		index := map[string]int{}
		for i, session := range out.Payload.Sessions {
			index[session.ID] = i
		}
		for _, jump := range jumps {
			target, ok := byName[jump.jumpName]
			if !ok {
				out.Warnings = append(out.Warnings, fmt.Sprintf(
					"A connection hops through the session %q, which is not in this "+
						"configuration. The hop was left out.", jump.jumpName))
				continue
			}
			at := index[jump.sessionID]
			out.Payload.Sessions[at].JumpChain = []string{target}
		}
	}

	out.Payload.Folders = folders.all()

	recovered, stored := result.PasswordsRecovered()
	switch {
	case opts.SkipPasswords && stored > 0:
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d sessions had a saved password, which was left behind as you asked.", stored))
	case stored == 0:
		out.Notes = append(out.Notes, "No sessions had a saved password.")
	case recovered == stored:
		out.Notes = append(out.Notes, fmt.Sprintf(
			"Recovered all %d saved passwords. Check one against SecureCRT before "+
				"relying on the rest.", stored))
	default:
		out.Notes = append(out.Notes, fmt.Sprintf(
			"Recovered %d of %d saved passwords. The rest are listed in the warnings.",
			recovered, stored))
	}

	return out, nil
}

// folderTree builds bundle folders from paths as they are encountered.
type folderTree struct {
	// ids maps a joined path to the folder's identifier.
	ids     map[string]string
	folders []Folder
}

func newFolderTree() *folderTree {
	return &folderTree{ids: map[string]string{}}
}

// ensure returns the identifier for a folder path, creating it and any
// missing ancestors.
func (t *folderTree) ensure(path []string) string {
	parent := ""
	for i := range path {
		key := strings.Join(path[:i+1], "\x00")
		if id, ok := t.ids[key]; ok {
			parent = id
			continue
		}

		id := uuid.Must(uuid.NewV7()).String()
		t.ids[key] = id
		t.folders = append(t.folders, Folder{
			ID:       id,
			ParentID: parent,
			Name:     path[i],
		})
		parent = id
	}
	return parent
}

func (t *folderTree) all() []Folder {
	if t.folders == nil {
		return []Folder{}
	}
	return t.folders
}

// settingsJSON encodes a settings document, dropping it if it encodes to
// nothing meaningful.
func settingsJSON(values map[string]any) json.RawMessage {
	if len(values) == 0 {
		return nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil
	}
	return encoded
}
