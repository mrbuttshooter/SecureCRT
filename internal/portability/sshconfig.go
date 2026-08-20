package portability

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// Reading ~/.ssh/config.
//
// The point of difference from the other importers is that the keys are
// usually right there. A user who uploads their .ssh directory has the
// config, the private keys it names, and known_hosts — so the import can
// produce connections that work, rather than a device list with a note
// saying which key to go and find.

// SSHConfigOptions control an OpenSSH import.
type SSHConfigOptions struct {
	// ImportKeys reads the private keys the config names, when they are
	// present in the same directory. Without it only the connections come.
	ImportKeys bool

	// ImportKnownHosts reads ~/.ssh/known_hosts.
	ImportKnownHosts bool

	// CredentialPrefix labels credentials made from imported key files.
	CredentialPrefix string
}

// sshHost is one Host block, resolved.
type sshHost struct {
	alias      string
	hostName   string
	user       string
	port       int
	identities []string
	proxyJump  string
	keepAlive  int
}

// maxConfigBytes bounds a config file. Generous for a file of text.
const maxConfigBytes = 8 << 20

// FromSSHDirectory reads an OpenSSH configuration directory.
//
// fsys is usually a user's uploaded .ssh directory. The config is read from
// "config"; keys and known_hosts are read from the same place when asked for.
func FromSSHDirectory(fsys fs.FS, opts SSHConfigOptions) (Import, error) {
	out := Import{
		Source:   SourceOpenSSH,
		Warnings: []string{},
		Notes:    []string{},
		Payload: Payload{
			Folders: []Folder{}, Sessions: []Session{},
			Credentials: []Credential{}, KnownHosts: []KnownHost{},
		},
	}

	configPath := "config"
	if _, err := fs.Stat(fsys, configPath); err != nil {
		// Also accept being pointed at a directory containing .ssh.
		if _, nested := fs.Stat(fsys, ".ssh/config"); nested == nil {
			configPath = ".ssh/config"
		} else {
			out.Warnings = append(out.Warnings,
				"No config file was found. Point this at your .ssh directory.")
			return out, nil
		}
	}
	base := path.Dir(configPath)

	file, err := fsys.Open(configPath)
	if err != nil {
		return out, fmt.Errorf("portability: open the ssh config: %w", err)
	}
	defer func() { _ = file.Close() }()

	hosts, wildcards, warnings, err := parseSSHConfig(file)
	if err != nil {
		return out, err
	}
	out.Warnings = append(out.Warnings, warnings...)

	if len(hosts) == 0 {
		out.Warnings = append(out.Warnings,
			"No Host entries with a concrete name were found. Patterns like "+
				"\"Host *\" describe defaults rather than a host to connect to.")
	}

	// Wildcard blocks are defaults rather than hosts, so they become the
	// defaults on the folder everything lands in — which is what they mean.
	var folderID string
	if len(hosts) > 0 {
		folder := Folder{
			ID:   uuid.Must(uuid.NewV7()).String(),
			Name: "SSH config",
		}
		if defaults := wildcardDefaults(wildcards); defaults != nil {
			folder.Defaults = defaults
		}
		out.Payload.Folders = append(out.Payload.Folders, folder)
		folderID = folder.ID
	}

	// Keys, first, so a session can point at one. Read once per file even
	// when several hosts name it, which is the normal case for a person with
	// one key and forty hosts.
	keyCredentials := map[string]string{}
	if opts.ImportKeys {
		prefix := opts.CredentialPrefix
		if prefix == "" {
			prefix = "SSH"
		}
		for _, identity := range uniqueIdentities(hosts) {
			credential, warning := readIdentity(fsys, base, identity, prefix)
			if warning != "" {
				out.Warnings = append(out.Warnings, warning)
			}
			if credential != nil {
				out.Payload.Credentials = append(out.Payload.Credentials, *credential)
				keyCredentials[identity] = credential.ID
			}
		}
	}

	byAlias := map[string]string{}
	type pendingJump struct{ sessionID, target string }
	var jumps []pendingJump

	for _, host := range hosts {
		session := Session{
			ID:       uuid.Must(uuid.NewV7()).String(),
			FolderID: folderID,
			Name:     host.alias,
			Protocol: "ssh",
			Hostname: host.hostName,
			Port:     host.port,
			Username: host.user,
		}

		for _, identity := range host.identities {
			if id, ok := keyCredentials[identity]; ok {
				session.CredentialID = id
				break
			}
		}
		if session.CredentialID == "" && len(host.identities) > 0 && !opts.ImportKeys {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%q uses the key at %s. Import keys as well, or set one on the "+
					"connection afterwards.", host.alias, host.identities[0]))
		}

		if host.keepAlive > 0 {
			session.Settings = settingsJSON(map[string]any{"keepalive_seconds": host.keepAlive})
		}

		if host.proxyJump != "" {
			jumps = append(jumps, pendingJump{sessionID: session.ID, target: host.proxyJump})
		}

		byAlias[host.alias] = session.ID
		out.Payload.Sessions = append(out.Payload.Sessions, session)
	}

	// ProxyJump names an alias, so it resolves once every session exists.
	index := map[string]int{}
	for i, session := range out.Payload.Sessions {
		index[session.ID] = i
	}
	for _, jump := range jumps {
		chain, missing := resolveJumpChain(jump.target, byAlias)
		if len(missing) > 0 {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"A connection hops through %s, which is not in this config. "+
					"Those hops were left out.", strings.Join(missing, ", ")))
		}
		if len(chain) > 0 {
			out.Payload.Sessions[index[jump.sessionID]].JumpChain = chain
		}
	}

	if opts.ImportKnownHosts {
		entries, warning := readKnownHosts(fsys, path.Join(base, "known_hosts"))
		out.Payload.KnownHosts = append(out.Payload.KnownHosts, entries...)
		if warning != "" {
			out.Warnings = append(out.Warnings, warning)
		}
		if len(entries) > 0 {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"Carried %d host keys across, so you will not be asked to verify "+
					"them again.", len(entries)))
		}
	}

	out.Notes = append(out.Notes, fmt.Sprintf("Read %d hosts from the config.", len(hosts)))
	if opts.ImportKeys {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"Imported %d private keys.", len(out.Payload.Credentials)))
	}

	return out, nil
}

// parseSSHConfig reads Host blocks.
//
// Keywords are case-insensitive and may be separated by whitespace or "=",
// which is what ssh_config(5) says and what people's real files use. Anything
// this importer has no equivalent for is ignored rather than refused: a
// config full of Ciphers and ControlMaster settings is completely normal.
func parseSSHConfig(r io.Reader) (hosts []sshHost, wildcards []sshHost, warnings []string, err error) {
	scanner := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var current *sshHost
	var currentIsWildcard bool
	sawMatch := false

	flush := func() {
		if current == nil {
			return
		}
		if currentIsWildcard {
			wildcards = append(wildcards, *current)
		} else {
			hosts = append(hosts, *current)
		}
		current = nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		keyword, value := splitConfigLine(line)
		switch strings.ToLower(keyword) {
		case "host":
			flush()
			patterns := strings.Fields(value)
			if len(patterns) == 0 {
				continue
			}

			// A block can name several patterns. The first concrete one names
			// the session; the rest are aliases for the same host, and
			// importing each as its own connection would produce duplicates a
			// user then has to tidy up.
			alias := ""
			for _, pattern := range patterns {
				if !strings.ContainsAny(pattern, "*?!") {
					alias = pattern
					break
				}
			}

			if alias == "" {
				current = &sshHost{alias: strings.Join(patterns, " ")}
				currentIsWildcard = true
				continue
			}
			current = &sshHost{alias: alias}
			currentIsWildcard = false

		case "match":
			// Match blocks apply conditionally — on the local user, the
			// exec of a command, the final hostname. There is nothing to
			// evaluate them against here, and importing their settings
			// unconditionally would apply them where they do not belong.
			flush()
			current = nil
			if !sawMatch {
				warnings = append(warnings,
					"This config has Match blocks, which apply conditionally. "+
						"Their settings were not imported.")
				sawMatch = true
			}

		case "include":
			warnings = append(warnings, fmt.Sprintf(
				"This config includes %q, which was not followed. Import that "+
					"file separately if it holds hosts you need.", value))

		default:
			if current == nil {
				continue
			}
			applySSHKeyword(current, keyword, value)
		}
	}
	flush()

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, nil, warnings, fmt.Errorf("portability: read the ssh config: %w", scanErr)
	}
	return hosts, wildcards, warnings, nil
}

// splitConfigLine separates a keyword from its value.
func splitConfigLine(line string) (keyword, value string) {
	if index := strings.IndexAny(line, " \t="); index >= 0 {
		return line[:index], strings.TrimSpace(strings.TrimLeft(line[index:], " \t="))
	}
	return line, ""
}

// applySSHKeyword records the settings that have an equivalent here.
func applySSHKeyword(host *sshHost, keyword, value string) {
	value = strings.Trim(value, `"`)

	switch strings.ToLower(keyword) {
	case "hostname":
		host.hostName = value
	case "user":
		host.user = value
	case "port":
		if port, err := strconv.Atoi(value); err == nil && port > 0 && port < 65536 {
			host.port = port
		}
	case "identityfile":
		host.identities = append(host.identities, value)
	case "proxyjump":
		host.proxyJump = value
	case "serveraliveinterval":
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			host.keepAlive = seconds
		}
	}
}

// wildcardDefaults turns "Host *" settings into folder defaults.
func wildcardDefaults(wildcards []sshHost) []byte {
	values := map[string]any{}

	for _, wildcard := range wildcards {
		// Only the truly universal pattern. "Host *.internal" applies to some
		// hosts and not others, and there is no way to express that here —
		// applying it to everything would be wrong for the rest.
		if strings.TrimSpace(wildcard.alias) != "*" {
			continue
		}
		if wildcard.user != "" {
			values["username"] = wildcard.user
		}
		if wildcard.port > 0 {
			values["port"] = wildcard.port
		}
		if wildcard.keepAlive > 0 {
			values["keepalive_seconds"] = wildcard.keepAlive
		}
	}

	return settingsJSON(values)
}

// uniqueIdentities lists every key file named, once, in a stable order.
func uniqueIdentities(hosts []sshHost) []string {
	seen := map[string]bool{}
	var out []string
	for _, host := range hosts {
		for _, identity := range host.identities {
			if !seen[identity] {
				seen[identity] = true
				out = append(out, identity)
			}
		}
	}
	sort.Strings(out)
	return out
}

// maxKeyBytes bounds a private key file.
const maxKeyBytes = 1 << 20

// readIdentity reads a private key named by the config, if it is present.
//
// Paths in a config are frequently absolute or start with "~", neither of
// which means anything inside an uploaded directory. Both are reduced to a
// basename and looked for beside the config, which is where they are in
// practice.
func readIdentity(fsys fs.FS, base, identity, prefix string) (*Credential, string) {
	name := path.Base(strings.ReplaceAll(identity, `\`, "/"))
	candidate := path.Join(base, name)

	file, err := fsys.Open(candidate)
	if err != nil {
		return nil, fmt.Sprintf(
			"The key %s is named by the config but was not in what you uploaded. "+
				"Import it separately.", identity)
	}
	defer func() { _ = file.Close() }()

	material, err := io.ReadAll(io.LimitReader(file, maxKeyBytes))
	if err != nil {
		return nil, fmt.Sprintf("The key %s could not be read: %v", identity, err)
	}

	credential := Credential{
		ID:     uuid.Must(uuid.NewV7()).String(),
		Name:   fmt.Sprintf("%s: %s", prefix, name),
		Kind:   "ssh_key",
		Secret: string(material),
	}

	// The public half and fingerprint are stored in the clear so a credential
	// list renders on a locked vault, so they are worth computing now.
	signer, err := ssh.ParsePrivateKey(material)
	switch {
	case err == nil:
		credential.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		credential.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
		credential.KeyType = signer.PublicKey().Type()
		return &credential, ""

	case isPassphraseError(err):
		// An encrypted key still imports: the passphrase is asked for when it
		// is used, and refusing it here would mean leaving the key behind.
		return &credential, fmt.Sprintf(
			"The key %s is encrypted. It was imported, but its passphrase must be "+
				"set on the credential before it will connect.", name)

	default:
		return nil, fmt.Sprintf("%s is not a private key this reader understands: %v", name, err)
	}
}

func isPassphraseError(err error) bool {
	var missing *ssh.PassphraseMissingError
	if ok := asPassphraseError(err, &missing); ok {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "passphrase")
}

func asPassphraseError(err error, target **ssh.PassphraseMissingError) bool {
	e, ok := err.(*ssh.PassphraseMissingError)
	if ok {
		*target = e
	}
	return ok
}

// maxKnownHosts bounds how many entries are read.
const maxKnownHosts = 100000

// readKnownHosts reads an OpenSSH known_hosts file.
//
// Hashed entries are skipped: their hostnames cannot be recovered, and an
// entry whose host nobody can name is of no use in a list a person reads.
func readKnownHosts(fsys fs.FS, name string) ([]KnownHost, string) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, ""
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes))
	if err != nil {
		return nil, fmt.Sprintf("known_hosts could not be read: %v", err)
	}

	var (
		out    []KnownHost
		hashed int
	)

	for len(data) > 0 && len(out) < maxKnownHosts {
		_, patterns, key, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			break
		}
		data = rest

		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, "|1|") {
				hashed++
				continue
			}

			host, port := splitKnownHostPattern(pattern)
			if host == "" || strings.ContainsAny(host, "*?") {
				continue
			}

			out = append(out, KnownHost{
				Hostname:    host,
				Port:        port,
				KeyType:     key.Type(),
				Fingerprint: ssh.FingerprintSHA256(key),
				PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
			})
		}
	}

	if hashed > 0 {
		return out, fmt.Sprintf(
			"%d known_hosts entries are hashed, so their hostnames could not be "+
				"read. You will be asked to verify those hosts again.", hashed)
	}
	return out, ""
}

// splitKnownHostPattern reads the "[host]:port" form OpenSSH uses for a
// non-standard port.
func splitKnownHostPattern(pattern string) (string, int) {
	if strings.HasPrefix(pattern, "[") {
		if end := strings.Index(pattern, "]:"); end > 0 {
			host := pattern[1:end]
			if port, err := strconv.Atoi(pattern[end+2:]); err == nil {
				return host, port
			}
			return host, 22
		}
	}
	return pattern, 22
}

// resolveJumpChain turns a ProxyJump value into session identifiers.
//
// ProxyJump takes a comma-separated chain, and each element may carry its own
// user and port — "alice@bastion:2222" — which are the bastion's own settings
// and belong to the session it refers to, not to this one.
func resolveJumpChain(value string, byAlias map[string]string) (chain []string, missing []string) {
	for _, hop := range strings.Split(value, ",") {
		hop = strings.TrimSpace(hop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		if at := strings.LastIndex(hop, "@"); at >= 0 {
			hop = hop[at+1:]
		}
		if colon := strings.LastIndex(hop, ":"); colon >= 0 && !strings.Contains(hop, "]") {
			hop = hop[:colon]
		}

		if id, ok := byAlias[hop]; ok {
			chain = append(chain, id)
			continue
		}
		missing = append(missing, hop)
	}
	return chain, missing
}
