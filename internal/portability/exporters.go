package portability

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
)

// Ways back out.
//
// The bundle is the full-fidelity one and the only encrypted one. These are
// the others: a config a person can read, a file another tool can open, a
// spreadsheet somebody can put in a change record. They exist so that
// choosing bkd is not a decision anybody has to be talked out of later.
//
// Every format here except JSON and CSV is lossy — none of them can express
// a folder tree, a jump chain and an encrypted credential store at once — so
// each one says what it dropped rather than pretending otherwise.

// Format names an export format.
type Format string

const (
	// FormatBundle is the encrypted, full-fidelity one.
	FormatBundle Format = "bundle"

	// FormatSSHConfig writes an OpenSSH client config.
	FormatSSHConfig Format = "ssh_config"

	// FormatSecureCRT writes SecureCRT session files, to go back.
	FormatSecureCRT Format = "securecrt"

	// FormatPuTTY writes a Windows registry export.
	FormatPuTTY Format = "putty_reg"

	// FormatJSON writes the payload as it stands.
	FormatJSON Format = "json"

	// FormatCSV writes a host list a spreadsheet can open.
	FormatCSV Format = "csv"
)

// Plaintext reports whether a format writes secrets in the clear.
//
// The whole reason the export API gates some formats behind the vault
// passphrase, an explicit confirmation and a critical audit event.
func (f Format) Plaintext() bool {
	switch f {
	case FormatBundle:
		return false
	default:
		// Everything else is a text file somebody can read. Even the ones
		// that carry no secrets — an ssh_config has no passwords — describe
		// every device on the network, which is not nothing.
		return true
	}
}

// CarriesSecrets reports whether a format can hold passwords or keys at all.
func (f Format) CarriesSecrets() bool {
	switch f {
	case FormatBundle, FormatSecureCRT, FormatJSON, FormatCSV:
		return true
	default:
		// An ssh_config names a key file rather than holding one, and PuTTY
		// stores no passwords.
		return false
	}
}

// Filename suggests a name for a downloaded export.
func (f Format) Filename() string {
	switch f {
	case FormatBundle:
		return "connections.bkbundle"
	case FormatSSHConfig:
		return "ssh_config"
	case FormatSecureCRT:
		return "securecrt-sessions.txt"
	case FormatPuTTY:
		return "putty-sessions.reg"
	case FormatJSON:
		return "connections.json"
	case FormatCSV:
		return "connections.csv"
	default:
		return "export.txt"
	}
}

// ExportOptions control a plaintext export.
type ExportOptions struct {
	// IncludeSecrets writes passwords into the formats that can hold them.
	IncludeSecrets bool
}

// ExportResult reports what an export left behind.
type ExportResult struct {
	// Warnings name what the format could not express.
	Warnings []string
}

// Export writes a payload in one of the plaintext formats.
//
// FormatBundle is not handled here: it needs a passphrase and goes through
// Write, which is a different shape for a reason — everything in this
// function produces something readable.
func Export(w io.Writer, payload Payload, format Format, opts ExportOptions) (ExportResult, error) {
	switch format {
	case FormatSSHConfig:
		return exportSSHConfig(w, payload)
	case FormatSecureCRT:
		return exportSecureCRT(w, payload, opts)
	case FormatPuTTY:
		return exportPuTTY(w, payload)
	case FormatJSON:
		return exportJSON(w, payload, opts)
	case FormatCSV:
		return exportCSV(w, payload, opts)
	case FormatBundle:
		return ExportResult{}, fmt.Errorf("portability: a bundle needs a passphrase; use Write")
	default:
		return ExportResult{}, fmt.Errorf("portability: unknown export format %q", format)
	}
}

// pathOf renders a session's folder path, outermost first.
func pathOf(session Session, folders map[string]Folder) []string {
	var parts []string
	seen := map[string]bool{}

	for id := session.FolderID; id != ""; {
		folder, ok := folders[id]
		if !ok || seen[id] {
			break
		}
		seen[id] = true
		parts = append([]string{folder.Name}, parts...)
		id = folder.ParentID
	}
	return parts
}

func folderIndex(payload Payload) map[string]Folder {
	out := make(map[string]Folder, len(payload.Folders))
	for _, folder := range payload.Folders {
		out[folder.ID] = folder
	}
	return out
}

func credentialIndex(payload Payload) map[string]Credential {
	out := make(map[string]Credential, len(payload.Credentials))
	for _, cred := range payload.Credentials {
		out[cred.ID] = cred
	}
	return out
}

func sessionIndex(payload Payload) map[string]Session {
	out := make(map[string]Session, len(payload.Sessions))
	for _, session := range payload.Sessions {
		out[session.ID] = session
	}
	return out
}

// sortedSessions returns sessions in a stable, human order: by folder path
// then by name, so two exports of one tree are identical files.
func sortedSessions(payload Payload) []Session {
	folders := folderIndex(payload)

	out := append([]Session{}, payload.Sessions...)
	sort.SliceStable(out, func(i, j int) bool {
		left := strings.Join(pathOf(out[i], folders), "/")
		right := strings.Join(pathOf(out[j], folders), "/")
		if left != right {
			return left < right
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// exportSSHConfig writes an OpenSSH client configuration.
func exportSSHConfig(w io.Writer, payload Payload) (ExportResult, error) {
	var result ExportResult

	folders := folderIndex(payload)
	sessions := sessionIndex(payload)
	credentials := credentialIndex(payload)

	if _, err := fmt.Fprint(w,
		"# Exported from bkd.\n"+
			"#\n"+
			"# An ssh_config names a key file rather than carrying one, and has no\n"+
			"# way to express a password at all, so nothing secret is in this file.\n"+
			"# Export the keys separately and point IdentityFile at where you put\n"+
			"# them.\n\n"); err != nil {
		return result, err
	}

	var (
		usedNames  = map[string]bool{}
		neededKeys = map[string]bool{}
		telnet     int
	)

	for _, session := range sortedSessions(payload) {
		if session.Protocol != "" && session.Protocol != "ssh" {
			telnet++
			continue
		}

		alias := sshAlias(session, folders, usedNames)

		if _, err := fmt.Fprintf(w, "Host %s\n", alias); err != nil {
			return result, err
		}
		if _, err := fmt.Fprintf(w, "    HostName %s\n", session.Hostname); err != nil {
			return result, err
		}
		if session.Username != "" {
			if _, err := fmt.Fprintf(w, "    User %s\n", session.Username); err != nil {
				return result, err
			}
		}
		// The effective port, not the column: ssh_config has no folder
		// defaults, so a connection inheriting 8022 has to be written as 8022
		// or the exported file reaches the wrong port.
		if port := session.DialPort(); port > 0 && port != 22 {
			if _, err := fmt.Fprintf(w, "    Port %d\n", port); err != nil {
				return result, err
			}
		}

		if cred, ok := credentials[session.CredentialID]; ok && cred.Kind == "ssh_key" {
			neededKeys[cred.Name] = true
			if _, err := fmt.Fprintf(w, "    IdentityFile ~/.ssh/%s\n", keyFilename(cred)); err != nil {
				return result, err
			}
		}

		// ProxyJump takes aliases, so the chain has to name the sessions it
		// hops through by the alias they were given above.
		var hops []string
		for _, hop := range session.JumpChain {
			if target, ok := sessions[hop]; ok {
				hops = append(hops, sshAlias(target, folders, map[string]bool{}))
			}
		}
		if len(hops) > 0 {
			if _, err := fmt.Fprintf(w, "    ProxyJump %s\n", strings.Join(hops, ",")); err != nil {
				return result, err
			}
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return result, err
		}
	}

	if telnet > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d connections are not SSH and have no place in an ssh_config. "+
				"They were left out.", telnet))
	}
	if len(neededKeys) > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"This config points at %d key files that are not in it. Export the "+
				"credentials separately and put them where IdentityFile says.",
			len(neededKeys)))
	}
	if len(payload.Credentials) > 0 {
		result.Warnings = append(result.Warnings,
			"Passwords cannot be expressed in an ssh_config and were left out.")
	}

	return result, nil
}

// sshAlias makes a Host alias out of a session's name and folder path.
//
// Aliases cannot contain whitespace and are typed by hand, so a device called
// "Core Switch 01" in "Edge routers/London" becomes "core-switch-01" rather
// than something nobody could use.
func sshAlias(session Session, folders map[string]Folder, used map[string]bool) string {
	base := slug(session.Name)
	if base == "" {
		base = slug(session.Hostname)
	}
	if base == "" {
		base = "host"
	}

	if !used[base] {
		used[base] = true
		return base
	}

	// A collision: qualify with the folder path, which is what made them
	// different in the tree.
	qualified := base
	if path := pathOf(session, folders); len(path) > 0 {
		qualified = slug(path[len(path)-1]) + "-" + base
	}
	for i := 2; used[qualified]; i++ {
		qualified = fmt.Sprintf("%s-%d", base, i)
	}
	used[qualified] = true
	return qualified
}

// slug reduces a name to something typable on a command line.
func slug(name string) string {
	var b strings.Builder
	lastDash := true

	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteRune('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// keyFilename suggests where a credential's key would live on disk.
func keyFilename(cred Credential) string {
	name := slug(cred.Name)
	if name == "" {
		name = "id_key"
	}
	return name
}

// exportSecureCRT writes session files SecureCRT can read.
//
// One file per session would be a directory rather than a download, so they
// are concatenated with a header naming each one's path. The migration guide
// explains how to split them; a person going back to SecureCRT is doing
// something deliberate and can follow two lines of instruction.
func exportSecureCRT(w io.Writer, payload Payload, opts ExportOptions) (ExportResult, error) {
	var result ExportResult

	folders := folderIndex(payload)
	credentials := credentialIndex(payload)

	if _, err := fmt.Fprint(w,
		"; Exported from bkd, in SecureCRT's session format.\n"+
			";\n"+
			"; Each block below is one .ini file. Create it at the path in its\n"+
			"; header, under your SecureCRT Config/Sessions folder.\n"); err != nil {
		return result, err
	}
	if opts.IncludeSecrets {
		if _, err := fmt.Fprint(w,
			";\n"+
				"; This file contains passwords, obfuscated the way SecureCRT\n"+
				"; obfuscates them — which is to say, not protected. The key is a\n"+
				"; constant anyone can extract. Treat this file as plaintext.\n"); err != nil {
			return result, err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return result, err
	}

	var failed int

	for _, session := range sortedSessions(payload) {
		path := append(pathOf(session, folders), session.Name+".ini")

		if _, err := fmt.Fprintf(w, "; ---- %s ----\n", strings.Join(path, "/")); err != nil {
			return result, err
		}

		protocol := "SSH2"
		switch session.Protocol {
		case "telnet":
			protocol = "Telnet"
		case "serial":
			protocol = "Serial"
		}

		if _, err := fmt.Fprintf(w, "S:\"Protocol Name\"=%s\n", protocol); err != nil {
			return result, err
		}
		if _, err := fmt.Fprintf(w, "S:\"Hostname\"=%s\n", session.Hostname); err != nil {
			return result, err
		}
		if session.Username != "" {
			if _, err := fmt.Fprintf(w, "S:\"Username\"=%s\n", session.Username); err != nil {
				return result, err
			}
		}
		if port := session.DialPort(); port > 0 {
			key := "[SSH2] Port"
			if session.Protocol == "telnet" {
				key = "[TELNET] Port"
			}
			if _, err := fmt.Fprintf(w, "D:\"%s\"=%08x\n", key, port); err != nil {
				return result, err
			}
		}

		if opts.IncludeSecrets {
			if cred, ok := credentials[session.CredentialID]; ok && cred.Secret != "" {
				if cred.Kind == "ssh_key" {
					failed++
				} else {
					encoded, err := securecrt.EncryptV2(cred.Secret, "")
					if err != nil {
						failed++
					} else if _, err := fmt.Fprintf(w, "S:\"Password V2\"=%s\n", encoded); err != nil {
						return result, err
					}
				}
			}
		}

		if _, err := fmt.Fprintln(w); err != nil {
			return result, err
		}
	}

	if failed > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d connections use an SSH key. SecureCRT stores the path to a key "+
				"rather than the key, so those were left without a credential.", failed))
	}
	if opts.IncludeSecrets {
		result.Warnings = append(result.Warnings,
			"The passwords in this file are obfuscated with a key that is a "+
				"published constant. Anyone who obtains the file has them.")
	}
	if len(payload.KnownHosts) > 0 {
		result.Warnings = append(result.Warnings,
			"Accepted host keys have no equivalent in a session file and were "+
				"left out. SecureCRT will ask about each host again.")
	}

	return result, nil
}

// exportPuTTY writes a Windows registry file.
func exportPuTTY(w io.Writer, payload Payload) (ExportResult, error) {
	var result ExportResult

	if _, err := fmt.Fprint(w, "Windows Registry Editor Version 5.00\r\n\r\n"); err != nil {
		return result, err
	}

	used := map[string]bool{}
	folders := folderIndex(payload)
	serial := 0

	for _, session := range sortedSessions(payload) {
		if session.Protocol == "serial" {
			serial++
			continue
		}

		// PuTTY has no folders, so the path becomes part of the name — which
		// is what a user with a folder tree would otherwise lose entirely.
		name := session.Name
		if path := pathOf(session, folders); len(path) > 0 {
			name = strings.Join(path, " - ") + " - " + name
		}
		for used[name] {
			name += " (2)"
		}
		used[name] = true

		protocol := "ssh"
		if session.Protocol == "telnet" {
			protocol = "telnet"
		}

		port := session.DialPort()
		if port == 0 {
			port = 22
			if protocol == "telnet" {
				port = 23
			}
		}

		if _, err := fmt.Fprintf(w,
			"[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\%s]\r\n",
			url.QueryEscape(name)); err != nil {
			return result, err
		}
		if _, err := fmt.Fprintf(w, "\"HostName\"=\"%s\"\r\n", registryString(session.Hostname)); err != nil {
			return result, err
		}
		if _, err := fmt.Fprintf(w, "\"PortNumber\"=dword:%08x\r\n", port); err != nil {
			return result, err
		}
		if _, err := fmt.Fprintf(w, "\"Protocol\"=\"%s\"\r\n", protocol); err != nil {
			return result, err
		}
		if session.Username != "" {
			if _, err := fmt.Fprintf(w, "\"UserName\"=\"%s\"\r\n", registryString(session.Username)); err != nil {
				return result, err
			}
		}
		if _, err := fmt.Fprint(w, "\r\n"); err != nil {
			return result, err
		}
	}

	if serial > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d serial connections were left out: they need port settings this "+
				"export cannot infer.", serial))
	}
	if len(payload.Credentials) > 0 {
		result.Warnings = append(result.Warnings,
			"PuTTY stores no passwords and reads keys only in its own .ppk "+
				"format, so no credentials are in this file.")
	}
	result.Warnings = append(result.Warnings,
		"PuTTY has no folders. Folder names were folded into each session's "+
			"name so the structure is at least readable.")

	return result, nil
}

// registryString escapes a value for a .reg file.
func registryString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	// A newline in a registry string would end the line and turn the rest
	// into what looks like another value.
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

// exportJSON writes the payload as it stands.
func exportJSON(w io.Writer, payload Payload, opts ExportOptions) (ExportResult, error) {
	var result ExportResult

	if !opts.IncludeSecrets {
		payload = withoutSecrets(payload)
	} else {
		result.Warnings = append(result.Warnings,
			"This file contains private keys and passwords in the clear. Nothing "+
				"protects it but where you put it.")
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return result, fmt.Errorf("portability: write JSON: %w", err)
	}
	return result, nil
}

// exportCSV writes a host list.
func exportCSV(w io.Writer, payload Payload, opts ExportOptions) (ExportResult, error) {
	var result ExportResult

	folders := folderIndex(payload)
	credentials := credentialIndex(payload)

	writer := csv.NewWriter(w)
	header := []string{"Name", "Folder", "Protocol", "Hostname", "Port", "Username", "Credential"}
	if opts.IncludeSecrets {
		header = append(header, "Password")
	}
	if err := writer.Write(header); err != nil {
		return result, err
	}

	var keys int

	for _, session := range sortedSessions(payload) {
		cred := credentials[session.CredentialID]

		port := ""
		if session.DialPort() > 0 {
			port = fmt.Sprint(session.DialPort())
		}

		record := []string{
			session.Name,
			strings.Join(pathOf(session, folders), "/"),
			session.Protocol,
			session.Hostname,
			port,
			session.Username,
			cred.Name,
		}

		if opts.IncludeSecrets {
			// A key is thousands of characters of PEM and belongs in no
			// spreadsheet; the column says so rather than producing a cell
			// nothing can display.
			switch {
			case cred.Kind == "ssh_key" && cred.Secret != "":
				keys++
				record = append(record, "(SSH key — export as a bundle or JSON)")
			default:
				record = append(record, cred.Secret)
			}
		}

		if err := writer.Write(record); err != nil {
			return result, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return result, fmt.Errorf("portability: write CSV: %w", err)
	}

	if opts.IncludeSecrets {
		result.Warnings = append(result.Warnings,
			"This spreadsheet contains passwords in the clear.")
	}
	if keys > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d connections use an SSH key, which cannot go in a spreadsheet. "+
				"Use a bundle or JSON for those.", keys))
	}
	if len(payload.KnownHosts) > 0 {
		result.Warnings = append(result.Warnings,
			"Accepted host keys are not in this file.")
	}

	return result, nil
}

// withoutSecrets strips key material and passwords from a payload.
func withoutSecrets(payload Payload) Payload {
	out := payload
	out.Credentials = make([]Credential, 0, len(payload.Credentials))

	for _, cred := range payload.Credentials {
		cred.Secret = ""
		cred.Extra = ""
		out.Credentials = append(out.Credentials, cred)
	}
	return out
}
