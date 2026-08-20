package portability

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Reading PuTTY, and reading a spreadsheet.
//
// PuTTY keeps sessions in the Windows registry, exported as a .reg file, or
// in ~/.putty/sessions on Unix. Both are read here. It stores no passwords at
// all — a point in its favour — so a PuTTY import brings the device list and
// nothing that needs protecting.

// PuTTYOptions control a PuTTY import.
type PuTTYOptions struct {
	// FolderName is where the imported sessions land. PuTTY has no folders,
	// so without one they would all arrive at the top level.
	FolderName string

	// KeyPassphrase is tried against every encrypted .ppk in the upload.
	// PuTTY allows a different passphrase on each key, so this opens the ones
	// it fits and the rest are reported by name rather than silently dropped.
	KeyPassphrase string
}

// FromPuTTYRegistry reads a .reg export of PuTTY's sessions.
func FromPuTTYRegistry(r io.Reader, opts PuTTYOptions) (Import, error) {
	out := newImport(SourcePuTTY)

	sessions, warnings, err := parsePuTTYRegistry(r)
	if err != nil {
		return out, err
	}
	out.Warnings = append(out.Warnings, warnings...)

	// A .reg export carries session settings only; the key files live
	// elsewhere on the machine it came from.
	buildPuTTYPayload(&out, sessions, opts, nil)
	return out, nil
}

// FromPuTTYDirectory reads ~/.putty/sessions.
func FromPuTTYDirectory(fsys fs.FS, opts PuTTYOptions) (Import, error) {
	out := newImport(SourcePuTTY)

	root := "."
	if _, err := fs.Stat(fsys, "sessions"); err == nil {
		root = "sessions"
	} else if _, err := fs.Stat(fsys, ".putty/sessions"); err == nil {
		root = ".putty/sessions"
	}

	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		out.Warnings = append(out.Warnings,
			"No sessions directory was found. Point this at your .putty directory.")
		return out, nil
	}

	var sessions []puttySession
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		file, err := fsys.Open(path.Join(root, entry.Name()))
		if err != nil {
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("%s could not be opened: %v", entry.Name(), err))
			continue
		}

		values, err := parsePuTTYFile(file)
		_ = file.Close()
		if err != nil {
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("%s could not be read: %v", entry.Name(), err))
			continue
		}

		// PuTTY percent-encodes a session name to make it a valid filename.
		name := entry.Name()
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}

		sessions = append(sessions, puttySession{name: name, values: values})
	}

	// Keys are read before the sessions are built, so a session naming a key
	// file can be joined to the key itself rather than to a warning about it.
	keys := readPuTTYKeys(fsys, opts.KeyPassphrase)
	out.Payload.Credentials = append(out.Payload.Credentials, keys.credentials...)
	out.Warnings = append(out.Warnings, keys.warnings...)
	out.Notes = append(out.Notes, keys.notes...)

	buildPuTTYPayload(&out, sessions, opts, keys.byName)
	return out, nil
}

// puttySession is one session's settings.
type puttySession struct {
	name   string
	values map[string]string
}

// maxPuTTYSessions bounds an import.
const maxPuTTYSessions = 100000

// parsePuTTYRegistry reads a Windows .reg export.
//
// The format is a series of `[key path]` headers followed by `"name"=value`
// lines, where a value is either a quoted string or `dword:0000001a`.
func parsePuTTYRegistry(r io.Reader) ([]puttySession, []string, error) {
	var (
		sessions []puttySession
		warnings []string
		current  *puttySession
	)

	scanner := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	flush := func() {
		if current != nil && len(current.values) > 0 {
			sessions = append(sessions, *current)
		}
		current = nil
	}

	sawSessions := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()

			key := strings.Trim(line, "[]")
			const marker = `\PuTTY\Sessions\`
			index := strings.Index(key, marker)
			if index < 0 {
				continue
			}
			sawSessions = true

			name := key[index+len(marker):]
			if decoded, err := url.QueryUnescape(name); err == nil {
				name = decoded
			}
			if len(sessions) >= maxPuTTYSessions {
				return nil, warnings, fmt.Errorf("portability: more than %d PuTTY sessions", maxPuTTYSessions)
			}
			current = &puttySession{name: name, values: map[string]string{}}
			continue
		}

		if current == nil {
			continue
		}

		name, value, ok := parseRegistryValue(line)
		if ok {
			current.values[name] = value
		}
	}
	flush()

	if err := scanner.Err(); err != nil {
		return nil, warnings, fmt.Errorf("portability: read the registry export: %w", err)
	}
	if !sawSessions {
		warnings = append(warnings,
			"No PuTTY sessions were found in this file. Export the key "+
				`HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions from regedit.`)
	}
	return sessions, warnings, nil
}

// parseRegistryValue reads one `"name"=value` line.
func parseRegistryValue(line string) (name, value string, ok bool) {
	if !strings.HasPrefix(line, `"`) {
		return "", "", false
	}
	closing := strings.Index(line[1:], `"`)
	if closing < 0 {
		return "", "", false
	}

	name = line[1 : 1+closing]
	rest := line[2+closing:]
	if !strings.HasPrefix(rest, "=") {
		return "", "", false
	}
	rest = rest[1:]

	switch {
	case strings.HasPrefix(rest, `"`) && strings.HasSuffix(rest, `"`) && len(rest) >= 2:
		// Registry strings escape backslashes, which matters because every
		// key path in a PuTTY session is a Windows path.
		return name, strings.ReplaceAll(rest[1:len(rest)-1], `\\`, `\`), true

	case strings.HasPrefix(rest, "dword:"):
		number, err := strconv.ParseUint(strings.TrimPrefix(rest, "dword:"), 16, 32)
		if err != nil {
			return "", "", false
		}
		return name, strconv.FormatUint(number, 10), true

	default:
		// hex: values are binary blobs — fonts, colour tables — and mean
		// nothing here.
		return "", "", false
	}
}

// parsePuTTYFile reads a Unix ~/.putty/sessions file: plain Key=Value lines.
func parsePuTTYFile(r io.Reader) (map[string]string, error) {
	values := map[string]string{}

	scanner := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		equals := strings.Index(line, "=")
		if equals <= 0 {
			continue
		}
		values[strings.TrimSpace(line[:equals])] = strings.TrimSpace(line[equals+1:])
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no settings in this file")
	}
	return values, nil
}

// buildPuTTYPayload turns parsed sessions into a payload.
func buildPuTTYPayload(out *Import, sessions []puttySession, opts PuTTYOptions, keysByName map[string]string) {
	if len(sessions) == 0 {
		return
	}

	// Stable order, so two imports of one export produce the same tree.
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].name < sessions[j].name })

	folderName := opts.FolderName
	if folderName == "" {
		folderName = "PuTTY"
	}

	folder := Folder{ID: uuid.Must(uuid.NewV7()).String(), Name: folderName}
	out.Payload.Folders = append(out.Payload.Folders, folder)

	keyFiles := map[string]bool{}

	for _, source := range sessions {
		hostname := source.values["HostName"]
		if hostname == "" {
			continue
		}

		// PuTTY accepts "user@host" in the hostname field, which is how a
		// great many saved sessions actually carry their username.
		username := source.values["UserName"]
		if at := strings.Index(hostname, "@"); at > 0 {
			if username == "" {
				username = hostname[:at]
			}
			hostname = hostname[at+1:]
		}

		port := 0
		if value, err := strconv.Atoi(source.values["PortNumber"]); err == nil {
			port = value
		}

		session := Session{
			ID:       uuid.Must(uuid.NewV7()).String(),
			FolderID: folder.ID,
			Name:     source.name,
			Protocol: puttyProtocol(source.values["Protocol"]),
			Hostname: hostname,
			Port:     port,
			Username: username,
		}

		if key := source.values["PublicKeyFile"]; key != "" {
			// PuTTY stores a Windows path. Only the filename can mean anything
			// inside an upload, which is also how the keys are indexed.
			name := strings.ToLower(key)
			if slash := strings.LastIndexAny(name, `/\`); slash >= 0 {
				name = name[slash+1:]
			}
			if id, ok := keysByName[name]; ok {
				session.CredentialID = id
			} else {
				keyFiles[key] = true
			}
		}

		if proxy := source.values["ProxyHost"]; proxy != "" {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%q went through the proxy %s, which has no direct equivalent. "+
					"Set a jump host on the connection if it needs one.", source.name, proxy))
		}

		out.Payload.Sessions = append(out.Payload.Sessions, session)
	}

	if len(keyFiles) > 0 {
		names := make([]string, 0, len(keyFiles))
		for name := range keyFiles {
			names = append(names, name)
		}
		sort.Strings(names)

		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d session%s name a key file that was not in what you uploaded (%s). "+
				"PuTTY records the path rather than the key, so add the .ppk files "+
				"to the archive and import again — they are converted for you.",
			len(keyFiles), plural(len(keyFiles)),
			strings.Join(names[:min(3, len(names))], ", ")))
	}

	out.Notes = append(out.Notes, fmt.Sprintf(
		"Read %d sessions. PuTTY stores no passwords, so there were none to bring.",
		len(out.Payload.Sessions)))
}

func puttyProtocol(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "telnet":
		return "telnet"
	case "serial":
		return "serial"
	default:
		return "ssh"
	}
}

// --- spreadsheets ------------------------------------------------------------

// CSVOptions control a CSV import.
type CSVOptions struct {
	// FolderName is where the rows land.
	FolderName string
}

// maxCSVRows bounds an import.
const maxCSVRows = 100000

// FromCSV reads a host list from a spreadsheet export.
//
// The column names are matched case-insensitively and several spellings are
// accepted for each, because this is the format people arrive with — an
// inventory somebody exported from a spreadsheet — and rejecting a file over
// "Host" versus "hostname" would be a poor greeting.
//
// A "password" column is read where it exists. Anyone who keeps device
// passwords in a spreadsheet has bigger problems than this importer, and
// getting them out of the spreadsheet and into a vault is the fix.
func FromCSV(r io.Reader, opts CSVOptions) (Import, error) {
	out := newImport(SourceCSV)

	reader := csv.NewReader(io.LimitReader(r, maxConfigBytes))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		out.Warnings = append(out.Warnings, "This file has no rows.")
		return out, nil
	}

	columns := map[string]int{}
	for i, name := range header {
		columns[normaliseColumn(name)] = i
	}

	hostColumn, ok := firstColumn(columns, "hostname", "host", "address", "ipaddress", "ip", "target")
	if !ok {
		out.Warnings = append(out.Warnings,
			"No hostname column was found. Name one of the columns Hostname, Host or Address.")
		return out, nil
	}
	nameColumn, hasName := firstColumn(columns,
		"name", "session", "sessionname", "device", "devicename",
		"displayname", "label", "title", "alias", "description")
	if !hasName {
		// Spreadsheets people actually arrive with put all sorts in this
		// column — "Switch Name", "Router name", "AP name". Anything ending
		// in "name" that is not the address column is the label.
		nameColumn, hasName = columnEndingIn(columns, "name", hostColumn)
	}
	userColumn, _ := firstColumn(columns, "username", "user", "login", "account")
	portColumn, _ := firstColumn(columns, "port")
	passwordColumn, hasPassword := firstColumn(columns, "password", "pass", "secret")
	folderColumn, _ := firstColumn(columns, "folder", "group", "site", "location")
	protocolColumn, _ := firstColumn(columns, "protocol", "proto")

	folderName := opts.FolderName
	if folderName == "" {
		folderName = "Imported"
	}

	tree := newFolderTree()
	rootID := tree.ensure([]string{folderName})

	rows := 0
	skipped := 0
	withPasswords := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("A row could not be read: %v", err))
			continue
		}
		if rows >= maxCSVRows {
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("Only the first %d rows were read.", maxCSVRows))
			break
		}

		hostname := field(record, hostColumn)
		if hostname == "" {
			skipped++
			continue
		}

		name := hostname
		if hasName {
			if value := field(record, nameColumn); value != "" {
				name = value
			}
		}

		folderID := rootID
		if value := field(record, folderColumn); value != "" {
			folderID = tree.ensure([]string{folderName, value})
		}

		port := 0
		if value, err := strconv.Atoi(field(record, portColumn)); err == nil {
			port = value
		}

		session := Session{
			ID:       uuid.Must(uuid.NewV7()).String(),
			FolderID: folderID,
			Name:     name,
			Protocol: csvProtocol(field(record, protocolColumn)),
			Hostname: hostname,
			Port:     port,
			Username: field(record, userColumn),
		}

		if hasPassword {
			if password := field(record, passwordColumn); password != "" {
				credential := Credential{
					ID:       uuid.Must(uuid.NewV7()).String(),
					Name:     fmt.Sprintf("%s: %s", folderName, name),
					Kind:     "password",
					Username: session.Username,
					Secret:   password,
				}
				out.Payload.Credentials = append(out.Payload.Credentials, credential)
				session.CredentialID = credential.ID
				withPasswords++
			}
		}

		out.Payload.Sessions = append(out.Payload.Sessions, session)
		rows++
	}

	out.Payload.Folders = tree.all()

	if skipped > 0 {
		out.Warnings = append(out.Warnings,
			fmt.Sprintf("%d rows had no hostname and were skipped.", skipped))
	}
	out.Notes = append(out.Notes, fmt.Sprintf("Read %d rows.", rows))
	if withPasswords > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d rows carried a password. Delete the spreadsheet once you have "+
				"checked the import: it is the copy nothing is protecting.", withPasswords))
	}

	return out, nil
}

func normaliseColumn(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func firstColumn(columns map[string]int, candidates ...string) (int, bool) {
	for _, candidate := range candidates {
		if index, ok := columns[candidate]; ok {
			return index, true
		}
	}
	return -1, false
}

// columnEndingIn finds a column whose header ends with suffix, other than
// exclude. Deterministic when several match, so two imports of one file agree.
func columnEndingIn(columns map[string]int, suffix string, exclude int) (int, bool) {
	best := -1
	bestName := ""

	for name, index := range columns {
		if index == exclude || !strings.HasSuffix(name, suffix) {
			continue
		}
		if best < 0 || name < bestName {
			best, bestName = index, name
		}
	}
	return best, best >= 0
}

func field(record []string, index int) string {
	if index < 0 || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func csvProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "telnet":
		return "telnet"
	case "serial":
		return "serial"
	default:
		return "ssh"
	}
}

// newImport builds an Import with every slice non-nil, so an interface
// rendering the result never has to distinguish empty from absent.
func newImport(source Source) Import {
	return Import{
		Source:   source,
		Warnings: []string{},
		Notes:    []string{},
		Payload: Payload{
			Folders: []Folder{}, Sessions: []Session{},
			Credentials: []Credential{}, KnownHosts: []KnownHost{},
		},
	}
}
