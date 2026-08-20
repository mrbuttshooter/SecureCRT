package securecrt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// SecureCRT's session files are INI-ish rather than INI: every line is
//
//	<type>:"<key>"=<value>
//
// where the type letter says how to read the value — S for a string, D for a
// 32-bit number written as eight hex digits, B for a boolean, Z for a binary
// blob. There are no sections.
//
// The parser below is deliberately forgiving. It reads the lines it
// recognises and ignores everything else, because a session file carries
// dozens of appearance and emulation settings that mean nothing here, and
// because the format has accumulated keys across two decades of releases. A
// strict parser would fail on somebody's real configuration over a font.

// Entry is one parsed line.
type Entry struct {
	Type  string
	Key   string
	Value string
}

// File is a parsed session file, in order and indexed by key.
type File struct {
	Entries []Entry

	byKey map[string]Entry
}

// Get returns a value by key.
func (f *File) Get(key string) (Entry, bool) {
	entry, ok := f.byKey[key]
	return entry, ok
}

// String returns a string value, or the fallback.
func (f *File) String(key, fallback string) string {
	if entry, ok := f.byKey[key]; ok && entry.Value != "" {
		return entry.Value
	}
	return fallback
}

// Number returns a D-typed value.
//
// SecureCRT writes these as eight hexadecimal digits. A decimal fallback is
// accepted too, because hand-edited files exist and refusing one over a
// number written the obvious way would be needlessly strict.
func (f *File) Number(key string, fallback int) int {
	entry, ok := f.byKey[key]
	if !ok || entry.Value == "" {
		return fallback
	}
	if value, err := strconv.ParseUint(entry.Value, 16, 32); err == nil {
		return int(value)
	}
	if value, err := strconv.Atoi(entry.Value); err == nil {
		return value
	}
	return fallback
}

// utf8BOM is what a session file saved on Windows begins with.
//
// Written as an escape rather than the character itself: a byte order mark
// sitting in the middle of a Go source file is a compile error, and one that
// took a moment to recognise.
const utf8BOM = "\uFEFF"

// maxLineBytes bounds one line of a session file.
//
// Session files contain base64 blobs for fonts and colour schemes, so the
// bound is generous; it exists so a file that is not a session file at all
// cannot be read into memory a gigabyte at a time.
const maxLineBytes = 1 << 20

// maxEntries bounds how many lines are kept from one file.
const maxEntries = 10000

// ParseFile reads a SecureCRT session file.
func ParseFile(r io.Reader) (*File, error) {
	file := &File{byKey: map[string]Entry{}}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), utf8BOM))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		entry, ok := parseLine(line)
		if !ok {
			continue
		}

		if len(file.Entries) >= maxEntries {
			return nil, fmt.Errorf("securecrt: file has more than %d entries", maxEntries)
		}

		file.Entries = append(file.Entries, entry)
		// First wins. SecureCRT does not normally repeat a key, and if a
		// hand-edited file does, taking the first matches how the format
		// reads top to bottom.
		if _, seen := file.byKey[entry.Key]; !seen {
			file.byKey[entry.Key] = entry
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("securecrt: read session file: %w", err)
	}
	if len(file.Entries) == 0 {
		return nil, errors.New("securecrt: no recognisable settings in this file")
	}
	return file, nil
}

// parseLine reads one `<type>:"<key>"=<value>` line.
func parseLine(line string) (Entry, bool) {
	colon := strings.Index(line, ":")
	if colon <= 0 || colon > 2 {
		return Entry{}, false
	}

	rest := line[colon+1:]
	if !strings.HasPrefix(rest, `"`) {
		return Entry{}, false
	}

	closing := strings.Index(rest[1:], `"`)
	if closing < 0 {
		return Entry{}, false
	}

	key := rest[1 : 1+closing]
	remainder := rest[2+closing:]
	if !strings.HasPrefix(remainder, "=") {
		return Entry{}, false
	}

	return Entry{
		Type:  line[:colon],
		Key:   key,
		Value: strings.TrimSpace(remainder[1:]),
	}, true
}

// Session is one SecureCRT session, read into terms bkd understands.
type Session struct {
	// Path is where it came from, relative to the Sessions directory, so a
	// preview can show the user their own folder structure.
	Path string

	// Folders is Path split into the tree it belongs in.
	Folders []string

	Name     string
	Protocol string
	Hostname string
	Port     int
	Username string

	// Password is the decoded password, when there was one and it decoded.
	Password string

	// HasPassword reports that the file carried one, whether or not it
	// decoded. The difference matters: a session that had a password and
	// lost it in translation is something the user must be told about, not
	// something to silently treat as passwordless.
	HasPassword bool

	// PasswordError explains why a stored password did not decode.
	PasswordError string

	// IdentityFile is the private key path SecureCRT was configured with.
	// The key itself lives outside the configuration, so this is a
	// breadcrumb for the user rather than something that can be imported on
	// its own.
	IdentityFile string

	// FirewallName is SecureCRT's jump-host setting. "Session:name" refers
	// to another session; anything else is a firewall defined globally.
	FirewallName string

	// Emulation and Scrollback are carried across where they map cleanly.
	Emulation  string
	Scrollback int
}

// JumpSession returns the session this one hops through, if any.
func (s Session) JumpSession() string {
	const prefix = "Session:"
	if strings.HasPrefix(s.FirewallName, prefix) {
		return strings.TrimPrefix(s.FirewallName, prefix)
	}
	return ""
}

// ReadOptions control a read.
type ReadOptions struct {
	// ConfigPassphrase is SecureCRT's "Configuration Passphrase", when the
	// user set one. Off by default in SecureCRT, so usually empty.
	ConfigPassphrase string

	// SkipPasswords reads the tree without decoding any password, for a user
	// who wants their device list and nothing else.
	SkipPasswords bool
}

// ReadSession turns one parsed file into a Session.
func ReadSession(file *File, relativePath string, opts ReadOptions) Session {
	name := strings.TrimSuffix(path.Base(relativePath), ".ini")

	var folders []string
	if dir := path.Dir(relativePath); dir != "." && dir != "/" && dir != "" {
		for _, part := range strings.Split(dir, "/") {
			if part != "" {
				folders = append(folders, part)
			}
		}
	}

	session := Session{
		Path:         relativePath,
		Folders:      folders,
		Name:         name,
		Protocol:     protocolFrom(file.String("Protocol Name", "SSH2")),
		Hostname:     file.String("Hostname", ""),
		Username:     file.String("Username", ""),
		IdentityFile: file.String("Identity Filename V2", file.String("Identity Filename", "")),
		FirewallName: file.String("Firewall Name", ""),
		Emulation:    file.String("Emulation", ""),
		Scrollback:   file.Number("Scrollback", 0),
	}

	session.Port = portFrom(file, session.Protocol)

	if !opts.SkipPasswords {
		readPassword(file, &session, opts.ConfigPassphrase)
	} else if _, ok := file.Get("Password V2"); ok {
		session.HasPassword = true
	} else if _, ok := file.Get("Password"); ok {
		session.HasPassword = true
	}

	return session
}

// readPassword decodes whichever password format the file carries.
func readPassword(file *File, session *Session, configPassphrase string) {
	if entry, ok := file.Get("Password V2"); ok && entry.Value != "" {
		session.HasPassword = true

		password, err := DecryptV2(entry.Value, configPassphrase)
		if err != nil {
			session.PasswordError = describePasswordError(err, configPassphrase)
			return
		}
		session.Password = password
		return
	}

	if entry, ok := file.Get("Password"); ok && entry.Value != "" {
		session.HasPassword = true

		password, err := DecryptLegacy(entry.Value)
		if err != nil {
			session.PasswordError = describePasswordError(err, configPassphrase)
			return
		}
		session.Password = password
	}
}

// describePasswordError writes the failure for somebody who has to act on it.
func describePasswordError(err error, configPassphrase string) string {
	switch {
	case errors.Is(err, ErrWrongConfigPassphrase):
		if configPassphrase == "" {
			return "This password is protected by a SecureCRT configuration passphrase. " +
				"Supply it and import again."
		}
		return "That configuration passphrase did not decode this password."
	case errors.Is(err, ErrNotEncrypted):
		return "The stored password is not in a format this reader recognises."
	default:
		return "The stored password could not be decoded."
	}
}

// protocolFrom maps SecureCRT's protocol names onto bkd's.
func protocolFrom(name string) string {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SSH2", "SSH1":
		return "ssh"
	case "TELNET", "TELNET/SSL":
		return "telnet"
	case "SERIAL":
		return "serial"
	default:
		// Anything else — RLogin, TAPI, raw — has no equivalent here. It
		// imports as SSH so the host and username are not lost, and the
		// importer warns about it rather than dropping the session.
		return "ssh"
	}
}

// portFrom reads the port for whichever protocol the session uses.
//
// SecureCRT keys the port by protocol, so a session that was SSH and is now
// Telnet still carries both — reading the wrong one gives a plausible number
// for the wrong service.
func portFrom(file *File, protocol string) int {
	switch protocol {
	case "telnet":
		if port := file.Number("[TELNET] Port", 0); port > 0 {
			return port
		}
	case "ssh":
		if port := file.Number("[SSH2] Port", 0); port > 0 {
			return port
		}
		if port := file.Number("[SSH1] Port", 0); port > 0 {
			return port
		}
	}
	return file.Number("Port", 0)
}

// Result is everything read from a configuration directory.
type Result struct {
	Sessions []Session

	// Warnings are files that could not be read, and sessions that lost
	// something in translation.
	Warnings []string
}

// PasswordsRecovered reports how many sessions carried a password and got it.
//
// The number the migration guide tells a user to check: it is what turns "the
// import said it worked" into something they can verify.
func (r Result) PasswordsRecovered() (recovered, stored int) {
	for _, session := range r.Sessions {
		if session.HasPassword {
			stored++
			if session.Password != "" {
				recovered++
			}
		}
	}
	return recovered, stored
}

// maxSessions bounds how many session files are read from one directory tree.
const maxSessions = 100000

// ReadDirectory walks a SecureCRT configuration and reads every session in it.
//
// root may be the configuration folder itself or the Sessions directory
// inside it; both are accepted because users describe their configuration as
// either, and getting it wrong is a needless failure.
func ReadDirectory(fsys fs.FS, opts ReadOptions) (Result, error) {
	root := "."
	if _, err := fs.Stat(fsys, "Sessions"); err == nil {
		root = "Sessions"
	}

	var result Result

	err := fs.WalkDir(fsys, root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s could not be read: %v", name, err))
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.EqualFold(path.Ext(name), ".ini") {
			return nil
		}

		relative := strings.TrimPrefix(strings.TrimPrefix(name, root), "/")

		// SecureCRT's own bookkeeping files sit alongside the sessions and
		// are not sessions themselves.
		base := path.Base(relative)
		if strings.EqualFold(base, "__FolderData__.ini") {
			return nil
		}

		file, err := fsys.Open(name)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s could not be opened: %v", relative, err))
			return nil
		}
		defer func() { _ = file.Close() }()

		parsed, err := ParseFile(file)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s is not a session file: %v", relative, err))
			return nil
		}

		session := ReadSession(parsed, relative, opts)

		// A file with no hostname is a template or a default, not a session
		// anybody can connect with.
		if session.Hostname == "" {
			return nil
		}

		if len(result.Sessions) >= maxSessions {
			return fmt.Errorf("securecrt: more than %d sessions", maxSessions)
		}
		result.Sessions = append(result.Sessions, session)

		if session.PasswordError != "" {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s: %s", session.Name, session.PasswordError))
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	return result, nil
}
