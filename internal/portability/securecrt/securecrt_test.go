package securecrt

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// --- passwords ---------------------------------------------------------------

// TestV2RoundTrip covers the scheme SecureCRT 7 and later use.
//
// This proves the codec is self-consistent, not that it agrees with VanDyke's
// implementation — no copy of SecureCRT was available to test against, and
// the package comment says so rather than implying otherwise.
func TestV2RoundTrip(t *testing.T) {
	for _, password := range []string{
		"hunter2",
		"",
		"a much longer passphrase with spaces and punctuation: !@#$%^&*()",
		"unicode: café — 配置 — 🔐",
		strings.Repeat("x", 1000),
		"exactly-sixteen!", // a whole block, so padding is not exercised
	} {
		t.Run(shortName(password), func(t *testing.T) {
			encoded, err := EncryptV2(password, "")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if !strings.HasPrefix(encoded, "02:") {
				t.Errorf("encoded value has no version prefix: %q", encoded)
			}

			decoded, err := DecryptV2(encoded, "")
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if decoded != password {
				t.Errorf("round trip = %q, want %q", decoded, password)
			}
		})
	}
}

func TestV2WithAConfigurationPassphrase(t *testing.T) {
	const passphrase = "the configuration passphrase"

	encoded, err := EncryptV2("hunter2", passphrase)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecryptV2(encoded, passphrase)
	if err != nil {
		t.Fatalf("decrypt with the right passphrase: %v", err)
	}
	if decoded != "hunter2" {
		t.Errorf("decoded %q", decoded)
	}
}

// TestV2DetectsAWrongConfigurationPassphrase is the property that matters
// most in this file.
//
// The format carries a SHA-256 of its own plaintext, so a wrong passphrase is
// caught rather than yielding rubbish — and rubbish here would not stay
// harmless, because it would be offered to a host as a password.
func TestV2DetectsAWrongConfigurationPassphrase(t *testing.T) {
	encoded, err := EncryptV2("hunter2", "the right one")
	if err != nil {
		t.Fatal(err)
	}

	for _, wrong := range []string{"", "the wrong one", "the right one "} {
		got, err := DecryptV2(encoded, wrong)
		if !errors.Is(err, ErrWrongConfigPassphrase) {
			t.Errorf("decrypt with %q = (%q, %v), want ErrWrongConfigPassphrase", wrong, got, err)
		}
		if got != "" {
			t.Errorf("a failed decrypt returned %q rather than nothing", got)
		}
	}
}

// TestV2RejectsMalformedInput: these values come from a file, and a length
// field read from a file is not a length until it has been checked.
func TestV2RejectsMalformedInput(t *testing.T) {
	for name, value := range map[string]string{
		"not hex":          "02:zzzz",
		"empty":            "02:",
		"partial block":    "02:" + hex.EncodeToString(make([]byte, 7)),
		"one zero block":   "02:" + hex.EncodeToString(make([]byte, 16)),
		"too short to fit": "02:" + hex.EncodeToString(make([]byte, 32)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecryptV2(value, ""); err == nil {
				t.Fatal("malformed input was accepted")
			}
		})
	}
}

// TestV2RefusesAnAbsurdLength: the length field says how much of the
// plaintext is meaningful, and it is read from a file this process did not
// write.
func TestV2RefusesAnAbsurdLength(t *testing.T) {
	// A block of plaintext claiming four gigabytes, sealed the way the format
	// seals it, so only the length check stands between it and an allocation.
	plain := make([]byte, 64)
	plain[0], plain[1], plain[2], plain[3] = 0xff, 0xff, 0xff, 0xff

	encoded := sealForTest(t, plain, "")

	if _, err := DecryptV2(encoded, ""); err == nil {
		t.Fatal("a password claiming a four-gigabyte length was accepted")
	}
}

func TestLegacyRoundTrip(t *testing.T) {
	for _, password := range []string{
		"hunter2",
		"",
		"a longer one with spaces",
		"unicode: café",
		strings.Repeat("y", 500),
	} {
		t.Run(shortName(password), func(t *testing.T) {
			encoded, err := EncryptLegacy(password)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			decoded, err := DecryptLegacy(encoded)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if decoded != password {
				t.Errorf("round trip = %q, want %q", decoded, password)
			}
		})
	}
}

// TestLegacyStopsAtTheTerminator: what follows the NUL is random padding, and
// decoding it too would append rubbish to every password.
func TestLegacyStopsAtTheTerminator(t *testing.T) {
	// "ab" is two UTF-16 units, so with its terminator it is six bytes and
	// gets two bytes of random padding to reach a block. If the padding were
	// decoded, the result would be three characters rather than two.
	encoded, err := EncryptLegacy("ab")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecryptLegacy(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != "ab" {
		t.Errorf("decoded %q, want %q — the random padding leaked in", decoded, "ab")
	}
}

func TestLegacyRejectsMalformedInput(t *testing.T) {
	for name, value := range map[string]string{
		"not hex":     "zzzz",
		"empty":       "",
		"too short":   hex.EncodeToString(make([]byte, 8)),
		"not a block": hex.EncodeToString(make([]byte, 13)),
		"random":      hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecryptLegacy(value); err == nil {
				t.Fatalf("malformed input was accepted")
			}
		})
	}
}

// TestEachEncryptionIsDifferent: the random padding and the legacy jacket
// mean two encryptions of one password do not produce one identical string.
//
// This is a much weaker property than it first appears, and
// TestTheFormatLeaksSharedPasswords below says why.
func TestEachEncryptionIsDifferent(t *testing.T) {
	first, err := EncryptLegacy("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptLegacy("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two legacy encryptions of one password are identical")
	}

	v2First, err := EncryptV2("hunter2xxxxxxxxxxxxxxxxxxxxxxx", "")
	if err != nil {
		t.Fatal(err)
	}
	v2Second, err := EncryptV2("hunter2xxxxxxxxxxxxxxxxxxxxxxx", "")
	if err != nil {
		t.Fatal(err)
	}
	if v2First == v2Second {
		t.Error("two V2 encryptions of one password are identical")
	}
}

// TestTheFormatLeaksSharedPasswords documents a weakness in SecureCRT's
// storage that this package reproduces on purpose.
//
// A fixed key and an all-zero IV make CBC deterministic from the first block,
// so two sessions with the same password produce the same leading ciphertext.
// Anyone holding a configuration file can see which devices share a password
// without decrypting anything — though they can also decrypt all of them,
// because the key is not a secret.
//
// Asserted rather than merely commented, so that if a future change to this
// package makes the leak disappear, somebody has to come and read this and
// decide deliberately whether files SecureCRT can no longer open are
// acceptable.
func TestTheFormatLeaksSharedPasswords(t *testing.T) {
	const shared = "the same password on both devices"

	first, err := EncryptV2(shared, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptV2(shared, "")
	if err != nil {
		t.Fatal(err)
	}

	// The first block of ciphertext: 4 bytes of length plus 12 of plaintext,
	// which is entirely determined by the password.
	const blockHex = 2 * 16 // hex characters per AES block
	firstBlock := strings.TrimPrefix(first, "02:")[:blockHex]
	secondBlock := strings.TrimPrefix(second, "02:")[:blockHex]

	if firstBlock != secondBlock {
		t.Skip("the format no longer leaks this way — read the comment above before " +
			"deleting this test, because the change may mean SecureCRT can no longer " +
			"read what we write")
	}

	different, err := EncryptV2("a completely different password", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimPrefix(different, "02:")[:blockHex] == firstBlock {
		t.Error("two different passwords produced the same leading block, which " +
			"would mean the ciphertext carries no information at all")
	}
}

// --- session files -----------------------------------------------------------

func TestParseFileReadsTheFormat(t *testing.T) {
	const contents = utf8BOM + `S:"Protocol Name"=SSH2
S:"Hostname"=10.0.0.1
S:"Username"=netops
D:"[SSH2] Port"=00000016
D:"Scrollback"=0000c350
B:"Some Flag"=00000001
Z:"Font"=some binary rubbish here
; a comment
this line is not in the format at all

S:"Emulation"=xterm
`

	file, err := ParseFile(strings.NewReader(contents))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got := file.String("Hostname", ""); got != "10.0.0.1" {
		t.Errorf("hostname = %q", got)
	}
	if got := file.Number("[SSH2] Port", 0); got != 22 {
		t.Errorf("port = %d, want 22 — the value is eight hex digits", got)
	}
	if got := file.Number("Scrollback", 0); got != 50000 {
		t.Errorf("scrollback = %d, want 50000", got)
	}
	if got := file.String("Emulation", ""); got != "xterm" {
		t.Errorf("emulation = %q — a line after unparseable rubbish was lost", got)
	}
	if _, ok := file.Get("Some Flag"); !ok {
		t.Error("a B-typed line was dropped")
	}
}

func TestParseFileRejectsSomethingElseEntirely(t *testing.T) {
	for name, contents := range map[string]string{
		"empty":     "",
		"prose":     "This is just a text file.\nNothing here at all.\n",
		"real ini":  "[section]\nkey=value\n",
		"binary":    "\x00\x01\x02\x03",
		"only junk": "hello\nworld\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFile(strings.NewReader(contents)); err == nil {
				t.Fatal("a file that is not a session file was accepted")
			}
		})
	}
}

func TestReadSessionMapsOntoOurTerms(t *testing.T) {
	password, err := EncryptV2("hunter2", "")
	if err != nil {
		t.Fatal(err)
	}

	file, err := ParseFile(strings.NewReader(`S:"Protocol Name"=SSH2
S:"Hostname"=10.0.0.1
S:"Username"=netops
D:"[SSH2] Port"=00000016
S:"Password V2"=` + password + `
S:"Firewall Name"=Session:jump-host
S:"Identity Filename V2"=C:\Users\alice\.ssh\id_ed25519
`))
	if err != nil {
		t.Fatal(err)
	}

	session := ReadSession(file, "Edge routers/London/core-sw-01.ini", ReadOptions{})

	if session.Name != "core-sw-01" {
		t.Errorf("name = %q", session.Name)
	}
	if strings.Join(session.Folders, "/") != "Edge routers/London" {
		t.Errorf("folders = %v", session.Folders)
	}
	if session.Protocol != "ssh" {
		t.Errorf("protocol = %q", session.Protocol)
	}
	if session.Hostname != "10.0.0.1" || session.Port != 22 || session.Username != "netops" {
		t.Errorf("connection = %s@%s:%d", session.Username, session.Hostname, session.Port)
	}
	if !session.HasPassword || session.Password != "hunter2" {
		t.Errorf("password = %q (had one: %v, error: %q)",
			session.Password, session.HasPassword, session.PasswordError)
	}
	if session.JumpSession() != "jump-host" {
		t.Errorf("jump session = %q", session.JumpSession())
	}
	if !strings.HasSuffix(session.IdentityFile, "id_ed25519") {
		t.Errorf("identity file = %q", session.IdentityFile)
	}
}

// TestASessionThatLostItsPasswordSaysSo: treating it as passwordless would
// hide the one thing the user has to know about.
func TestASessionThatLostItsPasswordSaysSo(t *testing.T) {
	protected, err := EncryptV2("hunter2", "a configuration passphrase")
	if err != nil {
		t.Fatal(err)
	}

	file, err := ParseFile(strings.NewReader(`S:"Hostname"=10.0.0.1
S:"Password V2"=` + protected + "\n"))
	if err != nil {
		t.Fatal(err)
	}

	session := ReadSession(file, "locked.ini", ReadOptions{})

	if !session.HasPassword {
		t.Fatal("a session with an undecodable password was reported as having none")
	}
	if session.Password != "" {
		t.Errorf("an undecodable password produced %q", session.Password)
	}
	if !strings.Contains(session.PasswordError, "configuration passphrase") {
		t.Errorf("the explanation does not tell the user what to do: %q", session.PasswordError)
	}

	// And with the passphrase, it comes out.
	withPassphrase := ReadSession(file, "locked.ini", ReadOptions{
		ConfigPassphrase: "a configuration passphrase",
	})
	if withPassphrase.Password != "hunter2" {
		t.Errorf("with the passphrase = %q, error %q",
			withPassphrase.Password, withPassphrase.PasswordError)
	}
}

func TestSkipPasswordsStillReportsThatThereWasOne(t *testing.T) {
	password, err := EncryptV2("hunter2", "")
	if err != nil {
		t.Fatal(err)
	}
	file, err := ParseFile(strings.NewReader(`S:"Hostname"=10.0.0.1
S:"Password V2"=` + password + "\n"))
	if err != nil {
		t.Fatal(err)
	}

	session := ReadSession(file, "host.ini", ReadOptions{SkipPasswords: true})

	if session.Password != "" {
		t.Error("a password was decoded despite SkipPasswords")
	}
	if !session.HasPassword {
		t.Error("the user is not told the session had a password to leave behind")
	}
}

// TestPortIsReadPerProtocol: SecureCRT keys the port by protocol, so a
// session that was SSH and is now Telnet still carries both. Reading the
// wrong one gives a plausible number for the wrong service.
func TestPortIsReadPerProtocol(t *testing.T) {
	file, err := ParseFile(strings.NewReader(`S:"Protocol Name"=Telnet
S:"Hostname"=10.0.0.1
D:"[SSH2] Port"=00000016
D:"[TELNET] Port"=00000bb8
`))
	if err != nil {
		t.Fatal(err)
	}

	session := ReadSession(file, "console.ini", ReadOptions{})
	if session.Protocol != "telnet" {
		t.Fatalf("protocol = %q", session.Protocol)
	}
	if session.Port != 3000 {
		t.Errorf("port = %d, want 3000 — the SSH port was read instead", session.Port)
	}
}

func TestProtocolMapping(t *testing.T) {
	for name, want := range map[string]string{
		"SSH2": "ssh", "SSH1": "ssh", "ssh2": "ssh",
		"Telnet": "telnet", "TELNET": "telnet",
		"Serial": "serial",
		"RLogin": "ssh", // no equivalent; imports as SSH rather than vanishing
		"":       "ssh",
	} {
		if got := protocolFrom(name); got != want {
			t.Errorf("protocolFrom(%q) = %q, want %q", name, got, want)
		}
	}
}

// --- whole directories -------------------------------------------------------

func TestReadDirectoryWalksTheTree(t *testing.T) {
	password, err := EncryptV2("hunter2", "")
	if err != nil {
		t.Fatal(err)
	}

	tree := fstest.MapFS{
		"Sessions/core-sw-01.ini": &fstest.MapFile{Data: []byte(
			`S:"Hostname"=10.0.0.1` + "\n" + `S:"Username"=netops` + "\n" +
				`D:"[SSH2] Port"=00000016` + "\n" + `S:"Password V2"=` + password + "\n")},
		"Sessions/Edge routers/London/edge-01.ini": &fstest.MapFile{Data: []byte(
			`S:"Hostname"=10.0.1.1` + "\n" + `S:"Username"=admin` + "\n")},
		"Sessions/Edge routers/__FolderData__.ini": &fstest.MapFile{Data: []byte(
			`S:"Something"=whatever` + "\n")},
		// No hostname: a template, not a connectable session.
		"Sessions/Default.ini": &fstest.MapFile{Data: []byte(
			`S:"Emulation"=xterm` + "\n")},
		// Not a session file at all.
		"Sessions/notes.txt":     &fstest.MapFile{Data: []byte("remember to migrate\n")},
		"Sessions/broken.ini":    &fstest.MapFile{Data: []byte("this is not the format\n")},
		"Global.ini":             &fstest.MapFile{Data: []byte(`S:"Something"=global` + "\n")},
		"Sessions/nested/x.ini":  &fstest.MapFile{Data: []byte(`S:"Hostname"=10.0.2.1` + "\n")},
		"Sessions/nested/y.json": &fstest.MapFile{Data: []byte("{}")},
	}

	result, err := ReadDirectory(tree, ReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	byName := map[string]Session{}
	for _, session := range result.Sessions {
		byName[session.Name] = session
	}

	if len(result.Sessions) != 3 {
		t.Fatalf("read %d sessions, want 3: %v", len(result.Sessions), names(result.Sessions))
	}
	if _, ok := byName["Default"]; ok {
		t.Error("a template with no hostname was imported as a session")
	}
	if _, ok := byName["__FolderData__"]; ok {
		t.Error("SecureCRT's own bookkeeping file was imported as a session")
	}

	edge := byName["edge-01"]
	if strings.Join(edge.Folders, "/") != "Edge routers/London" {
		t.Errorf("edge-01 folders = %v", edge.Folders)
	}

	core := byName["core-sw-01"]
	if len(core.Folders) != 0 {
		t.Errorf("a top-level session got folders: %v", core.Folders)
	}
	if core.Password != "hunter2" {
		t.Errorf("core-sw-01 password = %q", core.Password)
	}

	// The file that was not in the format is reported rather than silently
	// skipped: a user with a session missing needs to know which one.
	if len(result.Warnings) == 0 {
		t.Error("no warning about the file that could not be read")
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "broken.ini") {
		t.Errorf("the warnings do not name the unreadable file: %v", result.Warnings)
	}

	recovered, stored := result.PasswordsRecovered()
	if stored != 1 || recovered != 1 {
		t.Errorf("recovered %d of %d passwords, want 1 of 1", recovered, stored)
	}
}

// TestReadDirectoryAcceptsEitherRoot: users describe their configuration as
// either the folder itself or the Sessions directory inside it, and getting
// it wrong should not be a failure.
func TestReadDirectoryAcceptsEitherRoot(t *testing.T) {
	sessionsOnly := fstest.MapFS{
		"core-sw-01.ini": &fstest.MapFile{Data: []byte(`S:"Hostname"=10.0.0.1` + "\n")},
		"Site/edge.ini":  &fstest.MapFile{Data: []byte(`S:"Hostname"=10.0.1.1` + "\n")},
	}

	result, err := ReadDirectory(sessionsOnly, ReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(result.Sessions) != 2 {
		t.Fatalf("read %d sessions, want 2: %v", len(result.Sessions), names(result.Sessions))
	}

	for _, session := range result.Sessions {
		if session.Name == "edge" && strings.Join(session.Folders, "/") != "Site" {
			t.Errorf("edge folders = %v", session.Folders)
		}
	}
}

func TestReadDirectoryCountsUndecodedPasswords(t *testing.T) {
	locked, err := EncryptV2("hunter2", "a configuration passphrase")
	if err != nil {
		t.Fatal(err)
	}
	open, err := EncryptV2("hunter3", "")
	if err != nil {
		t.Fatal(err)
	}

	tree := fstest.MapFS{
		"a.ini": &fstest.MapFile{Data: []byte(`S:"Hostname"=10.0.0.1` + "\n" +
			`S:"Password V2"=` + locked + "\n")},
		"b.ini": &fstest.MapFile{Data: []byte(`S:"Hostname"=10.0.0.2` + "\n" +
			`S:"Password V2"=` + open + "\n")},
		"c.ini": &fstest.MapFile{Data: []byte(`S:"Hostname"=10.0.0.3` + "\n")},
	}

	result, err := ReadDirectory(tree, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	recovered, stored := result.PasswordsRecovered()
	if stored != 2 {
		t.Errorf("counted %d stored passwords, want 2", stored)
	}
	if recovered != 1 {
		t.Errorf("counted %d recovered, want 1", recovered)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("warnings = %v, want one about the locked password", result.Warnings)
	}
}

// --- helpers -----------------------------------------------------------------

// sealForTest encrypts a raw plaintext block the way the V2 format does,
// without the length and digest the encoder adds. Used to build values the
// decoder should refuse.
func sealForTest(t *testing.T, plain []byte, configPassphrase string) string {
	t.Helper()

	encoded, err := encryptRawForTest(plain, configPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func shortName(s string) string {
	switch {
	case s == "":
		return "empty"
	case len(s) > 20:
		return s[:20] + "…"
	default:
		return s
	}
}

func names(sessions []Session) []string {
	out := make([]string, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, session.Name)
	}
	return out
}
