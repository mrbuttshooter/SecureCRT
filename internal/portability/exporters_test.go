package portability

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
)

// exportPayload is a tree with everything the formats have to cope with:
// nesting, a jump chain, a key, a password, a Telnet connection and a name
// that is not usable as an identifier.
func exportPayload() Payload {
	return Payload{
		Folders: []Folder{
			{ID: "f1", Name: "Edge routers"},
			{ID: "f2", ParentID: "f1", Name: "London"},
		},
		Sessions: []Session{
			{ID: "s-jump", Name: "jump-host", Protocol: "ssh",
				Hostname: "203.0.113.9", Port: 2222, Username: "bastion",
				CredentialID: "c-key"},
			{ID: "s-core", FolderID: "f2", Name: "Core Switch 01", Protocol: "ssh",
				Hostname: "10.0.0.1", Port: 22, Username: "netops",
				CredentialID: "c-pass", JumpChain: []string{"s-jump"}},
			{ID: "s-console", FolderID: "f1", Name: "console", Protocol: "telnet",
				Hostname: "10.1.0.1", Port: 3000},
		},
		Credentials: []Credential{
			{ID: "c-key", Name: "netops key", Kind: "ssh_key",
				Secret:    "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
				PublicKey: "ssh-ed25519 AAAA netops", KeyType: "ssh-ed25519"},
			{ID: "c-pass", Name: "console password", Kind: "password", Secret: "hunter2"},
		},
		KnownHosts: []KnownHost{
			{Hostname: "10.0.0.1", Port: 22, KeyType: "ssh-ed25519",
				Fingerprint: "SHA256:aaa", PublicKey: "ssh-ed25519 AAAA host"},
		},
	}
}

func export(t *testing.T, format Format, opts ExportOptions) (string, ExportResult) {
	t.Helper()

	var buf bytes.Buffer
	result, err := Export(&buf, exportPayload(), format, opts)
	if err != nil {
		t.Fatalf("export %s: %v", format, err)
	}
	return buf.String(), result
}

// --- ssh_config --------------------------------------------------------------

func TestExportSSHConfig(t *testing.T) {
	out, result := export(t, FormatSSHConfig, ExportOptions{})

	// A name with spaces and capitals is not usable as a Host alias, which is
	// typed on a command line.
	if !strings.Contains(out, "Host core-switch-01") {
		t.Errorf("no usable alias for \"Core Switch 01\":\n%s", out)
	}
	if !strings.Contains(out, "HostName 10.0.0.1") {
		t.Error("the address is missing")
	}
	if !strings.Contains(out, "User netops") {
		t.Error("the username is missing")
	}
	if !strings.Contains(out, "Port 2222") {
		t.Error("a non-default port is missing")
	}
	// Port 22 is the default and writing it is noise.
	if strings.Contains(out, "Port 22\n") {
		t.Error("the default port was written out")
	}
	if !strings.Contains(out, "ProxyJump jump-host") {
		t.Errorf("the jump chain did not become a ProxyJump:\n%s", out)
	}
	if !strings.Contains(out, "IdentityFile ~/.ssh/netops-key") {
		t.Errorf("the key was not named:\n%s", out)
	}

	// Telnet has no place in an ssh_config, and the user is told rather than
	// left to notice a missing device.
	if strings.Contains(out, "10.1.0.1") {
		t.Error("a Telnet connection was written into an ssh_config")
	}
	warnings := strings.Join(result.Warnings, "\n")
	if !strings.Contains(warnings, "not SSH") {
		t.Errorf("no warning about the Telnet connection: %v", result.Warnings)
	}
	if !strings.Contains(warnings, "Passwords cannot be expressed") {
		t.Errorf("no warning that the passwords were dropped: %v", result.Warnings)
	}

	// Nothing secret, ever: the format cannot express a secret, so a leak
	// here would mean something wrote one anyway.
	for _, secret := range []string{"hunter2", "PRIVATE KEY"} {
		if strings.Contains(out, secret) {
			t.Errorf("an ssh_config contains %q", secret)
		}
	}
}

// TestExportedSSHConfigCanBeReadBack is the round trip that matters for this
// format: what we write, we can read.
func TestExportedSSHConfigCanBeReadBack(t *testing.T) {
	out, _ := export(t, FormatSSHConfig, ExportOptions{})

	imported, err := FromSSHDirectory(fstest.MapFS{
		"config": &fstest.MapFile{Data: []byte(out)},
	}, SSHConfigOptions{})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}

	// The two SSH connections survive; the Telnet one was dropped on the way
	// out, which the export warned about.
	if len(byName) != 2 {
		t.Fatalf("read back %d hosts, want 2: %v", len(byName), sessionNames(imported.Payload))
	}

	core := byName["core-switch-01"]
	if core.Hostname != "10.0.0.1" || core.Username != "netops" {
		t.Errorf("core = %s@%s", core.Username, core.Hostname)
	}
	if core.Port != 0 && core.Port != 22 {
		t.Errorf("core port = %d", core.Port)
	}

	jump := byName["jump-host"]
	if jump.Port != 2222 || jump.Username != "bastion" {
		t.Errorf("jump = %s on %d", jump.Username, jump.Port)
	}
	if len(core.JumpChain) != 1 || core.JumpChain[0] != jump.ID {
		t.Errorf("the ProxyJump did not survive: %v", core.JumpChain)
	}
}

// TestSSHAliasesDoNotCollide: two devices with the same name in different
// folders are one alias in a flat config, and the second would silently
// shadow the first.
func TestSSHAliasesDoNotCollide(t *testing.T) {
	payload := Payload{
		Folders: []Folder{
			{ID: "f1", Name: "London"},
			{ID: "f2", Name: "Manchester"},
		},
		Sessions: []Session{
			{ID: "a", FolderID: "f1", Name: "core-01", Hostname: "10.0.0.1", Protocol: "ssh"},
			{ID: "b", FolderID: "f2", Name: "core-01", Hostname: "10.1.0.1", Protocol: "ssh"},
		},
	}

	var buf bytes.Buffer
	if _, err := Export(&buf, payload, FormatSSHConfig, ExportOptions{}); err != nil {
		t.Fatal(err)
	}

	imported, err := FromSSHDirectory(fstest.MapFS{
		"config": &fstest.MapFile{Data: buf.Bytes()},
	}, SSHConfigOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if len(imported.Payload.Sessions) != 2 {
		t.Fatalf("two devices became %d hosts: %v",
			len(imported.Payload.Sessions), sessionNames(imported.Payload))
	}

	addresses := map[string]bool{}
	for _, session := range imported.Payload.Sessions {
		addresses[session.Hostname] = true
	}
	if !addresses["10.0.0.1"] || !addresses["10.1.0.1"] {
		t.Errorf("one device shadowed the other: %v", addresses)
	}
}

// --- SecureCRT ---------------------------------------------------------------

func TestExportSecureCRT(t *testing.T) {
	out, result := export(t, FormatSecureCRT, ExportOptions{IncludeSecrets: true})

	if !strings.Contains(out, `S:"Hostname"=10.0.0.1`) {
		t.Errorf("the address is missing:\n%s", out)
	}
	if !strings.Contains(out, `S:"Protocol Name"=Telnet`) {
		t.Error("the Telnet connection did not keep its protocol")
	}
	// Ports are eight hex digits in this format: 3000 is 0xbb8.
	if !strings.Contains(out, `D:"[TELNET] Port"=00000bb8`) {
		t.Errorf("the Telnet port is wrong or missing:\n%s", out)
	}
	if !strings.Contains(out, `D:"[SSH2] Port"=000008ae`) {
		t.Errorf("the SSH port is wrong or missing:\n%s", out)
	}

	// The folder path is in each block's header, so a person can put the file
	// where it belongs.
	if !strings.Contains(out, "Edge routers/London/Core Switch 01.ini") {
		t.Errorf("the folder path is missing from the header:\n%s", out)
	}

	// The password is written in SecureCRT's own format, and is readable back
	// by the codec that reads real ones.
	var encoded string
	for _, line := range strings.Split(out, "\n") {
		if after, ok := strings.CutPrefix(line, `S:"Password V2"=`); ok {
			encoded = strings.TrimSpace(after)
		}
	}
	if encoded == "" {
		t.Fatalf("no password was written:\n%s", out)
	}
	decoded, err := securecrt.DecryptV2(encoded, "")
	if err != nil {
		t.Fatalf("the exported password does not decode: %v", err)
	}
	if decoded != "hunter2" {
		t.Errorf("the exported password decodes to %q", decoded)
	}

	// And the file says plainly what that protection is worth.
	if !strings.Contains(out, "not protected") {
		t.Error("the file does not warn that its passwords are only obfuscated")
	}

	warnings := strings.Join(result.Warnings, "\n")
	if !strings.Contains(warnings, "published constant") {
		t.Errorf("no warning about the obfuscation: %v", result.Warnings)
	}
	if !strings.Contains(warnings, "SSH key") {
		t.Errorf("no warning that keys cannot travel: %v", result.Warnings)
	}
}

func TestExportSecureCRTWithoutSecrets(t *testing.T) {
	out, _ := export(t, FormatSecureCRT, ExportOptions{})

	if strings.Contains(out, "Password") {
		t.Errorf("a password was written despite IncludeSecrets being off:\n%s", out)
	}
	if !strings.Contains(out, "10.0.0.1") {
		t.Error("the connections were dropped along with the passwords")
	}
}

// --- PuTTY -------------------------------------------------------------------

func TestExportPuTTY(t *testing.T) {
	out, result := export(t, FormatPuTTY, ExportOptions{IncludeSecrets: true})

	if !strings.HasPrefix(out, "Windows Registry Editor Version 5.00") {
		t.Errorf("no registry header:\n%s", out)
	}
	if !strings.Contains(out, `"HostName"="10.0.0.1"`) {
		t.Errorf("the address is missing:\n%s", out)
	}
	if !strings.Contains(out, `"PortNumber"=dword:000008ae`) {
		t.Errorf("the port is wrong or missing:\n%s", out)
	}
	// Registry files are CRLF, and a .reg with Unix endings is refused by
	// regedit.
	if !strings.Contains(out, "\r\n") {
		t.Error("the file does not use CRLF line endings")
	}

	// PuTTY has no folders, so the path is folded into the name rather than
	// lost.
	if !strings.Contains(out, url.QueryEscape("Edge routers - London - Core Switch 01")) {
		t.Errorf("the folder path was not folded into the session name:\n%s", out)
	}

	// It stores no passwords, so none may appear whatever was asked for.
	if strings.Contains(out, "hunter2") {
		t.Error("a password was written into a PuTTY export")
	}
	if !strings.Contains(strings.Join(result.Warnings, "\n"), "no passwords") {
		t.Errorf("no warning that credentials were dropped: %v", result.Warnings)
	}
}

// TestExportedPuTTYCanBeReadBack.
func TestExportedPuTTYCanBeReadBack(t *testing.T) {
	out, _ := export(t, FormatPuTTY, ExportOptions{})

	imported, err := FromPuTTYRegistry(strings.NewReader(out), PuTTYOptions{})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(imported.Payload.Sessions) != 3 {
		t.Fatalf("read back %d sessions, want 3: %v",
			len(imported.Payload.Sessions), sessionNames(imported.Payload))
	}

	byHost := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byHost[session.Hostname] = session
	}
	if byHost["10.0.0.1"].Username != "netops" {
		t.Errorf("the username did not survive: %+v", byHost["10.0.0.1"])
	}
	if byHost["10.1.0.1"].Protocol != "telnet" {
		t.Errorf("the protocol did not survive: %+v", byHost["10.1.0.1"])
	}
}

// TestRegistryStringsAreEscaped: a hostname containing a quote or a newline
// would otherwise end the line and turn the rest into what looks like another
// value.
func TestRegistryStringsAreEscaped(t *testing.T) {
	payload := Payload{
		Sessions: []Session{
			{ID: "a", Name: "odd", Protocol: "ssh",
				Hostname: "host\"with\\quotes\nand a newline", Username: "user"},
		},
	}

	var buf bytes.Buffer
	if _, err := Export(&buf, payload, FormatPuTTY, ExportOptions{}); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	body := strings.Split(out, "\r\n")
	for _, line := range body {
		if strings.HasPrefix(line, "and a newline") {
			t.Errorf("a newline in a hostname broke the file open:\n%s", out)
		}
	}
	if !strings.Contains(out, `\"`) || !strings.Contains(out, `\\`) {
		t.Errorf("quotes and backslashes were not escaped:\n%s", out)
	}
}

// --- JSON and CSV ------------------------------------------------------------

func TestExportJSONWithAndWithoutSecrets(t *testing.T) {
	withSecrets, result := export(t, FormatJSON, ExportOptions{IncludeSecrets: true})

	var payload Payload
	if err := json.Unmarshal([]byte(withSecrets), &payload); err != nil {
		t.Fatalf("the export is not valid JSON: %v", err)
	}
	if len(payload.Sessions) != 3 || len(payload.Credentials) != 2 {
		t.Errorf("payload = %+v", payload.Counts())
	}
	if !strings.Contains(withSecrets, "hunter2") {
		t.Error("the password is missing from an export that asked for secrets")
	}
	if !strings.Contains(strings.Join(result.Warnings, "\n"), "in the clear") {
		t.Errorf("no warning about an unprotected file: %v", result.Warnings)
	}

	without, _ := export(t, FormatJSON, ExportOptions{})
	for _, secret := range []string{"hunter2", "PRIVATE KEY"} {
		if strings.Contains(without, secret) {
			t.Errorf("a secretless export contains %q", secret)
		}
	}
	// The records themselves remain, so the connections still point at
	// something recognisable.
	if !strings.Contains(without, "netops key") {
		t.Error("the credential records were dropped along with their secrets")
	}
}

// TestExportedJSONRoundTripsThroughTheBundlePath: JSON is the payload as it
// stands, so it must import as one.
func TestExportedJSONRoundTripsThroughTheBundlePath(t *testing.T) {
	out, _ := export(t, FormatJSON, ExportOptions{IncludeSecrets: true})

	var payload Payload
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}

	instance := newInstance(t)
	result, err := instance.service.Import(t.Context(), instance.key, payload,
		ImportOptions{UserID: instance.userID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Sessions != 3 || result.Folders != 2 || result.Credentials != 2 {
		t.Errorf("imported %+v", result)
	}
}

func TestExportCSV(t *testing.T) {
	out, result := export(t, FormatCSV, ExportOptions{IncludeSecrets: true})

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("%d rows including the header, want 4", len(records))
	}

	header := records[0]
	if header[0] != "Name" || header[3] != "Hostname" {
		t.Errorf("header = %v", header)
	}

	byName := map[string][]string{}
	for _, record := range records[1:] {
		byName[record[0]] = record
	}

	core := byName["Core Switch 01"]
	if core[1] != "Edge routers/London" {
		t.Errorf("the folder path = %q", core[1])
	}
	if core[3] != "10.0.0.1" || core[5] != "netops" {
		t.Errorf("core = %v", core)
	}
	if core[7] != "hunter2" {
		t.Errorf("the password column = %q", core[7])
	}

	// A key is thousands of characters of PEM and belongs in no spreadsheet.
	jump := byName["jump-host"]
	if strings.Contains(jump[7], "PRIVATE KEY") {
		t.Error("a private key was written into a spreadsheet cell")
	}
	if !strings.Contains(jump[7], "SSH key") {
		t.Errorf("the cell does not explain what happened: %q", jump[7])
	}

	if !strings.Contains(strings.Join(result.Warnings, "\n"), "cannot go in a spreadsheet") {
		t.Errorf("no warning about the key: %v", result.Warnings)
	}
}

// TestExportedCSVCanBeReadBack.
func TestExportedCSVCanBeReadBack(t *testing.T) {
	out, _ := export(t, FormatCSV, ExportOptions{IncludeSecrets: true})

	imported, err := FromCSV(strings.NewReader(out), CSVOptions{})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(imported.Payload.Sessions) != 3 {
		t.Fatalf("read back %d rows: %v",
			len(imported.Payload.Sessions), sessionNames(imported.Payload))
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}
	if byName["Core Switch 01"].Hostname != "10.0.0.1" {
		t.Errorf("core = %+v", byName["Core Switch 01"])
	}
	if byName["console"].Protocol != "telnet" {
		t.Errorf("the protocol column did not survive: %+v", byName["console"])
	}
}

func TestExportCSVWithoutSecrets(t *testing.T) {
	out, _ := export(t, FormatCSV, ExportOptions{})

	if strings.Contains(out, "hunter2") {
		t.Error("a password was written despite IncludeSecrets being off")
	}
	if strings.Contains(strings.Split(out, "\n")[0], "Password") {
		t.Error("a password column was written for a secretless export")
	}
	// The credential's name still appears, so the row says which one to set.
	if !strings.Contains(out, "console password") {
		t.Error("the credential name was dropped")
	}
}

// --- the format table ---------------------------------------------------------

func TestFormatProperties(t *testing.T) {
	// Only the bundle is encrypted. Everything else is a text file somebody
	// can read, which is what gates it behind a passphrase and a confirmation
	// in the API.
	if FormatBundle.Plaintext() {
		t.Error("the bundle is marked as plaintext")
	}
	for _, format := range []Format{FormatSSHConfig, FormatSecureCRT, FormatPuTTY, FormatJSON, FormatCSV} {
		if !format.Plaintext() {
			t.Errorf("%s is not marked as plaintext", format)
		}
		if format.Filename() == "" {
			t.Errorf("%s suggests no filename", format)
		}
	}

	// The two that structurally cannot hold a secret.
	if FormatSSHConfig.CarriesSecrets() || FormatPuTTY.CarriesSecrets() {
		t.Error("a format that cannot hold a secret is marked as if it could")
	}
	if !FormatBundle.CarriesSecrets() || !FormatJSON.CarriesSecrets() {
		t.Error("a format that carries secrets is marked as if it could not")
	}
}

func TestExportRejectsTheBundleFormatAndTheUnknown(t *testing.T) {
	var buf bytes.Buffer

	if _, err := Export(&buf, exportPayload(), FormatBundle, ExportOptions{}); err == nil {
		t.Error("a bundle was written without a passphrase")
	}
	if _, err := Export(&buf, exportPayload(), Format("nonsense"), ExportOptions{}); err == nil {
		t.Error("an unknown format was accepted")
	}
}
