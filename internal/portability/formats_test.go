package portability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/crypto/ssh"
)

// --- ~/.ssh/config -----------------------------------------------------------

// generateKey makes a real OpenSSH private key, so the importer is tested
// against something it will actually meet rather than a placeholder.
func generateKey(t *testing.T) (private []byte, fingerprint string) {
	t.Helper()

	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	block, err := ssh.MarshalPrivateKey(secret, "")
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	_ = public

	return pem.EncodeToMemory(block), ssh.FingerprintSHA256(signer.PublicKey())
}

func TestSSHConfigImport(t *testing.T) {
	key, fingerprint := generateKey(t)

	tree := fstest.MapFS{
		"config": &fstest.MapFile{Data: []byte(`# my hosts
Host *
    User netops
    ServerAliveInterval 60

Host bastion
    HostName 203.0.113.9
    Port 2222
    User jump

Host core-sw-01
    HostName 10.0.0.1
    IdentityFile ~/.ssh/id_ed25519
    ProxyJump bastion

Host edge-01 edge-01.internal
    HostName=10.0.1.1
    Port=22

Host *.internal
    User someone-else

Match user root
    Port 2200
`)},
		"id_ed25519": &fstest.MapFile{Data: key},
	}

	imported, err := FromSSHDirectory(tree, SSHConfigOptions{ImportKeys: true})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}

	if len(byName) != 3 {
		t.Fatalf("imported %d hosts, want 3: %v", len(byName), sessionNames(imported.Payload))
	}

	core := byName["core-sw-01"]
	if core.Hostname != "10.0.0.1" {
		t.Errorf("core-sw-01 hostname = %q", core.Hostname)
	}
	// The username comes from "Host *", which is a default rather than a
	// setting on this host — so it belongs on the folder, not here.
	if core.Username != "" {
		t.Errorf("a wildcard default was copied onto the session: %q", core.Username)
	}

	// An alias list takes its first concrete name, rather than importing the
	// same host twice under two names.
	if _, ok := byName["edge-01.internal"]; ok {
		t.Error("an alias was imported as a second connection")
	}
	if byName["edge-01"].Port != 22 {
		t.Errorf("the keyword=value form was not parsed: port %d", byName["edge-01"].Port)
	}

	if byName["bastion"].Port != 2222 || byName["bastion"].Username != "jump" {
		t.Errorf("bastion = %s on port %d", byName["bastion"].Username, byName["bastion"].Port)
	}

	// --- ProxyJump resolved ------------------------------------------------

	if len(core.JumpChain) != 1 || core.JumpChain[0] != byName["bastion"].ID {
		t.Errorf("core-sw-01's jump chain = %v", core.JumpChain)
	}

	// --- Host * became folder defaults --------------------------------------

	if len(imported.Payload.Folders) != 1 {
		t.Fatalf("folders = %+v", imported.Payload.Folders)
	}
	defaults := string(imported.Payload.Folders[0].Defaults)
	if !strings.Contains(defaults, "netops") {
		t.Errorf("the wildcard username did not become a folder default: %s", defaults)
	}
	if !strings.Contains(defaults, "60") {
		t.Errorf("ServerAliveInterval did not become a folder default: %s", defaults)
	}
	// "Host *.internal" applies to some hosts and not others, and there is no
	// way to say that here. Applying it to everything would be wrong for the
	// rest.
	if strings.Contains(defaults, "someone-else") {
		t.Errorf("a partial wildcard was applied to everything: %s", defaults)
	}

	// --- the key came with it ------------------------------------------------

	if len(imported.Payload.Credentials) != 1 {
		t.Fatalf("imported %d keys, want 1", len(imported.Payload.Credentials))
	}
	credential := imported.Payload.Credentials[0]
	if credential.Kind != "ssh_key" {
		t.Errorf("kind = %q", credential.Kind)
	}
	if !strings.Contains(credential.Secret, "PRIVATE KEY") {
		t.Error("the key material did not come across")
	}
	if credential.Fingerprint != fingerprint {
		t.Errorf("fingerprint = %q, want %q", credential.Fingerprint, fingerprint)
	}
	if credential.KeyType != "ssh-ed25519" {
		t.Errorf("key type = %q", credential.KeyType)
	}
	if core.CredentialID != credential.ID {
		t.Error("core-sw-01 does not point at the key its config named")
	}

	// --- and what could not be honoured is reported --------------------------

	warnings := strings.Join(imported.Warnings, "\n")
	if !strings.Contains(warnings, "Match") {
		t.Errorf("no warning about the Match block: %v", imported.Warnings)
	}
}

func TestSSHConfigWithoutKeysWarnsAboutThem(t *testing.T) {
	tree := fstest.MapFS{
		"config": &fstest.MapFile{Data: []byte(`Host core
    HostName 10.0.0.1
    IdentityFile ~/.ssh/id_ed25519
`)},
	}

	imported, err := FromSSHDirectory(tree, SSHConfigOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Payload.Credentials) != 0 {
		t.Error("a key was imported without being asked for")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "id_ed25519") {
		t.Errorf("no warning naming the key: %v", imported.Warnings)
	}
}

func TestSSHConfigWithAMissingKeyFile(t *testing.T) {
	tree := fstest.MapFS{
		"config": &fstest.MapFile{Data: []byte(`Host core
    HostName 10.0.0.1
    IdentityFile ~/.ssh/id_not_uploaded
`)},
	}

	imported, err := FromSSHDirectory(tree, SSHConfigOptions{ImportKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Payload.Sessions) != 1 {
		t.Error("the host was dropped because its key was missing")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "not in what you uploaded") {
		t.Errorf("the warning does not explain what happened: %v", imported.Warnings)
	}
}

// TestSSHConfigImportsKnownHosts: carrying them across is why a restored
// instance does not ask about three hundred fingerprints in an afternoon.
func TestSSHConfigImportsKnownHosts(t *testing.T) {
	_, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	tree := fstest.MapFS{
		"config": &fstest.MapFile{Data: []byte("Host core\n    HostName 10.0.0.1\n")},
		"known_hosts": &fstest.MapFile{Data: []byte(
			"10.0.0.1 " + authorized + "\n" +
				"[10.0.0.2]:2222 " + authorized + "\n" +
				"|1|abcdef=|ghijkl= " + authorized + "\n")},
	}

	imported, err := FromSSHDirectory(tree, SSHConfigOptions{ImportKnownHosts: true})
	if err != nil {
		t.Fatal(err)
	}

	byHost := map[string]KnownHost{}
	for _, host := range imported.Payload.KnownHosts {
		byHost[host.Hostname] = host
	}

	if len(byHost) != 2 {
		t.Fatalf("imported %d known hosts, want 2: %+v", len(byHost), imported.Payload.KnownHosts)
	}
	if byHost["10.0.0.1"].Port != 22 {
		t.Errorf("default port = %d", byHost["10.0.0.1"].Port)
	}
	if byHost["10.0.0.2"].Port != 2222 {
		t.Errorf("the [host]:port form was not read: %d", byHost["10.0.0.2"].Port)
	}
	if byHost["10.0.0.1"].Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Error("the fingerprint does not match the key")
	}

	// A hashed entry cannot be named, so the user is told they will be asked
	// about those hosts again rather than left to discover it.
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "hashed") {
		t.Errorf("no warning about the hashed entry: %v", imported.Warnings)
	}
}

func TestSSHConfigPointedAtTheWrongPlace(t *testing.T) {
	imported, err := FromSSHDirectory(fstest.MapFS{
		"holiday.jpg": &fstest.MapFile{Data: []byte("\xff\xd8")},
	}, SSHConfigOptions{})
	if err != nil {
		t.Fatalf("this should not be an error: %v", err)
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), ".ssh directory") {
		t.Errorf("the warning does not say where to point it: %v", imported.Warnings)
	}
}

func TestProxyJumpChain(t *testing.T) {
	tree := fstest.MapFS{
		"config": &fstest.MapFile{Data: []byte(`Host outer
    HostName 203.0.113.1

Host inner
    HostName 203.0.113.2

Host target
    HostName 10.0.0.1
    ProxyJump alice@outer:2222,inner

Host lost
    HostName 10.0.0.2
    ProxyJump nowhere
`)},
	}

	imported, err := FromSSHDirectory(tree, SSHConfigOptions{})
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}

	chain := byName["target"].JumpChain
	if len(chain) != 2 {
		t.Fatalf("chain = %v, want two hops", chain)
	}
	// The user and port on a hop belong to that hop's own session, not to
	// this one, so they are stripped rather than misapplied.
	if chain[0] != byName["outer"].ID || chain[1] != byName["inner"].ID {
		t.Errorf("the chain hops through the wrong sessions: %v", chain)
	}

	if len(byName["lost"].JumpChain) != 0 {
		t.Error("a hop through a host that is not in the config was invented")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "nowhere") {
		t.Errorf("no warning naming the missing hop: %v", imported.Warnings)
	}
}

// --- PuTTY -------------------------------------------------------------------

func TestPuTTYRegistryImport(t *testing.T) {
	const export = `Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\core%20switch]
"HostName"="10.0.0.1"
"PortNumber"=dword:00000016
"UserName"="netops"
"Protocol"="ssh"
"PublicKeyFile"="C:\\Users\\alice\\keys\\id.ppk"
"FontHeight"=dword:0000000a

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\console]
"HostName"="admin@10.0.1.1"
"PortNumber"=dword:00000bb8
"Protocol"="telnet"
"ProxyHost"="proxy.example.com"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys]
"ssh-ed25519@22:10.0.0.1"="0x1,0x2"
`

	imported, err := FromPuTTYRegistry(strings.NewReader(export), PuTTYOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}

	if len(byName) != 2 {
		t.Fatalf("imported %d sessions, want 2: %v", len(byName), sessionNames(imported.Payload))
	}

	// The session name is percent-encoded in the registry key.
	core := byName["core switch"]
	if core.Hostname != "10.0.0.1" || core.Port != 22 || core.Username != "netops" {
		t.Errorf("core switch = %s@%s:%d", core.Username, core.Hostname, core.Port)
	}

	// PuTTY accepts "user@host" in the hostname field, which is how a great
	// many saved sessions actually carry their username.
	console := byName["console"]
	if console.Hostname != "10.0.1.1" || console.Username != "admin" {
		t.Errorf("console = %s@%s", console.Username, console.Hostname)
	}
	if console.Protocol != "telnet" || console.Port != 3000 {
		t.Errorf("console = %s on port %d", console.Protocol, console.Port)
	}

	// Everything lands in one folder, because PuTTY has none.
	if len(imported.Payload.Folders) != 1 || imported.Payload.Folders[0].Name != "PuTTY" {
		t.Errorf("folders = %+v", imported.Payload.Folders)
	}
	for _, session := range imported.Payload.Sessions {
		if session.FolderID != imported.Payload.Folders[0].ID {
			t.Errorf("%q landed outside the folder", session.Name)
		}
	}

	warnings := strings.Join(imported.Warnings, "\n")
	if !strings.Contains(warnings, ".ppk") {
		t.Errorf("no warning that a .ppk cannot be imported directly: %v", imported.Warnings)
	}
	if !strings.Contains(warnings, "proxy.example.com") {
		t.Errorf("no warning about the proxy: %v", imported.Warnings)
	}

	notes := strings.Join(imported.Notes, "\n")
	if !strings.Contains(notes, "stores no passwords") {
		t.Errorf("the notes do not explain why nothing authenticates yet: %v", imported.Notes)
	}
}

func TestPuTTYRegistryOfSomethingElse(t *testing.T) {
	imported, err := FromPuTTYRegistry(strings.NewReader(
		"Windows Registry Editor Version 5.00\n\n"+
			`[HKEY_CURRENT_USER\Software\Microsoft\Windows]`+"\n"+
			`"Something"="else"`+"\n"), PuTTYOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Payload.Sessions) != 0 {
		t.Error("sessions were invented from an unrelated registry export")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "SimonTatham") {
		t.Errorf("the warning does not say which key to export: %v", imported.Warnings)
	}
}

func TestPuTTYDirectoryImport(t *testing.T) {
	tree := fstest.MapFS{
		"sessions/core%20switch": &fstest.MapFile{Data: []byte(
			"HostName=10.0.0.1\nPortNumber=22\nUserName=netops\nProtocol=ssh\n")},
		"sessions/edge": &fstest.MapFile{Data: []byte(
			"HostName=10.0.1.1\nPortNumber=22\n")},
		"sessions/empty": &fstest.MapFile{Data: []byte("")},
	}

	imported, err := FromPuTTYDirectory(tree, PuTTYOptions{FolderName: "From PuTTY"})
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}
	if len(byName) != 2 {
		t.Fatalf("imported %d sessions: %v", len(byName), sessionNames(imported.Payload))
	}
	if byName["core switch"].Username != "netops" {
		t.Errorf("core switch = %+v", byName["core switch"])
	}
	if imported.Payload.Folders[0].Name != "From PuTTY" {
		t.Errorf("folder = %q", imported.Payload.Folders[0].Name)
	}
}

// --- CSV ---------------------------------------------------------------------

func TestCSVImport(t *testing.T) {
	const sheet = `Device Name,IP Address,User,Port,Site,Password
core-sw-01,10.0.0.1,netops,22,London,hunter2
core-sw-02,10.0.0.2,netops,,London,
edge-rtr-01,10.1.0.1,admin,2222,Manchester,secret
,10.2.0.1,nobody,,,
`

	imported, err := FromCSV(strings.NewReader(sheet), CSVOptions{FolderName: "Inventory"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	byName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		byName[session.Name] = session
	}

	// The row with no name still imports, under its address: a device with no
	// label is still a device.
	if len(byName) != 4 {
		t.Fatalf("imported %d rows: %v", len(byName), sessionNames(imported.Payload))
	}

	core := byName["core-sw-01"]
	if core.Hostname != "10.0.0.1" || core.Username != "netops" || core.Port != 22 {
		t.Errorf("core-sw-01 = %s@%s:%d", core.Username, core.Hostname, core.Port)
	}

	// Column names are matched loosely, because this is the format people
	// arrive with and "IP Address" is as common as "hostname".
	if byName["edge-rtr-01"].Port != 2222 {
		t.Errorf("edge-rtr-01 port = %d", byName["edge-rtr-01"].Port)
	}

	// A site column becomes a folder inside the import folder.
	folderNames := map[string]string{}
	for _, folder := range imported.Payload.Folders {
		folderNames[folder.Name] = folder.ID
	}
	if _, ok := folderNames["London"]; !ok {
		t.Errorf("folders = %+v", imported.Payload.Folders)
	}
	if core.FolderID != folderNames["London"] {
		t.Error("core-sw-01 did not land in its site folder")
	}

	// Passwords become credentials; blank ones do not.
	if len(imported.Payload.Credentials) != 2 {
		t.Fatalf("created %d credentials, want 2", len(imported.Payload.Credentials))
	}
	if byName["core-sw-02"].CredentialID != "" {
		t.Error("a row with an empty password column was given a credential")
	}

	notes := strings.Join(imported.Notes, "\n")
	if !strings.Contains(notes, "Delete the spreadsheet") {
		t.Errorf("the notes do not tell the user to delete the unprotected copy: %v", imported.Notes)
	}
}

func TestCSVWithoutAHostnameColumn(t *testing.T) {
	imported, err := FromCSV(strings.NewReader("Name,Notes\nsomething,else\n"), CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Payload.Sessions) != 0 {
		t.Error("connections were invented from a file with no addresses")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "Hostname") {
		t.Errorf("the warning does not say which column to add: %v", imported.Warnings)
	}
}

func TestCSVEmptyFile(t *testing.T) {
	imported, err := FromCSV(strings.NewReader(""), CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Payload.Sessions) != 0 {
		t.Error("connections were invented from an empty file")
	}
	if len(imported.Warnings) == 0 {
		t.Error("no warning about an empty file")
	}
}
