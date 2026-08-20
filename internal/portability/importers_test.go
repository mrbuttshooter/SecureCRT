package portability

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
)

// secureCRTTree builds a configuration that looks like a real one: nested
// folders, a mix of protocols, saved passwords, a jump host and a key path.
func secureCRTTree(t *testing.T, configPassphrase string) fstest.MapFS {
	t.Helper()

	password := func(plain string) string {
		encoded, err := securecrt.EncryptV2(plain, configPassphrase)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	file := func(lines ...string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte(strings.Join(lines, "\n") + "\n")}
	}

	return fstest.MapFS{
		"Sessions/jump-host.ini": file(
			`S:"Protocol Name"=SSH2`,
			`S:"Hostname"=203.0.113.9`,
			`S:"Username"=bastion`,
			`D:"[SSH2] Port"=000008ae`,
			`S:"Password V2"=`+password("bastion-password"),
		),
		"Sessions/Edge routers/London/core-sw-01.ini": file(
			`S:"Protocol Name"=SSH2`,
			`S:"Hostname"=10.0.0.1`,
			`S:"Username"=netops`,
			`D:"[SSH2] Port"=00000016`,
			`D:"Scrollback"=0000c350`,
			`S:"Password V2"=`+password("hunter2"),
			`S:"Firewall Name"=Session:jump-host`,
		),
		"Sessions/Edge routers/London/core-sw-02.ini": file(
			`S:"Protocol Name"=SSH2`,
			`S:"Hostname"=10.0.0.2`,
			`S:"Username"=netops`,
			`S:"Identity Filename V2"=C:\Users\alice\.ssh\id_ed25519`,
		),
		"Sessions/Edge routers/Manchester/console-01.ini": file(
			`S:"Protocol Name"=Telnet`,
			`S:"Hostname"=10.1.0.1`,
			`D:"[TELNET] Port"=00000bb8`,
		),
		"Sessions/Default.ini": file(`S:"Emulation"=xterm`),
		"Global.ini":           file(`S:"Something"=global`),
	}
}

func TestSecureCRTImportBuildsTheTree(t *testing.T) {
	imported, err := FromSecureCRT(secureCRTTree(t, ""), SecureCRTOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if imported.Source != SourceSecureCRT {
		t.Errorf("source = %q", imported.Source)
	}

	sessionsByName := map[string]Session{}
	for _, session := range imported.Payload.Sessions {
		sessionsByName[session.Name] = session
	}
	if len(sessionsByName) != 4 {
		t.Fatalf("imported %d sessions, want 4: %v", len(sessionsByName), sessionNames(imported.Payload))
	}

	// --- the folder tree came across, with its nesting ---------------------

	foldersByName := map[string]Folder{}
	for _, folder := range imported.Payload.Folders {
		foldersByName[folder.Name] = folder
	}
	if len(foldersByName) != 3 {
		t.Fatalf("built %d folders, want Edge routers, London, Manchester: %+v",
			len(foldersByName), foldersByName)
	}
	if foldersByName["London"].ParentID != foldersByName["Edge routers"].ID {
		t.Error("London is not inside Edge routers")
	}
	if foldersByName["Edge routers"].ParentID != "" {
		t.Error("Edge routers is not at the top level")
	}
	if sessionsByName["core-sw-01"].FolderID != foldersByName["London"].ID {
		t.Error("core-sw-01 did not land in London")
	}
	if sessionsByName["jump-host"].FolderID != "" {
		t.Error("a top-level session was put in a folder")
	}

	// --- connection details -------------------------------------------------

	core := sessionsByName["core-sw-01"]
	if core.Hostname != "10.0.0.1" || core.Port != 22 || core.Username != "netops" {
		t.Errorf("core-sw-01 = %s@%s:%d", core.Username, core.Hostname, core.Port)
	}
	if !strings.Contains(string(core.Settings), "50000") {
		t.Errorf("the scrollback setting was lost: %s", core.Settings)
	}

	jump := sessionsByName["jump-host"]
	if jump.Port != 2222 {
		t.Errorf("jump-host port = %d, want 2222", jump.Port)
	}

	console := sessionsByName["console-01"]
	if console.Protocol != "telnet" || console.Port != 3000 {
		t.Errorf("console-01 = %s on port %d", console.Protocol, console.Port)
	}

	// --- passwords became credentials --------------------------------------

	credsByName := map[string]Credential{}
	for _, cred := range imported.Payload.Credentials {
		credsByName[cred.Name] = cred
	}
	if len(credsByName) != 2 {
		t.Fatalf("created %d credentials, want 2: %+v", len(credsByName), credsByName)
	}

	coreCredential := credsByName["SecureCRT: core-sw-01"]
	if coreCredential.Secret != "hunter2" {
		t.Errorf("core-sw-01's password = %q", coreCredential.Secret)
	}
	if coreCredential.Username != "netops" {
		t.Errorf("the credential's username = %q", coreCredential.Username)
	}
	if core.CredentialID != coreCredential.ID {
		t.Error("core-sw-01 does not point at its own password")
	}

	// A session with no saved password gets no credential rather than an
	// empty one, so the list is not padded with things that cannot be used.
	if sessionsByName["core-sw-02"].CredentialID != "" {
		t.Error("a session with no saved password was given a credential")
	}

	// --- the jump host resolved --------------------------------------------

	if len(core.JumpChain) != 1 || core.JumpChain[0] != jump.ID {
		t.Errorf("core-sw-01's jump chain = %v, want [%s]", core.JumpChain, jump.ID)
	}

	// --- and the user is told what could not come across --------------------

	warnings := strings.Join(imported.Warnings, "\n")
	if !strings.Contains(warnings, "id_ed25519") {
		t.Errorf("no warning about the key file that cannot travel: %v", imported.Warnings)
	}

	notes := strings.Join(imported.Notes, "\n")
	if !strings.Contains(notes, "all 2 saved passwords") {
		t.Errorf("notes do not report the password tally: %v", imported.Notes)
	}
	if !strings.Contains(notes, "Check one against SecureCRT") {
		t.Error("the notes do not tell the user to verify a password before trusting the rest")
	}
}

// TestSecureCRTImportIsDeterministic: two runs over one configuration must
// produce the same tree, so a user comparing them sees no spurious churn.
func TestSecureCRTImportIsDeterministic(t *testing.T) {
	tree := secureCRTTree(t, "")

	first, err := FromSecureCRT(tree, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := FromSecureCRT(tree, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(sessionNames(first.Payload), ",") != strings.Join(sessionNames(second.Payload), ",") {
		t.Errorf("two imports ordered the sessions differently:\n %v\n %v",
			sessionNames(first.Payload), sessionNames(second.Payload))
	}
	if len(first.Payload.Folders) != len(second.Payload.Folders) {
		t.Error("two imports produced different numbers of folders")
	}
}

// TestSecureCRTImportWithAConfigurationPassphrase.
func TestSecureCRTImportWithAConfigurationPassphrase(t *testing.T) {
	const passphrase = "the configuration passphrase"
	tree := secureCRTTree(t, passphrase)

	// Without it, the sessions come across and the passwords do not — and the
	// user is told which, rather than getting a device list that silently
	// cannot authenticate.
	without, err := FromSecureCRT(tree, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(without.Payload.Sessions) != 4 {
		t.Errorf("imported %d sessions without the passphrase", len(without.Payload.Sessions))
	}
	if len(without.Payload.Credentials) != 0 {
		t.Errorf("recovered %d passwords without the passphrase", len(without.Payload.Credentials))
	}
	if !strings.Contains(strings.Join(without.Warnings, "\n"), "configuration passphrase") {
		t.Errorf("no warning explaining what is needed: %v", without.Warnings)
	}

	// With it, everything comes.
	with, err := FromSecureCRT(tree, SecureCRTOptions{ConfigPassphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	if len(with.Payload.Credentials) != 2 {
		t.Fatalf("recovered %d passwords with the passphrase, want 2", len(with.Payload.Credentials))
	}
}

func TestSecureCRTImportWithoutPasswords(t *testing.T) {
	imported, err := FromSecureCRT(secureCRTTree(t, ""), SecureCRTOptions{SkipPasswords: true})
	if err != nil {
		t.Fatal(err)
	}

	if len(imported.Payload.Credentials) != 0 {
		t.Errorf("created %d credentials despite SkipPasswords", len(imported.Payload.Credentials))
	}
	if len(imported.Payload.Sessions) != 4 {
		t.Errorf("imported %d sessions", len(imported.Payload.Sessions))
	}
	if !strings.Contains(strings.Join(imported.Notes, "\n"), "left behind as you asked") {
		t.Errorf("the notes do not say what was left behind: %v", imported.Notes)
	}
}

func TestSecureCRTImportOfSomethingElseEntirely(t *testing.T) {
	imported, err := FromSecureCRT(fstest.MapFS{
		"holiday.jpg": &fstest.MapFile{Data: []byte("\xff\xd8\xff\xe0")},
		"notes.txt":   &fstest.MapFile{Data: []byte("nothing to see")},
	}, SecureCRTOptions{})
	if err != nil {
		t.Fatalf("pointing the importer at the wrong folder should not be an error: %v", err)
	}

	if len(imported.Payload.Sessions) != 0 {
		t.Error("sessions were invented from a folder of photographs")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "Sessions directory") {
		t.Errorf("the warning does not tell the user where to point it: %v", imported.Warnings)
	}
}

// TestSecureCRTImportLandsInTheDatabase is the whole journey: a SecureCRT
// configuration on disk becomes working connections with usable passwords.
func TestSecureCRTImportLandsInTheDatabase(t *testing.T) {
	imported, err := FromSecureCRT(secureCRTTree(t, ""), SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	instance := newInstance(t)
	ctx := context.Background()

	plan, err := instance.service.Preview(ctx, imported.Payload,
		ImportOptions{UserID: instance.userID})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NewSessions) != 4 || len(plan.NewFolders) != 3 {
		t.Errorf("plan = %+v", plan)
	}
	if !plan.HasSecrets {
		t.Error("the plan does not report that passwords came across")
	}

	result, err := instance.service.Import(ctx, instance.key, imported.Payload,
		ImportOptions{UserID: instance.userID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Sessions != 4 || result.Folders != 3 || result.Credentials != 2 {
		t.Fatalf("imported %+v", result)
	}

	tree, err := instance.tree.LoadTree(ctx, instance.userID, false)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]sessions.Session{}
	for _, session := range tree.Sessions {
		byName[session.Name] = session
	}

	core := byName["core-sw-01"]
	if core.Hostname != "10.0.0.1" || core.Username != "netops" {
		t.Errorf("core-sw-01 = %s@%s", core.Username, core.Hostname)
	}

	// The jump host survived both remappings — SecureCRT's name-based
	// reference into a bundle identifier, and the bundle identifier into a
	// database row.
	if len(core.JumpChain) != 1 || core.JumpChain[0] != byName["jump-host"].ID {
		t.Errorf("the jump chain did not survive: %v", core.JumpChain)
	}

	// And the password is retrievable, encrypted under this user's vault key
	// rather than SecureCRT's fixed one.
	stored, err := instance.creds.List(ctx, instance.userID, false)
	if err != nil {
		t.Fatal(err)
	}
	var credentialID string
	for _, cred := range stored {
		if cred.Name == "SecureCRT: core-sw-01" {
			credentialID = cred.ID
		}
	}
	if credentialID == "" {
		t.Fatalf("the imported credential is missing: %+v", stored)
	}
	if core.CredentialID != credentialID {
		t.Error("the connection does not point at its imported password")
	}

	secret, err := instance.creds.Reveal(ctx, instance.key, instance.userID, credentialID)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if secret.Value != "hunter2" {
		t.Errorf("the imported password reads back as %q", secret.Value)
	}
}

func sessionNames(p Payload) []string {
	out := make([]string, 0, len(p.Sessions))
	for _, session := range p.Sessions {
		out = append(out, session.Name)
	}
	return out
}
