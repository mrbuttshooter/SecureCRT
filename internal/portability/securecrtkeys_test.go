package portability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/crypto/ssh"

	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
)

// newTestKey makes a throwaway ed25519 key and its OpenSSH private-key file,
// encrypted under passphrase when one is given.
func newTestKey(t *testing.T, passphrase string) ([]byte, ssh.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(private, "test key")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "test key", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), sshPublic
}

func iniFile(lines ...string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(strings.Join(lines, "\n") + "\n")}
}

func credentialByID(t *testing.T, imported Import, id string) Credential {
	t.Helper()
	for _, c := range imported.Payload.Credentials {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no credential %q", id)
	return Credential{}
}

func sessionNamed(t *testing.T, imported Import, name string) Session {
	t.Helper()
	for _, s := range imported.Payload.Sessions {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no session %q", name)
	return Session{}
}

func TestSecureCRTKeysComeAcrossWithoutAPassphrase(t *testing.T) {
	ownKey, ownPublic := newTestKey(t, "")
	globalKey, globalPublic := newTestKey(t, "")

	imported, err := FromSecureCRT(fstest.MapFS{
		// Its own key, named by its public half with SecureCRT's path
		// variable and option suffix — the shape SecureCRT 9 writes.
		"Sessions/core-sw-01.ini": iniFile(
			`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.0.1`, `S:"Username"=netops`,
			`D:"Use Global Public Key"=00000000`,
			`S:"Identity Filename V2"=${VDS_USER_DATA_PATH}\Identity.pub::rawkey`,
			`S:"SSH2 Authentications V2"=publickey,password`,
		),
		// Two sessions on the global key share one credential.
		"Sessions/edge-01.ini": iniFile(
			`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.1.1`,
			`D:"Use Global Public Key"=00000001`,
		),
		"Sessions/edge-02.ini": iniFile(
			`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.1.2`,
			`D:"Use Global Public Key"=00000001`,
		),
		"SSH2.ini": iniFile(`S:"Identity Filename V2"=C:\Users\alice\.ssh\id_ed25519`),
		// The key files, added to the zip beside the Config folder.
		"keys/Identity":   &fstest.MapFile{Data: ownKey},
		"keys/id_ed25519": &fstest.MapFile{Data: globalKey},
	}, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	core := sessionNamed(t, imported, "core-sw-01")
	if core.CredentialID == "" {
		t.Fatalf("the session's own key was not attached; warnings: %v", imported.Warnings)
	}
	own := credentialByID(t, imported, core.CredentialID)
	if own.Kind != "ssh_key" || own.Fingerprint != ssh.FingerprintSHA256(ownPublic) {
		t.Fatalf("own key credential = %+v", own)
	}
	if _, err := ssh.ParsePrivateKey([]byte(own.Secret)); err != nil {
		t.Fatalf("the imported key does not parse without a passphrase: %v", err)
	}

	edge1 := sessionNamed(t, imported, "edge-01")
	edge2 := sessionNamed(t, imported, "edge-02")
	if edge1.CredentialID == "" || edge1.CredentialID != edge2.CredentialID {
		t.Fatalf("sessions on the global key should share one credential: %q, %q",
			edge1.CredentialID, edge2.CredentialID)
	}
	if got := credentialByID(t, imported, edge1.CredentialID).Fingerprint; got != ssh.FingerprintSHA256(globalPublic) {
		t.Fatalf("global key fingerprint = %s", got)
	}

	keys := 0
	for _, c := range imported.Payload.Credentials {
		if c.Kind == "ssh_key" {
			keys++
		}
	}
	if keys != 2 {
		t.Fatalf("want 2 key credentials, got %d", keys)
	}
}

func TestSecureCRTKeyProblemsAreExplained(t *testing.T) {
	encrypted, _ := newTestKey(t, "correct horse")

	tree := fstest.MapFS{
		"Sessions/vandyke.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.0.1`,
			`S:"Identity Filename V2"=C:\Users\alice\Documents\Identity`),
		"Sessions/token.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.0.2`,
			`S:"Identity Filename V2"=pkcs11::prov=C:\eTPKCS11.dll::cert`),
		"Sessions/missing.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.0.3`,
			`S:"Identity Filename V2"=C:\Users\alice\.ssh\nowhere`),
		"Sessions/locked.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.0.4`,
			`S:"Identity Filename V2"=C:\keys\locked`),
		// Not a format this reads: stands in for SecureCRT's own.
		"Identity": &fstest.MapFile{Data: []byte("\x00\x00\x00\x07ssh-rsa\x00\x01opaque blob")},
		"locked":   &fstest.MapFile{Data: encrypted},
	}

	imported, err := FromSecureCRT(tree, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(imported.Warnings, "\n")
	for _, want := range []string{
		"Convert Private Key to OpenSSH Format", // SecureCRT's own format
		"smart card or token",                   // PKCS#11
		"was not in the upload",                 // the file is elsewhere
		"locked is encrypted",                   // imported, passphrase to follow
	} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, warnings)
		}
	}
	if sessionNamed(t, imported, "vandyke").CredentialID != "" {
		t.Error("a key that could not be read was still attached")
	}
	if sessionNamed(t, imported, "locked").CredentialID == "" {
		t.Error("an encrypted key should still be imported and attached")
	}

	// With its passphrase, the encrypted key is opened and stored decrypted.
	opened, err := FromSecureCRT(tree, SecureCRTOptions{KeyPassphrase: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	locked := credentialByID(t, opened, sessionNamed(t, opened, "locked").CredentialID)
	if _, err := ssh.ParsePrivateKey([]byte(locked.Secret)); err != nil {
		t.Fatalf("with the passphrase given, the key should be stored decrypted: %v", err)
	}
}

func TestSecureCRTPasswordFirstSessionsKeepTheirPassword(t *testing.T) {
	key, _ := newTestKey(t, "")
	password, err := securecrt.EncryptV2("hunter2", "")
	if err != nil {
		t.Fatal(err)
	}
	imported, err := FromSecureCRT(fstest.MapFS{
		"Sessions/router.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.0.1`,
			`D:"Use Global Public Key"=00000001`,
			`S:"SSH2 Authentications V2"=password,publickey`,
			`S:"Password V2"=`+password),
		"SSH2.ini":   iniFile(`S:"Identity Filename V2"=C:\Users\alice\.ssh\id_ed25519`),
		"id_ed25519": &fstest.MapFile{Data: key},
	}, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// SecureCRT tried the password first, so the connection keeps it.
	got := credentialByID(t, imported, sessionNamed(t, imported, "router").CredentialID)
	if got.Kind != "password" {
		t.Fatalf("a password-first session got a %s credential", got.Kind)
	}
}

func TestSecureCRTXMLSaysKeysNeedTheFolder(t *testing.T) {
	result := securecrt.Result{Sessions: []securecrt.Session{{
		Path: "router.ini", Name: "router", Protocol: "ssh", Hostname: "10.0.0.1", Port: 22,
		IdentityFile: `C:\Users\alice\Documents\Identity`,
	}}}
	imported, err := fromSecureCRTResult(result, SecureCRTOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "settings XML holds key paths") {
		t.Fatalf("warnings: %v", imported.Warnings)
	}
}

func TestSecureCRTFindsAPuTTYKeyAndTheRightOneOfTwo(t *testing.T) {
	ppkKey, err := os.ReadFile("ppk/testdata/v2-ecdsa.ppk")
	if err != nil {
		t.Fatal(err)
	}
	workKey, workPublic := newTestKey(t, "")
	homeKey, _ := newTestKey(t, "")

	imported, err := FromSecureCRT(fstest.MapFS{
		// SecureCRT names the bare file; only the .ppk beside it exists.
		"Sessions/lab.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.2.1`,
			`S:"Identity Filename V2"=D:\keys\lab`),
		"keys/lab.ppk": &fstest.MapFile{Data: ppkKey},
		// Two files called id_rsa; the stored path says which.
		"Sessions/work.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.2.2`,
			`S:"Identity Filename V2"=C:\Users\alice\work\id_rsa`),
		"home/id_rsa": &fstest.MapFile{Data: homeKey},
		"work/id_rsa": &fstest.MapFile{Data: workKey},
		// Two files called shared, and a path that names neither folder.
		"Sessions/unclear.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.2.3`,
			`S:"Identity Filename V2"=C:\elsewhere\shared`),
		"a/shared": &fstest.MapFile{Data: homeKey},
		"b/shared": &fstest.MapFile{Data: workKey},
	}, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}

	lab := credentialByID(t, imported, sessionNamed(t, imported, "lab").CredentialID)
	if _, err := ssh.ParsePrivateKey([]byte(lab.Secret)); err != nil {
		t.Fatalf("the .ppk fallback should import as OpenSSH: %v", err)
	}
	work := credentialByID(t, imported, sessionNamed(t, imported, "work").CredentialID)
	if work.Fingerprint != ssh.FingerprintSHA256(workPublic) {
		t.Fatal("the key from the folder the session names should win")
	}
	if sessionNamed(t, imported, "unclear").CredentialID != "" {
		t.Error("an ambiguous key must not be guessed at")
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "files called shared") {
		t.Errorf("the ambiguity should be explained: %v", imported.Warnings)
	}
}

func TestSecureCRTKeysAreForSSHSessionsOnly(t *testing.T) {
	key, _ := newTestKey(t, "")
	imported, err := FromSecureCRT(fstest.MapFS{
		"Sessions/console.ini": iniFile(`S:"Protocol Name"=Telnet`, `S:"Hostname"=10.0.3.1`,
			`D:"Use Global Public Key"=00000001`),
		"Sessions/old.ini": iniFile(`S:"Protocol Name"=RLogin`, `S:"Hostname"=10.0.3.2`,
			`D:"Use Global Public Key"=00000001`),
		"SSH2.ini":   iniFile(`S:"Identity Filename V2"=C:\Users\alice\.ssh\id_ed25519`),
		"id_ed25519": &fstest.MapFile{Data: key},
	}, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"console", "old"} {
		if sessionNamed(t, imported, name).CredentialID != "" {
			t.Errorf("%s is not an SSH session and should not be given a key", name)
		}
	}
	for _, c := range imported.Payload.Credentials {
		if c.Kind == "ssh_key" {
			t.Error("a key nothing uses was imported anyway")
		}
	}
}

func TestSecureCRTSaysWhenTheGlobalKeySettingIsMissing(t *testing.T) {
	imported, err := FromSecureCRT(fstest.MapFS{
		"Sessions/edge.ini": iniFile(`S:"Protocol Name"=SSH2`, `S:"Hostname"=10.0.4.1`,
			`D:"Use Global Public Key"=00000001`),
	}, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(imported.Warnings, "\n"), "SSH2.ini") {
		t.Errorf("a session on the global key with no SSH2.ini should be reported: %v", imported.Warnings)
	}
}

func TestSecureCRTReadsAKeyFileOnceAndWarnsOnce(t *testing.T) {
	tree := fstest.MapFS{
		"Identity": &fstest.MapFile{Data: []byte("\x00\x01not a key format this reads")},
	}
	for i := 0; i < 50; i++ {
		tree[fmt.Sprintf("Sessions/host-%02d.ini", i)] = iniFile(`S:"Protocol Name"=SSH2`,
			fmt.Sprintf(`S:"Hostname"=10.0.5.%d`, i+1),
			`S:"Identity Filename V2"=${VDS_USER_DATA_PATH}\Identity`)
	}
	imported, err := FromSecureCRT(tree, SecureCRTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(imported.Warnings, "\n"), "Convert Private Key"); n != 1 {
		t.Fatalf("one bad key file used by 50 sessions should be one warning, got %d", n)
	}
}
