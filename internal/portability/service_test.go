package portability

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"github.com/mrbuttshooter/securecrt/internal/vault"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

// instance is one bkd, with its own database and its own user.
//
// Two of them is what makes the round trip meaningful: exporting and
// importing into the same database would prove the format survives a
// function call, not that it survives leaving the building.
type instance struct {
	db      *store.DB
	service *Service
	tree    *sessions.Store
	creds   *credentials.Store
	hosts   *hostkeys.Store
	userID  string
	key     vault.Key
}

func newInstance(t *testing.T) *instance {
	t.Helper()

	db := storetest.New(t)
	ctx := context.Background()

	userID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, userID+"@example.com", userID+"@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}

	tree := sessions.NewStore(db)
	creds := credentials.NewStore(db)
	hosts := hostkeys.NewStore(db)

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	return &instance{
		db:      db,
		service: NewService(tree, creds, hosts, quiet),
		tree:    tree,
		creds:   creds,
		hosts:   hosts,
		userID:  userID,
		key:     key,
	}
}

// populate builds a small but representative world: nested folders with
// inherited defaults, connections referencing credentials, a jump chain, an
// accepted host key.
func (i *instance) populate(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	key, err := i.creds.Create(ctx, i.key, credentials.CreateParams{
		OwnerID: i.userID, Name: "netops key", Kind: credentials.KindSSHKey,
		Username: "netops",
		Secret:   "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
		Extra:    "the key passphrase",
		KeyType:  "ed25519", Fingerprint: "SHA256:aaa", PublicKey: "ssh-ed25519 AAAA netops",
	})
	if err != nil {
		t.Fatal(err)
	}

	password, err := i.creds.Create(ctx, i.key, credentials.CreateParams{
		OwnerID: i.userID, Name: "console password", Kind: credentials.KindPassword,
		Secret: "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}

	username := "netops"
	outer, err := i.tree.CreateFolder(ctx, sessions.CreateFolderParams{
		OwnerID: i.userID, Name: "Edge routers",
		Defaults: sessions.Settings{Username: &username},
	})
	if err != nil {
		t.Fatal(err)
	}

	inner, err := i.tree.CreateFolder(ctx, sessions.CreateFolderParams{
		OwnerID: i.userID, ParentID: outer.ID, Name: "London",
	})
	if err != nil {
		t.Fatal(err)
	}

	jump, err := i.tree.CreateSession(ctx, sessions.CreateSessionParams{
		OwnerID: i.userID, FolderID: outer.ID, Name: "jump-host",
		Protocol: sessions.ProtocolSSH, Hostname: "203.0.113.9", Port: 2222,
		Username: "bastion", CredentialID: key.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	scrollback := 50000
	if _, err := i.tree.CreateSession(ctx, sessions.CreateSessionParams{
		OwnerID: i.userID, FolderID: inner.ID, Name: "core-sw-01",
		Protocol: sessions.ProtocolSSH, Hostname: "10.0.0.1", Port: 22,
		CredentialID: password.ID,
		JumpChain:    []string{jump.ID},
		Settings:     sessions.Settings{Scrollback: &scrollback},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := i.hosts.Trust(ctx, i.userID, "10.0.0.1", 22, hostkeys.Presented{
		KeyType: "ssh-ed25519", PublicKey: "ssh-ed25519 AAAA host",
		Fingerprint: "SHA256:hostkey",
	}); err != nil {
		t.Fatal(err)
	}
}

// TestExportWipeImportOnASecondInstance is the phase's stated definition of
// done: everything comes back on a machine that has never seen it.
func TestExportWipeImportOnASecondInstance(t *testing.T) {
	source := newInstance(t)
	source.populate(t)

	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key, GatherOptions{
		UserID:            source.userID,
		IncludeSecrets:    true,
		IncludeKnownHosts: true,
	})
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var archive bytes.Buffer
	if err := Write(&archive, payload, WriteOptions{
		Passphrase: []byte(testPassphrase),
		CreatedBy:  "alice@example.com",
		KDF:        cheapKDF(t),
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// A different bkd, with a different database and a different vault key —
	// which is the point. Nothing about the source is available here except
	// the bytes and the passphrase.
	destination := newInstance(t)

	bundle, err := Read(&archive)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	restored, err := bundle.Open([]byte(testPassphrase))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	result, err := destination.service.Import(ctx, destination.key, restored, ImportOptions{
		UserID: destination.userID,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.Folders != 2 || result.Sessions != 2 || result.Credentials != 2 || result.KnownHosts != 1 {
		t.Fatalf("imported %+v", result)
	}

	// --- the tree came back, nesting and all -------------------------------

	tree, err := destination.tree.LoadTree(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}

	folders := map[string]sessions.Folder{}
	for _, folder := range tree.Folders {
		folders[folder.Name] = folder
	}
	if len(folders) != 2 {
		t.Fatalf("restored %d folders", len(folders))
	}
	if folders["London"].ParentID != folders["Edge routers"].ID {
		t.Error("the folder nesting was lost")
	}
	if folders["Edge routers"].Defaults.Username == nil ||
		*folders["Edge routers"].Defaults.Username != "netops" {
		t.Errorf("the folder's inherited username was lost: %+v", folders["Edge routers"].Defaults)
	}

	byName := map[string]sessions.Session{}
	for _, session := range tree.Sessions {
		byName[session.Name] = session
	}

	core := byName["core-sw-01"]
	if core.Hostname != "10.0.0.1" || core.Port != 22 {
		t.Errorf("core-sw-01 = %s:%d", core.Hostname, core.Port)
	}
	if core.FolderID != folders["London"].ID {
		t.Error("core-sw-01 did not land in its folder")
	}
	if core.Settings.Scrollback == nil || *core.Settings.Scrollback != 50000 {
		t.Errorf("the per-connection settings were lost: %+v", core.Settings)
	}

	// --- the jump chain points at the right host, remapped -----------------

	if len(core.JumpChain) != 1 {
		t.Fatalf("the jump chain came back as %v", core.JumpChain)
	}
	if core.JumpChain[0] != byName["jump-host"].ID {
		t.Error("the jump chain points at the wrong connection after remapping")
	}

	// --- the secrets came back, which is the whole point -------------------

	restoredCreds, err := destination.creds.List(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}
	credsByName := map[string]credentials.Credential{}
	for _, cred := range restoredCreds {
		credsByName[cred.Name] = cred
	}

	keySecret, err := destination.creds.Reveal(ctx, destination.key,
		destination.userID, credsByName["netops key"].ID)
	if err != nil {
		t.Fatalf("reveal the restored key: %v", err)
	}
	if !strings.Contains(keySecret.Value, "OPENSSH PRIVATE KEY") {
		t.Errorf("the private key came back as %q", keySecret.Value)
	}
	if keySecret.Extra != "the key passphrase" {
		t.Errorf("the key's passphrase came back as %q", keySecret.Extra)
	}

	passwordSecret, err := destination.creds.Reveal(ctx, destination.key,
		destination.userID, credsByName["console password"].ID)
	if err != nil {
		t.Fatalf("reveal the restored password: %v", err)
	}
	if passwordSecret.Value != "hunter2" {
		t.Errorf("the password came back as %q", passwordSecret.Value)
	}

	// The public half and fingerprint survived too, so the list renders
	// without unlocking anything.
	if credsByName["netops key"].Fingerprint != "SHA256:aaa" {
		t.Errorf("the fingerprint came back as %q", credsByName["netops key"].Fingerprint)
	}

	// --- connections still point at their credentials ----------------------

	if core.CredentialID != credsByName["console password"].ID {
		t.Error("core-sw-01 lost its credential in the remapping")
	}
	if byName["jump-host"].CredentialID != credsByName["netops key"].ID {
		t.Error("jump-host lost its credential in the remapping")
	}

	// --- the accepted host key came with it --------------------------------

	known, err := destination.hosts.ListForUser(ctx, destination.userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 1 || known[0].Fingerprint != "SHA256:hostkey" {
		t.Errorf("known hosts = %+v", known)
	}
}

// TestIdentifiersAreRemappedNotReused: honouring the identifiers in a file
// somebody else wrote would let a crafted bundle address — and overwrite —
// rows it was never given.
func TestIdentifiersAreRemappedNotReused(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key, GatherOptions{
		UserID: source.userID, IncludeSecrets: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	destination := newInstance(t)
	if _, err := destination.service.Import(ctx, destination.key, payload, ImportOptions{
		UserID: destination.userID,
	}); err != nil {
		t.Fatal(err)
	}

	tree, err := destination.tree.LoadTree(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}

	original := map[string]bool{}
	for _, folder := range payload.Folders {
		original[folder.ID] = true
	}
	for _, session := range payload.Sessions {
		original[session.ID] = true
	}

	for _, folder := range tree.Folders {
		if original[folder.ID] {
			t.Errorf("the folder %q kept the identifier from the bundle", folder.Name)
		}
	}
	for _, session := range tree.Sessions {
		if original[session.ID] {
			t.Errorf("the connection %q kept the identifier from the bundle", session.Name)
		}
	}
}

// TestImportingTwiceDoesNotDuplicate: the default policy leaves what is
// already here alone, because an import that silently replaces a working
// connection is worse than one that quietly declines to.
func TestImportingTwiceDoesNotDuplicate(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key,
		GatherOptions{UserID: source.userID, IncludeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}

	destination := newInstance(t)

	first, err := destination.service.Import(ctx, destination.key, payload,
		ImportOptions{UserID: destination.userID})
	if err != nil {
		t.Fatal(err)
	}
	if first.Skipped != 0 {
		t.Errorf("the first import skipped %d records", first.Skipped)
	}

	second, err := destination.service.Import(ctx, destination.key, payload,
		ImportOptions{UserID: destination.userID})
	if err != nil {
		t.Fatal(err)
	}
	if second.Sessions != 0 || second.Folders != 0 || second.Credentials != 0 {
		t.Errorf("the second import created records anyway: %+v", second)
	}
	if second.Skipped == 0 {
		t.Error("the second import reported nothing skipped")
	}

	tree, err := destination.tree.LoadTree(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Sessions) != 2 || len(tree.Folders) != 2 {
		t.Errorf("after importing twice: %d folders, %d connections",
			len(tree.Folders), len(tree.Sessions))
	}
}

func TestRenameOnConflictImportsAlongside(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key,
		GatherOptions{UserID: source.userID, IncludeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}

	destination := newInstance(t)
	if _, err := destination.service.Import(ctx, destination.key, payload,
		ImportOptions{UserID: destination.userID}); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.service.Import(ctx, destination.key, payload,
		ImportOptions{UserID: destination.userID, OnConflict: ConflictRename}); err != nil {
		t.Fatal(err)
	}

	tree, err := destination.tree.LoadTree(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, session := range tree.Sessions {
		names = append(names, session.Name)
	}
	sort.Strings(names)

	if len(names) != 4 {
		t.Fatalf("connections = %v, want four", names)
	}
	if !contains(names, "core-sw-01") || !contains(names, "core-sw-01 (2)") {
		t.Errorf("connections = %v, want the original and a renamed copy", names)
	}
}

// TestImportIntoAFolderQuarantinesIt: somebody restoring a colleague's bundle
// needs it somewhere they can look at before it is mixed into their own tree.
func TestImportIntoAFolderQuarantinesIt(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key,
		GatherOptions{UserID: source.userID, IncludeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}

	destination := newInstance(t)
	quarantine, err := destination.tree.CreateFolder(ctx, sessions.CreateFolderParams{
		OwnerID: destination.userID, Name: "Imported",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := destination.service.Import(ctx, destination.key, payload, ImportOptions{
		UserID: destination.userID, IntoFolder: quarantine.ID,
	}); err != nil {
		t.Fatal(err)
	}

	tree, err := destination.tree.LoadTree(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, folder := range tree.Folders {
		if folder.Name == "Edge routers" && folder.ParentID != quarantine.ID {
			t.Error("the bundle's top-level folder did not land inside the quarantine")
		}
	}
	// Nothing may be left at the top level except the quarantine folder.
	for _, session := range tree.Sessions {
		if session.FolderID == "" {
			t.Errorf("%q landed at the top level rather than inside the quarantine", session.Name)
		}
	}
}

// TestGatherWithoutSecretsCarriesNoSecrets: sharing a device list with a
// colleague must not hand over the keys with it.
func TestGatherWithoutSecretsCarriesNoSecrets(t *testing.T) {
	source := newInstance(t)
	source.populate(t)

	payload, err := source.service.Gather(context.Background(), source.key,
		GatherOptions{UserID: source.userID, IncludeSecrets: false})
	if err != nil {
		t.Fatal(err)
	}

	if len(payload.Credentials) != 2 {
		t.Fatalf("credentials = %d, want the records without their secrets", len(payload.Credentials))
	}
	for _, cred := range payload.Credentials {
		if cred.Secret != "" || cred.Extra != "" {
			t.Errorf("%q carries a secret despite IncludeSecrets being off", cred.Name)
		}
		// The public half still travels, so the connections remain
		// recognisable and the recipient can be told which key to supply.
		if cred.Name == "netops key" && cred.Fingerprint == "" {
			t.Error("the fingerprint was dropped along with the secret")
		}
	}
}

// TestPreviewSaysWhatWouldHappenBeforeItDoes.
func TestPreviewSaysWhatWouldHappenBeforeItDoes(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key,
		GatherOptions{UserID: source.userID, IncludeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}

	destination := newInstance(t)

	plan, err := destination.service.Preview(ctx, payload, ImportOptions{UserID: destination.userID})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NewSessions) != 2 || len(plan.NewFolders) != 2 {
		t.Errorf("plan = %+v", plan)
	}
	if len(plan.Conflicts) != 0 {
		t.Errorf("a fresh instance reported conflicts: %+v", plan.Conflicts)
	}
	if !plan.HasSecrets {
		t.Error("the plan does not report that the bundle carries secrets")
	}

	// Previewing must not have written anything.
	tree, err := destination.tree.LoadTree(ctx, destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Sessions) != 0 || len(tree.Folders) != 0 {
		t.Fatal("previewing an import created records")
	}

	// After importing, the same preview reports every one as a conflict.
	if _, err := destination.service.Import(ctx, destination.key, payload,
		ImportOptions{UserID: destination.userID}); err != nil {
		t.Fatal(err)
	}

	again, err := destination.service.Preview(ctx, payload, ImportOptions{UserID: destination.userID})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Conflicts) != 6 {
		t.Errorf("%d conflicts reported, want one per record: %+v", len(again.Conflicts), again.Conflicts)
	}
	if len(again.NewSessions) != 0 || len(again.NewFolders) != 0 {
		t.Error("the plan still claims records would be created")
	}
}

// TestPreviewWarnsAboutABundleWithNoSecrets: finding out after importing that
// nothing can authenticate is a bad afternoon.
func TestPreviewWarnsAboutABundleWithNoSecrets(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key,
		GatherOptions{UserID: source.userID, IncludeSecrets: false})
	if err != nil {
		t.Fatal(err)
	}

	destination := newInstance(t)
	plan, err := destination.service.Preview(ctx, payload, ImportOptions{UserID: destination.userID})
	if err != nil {
		t.Fatal(err)
	}

	if plan.HasSecrets {
		t.Error("a bundle without secrets reported having them")
	}
	if len(plan.Warnings) == 0 {
		t.Fatal("no warning about a bundle that cannot authenticate anything")
	}
	if !strings.Contains(strings.Join(plan.Warnings, " "), "keys or passwords") {
		t.Errorf("the warning does not explain the problem: %v", plan.Warnings)
	}
}

// TestACycleInTheFolderTreeDoesNotHang: a hand-edited or corrupt bundle can
// name a folder as its own ancestor, and an import that recursed on it would
// never return.
func TestACycleInTheFolderTreeDoesNotHang(t *testing.T) {
	payload := Payload{
		Folders: []Folder{
			{ID: "a", ParentID: "b", Name: "A"},
			{ID: "b", ParentID: "a", Name: "B"},
			{ID: "c", Name: "C"},
		},
	}

	destination := newInstance(t)

	done := make(chan error, 1)
	go func() {
		_, err := destination.service.Import(context.Background(), destination.key, payload,
			ImportOptions{UserID: destination.userID})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("import: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("importing a folder cycle did not finish")
	}

	tree, err := destination.tree.LoadTree(context.Background(), destination.userID, false)
	if err != nil {
		t.Fatal(err)
	}
	// Flattened rather than dropped: a user would rather find their folders
	// in the wrong place than not at all.
	if len(tree.Folders) != 3 {
		t.Errorf("restored %d folders from a cycle, want all 3", len(tree.Folders))
	}
}

// TestOrgWideHostKeysDoNotTravel: they belong to the administrator who
// published them, and carrying them would let a restored instance inherit
// trust decisions nobody made there.
func TestOrgWideHostKeysDoNotTravel(t *testing.T) {
	source := newInstance(t)
	ctx := context.Background()

	if _, err := source.hosts.TrustOrgWide(ctx, "shared.example.com", 22, hostkeys.Presented{
		KeyType: "ssh-ed25519", PublicKey: "ssh-ed25519 AAAA org", Fingerprint: "SHA256:org",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.hosts.Trust(ctx, source.userID, "mine.example.com", 22, hostkeys.Presented{
		KeyType: "ssh-ed25519", PublicKey: "ssh-ed25519 AAAA mine", Fingerprint: "SHA256:mine",
	}); err != nil {
		t.Fatal(err)
	}

	payload, err := source.service.Gather(ctx, source.key, GatherOptions{
		UserID: source.userID, IncludeKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(payload.KnownHosts) != 1 {
		t.Fatalf("known hosts = %+v, want only the user's own", payload.KnownHosts)
	}
	if payload.KnownHosts[0].Hostname != "mine.example.com" {
		t.Errorf("carried %q", payload.KnownHosts[0].Hostname)
	}
}

func TestSkipKnownHostsLeavesThemBehind(t *testing.T) {
	source := newInstance(t)
	source.populate(t)
	ctx := context.Background()

	payload, err := source.service.Gather(ctx, source.key, GatherOptions{
		UserID: source.userID, IncludeSecrets: true, IncludeKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.KnownHosts) == 0 {
		t.Fatal("the fixture carries no host keys, so this proves nothing")
	}

	destination := newInstance(t)
	result, err := destination.service.Import(ctx, destination.key, payload, ImportOptions{
		UserID: destination.userID, SkipKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KnownHosts != 0 {
		t.Errorf("imported %d host keys despite being asked not to", result.KnownHosts)
	}

	known, err := destination.hosts.ListForUser(ctx, destination.userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 0 {
		t.Errorf("%d host keys were recorded anyway", len(known))
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
