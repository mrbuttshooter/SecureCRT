package terminal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/credentials"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/remote"
	"github.com/mrbuttshooter/securecrt/internal/sessions"
	"github.com/mrbuttshooter/securecrt/internal/store"
	"github.com/mrbuttshooter/securecrt/internal/store/storetest"
	"github.com/mrbuttshooter/securecrt/internal/vault"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	code := m.Run()
	storetest.DropSchema()
	os.Exit(code)
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// --- a real SSH server, in-process ------------------------------------------

type sshServer struct {
	Host    string
	Port    int
	HostKey ssh.PublicKey
	server  *gssh.Server

	// auths counts credentials offered. Two terminals on one saved
	// connection must produce one authentication, not two — the assertion
	// that connection sharing is real rather than incidental.
	mu    sync.Mutex
	auths int
}

func (s *sshServer) authCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auths
}

func startSSHServer(t *testing.T, password string, seed []byte) *sshServer {
	t.Helper()

	if seed == nil {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	ts := &sshServer{HostKey: signer.PublicKey()}

	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		PasswordHandler: func(_ gssh.Context, given string) bool {
			ts.mu.Lock()
			ts.auths++
			ts.mu.Unlock()
			return given == password
		},
		Handler: func(s gssh.Session) {
			_, _, isPty := s.Pty()
			if !isPty {
				_ = s.Exit(1)
				return
			}
			_, _ = io.WriteString(s, "READY\r\n")

			buf := make([]byte, 512)
			for {
				n, err := s.Read(buf)
				if n > 0 {
					line := strings.TrimSpace(string(buf[:n]))
					if line == "exit" {
						_, _ = io.WriteString(s, "GOODBYE\r\n")
						_ = s.Exit(0)
						return
					}
					_, _ = s.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	ts.Host, ts.Port, ts.server = host, port, srv
	return ts
}

// --- test fixture -----------------------------------------------------------

type fixture struct {
	connector *Connector
	manager   *Manager
	pool      *remote.Pool
	sessions  *sessions.Store
	creds     *credentials.Store
	hostKeys  *hostkeys.Store
	db        *store.DB
	userID    string
	vaultKey  vault.Key
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	db := storetest.New(t)
	ctx := context.Background()

	userID := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, email_normalized, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, "alice@example.com", "alice@example.com", now, now); err != nil {
		t.Fatal(err)
	}

	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}

	manager := NewManager(quietLogger())
	t.Cleanup(manager.Close)

	sessStore := sessions.NewStore(db)
	credStore := credentials.NewStore(db)
	hkStore := hostkeys.NewStore(db)

	pool := remote.NewPool(quietLogger())
	t.Cleanup(pool.Close)
	dialer := remote.NewDialer(pool, sessStore, credStore, hkStore, quietLogger())

	return &fixture{
		connector: NewConnector(manager, dialer, quietLogger()),
		pool:      pool,
		manager:   manager,
		sessions:  sessStore,
		creds:     credStore,
		hostKeys:  hkStore,
		db:        db,
		userID:    userID,
		vaultKey:  key,
	}
}

// savedConnection creates a credential and a saved connection pointing at srv.
func (f *fixture) savedConnection(t *testing.T, srv *sshServer, password string) sessions.Session {
	t.Helper()
	ctx := context.Background()

	cred, err := f.creds.Create(ctx, f.vaultKey, credentials.CreateParams{
		OwnerID: f.userID, Name: "test password", Kind: credentials.KindPassword, Secret: password,
	})
	if err != nil {
		t.Fatal(err)
	}

	sess, err := f.sessions.CreateSession(ctx, sessions.CreateSessionParams{
		OwnerID:      f.userID,
		Name:         "test host",
		Hostname:     srv.Host,
		Port:         srv.Port,
		Username:     "alice",
		CredentialID: cred.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// acceptingPrompter approves whatever it is shown.
type acceptingPrompter struct {
	mu      sync.Mutex
	prompts []HostKeyInfo
}

func (p *acceptingPrompter) PromptHostKey(_ context.Context, info HostKeyInfo) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prompts = append(p.prompts, info)
	return true, nil
}

func (p *acceptingPrompter) seen() []HostKeyInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]HostKeyInfo, len(p.prompts))
	copy(out, p.prompts)
	return out
}

// decliningPrompter refuses, as a user who does not recognise a fingerprint
// would.
type decliningPrompter struct{ asked bool }

func (p *decliningPrompter) PromptHostKey(context.Context, HostKeyInfo) (bool, error) {
	p.asked = true
	return false, nil
}

// --- tests ------------------------------------------------------------------

func TestConnectAndRunACommand(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	prompter := &acceptingPrompter{}
	var progress []string

	term, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID:    f.userID,
		SessionID: sess.ID,
		VaultKey:  f.vaultKey,
		Cols:      100,
		Rows:      30,
		Prompter:  prompter,
		Progress:  func(s string) { progress = append(progress, s) },
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer f.manager.CloseTerminal(f.userID, term.ID) //nolint:errcheck

	// The user must be shown progress rather than a blank rectangle.
	if len(progress) == 0 {
		t.Error("no progress was reported during connection")
	}

	view := attach(t, term)
	view.waitFor(t, "READY", 5*time.Second)

	if err := term.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	view.waitFor(t, "hello", 5*time.Second)

	// First contact must have asked, with the fingerprint available.
	prompts := prompter.seen()
	if len(prompts) != 1 {
		t.Fatalf("the user was asked %d times, want once", len(prompts))
	}
	if !strings.HasPrefix(prompts[0].Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", prompts[0].Fingerprint)
	}
}

// TestASecondTerminalSharesTheConnection is what makes the file browser cheap
// and what keeps a device's session limit from being the thing that stops an
// engineer working.
//
// Two terminals on the same saved connection must ride one SSH connection:
// one TCP session, one authentication, one vty line on equipment that counts
// them.
func TestASecondTerminalSharesTheConnection(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	open := func() *Terminal {
		t.Helper()
		term, err := f.connector.Connect(context.Background(), ConnectParams{
			UserID:    f.userID,
			SessionID: sess.ID,
			VaultKey:  f.vaultKey,
			Prompter:  &acceptingPrompter{},
		})
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		return term
	}

	first := open()
	second := open()

	if n := srv.authCount(); n != 1 {
		t.Errorf("the host authenticated %d times for two terminals, want 1", n)
	}
	if n := f.pool.Len(); n != 1 {
		t.Errorf("%d SSH connections are open for two terminals, want 1", n)
	}

	// Both must actually work, which is the point of sharing rather than
	// merely counting.
	firstView := attach(t, first)
	firstView.waitFor(t, "READY", 5*time.Second)
	secondView := attach(t, second)
	secondView.waitFor(t, "READY", 5*time.Second)

	// Closing one must leave the other alive. Without reference counting this
	// is where the second terminal would silently die.
	if err := f.manager.CloseTerminal(f.userID, first.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.pool.Len(); n != 1 {
		t.Fatal("closing one terminal closed the shared connection")
	}

	if err := second.Write([]byte("still here\n")); err != nil {
		t.Fatalf("the surviving terminal is broken: %v", err)
	}
	secondView.waitFor(t, "still here", 5*time.Second)

	if err := f.manager.CloseTerminal(f.userID, second.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.pool.Len(); n != 0 {
		t.Errorf("%d connections remain after the last terminal closed", n)
	}
}

// TestSecondConnectionIsNotPromptedAgain confirms the accepted key was
// actually recorded, rather than the prompt merely being answered.
func TestSecondConnectionIsNotPromptedAgain(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	prompter := &acceptingPrompter{}
	connect := func() (*Terminal, error) {
		return f.connector.Connect(context.Background(), ConnectParams{
			UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: prompter,
		})
	}

	first, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.manager.CloseTerminal(f.userID, first.ID)

	second, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.manager.CloseTerminal(f.userID, second.ID)

	if n := len(prompter.seen()); n != 1 {
		t.Fatalf("the user was asked %d times; the accepted key should have been recorded", n)
	}
}

// TestDecliningAHostKeyConnectsToNothing is the guarantee that a refused key
// means no credential was sent.
func TestDecliningAHostKeyConnectsToNothing(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	prompter := &decliningPrompter{}
	_, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: prompter,
	})
	if err == nil {
		t.Fatal("declining the host key must fail the connection")
	}
	if !prompter.asked {
		t.Fatal("the user was never asked")
	}

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeHostKeyRejected {
		t.Fatalf("want a host_key_rejected ConnectError, got %v", err)
	}

	// And nothing must have been recorded, so the question is asked again.
	entries, listErr := f.hostKeys.ListForUser(context.Background(), f.userID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(entries) != 0 {
		t.Fatalf("%d host keys were recorded despite the user declining", len(entries))
	}
}

// TestChangedHostKeyIsRefusedWithoutAsking is the central protection: a
// changed key must not produce a prompt, because there is no answer that
// continues safely and offering one trains people to click through it.
func TestChangedHostKeyIsRefusedWithoutAsking(t *testing.T) {
	f := newFixture(t)

	seedA := bytes32(1)
	seedB := bytes32(2)

	original := startSSHServer(t, "hunter2", seedA)
	sess := f.savedConnection(t, original, "hunter2")

	// Trust the original key.
	prompter := &acceptingPrompter{}
	term, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: prompter,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = f.manager.CloseTerminal(f.userID, term.ID)

	// A different server now answers on a new address; point the saved
	// connection at it while keeping the recorded key for the old hostname.
	impostor := startSSHServer(t, "hunter2", seedB)
	if _, err := f.hostKeys.Trust(context.Background(), f.userID, impostor.Host, impostor.Port,
		hostkeys.DescribeKey(original.HostKey)); err != nil {
		t.Fatal(err)
	}

	newPort := impostor.Port
	newHost := impostor.Host
	if _, err := f.sessions.UpdateSession(context.Background(), f.userID, sess.ID,
		sessions.UpdateSessionParams{Hostname: &newHost, Port: &newPort}); err != nil {
		t.Fatal(err)
	}

	strict := &acceptingPrompter{}
	_, err = f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: strict,
	})
	if err == nil {
		t.Fatal("a changed host key must refuse the connection")
	}

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeHostKeyChanged {
		t.Fatalf("want a host_key_changed ConnectError, got %v", err)
	}

	// The user must NOT have been offered a choice.
	if n := len(strict.seen()); n != 0 {
		t.Fatalf("the user was prompted %d times about a changed key; there is no safe answer to offer", n)
	}

	// And the error must carry both fingerprints so the interface can show
	// the difference.
	if ce.HostKey == nil {
		t.Fatal("the error carries no host key detail")
	}
	if ce.HostKey.PreviousFingerprint == "" {
		t.Error("the previously recorded fingerprint is missing")
	}
	if ce.HostKey.PreviousFingerprint == ce.HostKey.Fingerprint {
		t.Error("the two fingerprints should differ")
	}
}

func TestConnectWithoutAnUnlockedVault(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	_, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: nil, Prompter: &acceptingPrompter{},
	})

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeVaultLocked {
		t.Fatalf("want a vault_locked ConnectError, got %v", err)
	}
}

func TestConnectWithTheWrongPassword(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "the real password", nil)
	sess := f.savedConnection(t, srv, "not the password")

	_, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeAuthFailed {
		t.Fatalf("want an auth_failed ConnectError, got %v", err)
	}
	// The message must tell the user what to check.
	if !strings.Contains(ce.Message, "credential") {
		t.Errorf("message = %q; it should say what to check", ce.Message)
	}
}

func TestConnectToAnUnreachableHost(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	cred, err := f.creds.Create(ctx, f.vaultKey, credentials.CreateParams{
		OwnerID: f.userID, Name: "pw", Kind: credentials.KindPassword, Secret: "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := f.sessions.CreateSession(ctx, sessions.CreateSessionParams{
		OwnerID: f.userID, Name: "nowhere", Hostname: "127.0.0.1", Port: 1,
		Username: "alice", CredentialID: cred.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.connector.Connect(ctx, ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeUnreachable {
		t.Fatalf("want an unreachable ConnectError, got %v", err)
	}
}

func TestConnectWithNoCredential(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	sess, err := f.sessions.CreateSession(ctx, sessions.CreateSessionParams{
		OwnerID: f.userID, Name: "bare", Hostname: "127.0.0.1", Port: 22, Username: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.connector.Connect(ctx, ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeNoCredential {
		t.Fatalf("want a no_credential ConnectError, got %v", err)
	}
}

func TestConnectToAnotherUsersSession(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	_, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: "somebody-else", SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})

	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Code != ErrCodeNotFound {
		t.Fatalf("want a not_found ConnectError, got %v", err)
	}
}

// TestTerminalSurvivesDetach is the property that makes this usable on a
// laptop: closing the browser must not kill the shell.
func TestTerminalSurvivesDetach(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	term, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.manager.CloseTerminal(f.userID, term.ID) //nolint:errcheck

	view := attach(t, term)
	view.waitFor(t, "READY", 5*time.Second)

	if err := term.Write([]byte("before the drop\n")); err != nil {
		t.Fatal(err)
	}
	view.waitFor(t, "before the drop", 5*time.Second)

	// The browser goes away.
	term.Detach()

	if term.Closed() {
		t.Fatal("detaching must not close the terminal")
	}

	// Output produced while nobody is watching must still be captured.
	if err := term.Write([]byte("while away\n")); err != nil {
		t.Fatalf("the shell should still accept input: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// The browser comes back and finds its scrollback.
	returned := attach(t, term)

	text := returned.acc.String()
	if !strings.Contains(text, "before the drop") {
		t.Error("the replay is missing what was on screen before the drop")
	}
	if !strings.Contains(text, "while away") {
		t.Error("the replay is missing output produced while detached")
	}

	// And the session still works.
	if err := term.Write([]byte("after returning\n")); err != nil {
		t.Fatal(err)
	}
	returned.waitFor(t, "after returning", 5*time.Second)
}

// TestAbandonedTerminalsAreReaped stops a forgotten tab holding a production
// session open indefinitely.
func TestAbandonedTerminalsAreReaped(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	term, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = term.Attach()
	if err != nil {
		t.Fatal(err)
	}
	term.Detach()

	// Still within the grace period.
	if n := f.manager.reapOnce(time.Now()); n != 0 {
		t.Fatalf("reaped %d terminals inside the grace period", n)
	}
	if term.Closed() {
		t.Fatal("a recently detached terminal must survive")
	}

	// Well past it.
	if n := f.manager.reapOnce(time.Now().Add(DetachedGrace + time.Minute)); n != 1 {
		t.Fatalf("reaped %d terminals past the grace period, want 1", n)
	}
	if !term.Closed() {
		t.Fatal("an abandoned terminal should have been closed")
	}
}

func TestListForUserIsScoped(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	term, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.manager.CloseTerminal(f.userID, term.ID) //nolint:errcheck

	mine := f.manager.ListForUser(f.userID)
	if len(mine) != 1 {
		t.Fatalf("listed %d terminals, want 1", len(mine))
	}
	if mine[0].Host != srv.Host {
		t.Errorf("host = %q", mine[0].Host)
	}

	if others := f.manager.ListForUser("somebody-else"); len(others) != 0 {
		t.Fatalf("another user saw %d of my terminals", len(others))
	}
	if _, err := f.manager.Get("somebody-else", term.ID); !errors.Is(err, ErrTerminalNotFound) {
		t.Fatalf("want ErrTerminalNotFound, got %v", err)
	}
}

func TestRemoteExitClosesTheTerminal(t *testing.T) {
	f := newFixture(t)
	srv := startSSHServer(t, "hunter2", nil)
	sess := f.savedConnection(t, srv, "hunter2")

	term, err := f.connector.Connect(context.Background(), ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})
	if err != nil {
		t.Fatal(err)
	}

	view := attach(t, term)
	view.waitFor(t, "READY", 5*time.Second)

	if err := term.Write([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}

	select {
	case <-term.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal did not end after the remote shell exited")
	}
	if !term.Closed() {
		t.Fatal("the terminal should read as closed")
	}
}

func TestFolderInheritanceReachesTheConnection(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	srv := startSSHServer(t, "hunter2", nil)

	cred, err := f.creds.Create(ctx, f.vaultKey, credentials.CreateParams{
		OwnerID: f.userID, Name: "shared", Kind: credentials.KindPassword, Secret: "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Username and credential set once on the folder, as an engineer with
	// three hundred devices would.
	folder, err := f.sessions.CreateFolder(ctx, sessions.CreateFolderParams{
		OwnerID: f.userID, Name: "Production",
		Defaults: sessions.Settings{
			Username:     sessions.Ptr("alice"),
			CredentialID: sessions.Ptr(cred.ID),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The connection itself names neither.
	sess, err := f.sessions.CreateSession(ctx, sessions.CreateSessionParams{
		OwnerID: f.userID, FolderID: folder.ID,
		Name: "device", Hostname: srv.Host, Port: srv.Port,
	})
	if err != nil {
		t.Fatal(err)
	}

	term, err := f.connector.Connect(ctx, ConnectParams{
		UserID: f.userID, SessionID: sess.ID, VaultKey: f.vaultKey, Prompter: &acceptingPrompter{},
	})
	if err != nil {
		t.Fatalf("the folder's username and credential should have been used: %v", err)
	}
	defer f.manager.CloseTerminal(f.userID, term.ID) //nolint:errcheck

	attach(t, term).waitFor(t, "READY", 5*time.Second)
}

// --- helpers ----------------------------------------------------------------

// screen accumulates what a browser would display: the replay handed over at
// attach time, followed by live output.
//
// Both halves matter. Output produced between the shell starting and the
// browser attaching lands in the replay buffer and never appears on the live
// channel — which is the design, and which an earlier version of these tests
// got wrong by watching only the channel.
type screen struct {
	acc    strings.Builder
	output <-chan []byte
}

func attach(t *testing.T, term *Terminal) *screen {
	t.Helper()

	att, err := term.Attach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	s := &screen{output: att.Output}
	s.acc.Write(att.Replay)
	return s
}

// waitFor blocks until want appears anywhere on the screen.
func (s *screen) waitFor(t *testing.T, want string, timeout time.Duration) {
	t.Helper()

	if strings.Contains(s.acc.String(), want) {
		return
	}

	deadline := time.After(timeout)
	for {
		select {
		case chunk, ok := <-s.output:
			if !ok {
				t.Fatalf("the terminal ended while waiting for %q; screen held %q", want, s.acc.String())
			}
			s.acc.Write(chunk)
			if strings.Contains(s.acc.String(), want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q; screen held %q", want, s.acc.String())
		}
	}
}

func bytes32(fill byte) []byte {
	b := make([]byte, ed25519.SeedSize)
	for i := range b {
		b[i] = fill
	}
	return b
}
