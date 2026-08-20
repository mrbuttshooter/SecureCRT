package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mrbuttshooter/securecrt/internal/terminal"
)

// Agent forwarding, from the far end's point of view.
//
// The property that matters is not "the code ran" but "the remote host can
// actually use these keys, and only these keys". So the test server here does
// what a real host does with a forwarded agent: it opens the channel back and
// asks what is in it, then reports the answer down the terminal — which makes
// the assertion an observation of the host's view rather than of our own
// bookkeeping.

// acceptHostKey answers the fingerprint prompt these tests are not about.
func acceptHostKey(t *testing.T, view *socketView) {
	t.Helper()
	view.waitFor(t, "", terminal.ControlHostKeyPrompt, 20*time.Second)
	view.sendControl(t, terminal.Control{Type: terminal.ControlHostKeyDecision, Accepted: true})
}

// agentServer is an SSH server that interrogates a forwarded agent.
type agentServer struct {
	Host string
	Port int

	mu       sync.Mutex
	saw      []string // key comments, as the host listed them
	wasAsked bool
}

func (a *agentServer) listed() (bool, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wasAsked, append([]string(nil), a.saw...)
}

// startAgentSSH runs an SSH server that lists a forwarded agent's keys and
// writes what it found to the terminal before the prompt.
//
// Written directly against golang.org/x/crypto/ssh rather than the
// gliderlabs harness the other tests use, and that is not a preference: the
// gliderlabs server answers auth-agent-req@openssh.com with success
// unconditionally — there is a TODO in its source saying as much — so there
// is no way to express a host that declines one. Half of what is worth
// testing here is the declining.
//
// The listing is written to the session rather than only recorded, so the
// test needs no synchronisation: by the time the prompt arrives on screen,
// the host has already asked and answered.
func startAgentSSH(t *testing.T, password string, allow bool) *agentServer {
	t.Helper()

	srv := &agentServer{}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, given []byte) (*ssh.Permissions, error) {
			if string(given) != password {
				return nil, fmt.Errorf("no")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.serve(raw, cfg, allow)
		}
	}()

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	srv.Host, srv.Port = host, port
	return srv
}

// serve handles one connection: authenticate, take a session channel, and
// answer its requests the way a real sshd would.
func (a *agentServer) serve(raw net.Conn, cfg *ssh.ServerConfig, allow bool) {
	conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only sessions here")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go a.handleSession(conn, channel, requests, allow)
	}
}

// handleSession answers the session's requests. The agent request is the one
// that matters: replying false is a host with AllowAgentForwarding no, and
// replying true is a host that will then open the channel back.
func (a *agentServer) handleSession(
	conn ssh.Conn, channel ssh.Channel, requests <-chan *ssh.Request, allow bool,
) {
	defer func() { _ = channel.Close() }()

	forwarded := false
	for req := range requests {
		switch req.Type {
		case "auth-agent-req@openssh.com":
			a.mu.Lock()
			a.wasAsked = true
			a.mu.Unlock()
			forwarded = allow
			_ = req.Reply(allow, nil)

		case "pty-req", "env", "window-change":
			_ = req.Reply(true, nil)

		case "shell":
			_ = req.Reply(true, nil)
			if forwarded {
				a.interrogate(conn, channel)
			}
			_, _ = fmt.Fprint(channel, "PROMPT>")

		default:
			_ = req.Reply(false, nil)
		}
	}
}

// interrogate opens the agent channel back and lists what is in it, exactly
// as `ssh-add -l` on the remote host would.
//
// This is the whole test, really: whatever bkd believes it forwarded, this is
// what the far end can actually reach.
func (a *agentServer) interrogate(conn ssh.Conn, out ssh.Channel) {
	agentChannel, reqs, err := conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		_, _ = fmt.Fprintf(out, "AGENT-ERROR:%v\n", err)
		return
	}
	go ssh.DiscardRequests(reqs)
	defer func() { _ = agentChannel.Close() }()

	keys, err := agent.NewClient(agentChannel).List()
	if err != nil {
		_, _ = fmt.Fprintf(out, "AGENT-ERROR:%v\n", err)
		return
	}

	comments := make([]string, 0, len(keys))
	for _, key := range keys {
		comments = append(comments, key.Comment)
	}
	sort.Strings(comments)

	a.mu.Lock()
	a.saw = comments
	a.mu.Unlock()

	_, _ = fmt.Fprintf(out, "AGENT:%s\n", strings.Join(comments, ","))
}

// generatedKey stores a fresh SSH key credential and returns its identifier.
func (h *harness) generatedKey(t *testing.T, name string) string {
	t.Helper()

	resp, body := h.post("/api/credentials/generate", map[string]string{
		"name": name, "key_type": "ed25519", "comment": name,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("generating %s = %d: %v", name, resp.StatusCode, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("no credential identifier for %s: %v", name, body)
	}
	return id
}

// savedHostWithAgent stores a connection that forwards the named keys.
func (h *harness) savedHostWithAgent(
	t *testing.T, name, host string, port int, password string, agentKeys []string,
) string {
	t.Helper()

	_, cred := h.post("/api/credentials", map[string]string{
		"name": name + " password", "kind": "password", "secret": password,
	})
	credID, _ := cred["id"].(string)
	if credID == "" {
		t.Fatalf("no credential for %s: %v", name, cred)
	}

	resp, sess := h.post("/api/tree/sessions", map[string]any{
		"name": name, "hostname": host, "port": port,
		"username": "alice", "credential_id": credID,
		"settings": map[string]any{"agent_forward_credentials": agentKeys},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %s = %d: %v", name, resp.StatusCode, sess)
	}
	id, _ := sess["id"].(string)
	return id
}

// TestAForwardedAgentOffersExactlyTheKeysNamed is the feature, observed from
// the host rather than from here.
//
// Two keys exist; one is named on the connection. A real agent would have
// offered both — that is the improvement this design buys, and it is only
// real if the second key is genuinely absent from the host's view.
func TestAForwardedAgentOffersExactlyTheKeysNamed(t *testing.T) {
	h := signedInWithVault(t)

	deployKey := h.generatedKey(t, "deploy-key")
	h.generatedKey(t, "production-key") // exists, not named

	srv := startAgentSSH(t, "hunter2", true)
	sessionID := h.savedHostWithAgent(t, "switch", srv.Host, srv.Port, "hunter2",
		[]string{deployKey})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	acceptHostKey(t, view)

	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	asked, saw := srv.listed()
	if !asked {
		t.Fatal("the host was never offered an agent")
	}
	if len(saw) != 1 || saw[0] != "deploy-key" {
		t.Fatalf("the host saw %v, want exactly [deploy-key] — a key it was "+
			"not offered must not be reachable through the agent", saw)
	}
}

// TestNoAgentIsOfferedUnlessAsked. The default has to be nothing, and the
// only way to know it is nothing is to have a host that would tell us.
func TestNoAgentIsOfferedUnlessAsked(t *testing.T) {
	h := signedInWithVault(t)

	srv := startAgentSSH(t, "hunter2", true)
	sessionID := h.savedHost(t, "switch", srv.Host, srv.Port, "hunter2")

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	acceptHostKey(t, view)
	view.waitFor(t, "PROMPT>", "", 20*time.Second)

	if asked, _ := srv.listed(); asked {
		t.Fatal("an agent was forwarded to a connection that never asked for one")
	}
}

// TestAgentForwardingIsNotInheritedFromAFolder.
//
// Settings.merge fills every unset field from the parent folder — every field
// but this one. A folder default here would offer somebody's keys to every
// host inside it, including hosts added later by somebody else, and the
// person who set the default would be the last to find out.
//
// The interface refuses the setting on a folder outright rather than storing
// something that does nothing, which is the second half of the same argument:
// a security setting that appears to be on and is not is worse than either.
func TestAgentForwardingIsNotInheritedFromAFolder(t *testing.T) {
	h := signedInWithVault(t)
	keyID := h.generatedKey(t, "deploy-key")

	resp, body := h.post("/api/tree/folders", map[string]any{
		"name": "Datacentre",
		"defaults": map[string]any{
			"agent_forward_credentials": []string{keyID},
		},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("= %d, want 400: %v", resp.StatusCode, body)
	}

	failure, _ := body["error"].(map[string]any)
	message, _ := failure["message"].(string)
	if !strings.Contains(message, "every host inside it") {
		t.Errorf("the refusal does not explain the risk: %q", message)
	}
}

// TestAnAgentKeyMustBeAKeyTheUserOwns covers both ways the setting can name
// something it should not.
func TestAnAgentKeyMustBeAKeyTheUserOwns(t *testing.T) {
	h := signedInWithVault(t)

	_, cred := h.post("/api/credentials", map[string]string{
		"name": "a password", "kind": "password", "secret": "hunter2",
	})
	passwordID, _ := cred["id"].(string)

	cases := map[string]string{
		"a credential that does not exist": "01920000-0000-7000-8000-000000000000",
		"a password rather than a key":     passwordID,
	}

	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body := h.post("/api/tree/sessions", map[string]any{
				"name": "switch " + name, "hostname": "10.0.0.1", "port": 22,
				"username": "alice",
				"settings": map[string]any{
					"agent_forward_credentials": []string{id},
				},
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("= %d, want 400: %v", resp.StatusCode, body)
			}
		})
	}
}

// TestAHostThatRefusesAnAgentStillGivesYouATerminal, and says so.
//
// AllowAgentForwarding is off on plenty of equipment. A terminal that opens
// without the agent is far better than one that does not open — but silently
// is not acceptable either, because the next thing the user does is try an
// authentication that fails somewhere they cannot see.
func TestAHostThatRefusesAnAgentStillGivesYouATerminal(t *testing.T) {
	h := signedInWithVault(t)
	keyID := h.generatedKey(t, "deploy-key")

	srv := startAgentSSH(t, "hunter2", false) // no agent forwarding
	sessionID := h.savedHostWithAgent(t, "switch", srv.Host, srv.Port, "hunter2",
		[]string{keyID})

	conn := h.dialTerminal(t, "session="+sessionID)
	view := newSocketView(conn)
	acceptHostKey(t, view)

	warning := view.waitFor(t, "", terminal.ControlWarning, 20*time.Second)
	if warning.Code != "agent_refused" {
		t.Errorf("warning code = %q", warning.Code)
	}

	// And the terminal is there regardless.
	view.waitFor(t, "PROMPT>", "", 20*time.Second)
}
