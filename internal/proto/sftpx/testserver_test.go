package sftpx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"

	gssh "github.com/gliderlabs/ssh"
	"github.com/mrbuttshooter/securecrt/internal/hostkeys"
	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// testServer is a real SSH server with a real SFTP subsystem, serving a real
// directory on disk.
//
// Every operation in these tests therefore ends in a syscall against a
// temporary directory the test can inspect directly. A mock SFTP server would
// only prove this package agrees with the mock; this proves that a chmod
// changes a mode, that a resumed write lands at the right offset, and that a
// recursive delete leaves nothing behind.
type testServer struct {
	Host string
	Port int
	Root string
}

const testPassword = "a throwaway password"

func startTestServer(t *testing.T) *testServer {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()

	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		PasswordHandler: func(_ gssh.Context, given string) bool {
			return given == testPassword
		},
		SubsystemHandlers: map[string]gssh.SubsystemHandler{
			"sftp": func(s gssh.Session) {
				server, err := sftp.NewServer(s)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				if err := server.Serve(); err != nil && err != io.EOF {
					t.Logf("sftp server: %v", err)
				}
			},
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

	return &testServer{Host: host, Port: port, Root: root}
}

// connect opens an SFTP client against the test server, through the real SSH
// client layer including host key verification.
func (ts *testServer) connect(t *testing.T) *Client {
	t.Helper()

	sshClient, err := sshx.Dial(context.Background(), sshx.Config{
		Target:     sshx.Target{Hostname: ts.Host, Port: ts.Port},
		Credential: sshx.Credential{Username: "tester", Password: testPassword},
		Verify: func(_ context.Context, _ string, _ int, _ ssh.PublicKey) (hostkeys.Check, error) {
			return hostkeys.Check{Verdict: hostkeys.VerdictUnknown}, nil
		},
		Decide: func(_ context.Context, _ hostkeys.Check) error { return nil },
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sshClient.Close() })

	client, err := Open(sshClient)
	if err != nil {
		t.Fatalf("open sftp: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client
}
