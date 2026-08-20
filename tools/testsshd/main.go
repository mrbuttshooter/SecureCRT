// Command testsshd runs a throwaway SSH server with a real pty and a real
// SFTP subsystem, for the browser end-to-end suite.
//
// The Go tests drive an in-process SSH server with a canned handler, which is
// enough to prove the protocol. This exists for the other half: proving that
// a real shell, on a real pty, behaves correctly when driven through a
// browser — that resize reaches `stty size`, that a full-screen program
// redraws, that UTF-8 and colour survive the round trip — and that files
// written through the browser land on a real filesystem the test can inspect
// afterwards.
//
// It is a test fixture, not part of the product. It is built by
// scripts/e2e.sh and never shipped.
//
//go:build tools

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	gssh "github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "address to listen on")
	user := flag.String("user", "tester", "the only username accepted")
	password := flag.String("password", "", "the only password accepted")
	shell := flag.String("shell", "/bin/sh", "shell to run")
	portFile := flag.String("port-file", "", "write the chosen port here once listening")
	flag.Parse()

	if *password == "" {
		log.Fatal("testsshd: -password is required")
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("testsshd: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		log.Fatalf("testsshd: %v", err)
	}

	forwarder := &gssh.ForwardedTCPHandler{}

	srv := &gssh.Server{
		HostSigners: []gssh.Signer{signer},
		PasswordHandler: func(ctx gssh.Context, given string) bool {
			return ctx.User() == *user && given == *password
		},
		Handler: func(s gssh.Session) { runShell(s, *shell) },
		SubsystemHandlers: map[string]gssh.SubsystemHandler{
			"sftp": serveSFTP,
		},
		// Forwarding, so one of these can act as a bastion for another and a
		// tunnel has something real to run over.
		//
		// Naming ChannelHandlers at all replaces the default map rather than
		// adding to it, so "session" has to be listed here too — leaving it
		// out would produce a server that forwards perfectly and cannot open
		// a shell.
		ChannelHandlers: map[string]gssh.ChannelHandler{
			"session":      gssh.DefaultSessionHandler,
			"direct-tcpip": gssh.DirectTCPIPHandler,
		},
		LocalPortForwardingCallback: func(_ gssh.Context, _ string, _ uint32) bool {
			return true
		},
		ReversePortForwardingCallback: func(_ gssh.Context, _ string, _ uint32) bool {
			return true
		},
		RequestHandlers: map[string]gssh.RequestHandler{
			"tcpip-forward":        forwarder.HandleSSHRequest,
			"cancel-tcpip-forward": forwarder.HandleSSHRequest,
		},
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("testsshd: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	if *portFile != "" {
		if err := os.WriteFile(*portFile, []byte(fmt.Sprintf("%d\n", port)), 0o600); err != nil {
			log.Fatalf("testsshd: %v", err)
		}
	}
	log.Printf("testsshd: listening on %s", listener.Addr())

	if err := srv.Serve(listener); err != nil && err != gssh.ErrServerClosed {
		log.Fatalf("testsshd: %v", err)
	}
}

// serveSFTP runs a real SFTP server over one channel.
//
// It serves the actual filesystem, so a file uploaded through the browser is
// a file the test can then read with os.ReadFile — which is the difference
// between proving a transfer happened and proving a request was accepted.
func serveSFTP(s gssh.Session) {
	server, err := sftp.NewServer(s)
	if err != nil {
		log.Printf("testsshd: sftp: %v", err)
		return
	}
	defer func() { _ = server.Close() }()

	if err := server.Serve(); err != nil && err != io.EOF {
		log.Printf("testsshd: sftp: %v", err)
	}
}

// runShell attaches a real pty to the session, so the shell behaves as it
// would on a console rather than as a pipe.
func runShell(s gssh.Session, shell string) {
	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		_, _ = io.WriteString(s.Stderr(), "a pty is required\n")
		_ = s.Exit(1)
		return
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(),
		"TERM="+ptyReq.Term,
		"PS1=testsshd$ ",
		"LANG=C.UTF-8",
	)

	f, err := pty.Start(cmd)
	if err != nil {
		_, _ = io.WriteString(s.Stderr(), "could not start a shell: "+err.Error()+"\n")
		_ = s.Exit(1)
		return
	}
	defer func() { _ = f.Close() }()

	setWinsize(f, ptyReq.Window.Width, ptyReq.Window.Height)
	go func() {
		for win := range winCh {
			setWinsize(f, win.Width, win.Height)
		}
	}()

	go func() { _, _ = io.Copy(f, s) }()
	_, _ = io.Copy(s, f)

	if err := cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if ok := asExitError(err, &exit); ok {
			_ = s.Exit(exit.ExitCode())
			return
		}
	}
	_ = s.Exit(0)
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func setWinsize(f *os.File, w, h int) {
	//nolint:errcheck // best effort; a failed resize is not fatal to the session
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
