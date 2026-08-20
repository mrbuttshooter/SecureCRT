# Roadmap

Each phase ends in working, tested software. Nothing is stubbed.

Phases 0–4 together are the point at which the team can stop using SecureCRT:
a working terminal, file transfer, and a migration path in and out. Everything
after that is additive and shippable on its own.

## Phase 0 — Foundations ✅

Repo scaffold, `Makefile`, config loader with validation, portable schema and
migration runner, structured logging, health endpoints, hardened systemd unit,
install script, CI.

## Phase 1 — Identity and vault ✅

- [x] Envelope encryption, key cache, master key handling
- [x] Local accounts, Argon2id login passwords
- [x] Single sign-on against Microsoft Entra (pulled forward from Phase 8)
- [x] TOTP MFA with recovery codes; Entra's own MFA honoured via `amr`
- [x] Opaque session tokens, sliding idle plus hard absolute expiry, revocation
- [x] Credential CRUD; in-app key generation (ed25519 / RSA-4096 / ECDSA)
- [x] Key import (OpenSSH and PEM, encrypted or not)
- [x] Rate limiting and account lockout
- [x] Append-only audit log
- [x] Admin CLI and `bkd test-sso`
- [x] Web interface, embedded in the binary
- [ ] WebAuthn for local accounts — deferred; see below

**WebAuthn was deliberately deferred.** Entra already covers multi-factor
authentication for everyone who signs in through it, so WebAuthn would only
protect the handful of break-glass local accounts. It is worth doing, but not
before the terminal exists.

## Phase 2 — SSH terminal ✅

- [x] SSH client layer with mandatory host key verification
- [x] Known-hosts store; personal and org-wide trust, changed keys a hard fail
- [x] Saved connections in nested folders, with inherited folder defaults
- [x] WebSocket ↔ SSH pty bridge, with server-side session survival
- [x] REST and WebSocket API for the tree, terminals and known hosts
- [x] xterm.js with the WebGL renderer, falling back to DOM without a GPU
- [x] True colour, Unicode 11 widths, mouse reporting, bracketed paste
- [x] Configurable scrollback, colour schemes and font size
- [x] Tabs, a two-pane split, and scrollback search
- [x] Drag-and-drop between folders; filter across the whole tree
- [x] Host key approval and changed-key alarm in the interface
- [x] Keyboard-interactive auth; keepalive; reconnect with replayed scrollback
- [x] Browser end-to-end suite against a real SSH server on a real pty

Two things named in the original scope moved out, and are worth being explicit
about rather than quietly dropping:

- **Arbitrary split layouts.** What shipped is one split into two panes. A
  full pane tree — nested horizontal and vertical splits, dragged dividers —
  is a substantial piece of interface work whose value is much lower than
  SFTP, so it waits.
- **Telnet and serial.** The saved-connection schema carries the protocol and
  the interface offers it, but only SSH is wired to a transport. Telnet and
  serial arrive with Phase 5.

## Phase 3 — SFTP

Dual-pane browser, drag-and-drop transfer, recursive directories, resumable
transfers, queue and progress UI, in-browser file editor, chmod/chown,
transfers over the same SSH connection as the terminal tab.

## Phase 4 — Import and export

**Import:** SecureCRT config folders and `.ini` sessions *including saved
passwords*, PuTTY sessions and `.ppk` keys, `~/.ssh/config` with OpenSSH keys,
CSV/spreadsheet host lists. Preview before anything is written.

**Export:** a full-fidelity `.bkbundle` encrypted under a passphrase given at
export time; plus `~/.ssh/config`, SecureCRT `.ini` (to go back), PuTTY `.reg`,
JSON and CSV. Plaintext export is gated behind the vault passphrase, an
explicit confirmation and a critical audit event, and admins can disable it.

Definition of done includes a round-trip test: export → wipe → import on a
second instance → byte-identical sessions, key fingerprints and passwords.

## Phase 5 — Tunnels and jump hosts

Proxy-jump chains of arbitrary depth with per-hop credentials, local and
remote port forwarding, dynamic SOCKS5, X11 forwarding, agent forwarding with
per-session opt-in, tunnel manager UI.

## Phase 6 — Telnet, serial and console servers

Telnet with full option negotiation (NAWS, TTYPE, ECHO, SGA). Serial over
`/dev/ttyUSB*` — which only works where the server is physically cabled to the
device, so it suits a lab box rather than the central instance. Console server
support (Opengear, Lantronix) covers the remote case and is more broadly
useful.

## Phase 7 — Power-user features

Broadcast input to many tabs at once; parameterised command snippets, personal
and team-shared; triggers and expect automation in a sandboxed JS runtime;
keyword highlighting; session transcript logging; scrollback search.

## Phase 8 — Enterprise

OIDC and SAML SSO, LDAP/AD group sync, RBAC with per-folder and per-host
grants, shared team credentials, session recording in asciinema format with a
web player, audit export to SIEM, admin dashboard with live view and forced
disconnect, org-wide policy enforcement.

## Phase 9 — Hardening and operations

Full security review, WebAuthn, backup and restore tooling including the master
key, Prometheus metrics, graceful drain on upgrade, load testing, HA notes,
operator runbook.
