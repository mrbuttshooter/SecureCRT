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

## Phase 3 — SFTP ✅

- [x] SFTP over the terminal tab's own SSH connection, reference-counted
- [x] Dual-pane browser with per-pane filter, path bar and navigation
- [x] Drag files in from the desktop to upload; drag between panes to copy
      one managed host straight to another
- [x] Recursive directory copy and delete, as cancellable server-side jobs
- [x] Byte-accurate progress for both, plus browser-side upload progress
- [x] Resumable uploads and downloads, by offset and by HTTP Range
- [x] In-browser editor, refusing binaries and anything over 2 MiB
- [x] chmod, chown by name or numeric id, rename, mkdir, delete
- [x] Owner and group names read from the host's own /etc/passwd
- [x] Browser end-to-end suite against two real SFTP hosts

Named in the original scope and deliberately not built:

- **A local-filesystem pane.** A browser cannot list your disk, so the
  traditional local side of an SFTP client is impossible. Both panes are
  remote instead, and the local side is served by dragging files in and by
  ordinary downloads — which buys something SecureCRT cannot do at all:
  copying a directory from one managed host straight to another without it
  passing through anybody's laptop.
- **A server-side queue for uploads and downloads.** Each is one streaming
  HTTP request, and the browser reports progress, resumes and saves far
  better than a queue relaying it second-hand. The server-side queue exists
  for the work with no browser in the middle.

## Phase 4 — Import and export ✅

- [x] SecureCRT configuration folders and `.ini` sessions, **including saved
      passwords** — both password formats, legacy double-Blowfish and V2
      AES-256, with or without a configuration passphrase
- [x] PuTTY sessions from a `.reg` export or a `.putty` directory
- [x] PuTTY `.ppk` keys converted to OpenSSH, versions 2 and 3, encrypted or
      not, RSA / ECDSA / ed25519, and joined to the sessions that name them
- [x] `~/.ssh/config` with its keys, `known_hosts`, and `ProxyJump` chains
      rebuilt by name
- [x] CSV and spreadsheet host lists, with columns matched by what real
      spreadsheets are actually called
- [x] Preview before anything is written, in the browser and on the command
      line alike; a staged preview is dropped when the vault is locked
- [x] Encrypted `.bkbundle` export under a passphrase given at export time
- [x] Export to `~/.ssh/config`, SecureCRT `.ini`, PuTTY `.reg`, JSON and CSV,
      each reporting what the format could not express
- [x] Plaintext export of secrets gated behind an explicit confirmation and a
      critical audit event that must land before the bytes go out, and
      disableable org-wide
- [x] `bkd import` and `bkd export` for migrating a team without the browser
- [x] [`docs/MIGRATING.md`](MIGRATING.md)
- [x] Browser end-to-end suite over the whole journey, in and out

**Round trip, the definition of done:** export → a second instance with its own
database and its own master key → import → the same connections, the same key
fingerprints, the same passwords. It is
`TestTheRoundTripThroughTheCommandLine` in `internal/server`, and it runs on
every build.

Every `.ppk` fixture in `internal/portability/ppk/testdata` was produced by
PuTTY's own puttygen, and beside each one is puttygen's OpenSSH export of the
same key. The tests check that what this converts to has the fingerprint PuTTY
says it has, and that a signature made with the converted key verifies under
the public key PuTTY published — a parser checked only against its own encoder
would prove nothing but self-consistency.

Two things named in the original scope are worth being explicit about:

- **"Byte-identical sessions"** was the wrong bar and is not what the round
  trip asserts. Identifiers are reassigned on import, deliberately — importing
  a bundle twice must produce two trees rather than a silent overwrite — so
  what is checked is that every field a person can observe survives: hostname,
  port, username, folder path, key fingerprint, password.
- **The gate is about secrets, not formats.** Exporting an `ssh_config` with no
  keys or passwords in it is not gated at all, whatever
  `policy.allow_plaintext_export` says. Refusing it would be holding people by
  making the exit difficult, which is not what that setting is for.

## Phase 5 — Tunnels and jump hosts — next

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
