# Bridgekeeper

A self-hosted, browser-based SSH / SFTP / Telnet / serial client with per-user
saved sessions, encrypted credential storage, and full audit — built to replace
per-seat SecureCRT and SecureFX licences across a team.

Engineers open a browser, log in, and get their own session tree, SSH keys and
saved passwords from any machine, with nothing installed locally.

> **Name.** `Bridgekeeper` is a working title. "SecureCRT" is a registered
> trademark of VanDyke Software; this project is an independent replacement and
> is not affiliated with or endorsed by them. Pick your own product name before
> rolling it out. Reading *from* SecureCRT's own configuration files, so a team
> can migrate off it, is a supported feature.

## Status

Early development. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the phase plan.

| Phase | Scope | State |
|---|---|---|
| 0 | Foundations: config, storage, build, deploy | in progress |
| 1 | Identity & encrypted credential vault | vault complete |
| 2 | SSH terminal | not started |
| 3 | SFTP file transfer | not started |
| 4 | Import / export (SecureCRT, PuTTY, OpenSSH) | not started |
| 5 | Tunnels & jump hosts | not started |
| 6 | Telnet, serial & console servers | not started |
| 7 | Power-user features (broadcast, snippets, triggers) | not started |
| 8 | Enterprise (SSO, RBAC, session recording) | not started |
| 9 | Hardening & operations | not started |

## Design in one page

```
Browser (React + xterm.js)
      │  HTTPS + WSS
      ▼
nginx / Caddy  ── TLS termination
      │
      ▼
bkd  ── one static Go binary, systemd unit, runs as an unprivileged user
      ├── REST API, WebSocket multiplexer
      ├── Vault: envelope encryption, in-memory key cache
      ├── Protocols: SSH · SFTP · Telnet · Serial · tunnels
      └── the built React app, embedded
      │
      ▼
PostgreSQL (or SQLite for a small install)
```

`bkd` compiles to a single static binary with no runtime dependencies:
deployment is a file, a systemd unit, and a database. Upgrades are stop,
replace, start.

## Security in one page

Credentials are protected by envelope encryption, so **a stolen database is
not enough to read them**:

- A vault passphrase derives a key-encryption key via Argon2id (64 MiB, t=3).
- That KEK wraps a random per-user data-encryption key (DEK).
- The DEK encrypts each credential with AES-256-GCM, bound to its owner,
  record and field through the authenticated additional data — so a ciphertext
  cannot be relocated to another user or record and still decrypt.
- The DEK is unwrapped **only at login**, held in memory for the session, and
  zeroed on logout, expiry or shutdown. It is never written to disk.

The server master key protects only shared team keys and credentials
explicitly marked for unattended use; on its own it does not open a user's
vault.

Host key verification is mandatory by default and a changed host key is a hard
failure, not a warning. Full details and the threat model are in
[`docs/SECURITY.md`](docs/SECURITY.md).

## Building

Requires Go 1.23+ and (for the frontend) Node 20+ with pnpm.

```sh
make test          # unit tests
make test-race     # unit tests under the race detector
make build         # produces bin/bkd
```

## Licence

Not yet chosen.
