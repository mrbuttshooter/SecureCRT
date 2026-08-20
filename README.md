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
| 0 | Foundations: config, storage, build, deploy | **complete** |
| 1 | Identity, SSO, MFA & credential vault | **complete** |
| 2 | SSH terminal | next |
| 3 | SFTP file transfer | not started |
| 4 | Import / export (SecureCRT, PuTTY, OpenSSH) | not started |
| 5 | Tunnels & jump hosts | not started |
| 6 | Telnet, serial & console servers | not started |
| 7 | Power-user features (broadcast, snippets, triggers) | not started |
| 8 | Enterprise (RBAC, session recording) | SSO delivered early, in Phase 1 |
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

## Trying it

Requires Go 1.25+, and Node 22 with pnpm for the frontend.

```sh
make release                      # frontend, then the static binary

./bin/bkd gen-master-key --config dev.yaml
./bin/bkd admin create-user --config dev.yaml -email you@example.com -admin
./bin/bkd serve --config dev.yaml
```

Then open the address in `server.external_url`. Sign in, choose a vault
passphrase, and generate a key.

For single sign-on against Microsoft Entra, follow
[`docs/SSO-SETUP.md`](docs/SSO-SETUP.md) and check it with:

```sh
./bin/bkd test-sso --config /etc/bkd/config.yaml
```

That performs real discovery against your tenant and reports Microsoft's own
error code when something is wrong, which beats a blank sign-in page.

## Building and testing

```sh
make test          # unit tests, on SQLite and — if BKD_TEST_POSTGRES_DSN is
                   # set — PostgreSQL as well
make test-race     # under the race detector
make e2e           # browser tests against a freshly provisioned instance
make sec           # gosec
make vuln          # govulncheck
make release       # frontend + static binary
```

The two database backends differ in placeholder syntax, type affinity and
foreign key enforcement, so the suite runs against both rather than whichever
the environment happened to select.

## Licence

Not yet chosen.
