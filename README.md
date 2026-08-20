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

Usable for its core purpose, and there is now a way in and a way out: sign in,
bring your connections across from SecureCRT, PuTTY or OpenSSH, open SSH
sessions in a browser, reach devices behind bastions and forward ports through
them, move files to and from the hosts you reach — and export the lot again
whenever you want to. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the phase
plan and what each completed phase actually contains,
[`docs/MIGRATING.md`](docs/MIGRATING.md) for moving a team over, and
[`docs/TUNNELS.md`](docs/TUNNELS.md) for jump hosts, port forwarding and agent
forwarding.

| Phase | Scope | State |
|---|---|---|
| 0 | Foundations: config, storage, build, deploy | **complete** |
| 1 | Identity, SSO, MFA & credential vault | **complete** |
| 2 | SSH terminal | **complete** |
| 3 | SFTP file transfer | **complete** |
| 4 | Import / export (SecureCRT, PuTTY, OpenSSH) | **complete** |
| 5 | Tunnels & jump hosts | **complete** |
| 6 | Telnet, serial & console servers | next |
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

On a fresh Debian or Ubuntu server, one command takes you from nothing to a
working install over real HTTPS.

```sh
git clone -b claude/vigilant-bell-11pf3z https://github.com/mrbuttshooter/SecureCRT.git
cd SecureCRT && sudo ./deploy/quickstart.sh
```

Clone and run, rather than piping from a URL. `raw.githubusercontent.com`
caches for several minutes, so a `curl … | bash` shortly after a push runs the
previous version of the script against the current version of the source —
which fails in ways that make no sense from the output, because the two halves
disagree. Cloning gets one consistent tree, and you can read what you are about
to run as root.

If the repository is private, the clone needs a token — create a fine-grained
one at **Settings → Developer settings → Personal access tokens**, scoped to
this repository with *Contents: read*, and pass it as `BKD_GITHUB_TOKEN`.

It installs the dependencies, builds, configures Caddy in front for TLS,
creates an administrator and prints the URL and password. With no domain of
your own it serves on `<your-ip>.sslip.io`, which is a real hostname and so
gets a real certificate — set `BKD_HOSTNAME` once you have your own. For a
company-wide install use [`deploy/install.sh`](deploy/install.sh) with
PostgreSQL and read [`docs/SECURITY.md`](docs/SECURITY.md) first.

### Or locally

Requires Go 1.25+, and Node 22 with pnpm for the frontend.

```sh
make release                      # frontend, then the static binary

./bin/bkd gen-master-key --config dev.yaml
./bin/bkd admin create-user --config dev.yaml -email you@example.com -admin
./bin/bkd serve --config dev.yaml
```

Then open the address in `server.external_url`. Sign in, choose a vault
passphrase, and generate a key.

To bring your existing connections with you, zip your SecureCRT configuration
folder (or your `.putty` or `.ssh` directory) and upload it under **Import /
export**. Nothing is written until you have read what would happen. For a whole
team there is a command-line equivalent, and both are covered in
[`docs/MIGRATING.md`](docs/MIGRATING.md):

```sh
./bin/bkd import -user you@example.com -source securecrt -file config.zip
./bin/bkd import -user you@example.com -source securecrt -file config.zip -commit
```

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
make e2e           # browser tests against a freshly provisioned instance,
                   # including a real SSH server on a real pty
make sec           # gosec
make vuln          # govulncheck
make release       # frontend + static binary
```

The two database backends differ in placeholder syntax, type affinity and
foreign key enforcement, so the suite runs against both rather than whichever
the environment happened to select.

`make e2e` needs `make release` first — it drives the real binary with the
frontend embedded. It provisions a throwaway instance and a throwaway SSH
server per run and tears both down, so it is repeatable rather than dependent
on what a previous run left behind.

## Licence

Not yet chosen.
