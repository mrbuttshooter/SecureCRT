# Architecture

## Shape of the system

```
Browser (React + TypeScript + xterm.js)
      │  HTTPS + WSS
      ▼
nginx / Caddy  ── TLS termination, on the same host
      │  HTTP to 127.0.0.1
      ▼
bkd  ── one static Go binary, systemd unit, unprivileged user
      ├── internal/api        REST handlers, middleware, the WebSocket bridges
      ├── internal/vault      envelope encryption, in-memory key cache
      ├── internal/auth       Argon2id, TOTP, tokens, OIDC/SAML
      ├── internal/proto      sshx · sftpx · telnetx · serialx · tunnel
      ├── internal/remote     the shared connection pool and the dial path
      ├── internal/terminal   live shells, replay buffers, reattachment
      ├── internal/files      SFTP sessions and the transfer engine
      ├── internal/sessions   the saved connection tree and jump chains
      ├── internal/portability import/export adapters
      ├── internal/store      schema, migrations, data access
      ├── internal/audit      append-only event log
      └── embed.FS            the built React app
      │
      ▼
PostgreSQL (shared deployment) or SQLite (single user / lab)
      +
/var/lib/bkd — master key, session logs, recordings
```

## Why a single Go binary

The deployment target is "a Linux server, not Docker", for a whole company.
Go produces one static executable with no runtime dependencies: install is a
file plus a systemd unit, and upgrade is stop, replace, start. There is no
runtime to keep version-matched across hosts and no third-party package tree
on production machines.

Goroutines also make the concurrency profile cheap. Fifty engineers with ten
tabs each is five hundred long-lived connections, each mostly idle — a
scenario that suits Go's scheduler and costs little memory per session.

The costs, accepted: Go is more verbose than JS or Python, and type
definitions cannot be shared with the React frontend, so a few request and
response shapes are written twice.

## Why PostgreSQL, with SQLite as an option

The same schema and the same queries run on both. Postgres is the default for
shared use: concurrent writers, real transactions — which the team-key rewrap
path depends on, since resealing a team key for twenty members must be all or
nothing — and mature backup and replication.

SQLite exists for a single user or a lab box, where administering a database
server is not worth it. Its single-writer lock makes it unsuitable for a
company instance.

`internal/store` keeps the two identical:

- Every query is written with portable `?` placeholders; `DB.Rebind` rewrites
  them to `$1`-style for Postgres, skipping question marks inside string
  literals.
- Binary values are stored as base64 `TEXT`. Postgres has no `BLOB` and SQLite
  gives an unrecognised `BYTEA` the wrong type affinity, so the types genuinely
  diverge; encoding to text avoids maintaining two schemas, for about 33%
  overhead on values that are at most a few kilobytes.
- SQLite connections set `journal_mode=WAL`, `busy_timeout`, and
  `foreign_keys=ON` — the last is essential, because SQLite otherwise parses
  `ON DELETE CASCADE` and then ignores it.

## Migrations

Migrations are embedded in the binary (`//go:embed`), so a deployed `bkd`
always carries exactly the schema it expects. Each runs in its own
transaction; both databases support transactional DDL, so a failure leaves the
schema at the last complete version rather than half-applied.

The applied checksum of every migration is recorded. Editing a migration that
has already run is detected at startup and refused, which catches the classic
failure where environments silently diverge.

`Rollback` reverts exactly one migration at a time, and the CLI requires an
explicit `-yes`, because rolling back drops tables.

## Data model

Users own folders, sessions and credentials. Teams own the same three kinds of
object, for sharing.

A `CHECK ((user_id IS NULL) <> (team_id IS NULL))` on those tables enforces
that every object has exactly one owner — never both, never neither — at the
database level rather than in application code.

Sessions store their jump-host chain as an ordered JSON array so
arbitrary-depth `ProxyJump` configurations survive import. Per-session
appearance, keepalive, logon actions and trigger rules also live in JSON, so
adding a setting does not require a migration.

Folders carry a `defaults` document that child sessions inherit, mirroring
SecureCRT's behaviour so imported trees behave the way users expect.

## Request lifecycle

1. nginx terminates TLS and forwards to loopback.
2. `securityHeaders` applies a strict CSP and framing/referrer policy to every
   response, including errors.
3. Auth middleware validates the access token and loads the session.
4. For anything touching a credential, the handler asks `vault.Cache` for the
   session's data-encryption key. A locked vault returns `ErrLocked`, and the
   UI prompts for the passphrase.
5. Protocol handlers unwrap only the specific credential they need, use it,
   and let it go out of scope.

## Startup and shutdown

Startup does everything that can fail before the listener opens: create state
directories, connect and migrate, load and validate the master key. A
misconfigured deployment fails immediately rather than on a user's first
connection.

Shutdown, on SIGTERM: stop accepting connections, drain in flight work within
the grace period, zero every cached key, zero the master key, close the
database. Key material is cleared before anything else, so a fault during
shutdown still leaves nothing recoverable in memory.

## Health endpoints

- `GET /healthz` — liveness. Deliberately does not touch the database, so a
  database blip does not cause an orchestrator to kill a process that would
  have recovered.
- `GET /readyz` — readiness. Pings the database and returns 503 if it is
  unreachable.

## The terminal

A terminal is a server-side object, not a WebSocket. The SSH connection is
owned by `internal/terminal`, and a browser attaches to it and detaches from
it; closing a laptop lid detaches, it does not disconnect. Each terminal keeps
a bounded ring buffer of recent output, which is replayed on reattach so the
screen comes back as it was rather than blank. A terminal nobody has attached
to for fifteen minutes is reaped.

The wire protocol uses what WebSocket already gives:

| Frame | Carries |
|---|---|
| binary | raw terminal bytes, both directions |
| text | one JSON control message: resize, status, host key, error, close |

Terminal traffic is overwhelmingly raw bytes, so leaving them unwrapped costs
nothing per keystroke and does not inflate output by a third the way base64
would when someone cats a large file.

The upgrade checks `Origin` explicitly. A WebSocket is not covered by the
same-origin policy, so without that check any page on the internet could open
a terminal using a signed-in visitor's cookies.

## Files

A file session is SFTP layered on an existing SSH connection rather than a
connection of its own. SSH multiplexes channels, so browsing a switch you
already have a terminal on costs one more channel — not one more TCP
connection, one more authentication, and one more vty line against a limit
that on plenty of equipment is four.

Connections are shared by reference count in `internal/remote`. They live
while anything holds a lease and close when the last one is released, so
closing a file browser never disconnects a terminal and closing a terminal
never interrupts a transfer.

**Nothing is spooled to this server's disk.** A download streams from the
host through the process to the browser, an upload streams the other way, and
a host-to-host copy streams through without ever landing. A server that never
writes a user's files anywhere is one whose disk cannot leak them, and it
removes every question about retention, encryption at rest and cleanup.

What is a request and what is a job:

| Work | Shape | Why |
|---|---|---|
| Upload, download | One streaming HTTP request | The browser already reports progress, resumes and saves; a server-side queue would relay all three worse |
| Host-to-host copy, recursive delete | A cancellable server-side job | No browser in the middle, and both run past any sensible request timeout on a slow link |

A host key nobody has accepted cannot be answered mid-handshake over a plain
HTTP request the way it can over the terminal's WebSocket. So the first
attempt refuses and reports the fingerprint, and the answer returns as
`accept_host_key` on a second attempt — which must match the key the host then
presents, so a host that swaps keys between the two is refused rather than
approved by an answer about a different one.

Downloads are always `Content-Disposition: attachment`. A file fetched from a
managed host must never render in this origin, where an HTML or SVG payload
would execute as though this application had served it.

## Import and export

Everything a person owns can leave and come back, which is a design constraint
rather than a feature: a tool nobody can leave is a tool nobody should adopt.

Three properties shape the code.

**One reader, two doors.** `portability.ReadUpload` turns uploaded bytes into a
payload, and both the HTTP endpoint and `bkd import` call it. The handler's
whole job is translating form fields into options. An import cannot behave
differently depending on which door it came through, because there is only one
implementation for it to differ from.

**Preview is a separate step from writing.** An upload is parsed, matched
against what the user already has, and answered with a plan — new connections,
name collisions, whether key material came across. The parsed payload waits in
memory under a token for fifteen minutes; nothing reaches the database until
that token is redeemed, and redeeming consumes it, so pressing the button twice
on a slow connection imports once. Locking the vault discards every staged
import, because a staged import holds decrypted passwords and "lock" has to
mean what it says.

**The bundle is the only encrypted format.** A `.bkbundle` is two lines: a
readable JSON header, then one `vault.Envelope` sealed under a key derived from
a passphrase given at export time. The header is bound in as additional
authenticated data — via the SHA-256 of its exact bytes — so editing it to
claim different key-derivation parameters breaks decryption rather than
weakening it. What the readable half discloses is stated in
[`SECURITY.md`](SECURITY.md).

Every other format is plaintext, and each one loses something: an `ssh_config`
cannot express a password, a `.reg` has nowhere to put a key. So an export
reports what the format could not carry rather than dropping it silently.
Exporting *secrets* in a plaintext format is gated on policy, an explicit
confirmation and a critical audit event that must be written before the bytes
go out. Exporting the same format *without* secrets is not gated at all — it
carries no credentials, and it is how somebody leaves for plain OpenSSH.

## Layout

| Path | Responsibility |
|---|---|
| `cmd/bkd` | CLI: serve, migrate, rollback, gen-master-key, admin, import, export, test-sso, version |
| `internal/server` | wiring, lifecycle, routing, health |
| `internal/config` | defaults → YAML → `BKD_*` env, with validation |
| `internal/store` | schema, migrations, portable data access |
| `internal/vault` | envelope encryption and the in-memory key cache |
| `internal/logging` | structured logging and redaction helpers |
| `internal/auth` | passwords, MFA, tokens, SSO |
| `internal/credentials` | credential CRUD, SSH key generation and import |
| `internal/sessions` | saved connections, folders, inherited defaults |
| `internal/hostkeys` | host key trust decisions, personal and org-wide |
| `internal/remote` | shared, reference-counted SSH connections and the dial path |
| `internal/files` | SFTP sessions and the server-side transfer queue |
| `internal/terminal` | live SSH sessions, the WebSocket bridge, survival |
| `internal/proto/sshx`, `internal/proto/sftpx` | SSH and SFTP |
| `internal/proto/*` | Telnet, serial, tunnels *(phases 5–6)* |
| `internal/portability` | import and export adapters, and the upload reader both the API and the CLI drive |
| `internal/portability/ppk` | PuTTY private key files, converted to OpenSSH |
| `internal/portability/securecrt` | SecureCRT's two password formats and its `.ini` syntax |
| `internal/api` | REST and WebSocket surface |
| `internal/audit` | append-only event writer |
| `web/` | React frontend, embedded into the binary |
| `tools/` | test fixtures behind the `tools` build tag, never shipped |
| `deploy/` | systemd unit, install script, example configs |
