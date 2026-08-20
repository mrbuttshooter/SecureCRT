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
      ├── internal/api        REST handlers, middleware
      ├── internal/wsmux      WebSocket multiplexer (terminal, transfers, tunnels)
      ├── internal/vault      envelope encryption, in-memory key cache
      ├── internal/auth       Argon2id, TOTP, tokens, OIDC/SAML
      ├── internal/proto      ssh · sftp · telnet · serial · tunnel
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

## Layout

| Path | Responsibility |
|---|---|
| `cmd/bkd` | CLI: serve, migrate, rollback, gen-master-key, version |
| `internal/server` | wiring, lifecycle, routing, health |
| `internal/config` | defaults → YAML → `BKD_*` env, with validation |
| `internal/store` | schema, migrations, portable data access |
| `internal/vault` | envelope encryption and the in-memory key cache |
| `internal/logging` | structured logging and redaction helpers |
| `internal/auth` | passwords, MFA, tokens, SSO |
| `internal/credentials` | credential CRUD, SSH key generation and import |
| `internal/sessions` | saved connections, folders, inherited defaults |
| `internal/hostkeys` | host key trust decisions, personal and org-wide |
| `internal/terminal` | live SSH sessions, the WebSocket bridge, survival |
| `internal/proto/*` | SSH, SFTP, Telnet, serial, tunnels *(phases 2–6)* |
| `internal/portability` | import and export adapters *(phase 4)* |
| `internal/api` | REST and WebSocket surface |
| `internal/audit` | append-only event writer |
| `web/` | React frontend, embedded into the binary |
| `tools/` | test fixtures behind the `tools` build tag, never shipped |
| `deploy/` | systemd unit, install script, example configs |
