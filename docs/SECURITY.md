# Security model

This document states what Bridgekeeper protects, what it does not, and why
each decision was made. It is meant to be read by whoever has to sign off on
deploying it, not only by developers.

## What the system holds

A running instance holds, for every engineer using it:

- SSH private keys, passwords, key passphrases and enable secrets
- The hostnames, addresses and usernames of the infrastructure they administer
- Live terminal sessions to that infrastructure

That is a concentration of access far above any single engineer's laptop. The
design starts from the assumption that this makes the server a target.

## Threat model

### Threats defended against

**T1 — Stolen database.** An attacker obtains a dump (backup tape, replica,
SQL injection, a misconfigured cloud bucket).

*Defence.* Every credential is stored only as AES-256-GCM ciphertext. The key
that decrypts it is itself encrypted under a key derived from the user's vault
passphrase by Argon2id at 64 MiB / t=3 / p=4. The dump contains no plaintext
and no usable key. Recovering one credential requires an offline attack
against one user's passphrase, at roughly 64 MiB and several milliseconds per
guess, per user, because every user has a distinct salt.

**T2 — Stolen database *and* master key file.** The attacker also reads
`/var/lib/bkd/master.key`.

*Defence.* The master key does not open user vaults. It wraps only shared team
keys and credentials explicitly marked `server_unlockable`. Ordinary user
credentials remain protected by T1's passphrase barrier.

**T3 — Database write access.** The attacker can modify rows, not just read
them — for instance through a SQL injection bug in a future handler.

*Defence.* Every ciphertext is bound by GCM additional authenticated data to
its scope, owner, record and field. Moving Alice's encrypted key into Bob's
row, swapping two of Alice's own credentials, or re-labelling a team key as a
personal one all cause authentication to fail. The AAD is length-prefixed, so
no pair of different identities can encode identically.

**T4 — Man-in-the-middle on an outbound session.** Someone intercepts the
connection between the server and a managed host.

*Defence.* Host key verification is mandatory by default. First contact shows
the fingerprint for explicit approval; a *changed* key is a hard failure with
a critical audit event, never a dismissible warning. Admins can publish an
org-wide trusted host key list.

The check happens inside the SSH handshake, before any credential is offered,
so declining a fingerprint — or being unable to verify one — sends the host
nothing. The dialog is built to be answered rather than dismissed: the
fingerprint is the largest element on screen, accept and refuse are equally
weighted, and neither is preselected. A dialog that offers an obvious "yes"
trains people to accept anything, which is the failure this defence exists to
prevent.

**T5 — Credential exfiltration by a legitimate user.** An employee with a
valid login copies the team's credentials before leaving.

*Defence.* Plaintext export is disabled by default. When enabled, it requires
re-entering the vault passphrase plus an explicit confirmation, and writes a
critical audit event naming every credential included. Encrypted-bundle export
remains available and is itself audited. Admins can disable export entirely
per role. This raises the cost and guarantees a record; it cannot prevent a
determined user from transcribing what they can already see.

**T5a — A hostile page drives a signed-in user's terminals.** Someone visits
a malicious site while signed in here.

*Defence.* The terminal WebSocket checks `Origin` on upgrade against the
configured external URL. This is explicit rather than inherited, because a
WebSocket is not covered by the same-origin policy the way `fetch` is: the
browser will open one cross-origin and send the session cookie with it. The
REST surface is separately covered by `SameSite=Strict` plus a double-submit
CSRF token.

**T5b — A file taken from a managed host is used to attack this service.**
Someone downloads a crafted HTML or SVG file through the file browser.

*Defence.* Downloads are always `Content-Disposition: attachment` with
`Content-Type: application/octet-stream` and `X-Content-Type-Options: nosniff`,
so a file fetched from a host is never rendered in this origin — where it
would execute with the user's session. Remote filenames are not under this
service's control either, so the header's filename parameter is sanitised to
safe ASCII and the exact name travels separately in the RFC 5987 form: a name
containing a quote, a semicolon or a CRLF would otherwise break the header or
inject another.

**T6 — Stolen session token.** An attacker obtains a browser cookie.

*Defence.* Tokens are `HttpOnly`, `Secure`, `SameSite=Strict`, short-lived,
and revocable server-side; only a hash is stored, so a database dump yields no
usable token. Critically, a stolen token alone does **not** unlock the vault:
the data-encryption key lives in server memory keyed to the session, and any
new session must unlock with the passphrase.

### Threats NOT defended against

Stated plainly, because a security document that claims everything is worth
nothing.

**T7 — Root on the server, while users are logged in.** An attacker with root
can read process memory and extract every currently-unlocked data-encryption
key. Nothing in this design prevents that. Mitigations are operational: keep
the host minimal, restrict who can become root, monitor for it. This is the
single most important limit to understand — it is why the box running
Bridgekeeper deserves the same care as a domain controller.

**T8 — Malicious or compromised server code.** A backdoored build can capture
passphrases as users type them. Deploy only builds you trust, from source you
have reviewed.

**T9 — Compromised user endpoint.** Malware on an engineer's laptop can read
their session and keylog their passphrase. Out of scope for a server.

**T10 — Credential misuse by an authorised user.** Someone entitled to a
credential can use it. Audit logging and session recording detect this; they
do not prevent it.

## Files on the server

Nothing a user transfers is written to this server's disk. Downloads,
uploads and host-to-host copies all stream through the process without
landing, so there is no spool directory to protect, no retention question to
answer and nothing left behind for a later reader to find. The only files bkd
writes are its own: the database, the master key, and — when an operator
enables them — session transcripts and recordings, all of which live under
`paths.data_dir` at 0700.

## Cryptography

| Purpose | Algorithm | Parameters |
|---|---|---|
| Passphrase → key-encryption key | Argon2id | t=3, m=64 MiB, p=4, 16-byte per-user salt |
| Credential and key encryption | AES-256-GCM | 96-bit random nonce per operation, AAD-bound |
| Login password hashing | Argon2id | PHC string format, per-user salt |
| Refresh token storage | SHA-256 | hash only; the token itself is never stored |
| Key generation | `crypto/rand` | OS CSPRNG |

Nonces are drawn at random per operation and never derived from record
identity or a counter. Nonce reuse under one key would leak the GCM
authentication subkey; the test suite asserts uniqueness across thousands of
operations.

### Key hierarchy

```
vault passphrase
      │ Argon2id(per-user salt)
      ▼
    KEK ──── never stored, zeroed immediately after use
      │ AES-256-GCM unwrap
      ▼
    DEK ──── stored wrapped; held in memory only while logged in
      │ AES-256-GCM, AAD = scope ‖ owner ‖ record ‖ field
      ▼
 credentials, TOTP secrets, team keys
```

A passphrase change rewraps the DEK rather than re-encrypting credentials, so
the operation is a single atomic row update regardless of how many sessions
the user has saved.

Shared team credentials use a team DEK sealed once per member under that
member's personal DEK. Adding a member reseals; removing one deletes their
row. No plaintext key is written at any point.

## Single sign-on and the vault

This is the decision worth putting in front of whoever owns security before
rollout, because it determines whether T1 and T2 above hold at all for the
majority of users.

With a local password, the server sees the password at sign-in, so it can
derive the user's vault key from it (under a different salt, so the stored
login hash gives no head start) and the user notices nothing.

**With single sign-on there is no password to derive from.** Entra returns an
identity token, not a secret. So there are exactly two options, and they are
not equivalent:

| `vault.sso_unlock_mode` | What the user does | What a stolen database **and** master key yields |
|---|---|---|
| `passphrase` *(default)* | Types a vault passphrase once per working day, after the Microsoft redirect | **Nothing.** T1 and T2 hold. |
| `server_managed` | Nothing extra — signing in opens everything | **Every credential in the system.** |

`server_managed` is what most commercial web-SSH products do. It is a
defensible choice for a team that judges the operational simplicity worth it.
But it silently discards the property this system was built around, so it is
not the default, `bkd` logs a warning at every startup in that mode, and
affected credentials are marked in the interface.

With `unlock_ttl` at its default of 12 hours, the real cost of the secure
option is one extra prompt each morning.

## Key lifetime in memory

Data-encryption keys are unwrapped at login and cached in memory only:

- Zeroed on logout, on expiry, and on process shutdown
- Never written to disk, never sent to another process, never logged
- Expiry refreshes on activity so working users are not interrupted, while
  abandoned sessions still expire

**Accepted consequence:** after a restart, users must re-enter their vault
passphrase. This is the visible cost of the server not being able to decrypt
on its own, and it is the property that makes T1 and T2 hold.

Zeroing is best-effort. Go's garbage collector may copy a heap allocation
before it is cleared, and without `mlock` the OS may page it to swap. Disable
swap or use encrypted swap on hosts handling sensitive fleets. `LimitCORE=0`
in the systemd unit prevents key material reaching a core dump.

## Unattended credentials

Automation that must run with nobody logged in uses credentials flagged
`server_unlockable`, wrapped under the server master key alone.

This is a deliberate, visible weakening: for these credentials, the master key
file *is* sufficient to decrypt. They are marked in the UI, recorded in the
audit log, and should be scoped to the narrowest possible access. Do not use
this flag for convenience.

## Process isolation

The service runs as an unprivileged `bkd` user with no shell and no login. It
holds no SSH keys of its own: every outbound connection uses a credential
unwrapped for a specific logged-in user, so there is no ambient authority for
an attacker to inherit. The systemd unit adds `NoNewPrivileges`,
`ProtectSystem=strict`, `PrivateDevices`, `MemoryDenyWriteExecute`, a
system-call filter, and a single writable path.

`bkd` binds to loopback and speaks plain HTTP; TLS terminates in nginx or
Caddy in front of it.

## Audit

Append-only. The application has no update or delete path for audit rows;
retention requires an explicit admin command that archives before pruning.

Recorded: logins and failures, vault unlock attempts, credential create /
read / update / delete, every connection with its target and the credential
used, file transfers, tunnel creation, **every import and export**, and all
admin actions.

Audit detail fields never contain secret material.

## What is enforced where

Some properties are easier to state than to keep. These are the ones with a
test that fails if they regress, rather than only a convention:

| Property | Enforced by |
|---|---|
| A stolen ciphertext cannot be moved to another user or record | GCM additional authenticated data; tests perform the relocation directly against the database |
| The private half of a key never reaches the browser | `Credential` has no field able to hold it (asserted by reflection); a browser test scans the rendered page |
| A wrong password and an unknown account are indistinguishable | Responses compared byte-for-byte in a test; a dummy Argon2id verification equalises the timing |
| Session tokens are useless from a database dump | Only a SHA-256 is stored; asserted in a test |
| Audit records never carry secrets | Detail keys screened against a deny list; the write is refused |
| The audit log cannot be rewritten by the application | A test reads the package source and fails on any `UPDATE`/`DELETE` against `audit_events` |
| Cookies keep their security attributes | Read back from a real browser and asserted |
| The content security policy is not quietly relaxed | Browser tests fail on any console error, which is the only way a violation surfaces |
| `unsafe-inline` never spreads beyond styles | A test parses the policy and fails if any directive other than `style-src` carries it, and on `unsafe-eval` anywhere |
| A cross-origin page cannot open a terminal | A test performs the upgrade with a foreign `Origin` and asserts it is refused |
| A declined host key sends no credential | A test declines at the prompt against a real SSH server and asserts the host recorded no authentication attempt |
| Accepting one host key cannot approve a different one | The file browser's two-step approval carries the fingerprint the user saw; a test confirms with the wrong one and asserts it is refused |
| A downloaded file cannot render in this origin | A test asserts the attachment disposition, the octet-stream type and nosniff on a file whose contents are a script |
| A remote filename cannot forge a response header | A test passes names containing quotes, semicolons and CRLF and asserts the header stays intact |
| One user's file session is unreachable by another | A test opens a session, signs in as a second account, and asserts that listing it, downloading through it and enumerating it are all refused |
| Queries work on PostgreSQL, not just SQLite | An AST-walking test rejects `ExecContext`/`QueryContext` outside `internal/store`, since those bypass placeholder rewriting |

## Reporting a vulnerability

Not yet established. Add a contact and disclosure policy here before this is
deployed anywhere real.
