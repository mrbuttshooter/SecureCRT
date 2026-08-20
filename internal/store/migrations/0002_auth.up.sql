-- Authentication, MFA, and vault-unlock policy.
--
-- Portability: same rules as 0001 — TEXT identifiers, RFC3339 UTC TEXT
-- timestamps, INTEGER booleans, and base64 TEXT for anything encrypted.
--
-- SQLite's ALTER TABLE supports ADD COLUMN only, and only with a constant
-- default, so every added column below is nullable or has a literal default.

-- ---------------------------------------------------------------------------
-- users: how this account proves identity, and how its vault opens
-- ---------------------------------------------------------------------------

-- How the user's data-encryption key is wrapped:
--
--   unset     no vault yet; set on first passphrase enrolment
--   derived   KEK from the local login password (different salt, so the
--             login hash and the vault key are cryptographically unrelated)
--   separate  KEK from a distinct vault passphrase. Mandatory for SSO users,
--             because the server never sees a password it could derive from.
--   server    DEK wrapped under the server master key alone. Convenient, and
--             strictly weaker: a stolen database plus master key opens it.
--             Only reachable when vault.sso_unlock_mode is server_managed.
ALTER TABLE users ADD COLUMN vault_unlock_kind TEXT NOT NULL DEFAULT 'unset';

-- Entra's tid claim, recorded so a token minted by a different tenant can
-- never be matched to an existing account even if the oid were to collide.
ALTER TABLE users ADD COLUMN sso_tenant TEXT;

-- Per-user override of the org-wide MFA policy: NULL means inherit.
ALTER TABLE users ADD COLUMN mfa_policy_override TEXT;

-- Set when an admin resets a forgotten vault. The old credentials are
-- unrecoverable by design, so the event is recorded on the account rather
-- than only in the audit log, and the UI can explain why the vault is empty.
ALTER TABLE users ADD COLUMN vault_reset_at TEXT;

-- ---------------------------------------------------------------------------
-- auth_sessions: richer state per login
-- ---------------------------------------------------------------------------

-- Whether a second factor has been satisfied for this session. For SSO logins
-- this is set from Entra's amr claim rather than by prompting again.
ALTER TABLE auth_sessions ADD COLUMN mfa_satisfied INTEGER NOT NULL DEFAULT 0;

-- Sliding idle deadline. expires_at remains the hard ceiling: activity
-- refreshes idle_expires_at but can never push a session past expires_at.
ALTER TABLE auth_sessions ADD COLUMN idle_expires_at TEXT;

-- local | oidc. Kept so an admin can see at a glance which sessions would
-- survive an Entra outage, and so break-glass logins stand out in an audit.
ALTER TABLE auth_sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'local';

-- ---------------------------------------------------------------------------
-- TOTP
-- ---------------------------------------------------------------------------

CREATE TABLE mfa_totp (
    user_id       TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,

    -- The shared secret, encrypted under the user's DEK. Consequence worth
    -- knowing: enrolling TOTP requires an unlocked vault, and so does
    -- verifying a code. That is the correct trade — a plaintext TOTP secret
    -- in the database would let anyone with a dump mint valid codes forever.
    secret_enc    TEXT NOT NULL,

    -- Confirmed only once the user has entered a code from their app, so a
    -- half-finished enrolment cannot lock them out.
    confirmed_at  TEXT,

    -- Highest time-step already accepted. A code is refused if its step is
    -- not strictly greater, which stops an observed code being replayed
    -- inside its validity window.
    last_step     INTEGER NOT NULL DEFAULT 0,

    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Recovery codes
-- ---------------------------------------------------------------------------

-- One row per code, Argon2id-hashed. Hashed rather than encrypted so they
-- remain usable when the vault is locked: a user who has lost their
-- authenticator needs a way in that does not depend on TOTP.
CREATE TABLE mfa_recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_recovery_codes_user ON mfa_recovery_codes (user_id);

-- ---------------------------------------------------------------------------
-- WebAuthn
-- ---------------------------------------------------------------------------

CREATE TABLE webauthn_credentials (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- Raw credential id and COSE public key, base64. Public data: no
    -- encryption needed, and keeping them readable means WebAuthn works
    -- while the vault is locked.
    credential_id   TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,

    -- Authenticator signature counter. A value that fails to advance
    -- indicates a cloned authenticator and is rejected.
    sign_count      INTEGER NOT NULL DEFAULT 0,

    aaguid          TEXT NOT NULL DEFAULT '',
    transports      TEXT NOT NULL DEFAULT '[]',
    label           TEXT NOT NULL DEFAULT '',

    created_at      TEXT NOT NULL,
    last_used_at    TEXT
);

CREATE INDEX idx_webauthn_user ON webauthn_credentials (user_id);

-- ---------------------------------------------------------------------------
-- Login throttling
-- ---------------------------------------------------------------------------

-- Failed attempts, persisted so a restart cannot clear an attacker's counter
-- and so throttling still works across multiple nodes in Phase 9.
CREATE TABLE login_attempts (
    id           TEXT PRIMARY KEY,
    identifier   TEXT NOT NULL,   -- normalized email or IP
    kind         TEXT NOT NULL,   -- account | ip
    attempted_at TEXT NOT NULL,
    outcome      TEXT NOT NULL    -- success | failure
);

CREATE INDEX idx_login_attempts_lookup ON login_attempts (identifier, kind, attempted_at);
