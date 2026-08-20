-- Initial schema for bkd.
--
-- Portability note: one schema serves both PostgreSQL and SQLite.
--
-- Identifiers are TEXT (UUIDv7 generated in Go, which stays time-sortable for
-- index locality without needing a database extension), and timestamps are
-- UTC RFC3339 TEXT rather than TIMESTAMPTZ.
--
-- Binary material is stored as base64 TEXT rather than BYTEA/BLOB. Postgres
-- has no BLOB type and SQLite gives an unrecognised "BYTEA" the wrong type
-- affinity, so the two genuinely diverge; encoding to text sidesteps the
-- divergence for about 33% size overhead on values that are at most a few KB.
-- Maintaining a single schema is worth more than those bytes, and it keeps
-- database dumps readable during incident response.
--
-- Every "_enc" column below holds a base64 vault.Envelope: AES-256-GCM
-- ciphertext bound by AAD to its owner, record and field. Nothing in this
-- schema stores a secret in a form the database itself can read.

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    -- Lowercased copy of email; UNIQUE lives here so that Alice@x and
    -- alice@x cannot both register, without depending on a database-specific
    -- case-insensitive collation.
    email_normalized    TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL DEFAULT '',

    -- Argon2id hash of the *login* password, in PHC string format. Distinct
    -- from the vault passphrase: this proves identity, the vault passphrase
    -- unlocks secrets.
    password_hash       TEXT NOT NULL DEFAULT '',

    -- Wrapped per-user DEK plus the Argon2id parameters used to derive its
    -- KEK. Stored as JSON so raising costs for new users does not invalidate
    -- existing vaults. Empty until the user sets a vault passphrase.
    wrapped_dek_enc     TEXT,
    kdf_params          TEXT,

    totp_secret_enc     TEXT,          -- encrypted under the user's DEK
    totp_enabled        INTEGER NOT NULL DEFAULT 0,

    is_admin            INTEGER NOT NULL DEFAULT 0,
    is_disabled         INTEGER NOT NULL DEFAULT 0,

    -- External identity, once SSO lands. Null for local accounts.
    sso_provider        TEXT,
    sso_subject         TEXT,

    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    last_login_at       TEXT
);

CREATE UNIQUE INDEX idx_users_sso ON users (sso_provider, sso_subject)
    WHERE sso_provider IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Teams (shared credentials)
-- ---------------------------------------------------------------------------

CREATE TABLE teams (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- One row per member: the team DEK sealed under that member's personal DEK.
-- Revoking a member is a single DELETE, and no plaintext key is ever written.
CREATE TABLE team_members (
    team_id            TEXT NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    user_id            TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role               TEXT NOT NULL DEFAULT 'member',   -- member | admin
    wrapped_team_dek_enc TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX idx_team_members_user ON team_members (user_id);

-- ---------------------------------------------------------------------------
-- Credentials
-- ---------------------------------------------------------------------------

CREATE TABLE credentials (
    id              TEXT PRIMARY KEY,

    -- Exactly one of these is set. A credential belongs either to one user or
    -- to one team; the CHECK below enforces it rather than trusting callers.
    user_id         TEXT REFERENCES users (id) ON DELETE CASCADE,
    team_id         TEXT REFERENCES teams (id) ON DELETE CASCADE,

    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,   -- ssh_key | password | passphrase | enable_secret
    username        TEXT NOT NULL DEFAULT '',

    -- Encrypted payloads. Each is a serialised vault.Envelope, bound by AAD
    -- to (owner, credential id, field name).
    secret_enc      TEXT,            -- private key or password
    secret_extra_enc TEXT,           -- key passphrase, where applicable

    -- Safe to store in the clear: needed to list and match credentials
    -- without unlocking the vault.
    public_key      TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL DEFAULT '',
    key_type        TEXT NOT NULL DEFAULT '',

    -- When true the credential is wrapped under the server master key rather
    -- than a user DEK, so unattended jobs can use it with nobody logged in.
    -- Surfaced prominently in the UI: it is a deliberate weakening.
    server_unlockable INTEGER NOT NULL DEFAULT 0,

    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT,

    CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE INDEX idx_credentials_user ON credentials (user_id);
CREATE INDEX idx_credentials_team ON credentials (team_id);

-- ---------------------------------------------------------------------------
-- Session tree
-- ---------------------------------------------------------------------------

CREATE TABLE folders (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users (id) ON DELETE CASCADE,
    team_id     TEXT REFERENCES teams (id) ON DELETE CASCADE,
    parent_id   TEXT REFERENCES folders (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    sort_order  INTEGER NOT NULL DEFAULT 0,

    -- Folder-level defaults inherited by child sessions, as JSON. Mirrors
    -- SecureCRT's folder-inherits-settings behaviour so imports round-trip.
    defaults    TEXT NOT NULL DEFAULT '{}',

    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,

    CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE INDEX idx_folders_user_parent ON folders (user_id, parent_id);
CREATE INDEX idx_folders_team_parent ON folders (team_id, parent_id);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users (id) ON DELETE CASCADE,
    team_id         TEXT REFERENCES teams (id) ON DELETE CASCADE,
    folder_id       TEXT REFERENCES folders (id) ON DELETE SET NULL,

    name            TEXT NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'ssh',   -- ssh | telnet | serial
    hostname        TEXT NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 22,
    username        TEXT NOT NULL DEFAULT '',

    credential_id   TEXT REFERENCES credentials (id) ON DELETE SET NULL,

    -- Ordered list of jump-host session ids, as a JSON array. A chain rather
    -- than a single field so arbitrary-depth ProxyJump imports survive.
    jump_chain      TEXT NOT NULL DEFAULT '[]',

    -- Appearance, keepalive, logon actions, trigger rules, per-session
    -- overrides. JSON so the shape can grow without a migration per setting.
    settings        TEXT NOT NULL DEFAULT '{}',

    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT,

    CHECK ((user_id IS NULL) <> (team_id IS NULL)),
    CHECK (port BETWEEN 1 AND 65535)
);

CREATE INDEX idx_sessions_user_folder ON sessions (user_id, folder_id);
CREATE INDEX idx_sessions_team_folder ON sessions (team_id, folder_id);
CREATE INDEX idx_sessions_last_used ON sessions (user_id, last_used_at);

-- ---------------------------------------------------------------------------
-- Host key trust
-- ---------------------------------------------------------------------------

-- Per-user known_hosts. A NULL user_id marks an org-wide entry published by an
-- admin, which is trusted ahead of any per-user record.
CREATE TABLE known_hosts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users (id) ON DELETE CASCADE,
    hostname    TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22,
    key_type    TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (user_id, hostname, port, key_type)
);

CREATE INDEX idx_known_hosts_lookup ON known_hosts (hostname, port, key_type);

-- ---------------------------------------------------------------------------
-- Auth sessions
-- ---------------------------------------------------------------------------

CREATE TABLE auth_sessions (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- Hex-encoded SHA-256 of the refresh token. Storing the hash means a
    -- database dump does not yield usable session tokens.
    refresh_token_hash  TEXT NOT NULL UNIQUE,

    user_agent          TEXT NOT NULL DEFAULT '',
    ip_address          TEXT NOT NULL DEFAULT '',

    -- Whether the vault is currently unlocked for this session. The DEK
    -- itself lives only in process memory; this column is a UI hint, never a
    -- source of key material.
    vault_unlocked      INTEGER NOT NULL DEFAULT 0,

    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    revoked_at          TEXT
);

CREATE INDEX idx_auth_sessions_user ON auth_sessions (user_id);
CREATE INDEX idx_auth_sessions_expiry ON auth_sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

-- Append-only. No UPDATE or DELETE path exists in the application; retention
-- is handled by an explicit admin command that archives before pruning.
CREATE TABLE audit_events (
    id           TEXT PRIMARY KEY,
    occurred_at  TEXT NOT NULL,

    actor_id     TEXT,          -- no FK: events outlive deleted accounts
    actor_email  TEXT NOT NULL DEFAULT '',
    ip_address   TEXT NOT NULL DEFAULT '',

    action       TEXT NOT NULL, -- e.g. login, vault.unlock, credential.export
    severity     TEXT NOT NULL DEFAULT 'info',   -- info | notice | warning | critical

    target_type  TEXT NOT NULL DEFAULT '',
    target_id    TEXT NOT NULL DEFAULT '',
    target_label TEXT NOT NULL DEFAULT '',

    outcome      TEXT NOT NULL DEFAULT 'success', -- success | failure | denied
    detail       TEXT NOT NULL DEFAULT '{}'       -- JSON; never holds secrets
);

CREATE INDEX idx_audit_time ON audit_events (occurred_at);
CREATE INDEX idx_audit_actor ON audit_events (actor_id, occurred_at);
CREATE INDEX idx_audit_action ON audit_events (action, occurred_at);
