-- Restore the constraint that made a port mandatory.
--
-- Rows storing 0 — connections whose port is inherited — are given the
-- protocol's default on the way down, because the old CHECK will not accept
-- zero and there is nowhere else for the information to go. A folder default
-- is lost in that translation, which is unavoidable: the old schema has no
-- way to express one.

CREATE TABLE sessions_rebuilt (
    id              TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users (id) ON DELETE CASCADE,
    team_id         TEXT REFERENCES teams (id) ON DELETE CASCADE,
    folder_id       TEXT REFERENCES folders (id) ON DELETE SET NULL,

    name            TEXT NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'ssh',
    hostname        TEXT NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 22,
    username        TEXT NOT NULL DEFAULT '',

    credential_id   TEXT REFERENCES credentials (id) ON DELETE SET NULL,

    jump_chain      TEXT NOT NULL DEFAULT '[]',
    settings        TEXT NOT NULL DEFAULT '{}',

    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT,

    CHECK ((user_id IS NULL) <> (team_id IS NULL)),
    CHECK (port BETWEEN 1 AND 65535)
);

INSERT INTO sessions_rebuilt (
    id, user_id, team_id, folder_id,
    name, protocol, hostname, port, username, credential_id,
    jump_chain, settings, sort_order, created_at, updated_at, last_used_at
)
SELECT
    id, user_id, team_id, folder_id,
    name, protocol, hostname,
    CASE
        WHEN port <> 0 THEN port
        WHEN protocol = 'telnet' THEN 23
        ELSE 22
    END,
    username, credential_id,
    jump_chain, settings, sort_order, created_at, updated_at, last_used_at
FROM sessions;

DROP TABLE sessions;

ALTER TABLE sessions_rebuilt RENAME TO sessions;

CREATE INDEX idx_sessions_user_folder ON sessions (user_id, folder_id);
CREATE INDEX idx_sessions_team_folder ON sessions (team_id, folder_id);
CREATE INDEX idx_sessions_last_used ON sessions (user_id, last_used_at);
