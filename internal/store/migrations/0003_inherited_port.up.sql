-- Let a session's port be inherited from its folder.
--
-- The bug this fixes has been there since 0001 and is entirely invisible from
-- the outside: a folder could carry a default port, the interface offered the
-- field, the importers wrote it, and it never took effect on a single
-- connection.
--
-- The reason is here rather than in the Go: `port INTEGER NOT NULL DEFAULT 22`
-- with `CHECK (port BETWEEN 1 AND 65535)` gives the column no way to say
-- "unset". So CreateSession filled in the protocol's default before storing,
-- the column was never empty, and Resolve's fallback to the folder default
-- was unreachable code. Zero now means inherit — the same convention the
-- username and credential columns already use with the empty string.
--
-- Existing rows are left exactly as they are. A connection created before
-- this migration has an explicit port whether its owner typed one or not, and
-- rewriting 22 to 0 would silently re-point every default-port connection at
-- whatever its folder happens to say. That is a change of behaviour nobody
-- asked for, applied to data, by a migration. Anyone wanting inheritance on
-- an existing connection clears the field.
--
-- Portability: a table rebuild, because SQLite's ALTER TABLE cannot alter or
-- drop a CHECK constraint. It works identically on PostgreSQL, and avoids
-- naming a constraint that 0001 left unnamed — PostgreSQL's generated names
-- for the two table-level CHECKs on this table are not something to depend
-- on. Nothing has a foreign key *into* sessions, which is what makes the drop
-- safe on both.

CREATE TABLE sessions_rebuilt (
    id              TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users (id) ON DELETE CASCADE,
    team_id         TEXT REFERENCES teams (id) ON DELETE CASCADE,
    folder_id       TEXT REFERENCES folders (id) ON DELETE SET NULL,

    name            TEXT NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'ssh',   -- ssh | telnet | serial
    hostname        TEXT NOT NULL DEFAULT '',

    -- 0 means "inherit": the folder's default if it has one, otherwise the
    -- protocol's.
    port            INTEGER NOT NULL DEFAULT 0,
    username        TEXT NOT NULL DEFAULT '',

    credential_id   TEXT REFERENCES credentials (id) ON DELETE SET NULL,

    jump_chain      TEXT NOT NULL DEFAULT '[]',
    settings        TEXT NOT NULL DEFAULT '{}',

    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_used_at    TEXT,

    CHECK ((user_id IS NULL) <> (team_id IS NULL)),
    CHECK (port = 0 OR port BETWEEN 1 AND 65535)
);

INSERT INTO sessions_rebuilt (
    id, user_id, team_id, folder_id,
    name, protocol, hostname, port, username, credential_id,
    jump_chain, settings, sort_order, created_at, updated_at, last_used_at
)
SELECT
    id, user_id, team_id, folder_id,
    name, protocol, hostname, port, username, credential_id,
    jump_chain, settings, sort_order, created_at, updated_at, last_used_at
FROM sessions;

DROP TABLE sessions;

ALTER TABLE sessions_rebuilt RENAME TO sessions;

CREATE INDEX idx_sessions_user_folder ON sessions (user_id, folder_id);
CREATE INDEX idx_sessions_team_folder ON sessions (team_id, folder_id);
CREATE INDEX idx_sessions_last_used ON sessions (user_id, last_used_at);
