-- Command snippets: the thing people paste into a terminal for the hundredth
-- time.
--
-- Ownership mirrors folders and sessions exactly — a user_id or a team_id,
-- never both, never neither — even though nothing sets team_id yet. Teams are
-- schema-only until RBAC arrives in Phase 8, and a snippets table that could
-- only ever belong to one person would need this migration written again to
-- turn sharing on. The constraint is here now so that phase is an API change
-- rather than a schema change on a table full of people's data.
--
-- Portability: TEXT identifiers, RFC3339 UTC TEXT timestamps, JSON in TEXT.
-- The same rules as 0001.

CREATE TABLE snippets (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users (id) ON DELETE CASCADE,
    team_id     TEXT REFERENCES teams (id) ON DELETE CASCADE,

    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',

    -- What gets typed. Parameters are written {{name}} and filled in before
    -- sending; the values are never stored, which is what keeps a snippet
    -- from quietly becoming a place people keep passwords.
    body        TEXT NOT NULL,

    -- Ordered list of parameter names, as a JSON array. Derived from the body
    -- when a snippet is saved rather than typed separately, so the two cannot
    -- disagree — but stored, so listing snippets does not mean parsing every
    -- body to find out whether one will ask a question.
    parameters  TEXT NOT NULL DEFAULT '[]',

    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,

    CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE INDEX idx_snippets_user ON snippets (user_id, sort_order);
CREATE INDEX idx_snippets_team ON snippets (team_id, sort_order);

-- A person cannot have two snippets with the same name, because the interface
-- picks them by name and an ambiguous list is worse than a rejected save.
-- Partial, so the two owner kinds are independent of each other.
CREATE UNIQUE INDEX idx_snippets_user_name
    ON snippets (user_id, name) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX idx_snippets_team_name
    ON snippets (team_id, name) WHERE team_id IS NOT NULL;
