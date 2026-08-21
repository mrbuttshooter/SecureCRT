-- Phase 8: the dormant team schema comes alive.
--
-- Teams, team-owned folders and sessions have existed since 0001; what was
-- missing was the one thing sharing a tree without sharing credentials
-- needs: each member's own answer to "which of MY credentials opens the
-- devices in this shared folder". One row per (user, folder), because the
-- choice is remembered per shared folder — one decision covers a rack.
--
-- Portability: TEXT identifiers, RFC3339 UTC TEXT timestamps. The same rules
-- as 0001.

CREATE TABLE user_folder_credentials (
    user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    folder_id     TEXT NOT NULL REFERENCES folders (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    updated_at    TEXT NOT NULL,

    PRIMARY KEY (user_id, folder_id)
);

CREATE INDEX idx_user_folder_credentials_folder
    ON user_folder_credentials (folder_id);
