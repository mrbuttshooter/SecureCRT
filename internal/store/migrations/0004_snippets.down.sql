-- Drop the snippets table.
--
-- The indexes go with it on both backends; naming them here as well would
-- fail on PostgreSQL, which has already removed them.

DROP TABLE snippets;
