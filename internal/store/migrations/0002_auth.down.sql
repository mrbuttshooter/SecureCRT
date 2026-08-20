DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_totp;

-- SQLite gained DROP COLUMN in 3.35; both supported backends have it.
ALTER TABLE auth_sessions DROP COLUMN auth_method;
ALTER TABLE auth_sessions DROP COLUMN idle_expires_at;
ALTER TABLE auth_sessions DROP COLUMN mfa_satisfied;

ALTER TABLE users DROP COLUMN vault_reset_at;
ALTER TABLE users DROP COLUMN mfa_policy_override;
ALTER TABLE users DROP COLUMN sso_tenant;
ALTER TABLE users DROP COLUMN vault_unlock_kind;
