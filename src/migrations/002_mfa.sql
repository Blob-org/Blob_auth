-- Multi-factor authentication (TOTP and recovery codes).

-- Encrypted TOTP secret (see src/mfa.ts). Set but not enabled while setup
-- is unconfirmed.
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled_at INTEGER;
-- The last 30-second step accepted, so a code can't be used twice.
ALTER TABLE users ADD COLUMN totp_last_step INTEGER;

-- 1 when the session was opened with a second factor.
ALTER TABLE refresh_tokens ADD COLUMN mfa INTEGER NOT NULL DEFAULT 0;

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id, code_hash);
