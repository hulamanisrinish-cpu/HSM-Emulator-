-- V6: Add token_prefix column for fast bearer-token lookup
ALTER TABLE hsm_users ADD COLUMN token_prefix VARCHAR(16);
CREATE INDEX idx_users_token_prefix ON hsm_users(token_prefix);
