-- V2: Users table (hashed API tokens, roles)
CREATE TABLE hsm_users (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(128) NOT NULL UNIQUE,
    token_hash  VARCHAR(512) NOT NULL,
    role        VARCHAR(32)  NOT NULL CHECK (role IN ('ADMIN','CRYPTO_OFFICER','APP_CLIENT','AUDITOR')),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_hsm_users_username ON hsm_users (username);
