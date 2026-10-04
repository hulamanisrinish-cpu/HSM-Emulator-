-- V3: Keys table (wrapped DEKs, metadata — no raw key material)
CREATE TABLE hsm_keys (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(256) NOT NULL UNIQUE,
    algorithm        VARCHAR(32)  NOT NULL CHECK (algorithm IN ('AES_256','RSA_2048','EC_P256')),
    key_state        VARCHAR(16)  NOT NULL CHECK (key_state IN ('ACTIVE','DISABLED','DESTROYED')) DEFAULT 'ACTIVE',
    version          INTEGER      NOT NULL DEFAULT 1,
    wrapped_dek      BYTEA        NOT NULL,
    iv_dek           BYTEA        NOT NULL,
    auth_tag_dek     BYTEA        NOT NULL,
    key_type         VARCHAR(16)  NOT NULL CHECK (key_type IN ('SYMMETRIC','ASYMMETRIC')),
    public_key_bytes BYTEA,
    created_by       UUID         REFERENCES hsm_users(id),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_rotated_at  TIMESTAMPTZ,
    disabled_at      TIMESTAMPTZ,
    destroyed_at     TIMESTAMPTZ
);

CREATE INDEX idx_hsm_keys_state   ON hsm_keys (key_state);
CREATE INDEX idx_hsm_keys_created ON hsm_keys (created_at);
