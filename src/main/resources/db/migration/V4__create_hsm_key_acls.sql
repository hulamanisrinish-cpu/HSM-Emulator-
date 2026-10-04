-- V4: Per-key ACLs (controls which AppClient principals can use each key)
CREATE TABLE hsm_key_acls (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id       UUID        NOT NULL REFERENCES hsm_keys(id),
    principal_id UUID        NOT NULL REFERENCES hsm_users(id),
    permission   VARCHAR(16) NOT NULL CHECK (permission IN ('ALLOW')) DEFAULT 'ALLOW',
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by   UUID        REFERENCES hsm_users(id),
    CONSTRAINT uq_acl_key_principal UNIQUE (key_id, principal_id)
);

CREATE INDEX idx_acl_key_id ON hsm_key_acls (key_id);
CREATE INDEX idx_acl_principal_id ON hsm_key_acls (principal_id);
