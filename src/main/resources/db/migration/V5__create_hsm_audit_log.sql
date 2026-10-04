-- V5: Audit log (append-only, hash-chained for tamper evidence)
CREATE TABLE hsm_audit_log (
    sequence_number BIGSERIAL    PRIMARY KEY,
    id              UUID         NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    recorded_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    principal_id    UUID,
    action          VARCHAR(64)  NOT NULL,
    key_id          UUID,
    outcome         VARCHAR(16)  NOT NULL CHECK (outcome IN ('SUCCESS','DENIED','ERROR')),
    chain_hash      VARCHAR(64)  NOT NULL
);

CREATE INDEX idx_audit_recorded_at    ON hsm_audit_log (recorded_at);
CREATE INDEX idx_audit_principal_id   ON hsm_audit_log (principal_id);
CREATE INDEX idx_audit_key_id         ON hsm_audit_log (key_id);
