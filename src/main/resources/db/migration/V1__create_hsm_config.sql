-- V1: HSM configuration table (stores persistent config like the PBKDF2 salt)
CREATE TABLE hsm_config (
    id          BIGSERIAL    PRIMARY KEY,
    config_key  VARCHAR(128) NOT NULL UNIQUE,
    config_value TEXT        NOT NULL
);
