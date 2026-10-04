package com.example.hsm.entity;

/** Roles assignable to HSM users. Each role has a strictly limited permission set. */
public enum HsmRole {
    /** Creates users and assigns roles. Cannot perform crypto operations. */
    ADMIN,
    /** Manages the key lifecycle (generate, rotate, disable, destroy). Cannot use keys directly. */
    CRYPTO_OFFICER,
    /** Performs crypto operations (encrypt, decrypt, sign, verify) on keys it has been granted. */
    APP_CLIENT,
    /** Read-only access to the audit log. Cannot manage keys or users. */
    AUDITOR
}
