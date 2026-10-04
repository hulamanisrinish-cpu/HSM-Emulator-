package com.example.hsm.entity;

/** All auditable actions in the HSM emulator. */
public enum AuditAction {
    USER_CREATE, USER_DISABLE,
    ROLE_ASSIGN, ROLE_REVOKE,
    KEY_GENERATE, KEY_ROTATE, KEY_DISABLE, KEY_ENABLE, KEY_DESTROY,
    ACL_GRANT, ACL_REVOKE,
    ENCRYPT, DECRYPT, SIGN, VERIFY,
    AUDIT_READ, AUDIT_VERIFY
}
