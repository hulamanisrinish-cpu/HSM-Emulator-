package com.example.hsm.entity;

/** Lifecycle state of a cryptographic key. */
public enum KeyState {
    /** Key is available for all operations. */
    ACTIVE,
    /** Key is suspended. Existing ciphertext can still be decrypted; new operations rejected. */
    DISABLED,
    /** Key has been permanently destroyed. Wrapped key material has been zeroed in the DB. Terminal state. */
    DESTROYED
}
