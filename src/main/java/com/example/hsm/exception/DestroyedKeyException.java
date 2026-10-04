package com.example.hsm.exception;

import java.util.UUID;

/** Thrown when an operation is attempted on a permanently destroyed key (→ HTTP 410). */
public class DestroyedKeyException extends InvalidKeyStateException {
    public DestroyedKeyException(UUID keyId) {
        super("Key " + keyId + " has been permanently destroyed");
    }
}
