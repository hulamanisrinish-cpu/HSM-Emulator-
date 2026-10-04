package com.example.hsm.exception;

/** Thrown when an operation is not allowed in the key's current state (→ HTTP 422 or 410). */
public class InvalidKeyStateException extends HsmException {
    public InvalidKeyStateException(String message) { super(message); }
}
