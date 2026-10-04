package com.example.hsm.exception;

/** Thrown when a cryptographic operation fails (e.g. authentication tag mismatch) (→ HTTP 400). */
public class CryptographicOperationException extends HsmException {
    public CryptographicOperationException(String message) { super(message); }
    public CryptographicOperationException(String message, Throwable cause) { super(message, cause); }
}
