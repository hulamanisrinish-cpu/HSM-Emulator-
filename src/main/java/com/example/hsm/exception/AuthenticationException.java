package com.example.hsm.exception;

/** Thrown when a request cannot be authenticated (→ HTTP 401). */
public class AuthenticationException extends HsmException {
    public AuthenticationException(String message) { super(message); }
}
