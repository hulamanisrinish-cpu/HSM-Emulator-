package com.example.hsm.exception;

/** Thrown when an authenticated principal lacks permission for an operation (→ HTTP 403). */
public class AccessDeniedException extends HsmException {
    public AccessDeniedException(String message) { super(message); }
}
