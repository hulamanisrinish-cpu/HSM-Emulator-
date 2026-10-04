package com.example.hsm.exception;

/** Thrown for unexpected internal errors (→ HTTP 500). Details are NOT surfaced to the caller. */
public class HsmInternalException extends HsmException {
    public HsmInternalException(String message) { super(message); }
    public HsmInternalException(String message, Throwable cause) { super(message, cause); }
}
