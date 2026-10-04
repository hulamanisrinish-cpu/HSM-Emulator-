package com.example.hsm.exception;

/** Base class for all HSM-specific exceptions. Message must never contain raw key bytes. */
public abstract class HsmException extends RuntimeException {
    protected HsmException(String message) { super(message); }
    protected HsmException(String message, Throwable cause) { super(message, cause); }
}
