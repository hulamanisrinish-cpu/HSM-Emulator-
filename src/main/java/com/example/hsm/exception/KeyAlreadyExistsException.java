package com.example.hsm.exception;

/** Thrown when creating a key/user with a name that already exists (→ HTTP 409). */
public class KeyAlreadyExistsException extends HsmException {
    public KeyAlreadyExistsException(String name) { super("Already exists: " + name); }
}
