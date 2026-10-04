package com.example.hsm.exception;

import java.util.UUID;

/** Thrown when a requested key does not exist (→ HTTP 404). */
public class KeyNotFoundException extends HsmException {
    public KeyNotFoundException(UUID id) { super("Key not found: " + id); }
    public KeyNotFoundException(String name) { super("Key not found: " + name); }
}
