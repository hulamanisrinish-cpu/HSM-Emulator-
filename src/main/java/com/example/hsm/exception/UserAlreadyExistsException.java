package com.example.hsm.exception;

/** Thrown when creating a user with a username that already exists (→ HTTP 409). */
public class UserAlreadyExistsException extends HsmException {
    public UserAlreadyExistsException(String username) { super("User already exists: " + username); }
}
