package com.example.hsm.dto;

import java.util.UUID;

/** Decryption response — plaintext is Base64-encoded. */
public record DecryptResponse(UUID keyId, String plaintext) {}
