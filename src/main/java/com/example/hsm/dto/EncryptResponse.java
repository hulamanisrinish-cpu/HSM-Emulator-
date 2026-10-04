package com.example.hsm.dto;

import java.util.UUID;

/** Encryption response — all byte fields are Base64-encoded strings. */
public record EncryptResponse(UUID keyId, int keyVersion, String algorithm, String iv, String ciphertext, String authTag) {}
