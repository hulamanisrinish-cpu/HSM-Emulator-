package com.example.hsm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Decryption request — all byte fields are Base64-encoded strings. */
public record DecryptRequest(
        @NotNull UUID keyId,
        @NotBlank String iv,
        @NotBlank String ciphertext,
        @NotBlank String authTag
) {}
