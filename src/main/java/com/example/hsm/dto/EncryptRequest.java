package com.example.hsm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Encryption request — plaintext is Base64-encoded. */
public record EncryptRequest(@NotNull UUID keyId, @NotBlank String plaintext) {}
