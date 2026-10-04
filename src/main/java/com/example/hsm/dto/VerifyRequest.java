package com.example.hsm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Signature verification request — data and signature are Base64-encoded. */
public record VerifyRequest(@NotNull UUID keyId, @NotBlank String data, @NotBlank String signature) {}
