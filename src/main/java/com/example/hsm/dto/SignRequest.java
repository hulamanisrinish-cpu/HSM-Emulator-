package com.example.hsm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Signing request — data is Base64-encoded. */
public record SignRequest(@NotNull UUID keyId, @NotBlank String data) {}
