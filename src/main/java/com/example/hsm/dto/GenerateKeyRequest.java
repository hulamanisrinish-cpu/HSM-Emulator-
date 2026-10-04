package com.example.hsm.dto;

import com.example.hsm.entity.HsmAlgorithm;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Request to generate a new cryptographic key. */
public record GenerateKeyRequest(
        @NotBlank String name,
        @NotNull HsmAlgorithm algorithm,
        String description
) {}
