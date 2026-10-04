package com.example.hsm.dto;

import com.example.hsm.entity.HsmRole;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Request to create a new HSM user. */
public record CreateUserRequest(@NotBlank String username, @NotNull HsmRole role) {}
