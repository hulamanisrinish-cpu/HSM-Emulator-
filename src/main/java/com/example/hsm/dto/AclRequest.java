package com.example.hsm.dto;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/** Request to grant a principal access to a key. */
public record AclRequest(@NotNull UUID principalId) {}
