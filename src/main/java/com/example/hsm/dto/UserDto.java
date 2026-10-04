package com.example.hsm.dto;

import com.example.hsm.entity.HsmRole;

import java.time.Instant;
import java.util.UUID;

/** User metadata — never includes token or hash. */
public record UserDto(UUID id, String username, HsmRole role, Instant createdAt, boolean enabled) {}
