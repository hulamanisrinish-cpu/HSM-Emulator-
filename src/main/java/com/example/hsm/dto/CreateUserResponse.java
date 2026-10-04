package com.example.hsm.dto;

import com.example.hsm.entity.HsmRole;

import java.util.UUID;

/**
 * Response containing the new user's plain bearer token.
 * The token is shown ONCE — it is never stored in plain form.
 */
public record CreateUserResponse(UUID id, String username, HsmRole role, String token, String warning) {}
