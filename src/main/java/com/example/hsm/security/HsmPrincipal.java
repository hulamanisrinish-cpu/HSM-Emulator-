package com.example.hsm.security;

import com.example.hsm.entity.HsmRole;

import java.util.UUID;

/**
 * Authenticated HSM principal injected into Spring Security context.
 * Token hash is never stored here.
 */
public record HsmPrincipal(UUID id, String username, HsmRole role) {}
