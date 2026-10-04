package com.example.hsm.dto;

import java.util.UUID;

/** Signature verification response. */
public record VerifyResponse(UUID keyId, boolean valid) {}
