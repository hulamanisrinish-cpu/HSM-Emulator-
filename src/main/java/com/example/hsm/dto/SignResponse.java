package com.example.hsm.dto;

import java.util.UUID;

/** Signing response — signature is Base64-encoded. */
public record SignResponse(UUID keyId, String algorithm, String signature) {}
