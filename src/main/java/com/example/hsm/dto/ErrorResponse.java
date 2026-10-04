package com.example.hsm.dto;

import java.time.Instant;

/** Standard error response body. Stack traces are never included. */
public record ErrorResponse(Instant timestamp, int status, String error, String message, String path) {}
