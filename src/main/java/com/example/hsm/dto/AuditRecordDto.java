package com.example.hsm.dto;

import com.example.hsm.entity.AuditAction;
import com.example.hsm.entity.AuditOutcome;

import java.time.Instant;
import java.util.UUID;

/** Immutable audit record DTO. */
public record AuditRecordDto(
        long sequenceNumber,
        UUID id,
        Instant recordedAt,
        UUID principalId,
        AuditAction action,
        UUID keyId,
        AuditOutcome outcome,
        String chainHash
) {}
