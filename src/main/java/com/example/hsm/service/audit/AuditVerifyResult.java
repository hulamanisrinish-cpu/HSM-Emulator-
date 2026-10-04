package com.example.hsm.service.audit;

import java.time.Instant;

/** Result of an audit chain integrity verification. */
public record AuditVerifyResult(boolean valid, long recordCount, Long firstTamperedSequence, Instant verifiedAt) {}
