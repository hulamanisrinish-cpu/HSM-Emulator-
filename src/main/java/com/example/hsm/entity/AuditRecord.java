package com.example.hsm.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/** Append-only, hash-chained audit log record. */
@Entity
@Table(name = "hsm_audit_log")
public class AuditRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "audit_seq")
    @SequenceGenerator(name = "audit_seq", sequenceName = "hsm_audit_log_sequence_number_seq", allocationSize = 1)
    @Column(name = "sequence_number")
    private Long sequenceNumber;

    @Column(nullable = false, unique = true)
    private UUID id = UUID.randomUUID();

    /**
     * Truncated to microseconds: PostgreSQL {@code TIMESTAMPTZ} stores microsecond precision,
     * so an untruncated {@code Instant.now()} (nanosecond) would be silently rounded on write.
     * The audit chain hash is computed from this value in memory and re-computed from the DB
     * value on verification — they must be byte-identical or every verification would fail.
     */
    @Column(name = "recorded_at", nullable = false)
    private Instant recordedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);

    @Column(name = "principal_id")
    private UUID principalId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 64)
    private AuditAction action;

    @Column(name = "key_id")
    private UUID keyId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AuditOutcome outcome;

    @Column(name = "chain_hash", nullable = false, length = 64)
    private String chainHash;

    protected AuditRecord() {}

    public AuditRecord(UUID principalId, AuditAction action, UUID keyId,
                       AuditOutcome outcome, String chainHash) {
        this.principalId = principalId;
        this.action = action;
        this.keyId = keyId;
        this.outcome = outcome;
        this.chainHash = chainHash;
        this.recordedAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
    }

    public Long getSequenceNumber() { return sequenceNumber; }
    public UUID getId() { return id; }
    public Instant getRecordedAt() { return recordedAt; }
    public UUID getPrincipalId() { return principalId; }
    public AuditAction getAction() { return action; }
    public UUID getKeyId() { return keyId; }
    public AuditOutcome getOutcome() { return outcome; }
    public String getChainHash() { return chainHash; }
    public void setChainHash(String chainHash) { this.chainHash = chainHash; }
}
