package com.example.hsm.service.audit;

import com.example.hsm.entity.AuditAction;
import com.example.hsm.entity.AuditOutcome;
import com.example.hsm.entity.AuditRecord;
import com.example.hsm.repository.AuditRecordRepository;
import com.example.hsm.security.HsmPrincipal;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Append-only, hash-chained audit log service.
 *
 * <p>Every operation in the HSM emulator calls {@link #appendRecord} to persist an immutable
 * audit entry. The {@code chainHash} field is a SHA-256 hash over the previous hash plus the
 * current record's fields, making any tampering detectable via {@link #verifyChain()}.
 *
 * <p>DENIED and ERROR outcomes use {@link Propagation#REQUIRES_NEW} so they commit even when
 * the surrounding transaction rolls back.
 */
@Service
public class AuditService {

    private static final String ZERO_HASH = "0".repeat(64);
    private final AuditRecordRepository auditRepo;

    public AuditService(AuditRecordRepository auditRepo) {
        this.auditRepo = auditRepo;
    }

    /**
     * Appends an audit record using {@link Propagation#REQUIRED} (SUCCESS path).
     *
     * @param action    the action taken
     * @param keyId     optional key involved
     * @param outcome   SUCCESS
     * @param principal the authenticated caller (null for system events)
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void appendRecord(AuditAction action, UUID keyId, AuditOutcome outcome, HsmPrincipal principal) {
        persistRecord(action, keyId, outcome, principal);
    }

    /**
     * Appends an audit record in a NEW transaction (DENIED/ERROR paths).
     * This ensures denial events are always persisted even when the primary tx rolls back.
     *
     * @param action    the action taken
     * @param keyId     optional key involved
     * @param outcome   DENIED or ERROR
     * @param principal the authenticated caller
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void appendDeniedOrError(AuditAction action, UUID keyId, AuditOutcome outcome, HsmPrincipal principal) {
        persistRecord(action, keyId, outcome, principal);
    }

    /**
     * Returns a paginated audit log for the given time range.
     * Requires AUDITOR role. The read itself is audited.
     *
     * @param pageable pagination parameters
     * @param from     start of time range
     * @param to       end of time range
     * @param caller   the auditor reading the log
     * @return page of audit records
     */
    // NB: not readOnly — the method appends an AUDIT_READ record, and Postgres rejects
    // nextval()/INSERT inside a read-only transaction (SQLState 25006).
    @Transactional
    @PreAuthorize("hasRole('AUDITOR')")
    public Page<AuditRecord> getRecords(Pageable pageable, Instant from, Instant to, HsmPrincipal caller) {
        Page<AuditRecord> page = auditRepo.findByRecordedAtBetween(from, to, pageable);
        appendRecord(AuditAction.AUDIT_READ, null, AuditOutcome.SUCCESS, caller);
        return page;
    }

    /**
     * Verifies the entire audit chain by recomputing each record's hash.
     * Requires AUDITOR role.
     *
     * @param caller the auditor performing the verification
     * @return a {@link AuditVerifyResult} indicating whether the chain is intact
     */
    // NB: not readOnly — the method appends an AUDIT_VERIFY record (see getRecords).
    @Transactional
    @PreAuthorize("hasRole('AUDITOR')")
    public AuditVerifyResult verifyChain(HsmPrincipal caller) {
        List<AuditRecord> records = auditRepo.findAllByOrderBySequenceNumberAsc();
        appendRecord(AuditAction.AUDIT_VERIFY, null, AuditOutcome.SUCCESS, caller);
        if (records.isEmpty()) {
            return new AuditVerifyResult(true, 0, null, Instant.now());
        }
        String prevHash = ZERO_HASH;
        for (AuditRecord rec : records) {
            String expected = computeHash(prevHash, rec);
            if (!expected.equals(rec.getChainHash())) {
                return new AuditVerifyResult(false, records.size(), rec.getSequenceNumber(), Instant.now());
            }
            prevHash = rec.getChainHash();
        }
        return new AuditVerifyResult(true, records.size(), null, Instant.now());
    }

    // ── private ────────────────────────────────────────────────────────────────

    private void persistRecord(AuditAction action, UUID keyId, AuditOutcome outcome, HsmPrincipal principal) {
        String prevHash = auditRepo.findTopByOrderBySequenceNumberDesc()
                .map(AuditRecord::getChainHash)
                .orElse(ZERO_HASH);
        UUID principalId = principal != null ? principal.id() : null;
        // Sequence number is not yet assigned here — we use a placeholder for hash input
        // The hash is computed after save so we re-save with the real seq number
        AuditRecord rec = new AuditRecord(principalId, action, keyId, outcome, ZERO_HASH);
        rec = auditRepo.saveAndFlush(rec); // get real sequence number
        String hash = computeHash(prevHash, rec);
        rec.setChainHash(hash);
        auditRepo.save(rec);
    }

    public String computeHash(String prevHash, AuditRecord rec) {
        String input = prevHash + "|" +
                rec.getSequenceNumber() + "|" +
                rec.getRecordedAt().toString() + "|" +
                (rec.getPrincipalId() != null ? rec.getPrincipalId().toString() : "SYSTEM") + "|" +
                rec.getAction().name() + "|" +
                (rec.getKeyId() != null ? rec.getKeyId().toString() : "null") + "|" +
                rec.getOutcome().name();
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
