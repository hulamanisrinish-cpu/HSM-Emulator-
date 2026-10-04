package com.example.hsm.repository;

import com.example.hsm.entity.AuditRecord;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Repository for immutable audit log records. */
public interface AuditRecordRepository extends JpaRepository<AuditRecord, Long> {

    /** Returns the most recent record for hash-chain computation. */
    Optional<AuditRecord> findTopByOrderBySequenceNumberDesc();

    /** Paginated time-range query for audit log reads. */
    Page<AuditRecord> findByRecordedAtBetween(Instant from, Instant to, Pageable pageable);

    /** Full ordered sequence for chain verification. */
    List<AuditRecord> findAllByOrderBySequenceNumberAsc();
}
