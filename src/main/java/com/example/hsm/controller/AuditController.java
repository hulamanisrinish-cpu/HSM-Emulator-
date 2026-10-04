package com.example.hsm.controller;

import com.example.hsm.dto.AuditPageResponse;
import com.example.hsm.dto.AuditRecordDto;
import com.example.hsm.entity.AuditRecord;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.audit.AuditService;
import com.example.hsm.service.audit.AuditVerifyResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

/** REST endpoints for audit log access. Auditor role required. */
@RestController
@RequestMapping("/api/v1/audit")
@Tag(name = "Audit Log", description = "Read-only audit log access — Auditor role required")
@PreAuthorize("hasRole('AUDITOR')")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) { this.auditService = auditService; }

    @GetMapping
    @Operation(summary = "List audit records with optional time range and pagination")
    public AuditPageResponse getRecords(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @AuthenticationPrincipal HsmPrincipal caller) {
        Instant start = from != null ? from : Instant.EPOCH;
        Instant end = to != null ? to : Instant.now().plusSeconds(60);
        Page<AuditRecord> p = auditService.getRecords(PageRequest.of(page, size), start, end, caller);
        List<AuditRecordDto> dtos = p.getContent().stream().map(this::toDto).toList();
        return new AuditPageResponse((int) p.getNumber(), p.getSize(), p.getTotalElements(), dtos);
    }

    @GetMapping("/verify")
    @Operation(summary = "Verify audit log chain integrity")
    public AuditVerifyResult verifyChain(@AuthenticationPrincipal HsmPrincipal caller) {
        return auditService.verifyChain(caller);
    }

    private AuditRecordDto toDto(AuditRecord r) {
        return new AuditRecordDto(r.getSequenceNumber(), r.getId(), r.getRecordedAt(),
                r.getPrincipalId(), r.getAction(), r.getKeyId(), r.getOutcome(), r.getChainHash());
    }
}
