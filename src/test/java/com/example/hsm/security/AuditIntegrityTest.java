package com.example.hsm.security;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.controller.BaseControllerIT;
import com.example.hsm.entity.HsmRole;
import com.example.hsm.service.audit.AuditVerifyResult;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

/** Verifies hash-chain tampering is detected. */
@Tag("security")
class AuditIntegrityTest extends BaseControllerIT {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String auditorToken;

    @BeforeEach
    void setup() {
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        auditorToken = createUserAndGetToken("aud-integrity-" + ts, HsmRole.AUDITOR, adminToken);
        // Generate some audit records by reading the log
        get("/api/v1/audit", auditorToken, String.class);
        get("/api/v1/audit", auditorToken, String.class);
    }

    @Test
    void tamperedRecordIsDetected() {
        // Corrupt a chain_hash in the middle of the log
        jdbcTemplate.update(
            "UPDATE hsm_audit_log SET chain_hash = '0000000000000000000000000000000000000000000000000000000000000000' " +
            "WHERE sequence_number = (SELECT MIN(sequence_number) FROM hsm_audit_log)");

        var resp = get("/api/v1/audit/verify", auditorToken, AuditVerifyResult.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertFalse(resp.getBody().valid(), "Tampered chain_hash must be detected");
        assertNotNull(resp.getBody().firstTamperedSequence());
    }

    @Test
    void tamperedFieldDetected() {
        // Change the action field in a record — hash will no longer match
        jdbcTemplate.update(
            "UPDATE hsm_audit_log SET action = 'KEY_DESTROY' " +
            "WHERE sequence_number = (SELECT MIN(sequence_number) FROM hsm_audit_log) " +
            "  AND action != 'KEY_DESTROY'");

        var resp = get("/api/v1/audit/verify", auditorToken, AuditVerifyResult.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertFalse(resp.getBody().valid(), "Tampered action field must be detected");
    }
}
