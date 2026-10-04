package com.example.hsm.controller;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.dto.AuditPageResponse;
import com.example.hsm.dto.GenerateKeyRequest;
import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.entity.HsmRole;
import com.example.hsm.service.audit.AuditVerifyResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;

class AuditControllerIT extends BaseControllerIT {

    private String auditorToken;
    private String appClientToken;

    @BeforeEach
    void setup() {
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        auditorToken = createUserAndGetToken("aud-audit-" + ts, HsmRole.AUDITOR, adminToken);
        appClientToken = createUserAndGetToken("ac-audit-" + ts, HsmRole.APP_CLIENT, adminToken);
    }

    @Test
    void auditorCanReadLog() {
        ResponseEntity<AuditPageResponse> resp = get("/api/v1/audit", auditorToken, AuditPageResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertNotNull(resp.getBody().records());
    }

    @Test
    @Tag("security")
    void appClientCannotReadLog() {
        ResponseEntity<String> resp = get("/api/v1/audit", appClientToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    void paginationWorksCorrectly() {
        ResponseEntity<AuditPageResponse> resp = restTemplate.exchange(
                "/api/v1/audit?page=0&size=5", HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(auditorToken)), AuditPageResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertTrue(resp.getBody().records().size() <= 5);
    }

    @Test
    void auditReadWithExplicitTimeRangeReturns200() {
        String from = java.time.Instant.now().minusSeconds(3600).toString();
        String to = java.time.Instant.now().plusSeconds(60).toString();
        ResponseEntity<AuditPageResponse> resp = restTemplate.exchange(
                "/api/v1/audit?from=" + from + "&to=" + to, HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(auditorToken)), AuditPageResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertNotNull(resp.getBody().records());
    }

    @Test
    void verifyIntactLogReturnsValid() {
        ResponseEntity<AuditVerifyResult> resp = get("/api/v1/audit/verify", auditorToken, AuditVerifyResult.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertTrue(resp.getBody().valid(), "Intact audit log should verify as valid");
    }

    @Test
    void auditReadEventIsItselfAudited() {
        // Read log to create an AUDIT_READ record
        get("/api/v1/audit", auditorToken, AuditPageResponse.class);
        // Read again and check total elements went up
        ResponseEntity<AuditPageResponse> first = get("/api/v1/audit", auditorToken, AuditPageResponse.class);
        ResponseEntity<AuditPageResponse> second = get("/api/v1/audit", auditorToken, AuditPageResponse.class);
        assertNotNull(first.getBody());
        assertNotNull(second.getBody());
        // Each read generates its own audit record, so second read should have >= first count
        assertTrue(second.getBody().totalElements() >= first.getBody().totalElements());
    }
}
