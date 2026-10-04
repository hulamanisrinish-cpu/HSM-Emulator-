package com.example.hsm.controller;

import com.example.hsm.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;

class OpenApiIT extends AbstractIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void allEndpointsAppearInApiDocs() {
        ResponseEntity<String> resp = restTemplate.getForEntity("/v3/api-docs", String.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        String body = resp.getBody();
        assertNotNull(body);
        assertTrue(body.contains("/api/v1/keys"), "Keys endpoint missing from API docs");
        assertTrue(body.contains("/api/v1/crypto/encrypt"), "Encrypt endpoint missing");
        assertTrue(body.contains("/api/v1/crypto/decrypt"), "Decrypt endpoint missing");
        assertTrue(body.contains("/api/v1/crypto/sign"), "Sign endpoint missing");
        assertTrue(body.contains("/api/v1/crypto/verify"), "Verify endpoint missing");
        assertTrue(body.contains("/api/v1/audit"), "Audit endpoint missing");
        assertTrue(body.contains("/api/v1/users"), "Users endpoint missing");
    }
}
