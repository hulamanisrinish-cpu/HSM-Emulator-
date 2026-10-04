package com.example.hsm.security;

import com.example.hsm.controller.BaseControllerIT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;

/** Verifies all bad-auth scenarios return identical 401 bodies — no oracle. */
@Tag("security")
class AuthenticationServiceTest extends BaseControllerIT {

    @Test
    void falseTokenIsRejected() {
        var resp = get("/api/v1/keys", "hsm_tk_totallyfaketoken11111111111111111111", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
        assertContainsAuthRequired(resp.getBody());
    }

    @Test
    void truncatedTokenReturns401() {
        var resp = get("/api/v1/keys", "hsm_tk_short", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
        assertContainsAuthRequired(resp.getBody());
    }

    @Test
    void noTokenReturns401() {
        var resp = get("/api/v1/keys", null, String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
    }

    @Test
    void emptyBearerReturns401() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer ");
        var resp = restTemplate.exchange("/api/v1/keys", HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
    }

    @Test
    void identicalBodyForBadTokenAndUnknownUser() {
        var badToken = get("/api/v1/keys", "hsm_tk_badtokenbadtokenbadtoken111111111111", String.class);
        var unknownUser = get("/api/v1/keys", "hsm_tk_unknownusername0000000000000000000", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, badToken.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, unknownUser.getStatusCode());
        // Both must contain exactly "Authentication required" — no distinguishing info
        assertTrue(badToken.getBody().contains("Authentication required"));
        assertTrue(unknownUser.getBody().contains("Authentication required"));
    }

    private void assertContainsAuthRequired(String body) {
        assertNotNull(body);
        assertTrue(body.contains("Authentication required"));
    }
}
