package com.example.hsm.security;

import com.example.hsm.AbstractIntegrationTest;
import com.example.hsm.dto.CreateUserRequest;
import com.example.hsm.dto.CreateUserResponse;
import com.example.hsm.entity.HsmRole;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;

@Tag("security")
class SecurityFilterTest extends AbstractIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void missingTokenReturns401() {
        ResponseEntity<String> resp = restTemplate.getForEntity("/api/v1/keys", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
    }

    @Test
    void invalidTokenReturns401() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth("hsm_tk_invalid_garbage_token_that_doesnt_exist");
        ResponseEntity<String> resp = restTemplate.exchange(
                "/api/v1/keys", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
    }

    @Test
    void unknownTokenReturnsGeneric401() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth("hsm_tk_unknownuser00000000000000000000000");
        ResponseEntity<String> resp = restTemplate.exchange(
                "/api/v1/keys", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
        // Body must be identical to invalidTokenReturns401 — no oracle
        assertTrue(resp.getBody().contains("Authentication required"));
    }

    @Test
    void noTokenReturns401() {
        ResponseEntity<String> resp = restTemplate.getForEntity("/api/v1/users", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
    }
}
