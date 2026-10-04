package com.example.hsm.controller;

import com.example.hsm.AbstractIntegrationTest;
import com.example.hsm.dto.CreateUserRequest;
import com.example.hsm.dto.CreateUserResponse;
import com.example.hsm.dto.UserDto;
import com.example.hsm.entity.HsmRole;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.http.client.JdkClientHttpRequestFactory;

import java.net.http.HttpClient;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/** Base class with helpers for building authenticated requests in integration tests. */
public abstract class BaseControllerIT extends AbstractIntegrationTest {

    @Autowired
    protected TestRestTemplate restTemplate;

    /**
     * TestRestTemplate defaults to {@code SimpleClientHttpRequestFactory} (JDK HttpURLConnection),
     * which rejects PATCH with "Invalid HTTP method: PATCH". The Java 11 HttpClient-based
     * factory supports it, so key lifecycle endpoints (PATCH /keys/{id}/disable) are testable.
     */
    @BeforeEach
    void configurePatchCapableRequestFactory() {
        restTemplate.getRestTemplate()
                .setRequestFactory(new JdkClientHttpRequestFactory(HttpClient.newHttpClient()));
    }

    /** Creates a user of the given role and returns their plain token. */
    protected String createUserAndGetToken(String username, HsmRole role, String adminToken) {
        HttpHeaders headers = bearerHeaders(adminToken);
        CreateUserRequest req = new CreateUserRequest(username, role);
        ResponseEntity<CreateUserResponse> resp = restTemplate.exchange(
                "/api/v1/users", HttpMethod.POST,
                new HttpEntity<>(req, headers), CreateUserResponse.class);
        if (resp.getStatusCode() != HttpStatus.CREATED || resp.getBody() == null) {
            throw new IllegalStateException("Failed to create user " + username + ": " + resp.getStatusCode());
        }
        return resp.getBody().token();
    }

    protected HttpHeaders bearerHeaders(String token) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) h.setBearerAuth(token);
        return h;
    }

    /**
     * Resolves a user id by EXACT username. Never match by prefix: earlier test methods in the
     * same class create users with the same prefix, and a prefix match can silently grant the
     * ACL to a stale user, making the current user fail authorization.
     */
    protected UUID userIdByUsername(String username, String adminToken) {
        UserDto[] users = restTemplate.exchange("/api/v1/users", HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(adminToken)), UserDto[].class).getBody();
        assertNotNull(users, "GET /api/v1/users returned no body");
        for (UserDto u : users) {
            if (u.username().equals(username)) {
                return u.id();
            }
        }
        throw new IllegalStateException("User not found: " + username);
    }

    protected <T> ResponseEntity<T> post(String url, Object body, String token, Class<T> type) {
        return restTemplate.exchange(url, HttpMethod.POST,
                new HttpEntity<>(body, bearerHeaders(token)), type);
    }

    protected <T> ResponseEntity<T> get(String url, String token, Class<T> type) {
        return restTemplate.exchange(url, HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(token)), type);
    }

    protected <T> ResponseEntity<T> patch(String url, String token, Class<T> type) {
        return restTemplate.exchange(url, HttpMethod.PATCH,
                new HttpEntity<>(bearerHeaders(token)), type);
    }

    protected <T> ResponseEntity<T> delete(String url, String token, Class<T> type) {
        return restTemplate.exchange(url, HttpMethod.DELETE,
                new HttpEntity<>(bearerHeaders(token)), type);
    }
}
