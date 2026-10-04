package com.example.hsm.controller;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.dto.CreateUserRequest;
import com.example.hsm.dto.CreateUserResponse;
import com.example.hsm.dto.UserDto;
import com.example.hsm.entity.HsmRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class UserControllerIT extends BaseControllerIT {

    private String adminToken;
    private String appClientToken;

    @BeforeEach
    void setup() {
        adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        appClientToken = createUserAndGetToken("ac-user-" + ts, HsmRole.APP_CLIENT, adminToken);
    }

    @Test
    void adminCreatesUserAndReceivesOneTimeToken() {
        var req = new CreateUserRequest("new-user-" + System.currentTimeMillis(), HsmRole.AUDITOR);
        ResponseEntity<CreateUserResponse> resp = post("/api/v1/users", req, adminToken, CreateUserResponse.class);
        assertEquals(HttpStatus.CREATED, resp.getStatusCode());
        CreateUserResponse body = resp.getBody();
        assertNotNull(body);
        assertNotNull(body.token());
        assertTrue(body.token().startsWith("hsm_tk_"));
        assertNotNull(body.warning());
    }

    @Test
    void tokenIsShownOnce() {
        // POST creates user with token; GET /users must NOT return the token
        ResponseEntity<UserDto[]> listResp = restTemplate.exchange(
                "/api/v1/users", HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(adminToken)), UserDto[].class);
        assertEquals(HttpStatus.OK, listResp.getStatusCode());
        assertNotNull(listResp.getBody());
        // UserDto has no 'token' field — verify JSON doesn't contain "hsm_tk_"
        ResponseEntity<String> rawResp = restTemplate.exchange(
                "/api/v1/users", HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(adminToken)), String.class);
        assertNotNull(rawResp.getBody());
        assertFalse(rawResp.getBody().contains("hsm_tk_"),
                "GET /users must not expose bearer tokens");
    }

    @Test
    void createdTokenCanAuthenticateImmediately() {
        long ts = System.currentTimeMillis();
        var req = new CreateUserRequest("auth-test-" + ts, HsmRole.AUDITOR);
        String token = post("/api/v1/users", req, adminToken, CreateUserResponse.class).getBody().token();
        // New token should be able to access protected endpoints
        ResponseEntity<String> resp = get("/api/v1/audit", token, String.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void nonAdminCannotCreateUser() {
        var req = new CreateUserRequest("should-fail-" + System.currentTimeMillis(), HsmRole.AUDITOR);
        ResponseEntity<String> resp = post("/api/v1/users", req, appClientToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    void duplicateUsernameReturns409() {
        String name = "dup-" + System.currentTimeMillis();
        post("/api/v1/users", new CreateUserRequest(name, HsmRole.AUDITOR), adminToken, CreateUserResponse.class);
        ResponseEntity<String> resp = post("/api/v1/users", new CreateUserRequest(name, HsmRole.AUDITOR),
                adminToken, String.class);
        assertEquals(HttpStatus.CONFLICT, resp.getStatusCode());
    }

    @Test
    void adminDisablesUser() {
        long ts = System.currentTimeMillis();
        var created = post("/api/v1/users",
                new CreateUserRequest("to-disable-" + ts, HsmRole.AUDITOR),
                adminToken, CreateUserResponse.class).getBody();
        assertNotNull(created);
        String disabledToken = created.token();

        // Disable the user
        ResponseEntity<UserDto> resp = restTemplate.exchange(
                "/api/v1/users/" + created.id(), HttpMethod.DELETE,
                new HttpEntity<>(bearerHeaders(adminToken)), UserDto.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertFalse(resp.getBody().enabled());

        // Disabled user's token must return 401
        ResponseEntity<String> authResp = get("/api/v1/audit", disabledToken, String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, authResp.getStatusCode());
    }

    @Test
    @Tag("security")
    void nonAdminCannotRevokeRole() {
        // Get any user ID
        UserDto[] users = restTemplate.exchange("/api/v1/users", HttpMethod.GET,
                new HttpEntity<>(bearerHeaders(adminToken)), UserDto[].class).getBody();
        assertNotNull(users);
        var target = Arrays.stream(users).findFirst().orElseThrow();
        ResponseEntity<String> resp = restTemplate.exchange(
                "/api/v1/users/" + target.id() + "/roles/AUDITOR", HttpMethod.DELETE,
                new HttpEntity<>(bearerHeaders(appClientToken)), String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }
}
