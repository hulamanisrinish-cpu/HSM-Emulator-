package com.example.hsm.exception;

import com.example.hsm.dto.ErrorResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();
    private final MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/test");

    @Test
    void accessDeniedReturns403WithStandardEnvelope() {
        var resp = handler.handleAccessDenied(new AccessDeniedException("no"), req);
        assertEquals(403, resp.getStatusCode().value());
        assertNotNull(resp.getBody());
        assertEquals(403, resp.getBody().status());
    }

    @Test
    void keyNotFoundReturns404() {
        var resp = handler.handleNotFound(new KeyNotFoundException(UUID.randomUUID()), req);
        assertEquals(404, resp.getStatusCode().value());
    }

    @Test
    void noStackTraceInResponse() {
        var resp = handler.handleAll(new RuntimeException("boom"), req);
        ErrorResponse body = resp.getBody();
        assertNotNull(body);
        // message must not contain stack trace text
        assertFalse(body.message().contains("at com."), "Stack trace must not appear in response");
    }

    @Test
    void genericInternalErrorHidesDetails() {
        var resp = handler.handleInternal(new HsmInternalException("secret internal detail"), req);
        assertEquals(500, resp.getStatusCode().value());
        // The sensitive detail must NOT be echoed to the caller
        assertNotEquals("secret internal detail", resp.getBody().message());
    }
}
