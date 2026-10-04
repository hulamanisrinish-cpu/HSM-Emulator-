package com.example.hsm.security;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.controller.BaseControllerIT;
import com.example.hsm.dto.*;
import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.entity.HsmRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Verifies per-key ACL enforcement for AppClient principals. */
@Tag("security")
class AclEnforcementTest extends BaseControllerIT {

    private String coToken;
    private String acToken;
    private UUID acUserId;
    private UUID keyId;

    /** Keeps generated user/key names unique across test methods. */
    private static final java.util.concurrent.atomic.AtomicInteger SEQ =
            new java.util.concurrent.atomic.AtomicInteger();

    @BeforeEach
    void setup() {
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        String acName = "ac-acl-" + ts + "-" + SEQ.incrementAndGet();
        coToken = createUserAndGetToken("co-acl-" + ts + "-" + SEQ.incrementAndGet(), HsmRole.CRYPTO_OFFICER, adminToken);
        acToken = createUserAndGetToken(acName, HsmRole.APP_CLIENT, adminToken);

        // Exact username match — a prefix match could resolve to a stale user from a
        // previous test method, sending the ACL grant to the wrong principal.
        acUserId = userIdByUsername(acName, adminToken);

        keyId = post("/api/v1/keys",
                new GenerateKeyRequest("acl-key-" + ts + "-" + SEQ.incrementAndGet(), HsmAlgorithm.AES_256, null),
                coToken, KeyMetadataDto.class).getBody().id();
    }

    @Test
    void appClientWithoutAclIsRejected() {
        var resp = post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("test")), acToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    void appClientAfterAclRevocationIsRejected() {
        // Grant ACL
        post("/api/v1/keys/" + keyId + "/acl", new AclRequest(acUserId), coToken, Void.class);
        // Verify it works
        assertEquals(HttpStatus.OK, post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("test")), acToken, EncryptResponse.class).getStatusCode());
        // Revoke ACL
        restTemplate.exchange("/api/v1/keys/" + keyId + "/acl/" + acUserId,
                HttpMethod.DELETE, new HttpEntity<>(bearerHeaders(coToken)), Void.class);
        // Should now be rejected
        var resp = post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("test")), acToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    private String b64(String s) { return Base64.getEncoder().encodeToString(s.getBytes()); }
}
