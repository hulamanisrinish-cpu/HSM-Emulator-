package com.example.hsm.security;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.controller.BaseControllerIT;
import com.example.hsm.dto.CreateUserRequest;
import com.example.hsm.dto.EncryptRequest;
import com.example.hsm.dto.GenerateKeyRequest;
import com.example.hsm.dto.KeyMetadataDto;
import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.entity.HsmRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** RBAC sweep: each role is blocked from every operation it should not perform. */
@Tag("security")
class RbacEnforcementTest extends BaseControllerIT {

    private String adminToken;
    private String coToken;
    private String acToken;
    private String auditorToken;
    private UUID keyId;

    @BeforeEach
    void setup() {
        adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        coToken = createUserAndGetToken("co-rbac-" + ts, HsmRole.CRYPTO_OFFICER, adminToken);
        acToken = createUserAndGetToken("ac-rbac-" + ts, HsmRole.APP_CLIENT, adminToken);
        auditorToken = createUserAndGetToken("aud-rbac-" + ts, HsmRole.AUDITOR, adminToken);

        // Create a key for crypto tests
        var resp = post("/api/v1/keys",
                new GenerateKeyRequest("rbac-key-" + ts, HsmAlgorithm.AES_256, null),
                coToken, KeyMetadataDto.class);
        keyId = resp.getBody().id();
    }

    @Test void appClientCannotGenerateKey() {
        assertForbidden(post("/api/v1/keys",
                new GenerateKeyRequest("ac-gen-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null),
                acToken, String.class));
    }

    @Test void appClientCannotRotateKey() {
        assertForbidden(post("/api/v1/keys/" + keyId + "/rotate", null, acToken, String.class));
    }

    @Test void appClientCannotDestroyKey() {
        assertForbidden(delete("/api/v1/keys/" + keyId, acToken, String.class));
    }

    @Test void appClientCannotGrantAcl() {
        assertForbidden(post("/api/v1/keys/" + keyId + "/acl",
                new com.example.hsm.dto.AclRequest(UUID.randomUUID()), acToken, String.class));
    }

    @Test void cryptoOfficerCannotEncrypt() {
        assertForbidden(post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("data")), coToken, String.class));
    }

    @Test void cryptoOfficerCannotReadAuditLog() {
        assertForbidden(get("/api/v1/audit", coToken, String.class));
    }

    @Test void adminCannotGenerateKey() {
        assertForbidden(post("/api/v1/keys",
                new GenerateKeyRequest("admin-gen-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null),
                adminToken, String.class));
    }

    @Test void adminCannotEncrypt() {
        assertForbidden(post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("data")), adminToken, String.class));
    }

    @Test void auditorCannotGenerateKey() {
        assertForbidden(post("/api/v1/keys",
                new GenerateKeyRequest("aud-gen-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null),
                auditorToken, String.class));
    }

    @Test void auditorCannotEncrypt() {
        assertForbidden(post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("data")), auditorToken, String.class));
    }

    private void assertForbidden(ResponseEntity<?> resp) {
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    private String b64(String s) { return Base64.getEncoder().encodeToString(s.getBytes()); }
}
