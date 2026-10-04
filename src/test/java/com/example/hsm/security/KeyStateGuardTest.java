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
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies key state transitions block operations on disabled/destroyed keys. */
@Tag("security")
class KeyStateGuardTest extends BaseControllerIT {

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
        String acName = "ac-state-" + ts + "-" + SEQ.incrementAndGet();
        coToken = createUserAndGetToken("co-state-" + ts + "-" + SEQ.incrementAndGet(), HsmRole.CRYPTO_OFFICER, adminToken);
        acToken = createUserAndGetToken(acName, HsmRole.APP_CLIENT, adminToken);

        // Exact username match (prefix match could resolve to a stale user from another method)
        acUserId = userIdByUsername(acName, adminToken);

        keyId = post("/api/v1/keys",
                new GenerateKeyRequest("state-key-" + ts + "-" + SEQ.incrementAndGet(), HsmAlgorithm.AES_256, null),
                coToken, KeyMetadataDto.class).getBody().id();
        post("/api/v1/keys/" + keyId + "/acl", new AclRequest(acUserId), coToken, Void.class);
    }

    @Test
    void disabledKeyRejectsEncrypt() {
        patch("/api/v1/keys/" + keyId + "/disable", coToken, String.class);
        var resp = post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("data")), acToken, String.class);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, resp.getStatusCode());
    }

    @Test
    void disabledKeyRejectsSign() {
        // Create RSA key, disable, try sign
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        String ac2Name = "ac-sig-" + ts + "-" + SEQ.incrementAndGet();
        String co2 = createUserAndGetToken("co-sig-" + ts + "-" + SEQ.incrementAndGet(), HsmRole.CRYPTO_OFFICER, adminToken);
        String ac2 = createUserAndGetToken(ac2Name, HsmRole.APP_CLIENT, adminToken);
        UUID rsaId = post("/api/v1/keys",
                new GenerateKeyRequest("rsa-state-" + ts + "-" + SEQ.incrementAndGet(), HsmAlgorithm.RSA_2048, null),
                co2, KeyMetadataDto.class).getBody().id();

        UUID ac2Id = userIdByUsername(ac2Name, adminToken);
        post("/api/v1/keys/" + rsaId + "/acl", new AclRequest(ac2Id), co2, Void.class);
        patch("/api/v1/keys/" + rsaId + "/disable", co2, String.class);

        var resp = post("/api/v1/crypto/sign", new SignRequest(rsaId, b64("data")), ac2, String.class);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, resp.getStatusCode());
    }

    @Test
    void destroyedKeyRejectsEncrypt() {
        delete("/api/v1/keys/" + keyId, coToken, String.class);
        var resp = post("/api/v1/crypto/encrypt",
                new EncryptRequest(keyId, b64("data")), acToken, String.class);
        assertEquals(HttpStatus.GONE, resp.getStatusCode());
    }

    @Test
    void destroyedKeyRejectsDisable() {
        delete("/api/v1/keys/" + keyId, coToken, String.class);
        var resp = patch("/api/v1/keys/" + keyId + "/disable", coToken, String.class);
        assertEquals(HttpStatus.GONE, resp.getStatusCode());
    }

    @Test
    void destroyedKeyRejectsRotate() {
        delete("/api/v1/keys/" + keyId, coToken, String.class);
        var resp = post("/api/v1/keys/" + keyId + "/rotate", null, coToken, String.class);
        assertEquals(HttpStatus.GONE, resp.getStatusCode());
    }

    private String b64(String s) { return Base64.getEncoder().encodeToString(s.getBytes()); }
}
