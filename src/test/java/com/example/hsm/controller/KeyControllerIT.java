package com.example.hsm.controller;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.dto.GenerateKeyRequest;
import com.example.hsm.dto.KeyMetadataDto;
import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.entity.HsmRole;
import com.example.hsm.entity.KeyState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;

class KeyControllerIT extends BaseControllerIT {

    private String adminToken;
    private String cryptoOfficerToken;
    private String appClientToken;
    private String auditorToken;

    @BeforeEach
    void setup() {
        adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        // Create fresh users for each test class run (names must be unique)
        long ts = System.currentTimeMillis();
        cryptoOfficerToken = createUserAndGetToken("co-" + ts, HsmRole.CRYPTO_OFFICER, adminToken);
        appClientToken = createUserAndGetToken("ac-" + ts, HsmRole.APP_CLIENT, adminToken);
        auditorToken = createUserAndGetToken("aud-" + ts, HsmRole.AUDITOR, adminToken);
    }

    @Test
    void generateAesKeyReturns201WithMetadataNoKeyBytes() {
        var req = new GenerateKeyRequest("aes-test-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null);
        var resp = post("/api/v1/keys", req, cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.CREATED, resp.getStatusCode());
        KeyMetadataDto body = resp.getBody();
        assertNotNull(body);
        assertNotNull(body.id());
        assertEquals(HsmAlgorithm.AES_256, body.algorithm());
        assertEquals(KeyState.ACTIVE, body.state());
        // Response body must not contain wrapped key fields (they're not in KeyMetadataDto)
        String json = restTemplate.exchange("/api/v1/keys/" + body.id(),
                HttpMethod.GET, new HttpEntity<>(bearerHeaders(cryptoOfficerToken)), String.class).getBody();
        assertNotNull(json);
        assertFalse(json.contains("wrappedDek"));
        assertFalse(json.contains("ivDek"));
    }

    @Test
    void generateRsaKeyReturns201() {
        var req = new GenerateKeyRequest("rsa-" + System.currentTimeMillis(), HsmAlgorithm.RSA_2048, null);
        var resp = post("/api/v1/keys", req, cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.CREATED, resp.getStatusCode());
        assertNotNull(resp.getBody());
    }

    @Test
    void generateEcKeyReturns201() {
        var req = new GenerateKeyRequest("ec-" + System.currentTimeMillis(), HsmAlgorithm.EC_P256, null);
        var resp = post("/api/v1/keys", req, cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void appClientCannotGenerateKey() {
        var req = new GenerateKeyRequest("ac-gen-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null);
        var resp = post("/api/v1/keys", req, appClientToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void auditorCannotGenerateKey() {
        var req = new GenerateKeyRequest("aud-gen-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null);
        var resp = post("/api/v1/keys", req, auditorToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void unauthenticatedCannotGenerateKey() {
        var req = new GenerateKeyRequest("unauth-" + System.currentTimeMillis(), HsmAlgorithm.AES_256, null);
        var resp = post("/api/v1/keys", req, null, String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
    }

    @Test
    void listKeysReturnsCryptoOfficerView() {
        var resp = get("/api/v1/keys", cryptoOfficerToken, KeyMetadataDto[].class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody());
    }

    @Test
    void disableActiveKeyReturns200() {
        var key = createKey("disable-test-" + System.currentTimeMillis());
        var resp = patch("/api/v1/keys/" + key.id() + "/disable", cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertEquals(KeyState.DISABLED, resp.getBody().state());
    }

    @Test
    void enableDisabledKeyReturns200() {
        var key = createKey("enable-test-" + System.currentTimeMillis());
        patch("/api/v1/keys/" + key.id() + "/disable", cryptoOfficerToken, String.class);
        var resp = patch("/api/v1/keys/" + key.id() + "/enable", cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertEquals(KeyState.ACTIVE, resp.getBody().state());
    }

    @Test
    void destroyedKeyReturns410() {
        var key = createKey("destroy-410-" + System.currentTimeMillis());
        delete("/api/v1/keys/" + key.id(), cryptoOfficerToken, String.class);
        // Second destroy should 410
        var resp = delete("/api/v1/keys/" + key.id(), cryptoOfficerToken, String.class);
        assertEquals(HttpStatus.GONE, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void appClientCannotDisableKey() {
        var key = createKey("ac-disable-" + System.currentTimeMillis());
        var resp = patch("/api/v1/keys/" + key.id() + "/disable", appClientToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    void rotateActiveKeyIncrementsVersion() {
        var key = createKey("rotate-" + System.currentTimeMillis());
        var resp = post("/api/v1/keys/" + key.id() + "/rotate", null, cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertEquals(2, resp.getBody().version());
    }

    private KeyMetadataDto createKey(String name) {
        var req = new GenerateKeyRequest(name, HsmAlgorithm.AES_256, null);
        var resp = post("/api/v1/keys", req, cryptoOfficerToken, KeyMetadataDto.class);
        assertEquals(HttpStatus.CREATED, resp.getStatusCode());
        return resp.getBody();
    }
}
