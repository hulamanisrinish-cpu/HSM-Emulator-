package com.example.hsm.controller;

import com.example.hsm.TestDataSeeder;
import com.example.hsm.dto.*;
import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.entity.HsmRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CryptoControllerIT extends BaseControllerIT {

    /** Keeps generated user/key names unique across test methods (avoids same-millisecond collisions). */
    private static final java.util.concurrent.atomic.AtomicInteger SEQ =
            new java.util.concurrent.atomic.AtomicInteger();

    private String cryptoOfficerToken;
    private String appClientToken;
    private UUID aesKeyId;
    private UUID rsaKeyId;
    private UUID ecKeyId;

    @BeforeEach
    void setup() {
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        long ts = System.currentTimeMillis();
        String coName = "co-crypto-" + ts + "-" + SEQ.incrementAndGet();
        String acName = "ac-crypto-" + ts + "-" + SEQ.incrementAndGet();
        cryptoOfficerToken = createUserAndGetToken(coName, HsmRole.CRYPTO_OFFICER, adminToken);
        appClientToken = createUserAndGetToken(acName, HsmRole.APP_CLIENT, adminToken);

        // Create keys
        aesKeyId = createKey("aes-crypto-" + ts + "-" + SEQ.incrementAndGet(), HsmAlgorithm.AES_256, cryptoOfficerToken);
        rsaKeyId = createKey("rsa-crypto-" + ts + "-" + SEQ.incrementAndGet(), HsmAlgorithm.RSA_2048, cryptoOfficerToken);
        ecKeyId = createKey("ec-crypto-" + ts + "-" + SEQ.incrementAndGet(), HsmAlgorithm.EC_P256, cryptoOfficerToken);

        // Resolve THIS test's AppClient by exact username (prefix matching would hit stale users)
        UUID appClientId = userIdByUsername(acName, adminToken);
        grantAcl(aesKeyId, appClientId, cryptoOfficerToken);
        grantAcl(rsaKeyId, appClientId, cryptoOfficerToken);
        grantAcl(ecKeyId, appClientId, cryptoOfficerToken);
    }

    @Test
    void encryptWithValidAclReturns200() {
        var req = new EncryptRequest(aesKeyId, b64("hello world"));
        var resp = post("/api/v1/crypto/encrypt", req, appClientToken, EncryptResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody().ciphertext());
    }

    @Test
    @Tag("security")
    void encryptWithoutAclReturns403() {
        // Create another AppClient with no ACL
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        String noAclToken = createUserAndGetToken("ac-noacl-" + System.currentTimeMillis(),
                HsmRole.APP_CLIENT, adminToken);
        var req = new EncryptRequest(aesKeyId, b64("test"));
        var resp = post("/api/v1/crypto/encrypt", req, noAclToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void cryptoOfficerCannotEncrypt() {
        var req = new EncryptRequest(aesKeyId, b64("data"));
        var resp = post("/api/v1/crypto/encrypt", req, cryptoOfficerToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    void ivIsUniquePerEncryptCall() {
        var req = new EncryptRequest(aesKeyId, b64("same data"));
        var r1 = post("/api/v1/crypto/encrypt", req, appClientToken, EncryptResponse.class);
        var r2 = post("/api/v1/crypto/encrypt", req, appClientToken, EncryptResponse.class);
        assertNotEquals(r1.getBody().iv(), r2.getBody().iv());
    }

    @Test
    void decryptRoundTripRecoverspPlaintext() {
        String original = "Hello decrypted world";
        var encResp = post("/api/v1/crypto/encrypt",
                new EncryptRequest(aesKeyId, b64(original)),
                appClientToken, EncryptResponse.class).getBody();
        assertNotNull(encResp);
        var decResp = post("/api/v1/crypto/decrypt",
                new DecryptRequest(aesKeyId, encResp.iv(), encResp.ciphertext(), encResp.authTag()),
                appClientToken, DecryptResponse.class).getBody();
        assertNotNull(decResp);
        assertEquals(original, new String(Base64.getDecoder().decode(decResp.plaintext())));
    }

    @Test
    @Tag("security")
    void tamperedCiphertextReturns400() {
        var encResp = post("/api/v1/crypto/encrypt",
                new EncryptRequest(aesKeyId, b64("tamper me")),
                appClientToken, EncryptResponse.class).getBody();
        assertNotNull(encResp);
        // Flip a byte in ciphertext
        byte[] ct = Base64.getDecoder().decode(encResp.ciphertext());
        if (ct.length > 0) ct[0] ^= 0xFF;
        var resp = post("/api/v1/crypto/decrypt",
                new DecryptRequest(aesKeyId, encResp.iv(), b64(ct), encResp.authTag()),
                appClientToken, String.class);
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
    }

    @Test
    void signWithRsaKeyReturns200() {
        var resp = post("/api/v1/crypto/sign",
                new SignRequest(rsaKeyId, b64("sign me")), appClientToken, SignResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertNotNull(resp.getBody().signature());
    }

    @Test
    void signWithEcKeyReturns200() {
        var resp = post("/api/v1/crypto/sign",
                new SignRequest(ecKeyId, b64("ec sign")), appClientToken, SignResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
    }

    @Test
    @Tag("security")
    void signWithoutAclReturns403() {
        String adminToken = System.getProperty(TestDataSeeder.BOOTSTRAP_ADMIN_TOKEN_PROP);
        String noAclToken = createUserAndGetToken("ac-sign-noacl-" + System.currentTimeMillis(),
                HsmRole.APP_CLIENT, adminToken);
        var resp = post("/api/v1/crypto/sign",
                new SignRequest(rsaKeyId, b64("data")), noAclToken, String.class);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    void verifyValidSignatureReturnsTrue() {
        String data = b64("verify me");
        var sigResp = post("/api/v1/crypto/sign",
                new SignRequest(rsaKeyId, data), appClientToken, SignResponse.class).getBody();
        assertNotNull(sigResp);
        var verResp = post("/api/v1/crypto/verify",
                new VerifyRequest(rsaKeyId, data, sigResp.signature()),
                appClientToken, VerifyResponse.class).getBody();
        assertNotNull(verResp);
        assertTrue(verResp.valid());
    }

    @Test
    void verifyInvalidSignatureReturnsFalseNot4xx() {
        var resp = post("/api/v1/crypto/verify",
                new VerifyRequest(rsaKeyId, b64("data"), b64(new byte[256])),
                appClientToken, VerifyResponse.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertFalse(resp.getBody().valid());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private UUID createKey(String name, HsmAlgorithm alg, String token) {
        var resp = post("/api/v1/keys", new GenerateKeyRequest(name, alg, null), token, KeyMetadataDto.class);
        assertEquals(HttpStatus.CREATED, resp.getStatusCode());
        return resp.getBody().id();
    }

    private void grantAcl(UUID keyId, UUID principalId, String token) {
        post("/api/v1/keys/" + keyId + "/acl", new AclRequest(principalId), token, Void.class);
    }

    private String b64(String s) { return Base64.getEncoder().encodeToString(s.getBytes()); }
    private String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
}
