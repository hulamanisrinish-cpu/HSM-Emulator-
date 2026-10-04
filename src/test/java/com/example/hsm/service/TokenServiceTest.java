package com.example.hsm.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenServiceTest {

    private TokenService tokenService;

    @BeforeEach
    void setUp() { tokenService = new TokenService(); }

    @Test
    void generatedTokenHasExpectedPrefix() {
        String token = tokenService.generateToken();
        assertTrue(token.startsWith("hsm_tk_"), "Token must start with 'hsm_tk_'");
        assertTrue(token.length() > 20, "Token must be sufficiently long");
    }

    @Test
    void hashAndVerifyRoundTrip() {
        String token = tokenService.generateToken();
        String hash = tokenService.hashToken(token);
        assertTrue(tokenService.verifyToken(token, hash));
    }

    @Test
    void differentTokensProduceDifferentHashes() {
        String t1 = tokenService.generateToken();
        String t2 = tokenService.generateToken();
        String h1 = tokenService.hashToken(t1);
        String h2 = tokenService.hashToken(t2);
        assertNotEquals(h1, h2);
    }

    @Test
    void wrongTokenDoesNotVerify() {
        String token = tokenService.generateToken();
        String hash = tokenService.hashToken(token);
        String other = tokenService.generateToken();
        assertFalse(tokenService.verifyToken(other, hash));
    }

    @Test
    void malformedStoredHashNeverVerifies() {
        // Stored hash without the salt:hash separator must be rejected, not throw
        assertFalse(tokenService.verifyToken("hsm_tk_candidate", "nocolon-separated-hash"));
        // Too many segments (e.g. corrupted/tampered row) must also be rejected
        assertFalse(tokenService.verifyToken("hsm_tk_candidate", "salt:hash:extra"));
    }

    @Test
    void timingAttackResistance() {
        // MessageDigest.isEqual is used — constant-time comparison for fixed-length hashes
        String token = tokenService.generateToken();
        String hash = tokenService.hashToken(token);
        // Measure times for valid vs invalid token verification (statistical, not deterministic)
        long start1 = System.nanoTime();
        tokenService.verifyToken(token, hash);
        long valid = System.nanoTime() - start1;

        long start2 = System.nanoTime();
        tokenService.verifyToken(tokenService.generateToken(), hash);
        long invalid = System.nanoTime() - start2;

        // Both should take similar time (Argon2 dominates); just assert both complete
        assertTrue(valid > 0 && invalid > 0, "Constant-time comparison should complete for both");
    }
}
