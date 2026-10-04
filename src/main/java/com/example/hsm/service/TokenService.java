package com.example.hsm.service;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Issues and verifies bearer tokens using Argon2id hashing.
 *
 * <p><strong>NOTE:</strong> Bouncy Castle is used ONLY in this class for Argon2id.
 * Do NOT use Bouncy Castle anywhere else in the codebase.
 *
 * <p>Plain tokens are never logged or stored.
 */
@Component
public class TokenService {

    private static final String TOKEN_PREFIX = "hsm_tk_";
    private static final int ARGON2_MEMORY = 65536;  // 64 MiB
    private static final int ARGON2_ITERATIONS = 3;
    private static final int ARGON2_PARALLELISM = 4;
    private static final int ARGON2_HASH_LENGTH = 32;
    private static final int SALT_BYTES = 16;

    /**
     * Generates a new random bearer token with the {@code hsm_tk_} prefix.
     * The plain token is returned once and must NOT be stored.
     *
     * @return plain-text token (never logged or persisted)
     */
    public String generateToken() {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    /**
     * Hashes a plain token using Argon2id with a random salt.
     * The stored format is {@code base64(salt):base64(hash)}.
     *
     * @param plainToken the token to hash (not logged)
     * @return the storable hash string
     */
    public String hashToken(String plainToken) {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] hash = argon2Hash(plainToken.toCharArray(), salt);
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Verifies a plain token against its stored Argon2id hash.
     * Uses constant-time comparison to resist timing attacks.
     *
     * @param plainToken the candidate token (not logged)
     * @param storedHash the stored hash string from {@link #hashToken(String)}
     * @return true if the token matches
     */
    public boolean verifyToken(String plainToken, String storedHash) {
        try {
            String[] parts = storedHash.split(":");
            if (parts.length != 2) return false;
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] expected = Base64.getDecoder().decode(parts[1]);
            byte[] actual = argon2Hash(plainToken.toCharArray(), salt);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns the first 16 characters of a token for fast DB lookup.
     *
     * @param plainToken the full plain token
     * @return token prefix for index lookup
     */
    public String extractPrefix(String plainToken) {
        return plainToken.length() >= 16 ? plainToken.substring(0, 16) : plainToken;
    }

    // ── private ───────────────────────────────────────────────────────────────

    private byte[] argon2Hash(char[] password, byte[] salt) {
        byte[] passwordBytes = toBytes(password);
        try {
            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(salt)
                    .withMemoryAsKB(ARGON2_MEMORY)
                    .withIterations(ARGON2_ITERATIONS)
                    .withParallelism(ARGON2_PARALLELISM)
                    .build();
            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.init(params);
            byte[] output = new byte[ARGON2_HASH_LENGTH];
            gen.generateBytes(passwordBytes, output);
            return output;
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    private byte[] toBytes(char[] chars) {
        byte[] bytes = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }
        return bytes;
    }
}
