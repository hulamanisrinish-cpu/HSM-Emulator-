package com.example.hsm.service.crypto;

import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.exception.CryptographicOperationException;
import com.example.hsm.exception.HsmInternalException;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Stateless cryptographic engine. All operations use standard JCA.
 * Bouncy Castle is NOT used here — only in {@code TokenService}.
 *
 * <p>All methods that accept raw key bytes zero them in a finally block.
 */
@Component
public class CryptoEngine {

    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    /**
     * Generates a 256-bit AES symmetric key.
     *
     * @return raw key bytes (caller must zero after use)
     */
    public byte[] generateSymmetricKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, new SecureRandom());
            return kg.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new HsmInternalException("AES key generation failed", e);
        }
    }

    /**
     * Generates an asymmetric key pair for the given algorithm.
     *
     * @param alg RSA_2048 or EC_P256
     * @return the generated {@link KeyPair}
     */
    public KeyPair generateAsymmetricKeyPair(HsmAlgorithm alg) {
        try {
            return switch (alg) {
                case RSA_2048 -> {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(2048, new SecureRandom());
                    yield kpg.generateKeyPair();
                }
                case EC_P256 -> {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
                    yield kpg.generateKeyPair();
                }
                default -> throw new HsmInternalException("Cannot generate asymmetric pair for " + alg);
            };
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new HsmInternalException("Key pair generation failed for " + alg, e);
        }
    }

    /**
     * Encrypts plaintext using AES-256-GCM with a fresh random IV.
     * Raw key bytes are zeroed after use.
     *
     * @param rawKey    32-byte AES key (zeroed after this call)
     * @param plaintext data to encrypt
     * @return {@link EncryptionResult} containing IV, ciphertext, and auth tag
     */
    public EncryptionResult encrypt(byte[] rawKey, byte[] plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] combined = cipher.doFinal(plaintext);
            int ctLen = combined.length - 16;
            byte[] ciphertext = Arrays.copyOfRange(combined, 0, ctLen);
            byte[] authTag = Arrays.copyOfRange(combined, ctLen, combined.length);
            return new EncryptionResult(iv, ciphertext, authTag);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new HsmInternalException("Encryption failed", e);
        } finally {
            Arrays.fill(rawKey, (byte) 0);
        }
    }

    /**
     * Decrypts AES-256-GCM ciphertext.
     * Raw key bytes are zeroed after use.
     * Throws {@link CryptographicOperationException} on auth tag mismatch.
     *
     * @param rawKey     32-byte AES key (zeroed after this call)
     * @param iv         GCM initialization vector
     * @param ciphertext encrypted bytes
     * @param authTag    GCM authentication tag
     * @return plaintext bytes
     */
    public byte[] decrypt(byte[] rawKey, byte[] iv, byte[] ciphertext, byte[] authTag) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] combined = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(authTag, 0, combined, ciphertext.length, authTag.length);
            return cipher.doFinal(combined);
        } catch (AEADBadTagException e) {
            throw new CryptographicOperationException("Decryption failed: authentication tag mismatch", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new HsmInternalException("Decryption failed", e);
        } finally {
            Arrays.fill(rawKey, (byte) 0);
        }
    }

    /**
     * Signs data using the given private key.
     * Private key bytes are zeroed after use.
     *
     * @param privateKeyBytes PKCS#8-encoded private key (zeroed after this call)
     * @param data            data to sign
     * @param alg             algorithm determining signature scheme
     * @return signature bytes
     */
    public byte[] sign(byte[] privateKeyBytes, byte[] data, HsmAlgorithm alg) {
        try {
            PrivateKey pk = toPrivateKey(privateKeyBytes, alg);
            String sigAlg = sigAlgorithm(alg);
            Signature sig = Signature.getInstance(sigAlg);
            sig.initSign(pk);
            sig.update(data);
            return sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new HsmInternalException("Signing failed", e);
        } finally {
            Arrays.fill(privateKeyBytes, (byte) 0);
        }
    }

    /**
     * Verifies a signature. Returns {@code false} on invalid signature rather than throwing.
     *
     * @param publicKeyBytes X.509-encoded public key
     * @param data           original data
     * @param signature      signature bytes to verify
     * @param alg            algorithm determining signature scheme
     * @return true if valid, false if invalid
     */
    public boolean verify(byte[] publicKeyBytes, byte[] data, byte[] signature, HsmAlgorithm alg) {
        try {
            PublicKey pk = toPublicKey(publicKeyBytes, alg);
            Signature sig = Signature.getInstance(sigAlgorithm(alg));
            sig.initVerify(pk);
            sig.update(data);
            return sig.verify(signature);
        } catch (SignatureException e) {
            return false; // malformed signature — not an error condition
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new HsmInternalException("Signature verification failed", e);
        }
    }

    /** Returns X.509-encoded public key bytes. */
    public byte[] serializePublicKey(PublicKey key) {
        return key.getEncoded();
    }

    /** Returns PKCS#8-encoded private key bytes. */
    public byte[] serializePrivateKey(PrivateKey key) {
        return key.getEncoded();
    }

    // ── private helpers ────────────────────────────────────────────────────────

    private PrivateKey toPrivateKey(byte[] bytes, HsmAlgorithm alg) {
        try {
            String algorithm = alg == HsmAlgorithm.RSA_2048 ? "RSA" : "EC";
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new HsmInternalException("Failed to reconstruct private key", e);
        }
    }

    private PublicKey toPublicKey(byte[] bytes, HsmAlgorithm alg) {
        try {
            String algorithm = alg == HsmAlgorithm.RSA_2048 ? "RSA" : "EC";
            return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new HsmInternalException("Failed to reconstruct public key", e);
        }
    }

    private String sigAlgorithm(HsmAlgorithm alg) {
        return switch (alg) {
            case RSA_2048 -> "SHA256withRSA";
            case EC_P256 -> "SHA256withECDSA";
            default -> throw new HsmInternalException("Algorithm " + alg + " does not support sign/verify");
        };
    }
}
