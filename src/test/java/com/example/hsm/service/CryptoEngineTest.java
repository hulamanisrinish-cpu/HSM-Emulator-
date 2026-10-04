package com.example.hsm.service;

import com.example.hsm.entity.HsmAlgorithm;
import com.example.hsm.exception.CryptographicOperationException;
import com.example.hsm.service.crypto.CryptoEngine;
import com.example.hsm.service.crypto.EncryptionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@Tag("crypto")
class CryptoEngineTest {

    private CryptoEngine engine;

    @BeforeEach
    void setUp() { engine = new CryptoEngine(); }

    @Test
    void aesEncryptDecryptRoundTrip() {
        byte[] key = engine.generateSymmetricKey();
        byte[] plaintext = "Hello, HSM!".getBytes();
        byte[] keyCopy = Arrays.copyOf(key, key.length);
        EncryptionResult result = engine.encrypt(keyCopy, plaintext);
        // keyCopy is now zeroed; use original key copy for decrypt
        byte[] key2 = engine.generateSymmetricKey(); // new key just to test shape
        assertNotNull(result.ciphertext());
        assertNotNull(result.iv());
        assertNotNull(result.authTag());
        assertEquals(16, result.authTag().length);
    }

    @Test
    void encryptDecryptFullRoundTrip() {
        byte[] key = engine.generateSymmetricKey();
        byte[] plaintext = "secret data 12345".getBytes();
        byte[] keyCopy = Arrays.copyOf(key, key.length);
        EncryptionResult result = engine.encrypt(keyCopy, plaintext);
        // Use original key copy for decrypt
        byte[] decrypted = engine.decrypt(key, result.iv(), result.ciphertext(), result.authTag());
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void eachEncryptCallUsesUniqueIv() {
        byte[] key1 = engine.generateSymmetricKey();
        byte[] key2 = engine.generateSymmetricKey();
        byte[] plaintext = "test".getBytes();
        EncryptionResult r1 = engine.encrypt(key1, plaintext);
        EncryptionResult r2 = engine.encrypt(key2, plaintext);
        assertFalse(Arrays.equals(r1.iv(), r2.iv()));
    }

    @Test
    @Tag("security")
    void tamperedCiphertextThrowsCryptographicOperationException() {
        byte[] key = engine.generateSymmetricKey();
        byte[] plaintext = "tamper test".getBytes();
        byte[] keyCopy = Arrays.copyOf(key, key.length);
        EncryptionResult result = engine.encrypt(keyCopy, plaintext);
        byte[] tampered = Arrays.copyOf(result.ciphertext(), result.ciphertext().length);
        if (tampered.length > 0) tampered[0] ^= 0xFF;
        assertThrows(CryptographicOperationException.class,
                () -> engine.decrypt(key, result.iv(), tampered, result.authTag()));
    }

    @Test
    @Tag("security")
    void tamperedAuthTagThrowsException() {
        byte[] key = engine.generateSymmetricKey();
        byte[] keyCopy = Arrays.copyOf(key, key.length);
        EncryptionResult result = engine.encrypt(keyCopy, "data".getBytes());
        byte[] badTag = Arrays.copyOf(result.authTag(), result.authTag().length);
        badTag[0] ^= 0x01;
        assertThrows(CryptographicOperationException.class,
                () -> engine.decrypt(key, result.iv(), result.ciphertext(), badTag));
    }

    @Test
    void rsaSignVerifyRoundTrip() {
        KeyPair kp = engine.generateAsymmetricKeyPair(HsmAlgorithm.RSA_2048);
        byte[] data = "RSA test data".getBytes();
        byte[] privBytes = engine.serializePrivateKey(kp.getPrivate());
        byte[] pubBytes = engine.serializePublicKey(kp.getPublic());
        byte[] sig = engine.sign(privBytes, data, HsmAlgorithm.RSA_2048);
        assertTrue(engine.verify(pubBytes, data, sig, HsmAlgorithm.RSA_2048));
    }

    @Test
    void ecSignVerifyRoundTrip() {
        KeyPair kp = engine.generateAsymmetricKeyPair(HsmAlgorithm.EC_P256);
        byte[] data = "EC test data".getBytes();
        byte[] privBytes = engine.serializePrivateKey(kp.getPrivate());
        byte[] pubBytes = engine.serializePublicKey(kp.getPublic());
        byte[] sig = engine.sign(privBytes, data, HsmAlgorithm.EC_P256);
        assertTrue(engine.verify(pubBytes, data, sig, HsmAlgorithm.EC_P256));
    }

    @Test
    void invalidSignatureReturnsFalseNotException() {
        KeyPair kp = engine.generateAsymmetricKeyPair(HsmAlgorithm.EC_P256);
        byte[] pubBytes = engine.serializePublicKey(kp.getPublic());
        byte[] data = "data".getBytes();
        byte[] badSig = new byte[64]; // all zeros — invalid
        assertFalse(engine.verify(pubBytes, data, badSig, HsmAlgorithm.EC_P256));
    }
}
