package com.example.hsm.service.crypto;

import com.example.hsm.entity.HsmConfig;
import com.example.hsm.exception.CryptographicOperationException;
import com.example.hsm.exception.HsmInternalException;
import com.example.hsm.repository.HsmConfigRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Derives and holds the AES-256 master wrapping key from a startup passphrase via PBKDF2.
 *
 * <p><strong>Security note:</strong> This is an emulation. In a real HSM the master key would
 * be protected by tamper-resistant hardware. Here it lives in JVM heap memory.
 * The passphrase is never logged.
 */
@Component
public class MasterKeyService {

    private static final Logger log = LoggerFactory.getLogger(MasterKeyService.class);
    private static final String SALT_CONFIG_KEY = "master_key_salt";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MIN_ITERATIONS = 310_000;

    @Value("${hsm.master-key.iterations:310000}")
    private int iterations;

    @Value("${hsm.master-key.salt-length:16}")
    private int saltLength;

    /**
     * Passphrase as a Spring property. Supports relaxed env binding, test profiles, and
     * {@code @DynamicPropertySource}-injected values that are not OS environment variables.
     */
    @Value("${hsm.master-key.passphrase:}")
    private String configuredPassphrase;

    private final HsmConfigRepository configRepo;
    private SecretKey masterKey;

    public MasterKeyService(HsmConfigRepository configRepo) {
        this.configRepo = configRepo;
    }

    @PostConstruct
    @Transactional
    public void init() {
        String passphrase = resolvePassphrase();
        if (passphrase == null || passphrase.isBlank()) {
            throw new HsmInternalException("Master passphrase not configured. " +
                    "Set HSM_MASTER_PASSPHRASE environment variable (or the " +
                    "hsm.master-key.passphrase property).");
        }
        if (iterations < MIN_ITERATIONS) {
            throw new HsmInternalException("PBKDF2 iteration count " + iterations +
                    " is below minimum " + MIN_ITERATIONS);
        }

        byte[] salt = loadOrGenerateSalt();
        char[] passphraseChars = passphrase.toCharArray();
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(passphraseChars, salt, iterations, 256);
            try {
                byte[] derived = skf.generateSecret(spec).getEncoded();
                masterKey = new SecretKeySpec(derived, "AES");
                Arrays.fill(derived, (byte) 0);
            } finally {
                spec.clearPassword();
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new HsmInternalException("Failed to derive master key", e);
        } finally {
            Arrays.fill(passphraseChars, '\0');
        }
        log.info("Master key derived successfully ({} iterations)", iterations);
    }

    /**
     * Wraps raw key bytes using the master key (AES-256-GCM).
     * Raw key bytes are zeroed in the finally block.
     *
     * @param rawKeyBytes the plaintext key material to wrap
     * @return a {@link WrappedKey} containing the encrypted DEK, IV, and auth tag
     */
    public WrappedKey wrapKey(byte[] rawKeyBytes) {
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertextWithTag = cipher.doFinal(rawKeyBytes);
            // GCM appends the 16-byte tag to ciphertext
            int ciphertextLen = ciphertextWithTag.length - 16;
            byte[] ciphertext = Arrays.copyOfRange(ciphertextWithTag, 0, ciphertextLen);
            byte[] authTag = Arrays.copyOfRange(ciphertextWithTag, ciphertextLen, ciphertextWithTag.length);
            return new WrappedKey(ciphertext, iv, authTag);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new HsmInternalException("Key wrapping failed", e);
        } finally {
            Arrays.fill(rawKeyBytes, (byte) 0);
        }
    }

    /**
     * Unwraps a wrapped DEK using the master key.
     * Throws {@link CryptographicOperationException} on GCM tag mismatch (tamper detection).
     *
     * @param wrappedKey the wrapped key material including IV and auth tag
     * @return the raw unwrapped key bytes — caller must zero them after use
     */
    public byte[] unwrapKey(WrappedKey wrappedKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, masterKey,
                    new GCMParameterSpec(GCM_TAG_BITS, wrappedKey.iv()));
            // Reassemble ciphertext + tag
            byte[] ct = wrappedKey.wrappedDek();
            byte[] tag = wrappedKey.authTag();
            byte[] combined = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, combined, 0, ct.length);
            System.arraycopy(tag, 0, combined, ct.length, tag.length);
            return cipher.doFinal(combined);
        } catch (AEADBadTagException e) {
            throw new CryptographicOperationException("Key integrity check failed — possible tampering", e);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new HsmInternalException("Key unwrapping failed", e);
        }
    }

    // ── private helpers ────────────────────────────────────────────────────────

    private String resolvePassphrase() {
        String passphrase = System.getenv("HSM_MASTER_PASSPHRASE");
        if (passphrase == null || passphrase.isBlank()) {
            passphrase = configuredPassphrase;
        }
        if (passphrase == null || passphrase.isBlank()) {
            passphrase = System.getProperty("hsm.master-key.passphrase");
        }
        return passphrase;
    }

    private byte[] loadOrGenerateSalt() {
        return configRepo.findByConfigKey(SALT_CONFIG_KEY)
                .map(cfg -> Base64.getDecoder().decode(cfg.getConfigValue()))
                .orElseGet(() -> {
                    byte[] salt = new byte[saltLength];
                    new SecureRandom().nextBytes(salt);
                    configRepo.save(new HsmConfig(SALT_CONFIG_KEY, Base64.getEncoder().encodeToString(salt)));
                    return salt;
                });
    }
}
