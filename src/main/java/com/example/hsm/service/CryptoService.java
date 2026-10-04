package com.example.hsm.service;

import com.example.hsm.dto.*;
import com.example.hsm.entity.*;
import com.example.hsm.exception.*;
import com.example.hsm.repository.*;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.audit.AuditService;
import com.example.hsm.service.crypto.CryptoEngine;
import com.example.hsm.service.crypto.EncryptionResult;
import com.example.hsm.service.crypto.MasterKeyService;
import com.example.hsm.service.crypto.WrappedKey;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Performs cryptographic operations (encrypt/decrypt/sign/verify) using managed keys.
 *
 * <p>ACL check occurs BEFORE any key material is unwrapped. Raw key bytes are zeroed after use.
 */
@Service
@Transactional
public class CryptoService {

    private final HsmKeyRepository keyRepo;
    private final HsmKeyAclRepository aclRepo;
    private final MasterKeyService masterKeyService;
    private final CryptoEngine cryptoEngine;
    private final AuditService auditService;

    public CryptoService(HsmKeyRepository keyRepo, HsmKeyAclRepository aclRepo,
                         MasterKeyService masterKeyService, CryptoEngine cryptoEngine,
                         AuditService auditService) {
        this.keyRepo = keyRepo;
        this.aclRepo = aclRepo;
        this.masterKeyService = masterKeyService;
        this.cryptoEngine = cryptoEngine;
        this.auditService = auditService;
    }

    /**
     * Encrypts plaintext (Base64-encoded) using the specified key. Requires APP_CLIENT role and ACL.
     *
     * @param req    encryption request with Base64 plaintext
     * @param caller the authenticated caller
     * @return encryption response with Base64-encoded IV, ciphertext, and auth tag
     */
    @PreAuthorize("hasRole('APP_CLIENT')")
    public EncryptResponse encrypt(EncryptRequest req, HsmPrincipal caller) {
        HsmKey key = checkKeyAndAcl(req.keyId(), AuditAction.ENCRYPT, caller);
        byte[] rawKey = unwrapSymmetricKey(key);
        try {
            byte[] plaintext = Base64.getDecoder().decode(req.plaintext());
            EncryptionResult result = cryptoEngine.encrypt(rawKey, plaintext);
            auditService.appendRecord(AuditAction.ENCRYPT, key.getId(), AuditOutcome.SUCCESS, caller);
            return new EncryptResponse(key.getId(), key.getVersion(),
                    key.getAlgorithm().name(),
                    b64(result.iv()), b64(result.ciphertext()), b64(result.authTag()));
        } finally {
            Arrays.fill(rawKey, (byte) 0);
        }
    }

    /**
     * Decrypts ciphertext using the specified key. Requires APP_CLIENT role and ACL.
     *
     * @param req    decryption request with Base64 fields
     * @param caller the authenticated caller
     * @return decryption response with Base64-encoded plaintext
     */
    @PreAuthorize("hasRole('APP_CLIENT')")
    public DecryptResponse decrypt(DecryptRequest req, HsmPrincipal caller) {
        HsmKey key = checkKeyAndAcl(req.keyId(), AuditAction.DECRYPT, caller);
        byte[] rawKey = unwrapSymmetricKey(key);
        try {
            byte[] plaintext = cryptoEngine.decrypt(rawKey,
                    Base64.getDecoder().decode(req.iv()),
                    Base64.getDecoder().decode(req.ciphertext()),
                    Base64.getDecoder().decode(req.authTag()));
            auditService.appendRecord(AuditAction.DECRYPT, key.getId(), AuditOutcome.SUCCESS, caller);
            return new DecryptResponse(key.getId(), b64(plaintext));
        } finally {
            Arrays.fill(rawKey, (byte) 0);
        }
    }

    /**
     * Signs data using the specified asymmetric key. Requires APP_CLIENT role and ACL.
     *
     * @param req    sign request with Base64-encoded data
     * @param caller the authenticated caller
     * @return sign response with Base64-encoded signature
     */
    @PreAuthorize("hasRole('APP_CLIENT')")
    public SignResponse sign(SignRequest req, HsmPrincipal caller) {
        HsmKey key = checkKeyAndAcl(req.keyId(), AuditAction.SIGN, caller);
        if (key.getKeyType() == KeyType.SYMMETRIC) {
            throw new InvalidKeyStateException("Key " + req.keyId() + " is symmetric — cannot sign");
        }
        byte[] rawPrivKey = masterKeyService.unwrapKey(
                new WrappedKey(key.getWrappedDek(), key.getIvDek(), key.getAuthTagDek()));
        try {
            byte[] signature = cryptoEngine.sign(rawPrivKey,
                    Base64.getDecoder().decode(req.data()), key.getAlgorithm());
            auditService.appendRecord(AuditAction.SIGN, key.getId(), AuditOutcome.SUCCESS, caller);
            return new SignResponse(key.getId(), key.getAlgorithm().name(), b64(signature));
        } finally {
            Arrays.fill(rawPrivKey, (byte) 0);
        }
    }

    /**
     * Verifies a signature. Returns {@code valid=false} rather than 4xx on invalid signatures.
     * Requires APP_CLIENT role and ACL.
     *
     * @param req    verify request with Base64-encoded data and signature
     * @param caller the authenticated caller
     * @return verify response with boolean validity
     */
    @PreAuthorize("hasRole('APP_CLIENT')")
    public VerifyResponse verify(VerifyRequest req, HsmPrincipal caller) {
        HsmKey key = checkKeyAndAcl(req.keyId(), AuditAction.VERIFY, caller);
        if (key.getKeyType() == KeyType.SYMMETRIC) {
            throw new InvalidKeyStateException("Key " + req.keyId() + " is symmetric — cannot verify");
        }
        byte[] publicKeyBytes = key.getPublicKeyBytes();
        boolean valid = cryptoEngine.verify(publicKeyBytes,
                Base64.getDecoder().decode(req.data()),
                Base64.getDecoder().decode(req.signature()),
                key.getAlgorithm());
        auditService.appendRecord(AuditAction.VERIFY, key.getId(), AuditOutcome.SUCCESS, caller);
        return new VerifyResponse(key.getId(), valid);
    }

    // ── private helpers ────────────────────────────────────────────────────────

    /**
     * Loads the key and checks ACL. ACL check happens BEFORE unwrapping any key material.
     * Appends DENIED audit record and throws AccessDeniedException on failure.
     */
    private HsmKey checkKeyAndAcl(UUID keyId, AuditAction action, HsmPrincipal caller) {
        HsmKey key = keyRepo.findById(keyId)
                .orElseThrow(() -> new KeyNotFoundException(keyId));

        if (key.getKeyState() == KeyState.DESTROYED) {
            throw new DestroyedKeyException(keyId);
        }
        if (key.getKeyState() == KeyState.DISABLED) {
            throw new InvalidKeyStateException("Key " + keyId + " is disabled");
        }

        boolean hasAcl = aclRepo.findByKeyIdAndPrincipalId(keyId, caller.id()).isPresent();
        if (!hasAcl) {
            auditService.appendDeniedOrError(action, keyId, AuditOutcome.DENIED, caller);
            throw new AccessDeniedException("No ACL entry for key " + keyId);
        }
        return key;
    }

    private byte[] unwrapSymmetricKey(HsmKey key) {
        return masterKeyService.unwrapKey(
                new WrappedKey(key.getWrappedDek(), key.getIvDek(), key.getAuthTagDek()));
    }

    private String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
