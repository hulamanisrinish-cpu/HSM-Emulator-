package com.example.hsm.service;

import com.example.hsm.dto.AclRequest;
import com.example.hsm.dto.GenerateKeyRequest;
import com.example.hsm.dto.KeyMetadataDto;
import com.example.hsm.entity.*;
import com.example.hsm.exception.*;
import com.example.hsm.repository.*;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.audit.AuditService;
import com.example.hsm.service.crypto.CryptoEngine;
import com.example.hsm.service.crypto.MasterKeyService;
import com.example.hsm.service.crypto.WrappedKey;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Manages the full cryptographic key lifecycle (generate, list, disable, enable, destroy, rotate)
 * and per-key ACL management. All mutating operations require the CRYPTO_OFFICER role.
 *
 * <p>Raw key bytes are zeroed after use in finally blocks.
 */
@Service
@Transactional
public class KeyService {

    private final CryptoEngine cryptoEngine;
    private final MasterKeyService masterKeyService;
    private final HsmKeyRepository keyRepo;
    private final HsmKeyAclRepository aclRepo;
    private final HsmUserRepository userRepo;
    private final AuditService auditService;

    public KeyService(CryptoEngine cryptoEngine, MasterKeyService masterKeyService,
                      HsmKeyRepository keyRepo, HsmKeyAclRepository aclRepo,
                      HsmUserRepository userRepo, AuditService auditService) {
        this.cryptoEngine = cryptoEngine;
        this.masterKeyService = masterKeyService;
        this.keyRepo = keyRepo;
        this.aclRepo = aclRepo;
        this.userRepo = userRepo;
        this.auditService = auditService;
    }

    /**
     * Generates a new cryptographic key. Requires CRYPTO_OFFICER role.
     *
     * @param req    key generation parameters
     * @param caller the authenticated caller
     * @return key metadata (no raw key bytes)
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public KeyMetadataDto generateKey(GenerateKeyRequest req, HsmPrincipal caller) {
        if (keyRepo.findByName(req.name()).isPresent()) {
            throw new KeyAlreadyExistsException(req.name());
        }
        HsmKey key = switch (req.algorithm()) {
            case AES_256 -> generateSymmetric(req, caller);
            case RSA_2048, EC_P256 -> generateAsymmetric(req, caller);
        };
        auditService.appendRecord(AuditAction.KEY_GENERATE, key.getId(), AuditOutcome.SUCCESS, caller);
        return toDto(key);
    }

    /**
     * Lists keys. CryptoOfficers see all; AppClients see only keys they have ACL entries for.
     *
     * @param caller the authenticated caller
     * @return list of key metadata
     */
    @Transactional(readOnly = true)
    public List<KeyMetadataDto> listKeys(HsmPrincipal caller) {
        return switch (caller.role()) {
            case CRYPTO_OFFICER, ADMIN -> keyRepo.findAll().stream().map(this::toDto).toList();
            case APP_CLIENT -> aclRepo.findByPrincipalId(caller.id()).stream()
                    .map(acl -> toDto(acl.getHsmKey())).toList();
            default -> List.of();
        };
    }

    /**
     * Retrieves a single key's metadata by ID.
     *
     * @param id     the key UUID
     * @param caller the authenticated caller
     * @return key metadata
     * @throws KeyNotFoundException if no key with the given ID exists
     */
    @Transactional(readOnly = true)
    public KeyMetadataDto getKeyById(UUID id, HsmPrincipal caller) {
        return toDto(loadKey(id));
    }

    /**
     * Disables an ACTIVE key. Requires CRYPTO_OFFICER role.
     *
     * @param id     the key UUID
     * @param caller the authenticated caller
     * @return updated key metadata
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public KeyMetadataDto disableKey(UUID id, HsmPrincipal caller) {
        HsmKey key = loadKey(id);
        if (key.getKeyState() == KeyState.DESTROYED) {
            throw new DestroyedKeyException(id);
        }
        if (key.getKeyState() == KeyState.DISABLED) {
            throw new InvalidKeyStateException("Key " + id + " is already disabled");
        }
        key.setKeyState(KeyState.DISABLED);
        key.setDisabledAt(Instant.now());
        auditService.appendRecord(AuditAction.KEY_DISABLE, id, AuditOutcome.SUCCESS, caller);
        return toDto(key);
    }

    /**
     * Re-enables a DISABLED key. Requires CRYPTO_OFFICER role.
     *
     * @param id     the key UUID
     * @param caller the authenticated caller
     * @return updated key metadata
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public KeyMetadataDto enableKey(UUID id, HsmPrincipal caller) {
        HsmKey key = loadKey(id);
        if (key.getKeyState() == KeyState.DESTROYED) {
            throw new DestroyedKeyException(id);
        }
        if (key.getKeyState() == KeyState.ACTIVE) {
            throw new InvalidKeyStateException("Key " + id + " is already active");
        }
        key.setKeyState(KeyState.ACTIVE);
        key.setDisabledAt(null);
        auditService.appendRecord(AuditAction.KEY_ENABLE, id, AuditOutcome.SUCCESS, caller);
        return toDto(key);
    }

    /**
     * Permanently destroys a key. Zeroes wrapped DEK bytes in DB. Requires CRYPTO_OFFICER role.
     * This action is irreversible.
     *
     * @param id     the key UUID
     * @param caller the authenticated caller
     * @return updated key metadata
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public KeyMetadataDto destroyKey(UUID id, HsmPrincipal caller) {
        HsmKey key = loadKey(id);
        if (key.getKeyState() == KeyState.DESTROYED) {
            throw new DestroyedKeyException(id);
        }
        // Zero out key material before marking destroyed
        if (key.getWrappedDek() != null) Arrays.fill(key.getWrappedDek(), (byte) 0);
        if (key.getIvDek() != null) Arrays.fill(key.getIvDek(), (byte) 0);
        if (key.getAuthTagDek() != null) Arrays.fill(key.getAuthTagDek(), (byte) 0);
        key.setKeyState(KeyState.DESTROYED);
        key.setDestroyedAt(Instant.now());
        auditService.appendRecord(AuditAction.KEY_DESTROY, id, AuditOutcome.SUCCESS, caller);
        return toDto(key);
    }

    /**
     * Rotates a key: generates a new version, disables the old one. Requires CRYPTO_OFFICER role.
     *
     * @param id     the key UUID to rotate
     * @param caller the authenticated caller
     * @return the new key's metadata
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public KeyMetadataDto rotateKey(UUID id, HsmPrincipal caller) {
        HsmKey old = loadKey(id);
        if (old.getKeyState() == KeyState.DESTROYED) {
            throw new DestroyedKeyException(id);
        }
        if (old.getKeyState() == KeyState.DISABLED) {
            throw new InvalidKeyStateException("Cannot rotate a disabled key " + id);
        }
        // Rotated key gets a NEW row; hsm_keys.name is UNIQUE, so the new row must carry a
        // versioned name (e.g. "mykey_v2"). Reusing the old name violates the unique constraint.
        String newName = old.getName() + "_v" + (old.getVersion() + 1);
        int newVersion = old.getVersion() + 1;
        // Disable old key
        old.setKeyState(KeyState.DISABLED);
        old.setDisabledAt(Instant.now());

        HsmKey newKey = switch (old.getAlgorithm()) {
            case AES_256 -> generateSymmetricRaw(newName, old.getAlgorithm(), newVersion, caller);
            case RSA_2048, EC_P256 -> generateAsymmetricRaw(newName, old.getAlgorithm(), newVersion, caller);
        };
        auditService.appendRecord(AuditAction.KEY_ROTATE, newKey.getId(), AuditOutcome.SUCCESS, caller);
        return toDto(newKey);
    }

    /**
     * Grants an AppClient ACL access to a key. Requires CRYPTO_OFFICER role.
     *
     * @param keyId   the key UUID
     * @param req     ACL request with principal ID
     * @param caller  the authenticated caller
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public void grantAcl(UUID keyId, AclRequest req, HsmPrincipal caller) {
        HsmKey key = loadKey(keyId);
        HsmUser principal = userRepo.findById(req.principalId())
                .orElseThrow(() -> new KeyNotFoundException(req.principalId()));
        if (aclRepo.findByKeyIdAndPrincipalId(keyId, req.principalId()).isPresent()) {
            return; // idempotent
        }
        aclRepo.save(new HsmKeyAcl(key, principal, caller.id()));
        auditService.appendRecord(AuditAction.ACL_GRANT, keyId, AuditOutcome.SUCCESS, caller);
    }

    /**
     * Revokes an AppClient's ACL access to a key. Requires CRYPTO_OFFICER role.
     *
     * @param keyId       the key UUID
     * @param principalId the principal whose access is revoked
     * @param caller      the authenticated caller
     */
    @PreAuthorize("hasRole('CRYPTO_OFFICER')")
    public void revokeAcl(UUID keyId, UUID principalId, HsmPrincipal caller) {
        aclRepo.findByKeyIdAndPrincipalId(keyId, principalId)
                .ifPresent(acl -> {
                    aclRepo.delete(acl);
                    auditService.appendRecord(AuditAction.ACL_REVOKE, keyId, AuditOutcome.SUCCESS, caller);
                });
    }

    // ── private helpers ────────────────────────────────────────────────────────

    private HsmKey loadKey(UUID id) {
        return keyRepo.findById(id).orElseThrow(() -> new KeyNotFoundException(id));
    }

    private HsmKey generateSymmetric(GenerateKeyRequest req, HsmPrincipal caller) {
        return generateSymmetricRaw(req.name(), req.algorithm(), 1, caller);
    }

    private HsmKey generateSymmetricRaw(String name, HsmAlgorithm alg, int version, HsmPrincipal caller) {
        byte[] rawKey = cryptoEngine.generateSymmetricKey();
        try {
            WrappedKey wk = masterKeyService.wrapKey(rawKey); // wrapKey zeros rawKey
            HsmKey key = HsmKey.builder()
                    .name(name).algorithm(alg).keyState(KeyState.ACTIVE).version(version)
                    .wrappedDek(wk.wrappedDek()).ivDek(wk.iv()).authTagDek(wk.authTag())
                    .keyType(KeyType.SYMMETRIC).createdBy(caller != null ? caller.id() : null)
                    .build();
            return keyRepo.save(key);
        } finally {
            Arrays.fill(rawKey, (byte) 0);
        }
    }

    private HsmKey generateAsymmetric(GenerateKeyRequest req, HsmPrincipal caller) {
        return generateAsymmetricRaw(req.name(), req.algorithm(), 1, caller);
    }

    private HsmKey generateAsymmetricRaw(String name, HsmAlgorithm alg, int version, HsmPrincipal caller) {
        KeyPair kp = cryptoEngine.generateAsymmetricKeyPair(alg);
        byte[] privateKeyBytes = cryptoEngine.serializePrivateKey(kp.getPrivate());
        byte[] publicKeyBytes = cryptoEngine.serializePublicKey(kp.getPublic());
        try {
            WrappedKey wk = masterKeyService.wrapKey(privateKeyBytes); // zeros privateKeyBytes
            HsmKey key = HsmKey.builder()
                    .name(name).algorithm(alg).keyState(KeyState.ACTIVE).version(version)
                    .wrappedDek(wk.wrappedDek()).ivDek(wk.iv()).authTagDek(wk.authTag())
                    .keyType(KeyType.ASYMMETRIC).createdBy(caller != null ? caller.id() : null)
                    .build();
            key.setPublicKeyBytes(publicKeyBytes);
            return keyRepo.save(key);
        } finally {
            Arrays.fill(privateKeyBytes, (byte) 0);
        }
    }

    private KeyMetadataDto toDto(HsmKey key) {
        return new KeyMetadataDto(key.getId(), key.getName(), key.getAlgorithm(),
                key.getKeyType(), key.getKeyState(), key.getVersion(),
                key.getCreatedAt(), key.getCreatedBy());
    }
}
