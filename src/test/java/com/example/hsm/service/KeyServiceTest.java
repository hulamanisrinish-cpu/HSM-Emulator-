package com.example.hsm.service;

import com.example.hsm.dto.GenerateKeyRequest;
import com.example.hsm.entity.*;
import com.example.hsm.exception.DestroyedKeyException;
import com.example.hsm.exception.InvalidKeyStateException;
import com.example.hsm.exception.KeyAlreadyExistsException;
import com.example.hsm.exception.KeyNotFoundException;
import com.example.hsm.repository.HsmKeyAclRepository;
import com.example.hsm.repository.HsmKeyRepository;
import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.security.HsmPrincipal;
import com.example.hsm.service.audit.AuditService;
import com.example.hsm.service.crypto.CryptoEngine;
import com.example.hsm.service.crypto.MasterKeyService;
import com.example.hsm.service.crypto.WrappedKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the key lifecycle state machine (FR-01..FR-05) and role-scoped listing.
 *
 * <p>These cover the guard branches that integration tests do not reach: invalid state
 * transitions, duplicate names, rotation of destroyed/disabled keys, idempotent ACL grants,
 * and the per-role {@code listKeys} switch.
 */
class KeyServiceTest {

    private HsmKeyRepository keyRepo;
    private HsmKeyAclRepository aclRepo;
    private HsmUserRepository userRepo;
    private AuditService auditService;
    private KeyService keyService;
    private HsmPrincipal officer;

    @BeforeEach
    void setUp() {
        CryptoEngine cryptoEngine = mock(CryptoEngine.class);
        MasterKeyService masterKeyService = mock(MasterKeyService.class);
        keyRepo = mock(HsmKeyRepository.class);
        aclRepo = mock(HsmKeyAclRepository.class);
        userRepo = mock(HsmUserRepository.class);
        auditService = mock(AuditService.class);

        keyService = new KeyService(cryptoEngine, masterKeyService,
                keyRepo, aclRepo, userRepo, auditService);
        officer = new HsmPrincipal(UUID.randomUUID(), "officer", HsmRole.CRYPTO_OFFICER);

        when(keyRepo.save(any(HsmKey.class))).thenAnswer(inv -> inv.getArgument(0));
        when(cryptoEngine.generateSymmetricKey()).thenReturn(new byte[32]);
        when(masterKeyService.wrapKey(any(byte[].class)))
                .thenAnswer(inv -> new WrappedKey(new byte[]{1, 2, 3}, new byte[12], new byte[16]));
    }

    // ── generate ───────────────────────────────────────────────────────────────

    @Test
    void generateDuplicateNameIsRejected() {
        when(keyRepo.findByName("dup")).thenReturn(Optional.of(key("dup", KeyState.ACTIVE, 1)));
        assertThrows(KeyAlreadyExistsException.class, () ->
                keyService.generateKey(new GenerateKeyRequest("dup", HsmAlgorithm.AES_256, null), officer));
        verify(keyRepo, never()).save(any(HsmKey.class));
    }

    @Test
    void generateAesKeyPersistsWrappedMaterialAndAudits() {
        when(keyRepo.findByName("fresh")).thenReturn(Optional.empty());
        var dto = keyService.generateKey(
                new GenerateKeyRequest("fresh", HsmAlgorithm.AES_256, null), officer);
        assertEquals("fresh", dto.name());
        assertEquals(KeyState.ACTIVE, dto.state());
        assertEquals(1, dto.version());
        verify(keyRepo).save(any(HsmKey.class));
        verify(auditService).appendRecord(eq(AuditAction.KEY_GENERATE), any(),
                eq(AuditOutcome.SUCCESS), eq(officer));
    }

    // ── list (role-scoped) ─────────────────────────────────────────────────────

    @Test
    void cryptoOfficerSeesAllKeys() {
        when(keyRepo.findAll()).thenReturn(List.of(key("k1", KeyState.ACTIVE, 1)));
        assertEquals(1, keyService.listKeys(officer).size());
    }

    @Test
    void adminSeesAllKeys() {
        when(keyRepo.findAll()).thenReturn(List.of(key("k1", KeyState.ACTIVE, 1)));
        var admin = new HsmPrincipal(UUID.randomUUID(), "admin", HsmRole.ADMIN);
        assertEquals(1, keyService.listKeys(admin).size());
    }

    @Test
    void appClientSeesOnlyGrantedKeys() {
        HsmKey granted = key("granted", KeyState.ACTIVE, 1);
        HsmUser principal = new HsmUser("app", "hash", "hsm_tk_prefix00", HsmRole.APP_CLIENT);
        when(aclRepo.findByPrincipalId(any()))
                .thenReturn(List.of(new HsmKeyAcl(granted, principal, UUID.randomUUID())));
        var client = new HsmPrincipal(UUID.randomUUID(), "app", HsmRole.APP_CLIENT);
        var result = keyService.listKeys(client);
        assertEquals(1, result.size());
        assertEquals("granted", result.get(0).name());
        verify(keyRepo, never()).findAll(); // AppClient must not see the full key inventory
    }

    @Test
    void auditorSeesNoKeys() {
        var auditor = new HsmPrincipal(UUID.randomUUID(), "auditor", HsmRole.AUDITOR);
        assertTrue(keyService.listKeys(auditor).isEmpty());
        verify(keyRepo, never()).findAll();
    }

    // ── state machine guards ───────────────────────────────────────────────────

    @Test
    void disableDisabledKeyThrows() {
        stubKey(key("k", KeyState.DISABLED, 1));
        assertThrows(InvalidKeyStateException.class,
                () -> keyService.disableKey(UUID.randomUUID(), officer));
    }

    @Test
    void disableDestroyedKeyThrows() {
        stubKey(key("k", KeyState.DESTROYED, 1));
        assertThrows(DestroyedKeyException.class,
                () -> keyService.disableKey(UUID.randomUUID(), officer));
    }

    @Test
    void enableActiveKeyThrows() {
        stubKey(key("k", KeyState.ACTIVE, 1));
        assertThrows(InvalidKeyStateException.class,
                () -> keyService.enableKey(UUID.randomUUID(), officer));
    }

    @Test
    void enableDestroyedKeyThrows() {
        stubKey(key("k", KeyState.DESTROYED, 1));
        assertThrows(DestroyedKeyException.class,
                () -> keyService.enableKey(UUID.randomUUID(), officer));
    }

    @Test
    void destroyDestroyedKeyThrows() {
        stubKey(key("k", KeyState.DESTROYED, 1));
        assertThrows(DestroyedKeyException.class,
                () -> keyService.destroyKey(UUID.randomUUID(), officer));
    }

    @Test
    void destroyZeroesWrappedKeyMaterial() {
        HsmKey k = key("k", KeyState.ACTIVE, 1);
        stubKey(k);
        keyService.destroyKey(UUID.randomUUID(), officer);
        assertEquals(KeyState.DESTROYED, k.getKeyState());
        assertNotNull(k.getDestroyedAt());
        assertArrayEquals(new byte[]{0, 0, 0}, k.getWrappedDek(), "Wrapped DEK must be zeroed");
        verify(auditService).appendRecord(eq(AuditAction.KEY_DESTROY), any(),
                eq(AuditOutcome.SUCCESS), eq(officer));
    }

    @Test
    void rotateDestroyedKeyThrows() {
        stubKey(key("k", KeyState.DESTROYED, 1));
        assertThrows(DestroyedKeyException.class,
                () -> keyService.rotateKey(UUID.randomUUID(), officer));
    }

    @Test
    void rotateDisabledKeyThrows() {
        stubKey(key("k", KeyState.DISABLED, 1));
        assertThrows(InvalidKeyStateException.class,
                () -> keyService.rotateKey(UUID.randomUUID(), officer));
    }

    @Test
    void getMissingKeyThrowsNotFound() {
        when(keyRepo.findById(any())).thenReturn(Optional.empty());
        assertThrows(KeyNotFoundException.class,
                () -> keyService.getKeyById(UUID.randomUUID(), officer));
    }

    // ── rotate ─────────────────────────────────────────────────────────────────

    @Test
    void rotateCreatesVersionedKeyAndDisablesOld() {
        HsmKey old = key("mykey", KeyState.ACTIVE, 1);
        stubKey(old);

        var dto = keyService.rotateKey(UUID.randomUUID(), officer);

        // name is UNIQUE in hsm_keys — the rotated row must carry a versioned name
        assertEquals("mykey_v2", dto.name());
        assertEquals(2, dto.version());
        assertEquals(KeyState.ACTIVE, dto.state());
        assertEquals(KeyState.DISABLED, old.getKeyState(), "Old key must be disabled on rotate");
        assertNotNull(old.getDisabledAt());
        verify(keyRepo).save(any(HsmKey.class));
        verify(auditService).appendRecord(eq(AuditAction.KEY_ROTATE), any(),
                eq(AuditOutcome.SUCCESS), eq(officer));
    }

    // ── ACL ────────────────────────────────────────────────────────────────────

    @Test
    void grantAclIsIdempotentWhenAlreadyGranted() {
        HsmKey k = key("k", KeyState.ACTIVE, 1);
        stubKey(k);
        HsmUser principal = new HsmUser("app", "hash", "hsm_tk_prefix00", HsmRole.APP_CLIENT);
        when(userRepo.findById(any())).thenReturn(Optional.of(principal));
        when(aclRepo.findByKeyIdAndPrincipalId(any(), any()))
                .thenReturn(Optional.of(new HsmKeyAcl(k, principal, UUID.randomUUID())));

        keyService.grantAcl(UUID.randomUUID(),
                new com.example.hsm.dto.AclRequest(UUID.randomUUID()), officer);

        verify(aclRepo, never()).save(any(HsmKeyAcl.class));
        verify(auditService, never()).appendRecord(eq(AuditAction.ACL_GRANT), any(), any(), any());
    }

    @Test
    void revokeMissingAclIsANoOp() {
        when(aclRepo.findByKeyIdAndPrincipalId(any(), any())).thenReturn(Optional.empty());
        keyService.revokeAcl(UUID.randomUUID(), UUID.randomUUID(), officer);
        verify(aclRepo, never()).delete(any(HsmKeyAcl.class));
        verify(auditService, never()).appendRecord(eq(AuditAction.ACL_REVOKE), any(), any(), any());
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private void stubKey(HsmKey k) {
        when(keyRepo.findById(any())).thenReturn(Optional.of(k));
    }

    private HsmKey key(String name, KeyState state, int version) {
        HsmKey k = HsmKey.builder()
                .name(name)
                .algorithm(HsmAlgorithm.AES_256)
                .keyState(state)
                .version(version)
                .wrappedDek(new byte[]{9, 9, 9})
                .ivDek(new byte[12])
                .authTagDek(new byte[16])
                .keyType(KeyType.SYMMETRIC)
                .build();
        return k;
    }
}
