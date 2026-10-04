package com.example.hsm;

import com.example.hsm.entity.AuditAction;
import com.example.hsm.entity.AuditOutcome;
import com.example.hsm.entity.HsmRole;
import com.example.hsm.entity.HsmUser;
import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.service.TokenService;
import com.example.hsm.service.audit.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Verifies the first-boot bootstrap path: exactly one ADMIN on an empty database,
 * plaintext token never persisted, and re-runs are no-ops.
 */
class BootstrapAdminSeederTest {

    private HsmUserRepository userRepo;
    private TokenService tokenService;
    private AuditService auditService;
    private BootstrapAdminSeeder seeder;
    private final String plainToken = "hsm_tk_bootstrap_token_value";

    @BeforeEach
    void setUp() {
        userRepo = mock(HsmUserRepository.class);
        tokenService = mock(TokenService.class);
        auditService = mock(AuditService.class);
        seeder = new BootstrapAdminSeeder(userRepo, tokenService, auditService, true);

        when(tokenService.generateToken()).thenReturn(plainToken);
        when(tokenService.hashToken(anyString())).thenReturn("salt:argon2hash");
        when(tokenService.extractPrefix(anyString())).thenReturn(plainToken.substring(0, 16));
        when(userRepo.save(any(HsmUser.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void emptyDatabaseGetsExactlyOneAdmin() {
        when(userRepo.count()).thenReturn(0L);

        seeder.run(null);

        ArgumentCaptor<HsmUser> captor = ArgumentCaptor.forClass(HsmUser.class);
        verify(userRepo, times(1)).save(captor.capture());
        HsmUser saved = captor.getValue();
        assertEquals(BootstrapAdminSeeder.BOOTSTRAP_ADMIN_USERNAME, saved.getUsername());
        assertEquals(HsmRole.ADMIN, saved.getRole());
        assertEquals("salt:argon2hash", saved.getTokenHash(), "Only the hash may be stored");
        assertNotEquals(plainToken, saved.getTokenHash(), "Plaintext token must never be persisted");
        verify(auditService).appendRecord(eq(AuditAction.USER_CREATE), isNull(), eq(AuditOutcome.SUCCESS), isNull());
    }

    @Test
    void nonEmptyDatabaseIsUntouched() {
        when(userRepo.count()).thenReturn(3L);

        seeder.run(null);

        verify(userRepo, never()).save(any(HsmUser.class));
        verify(tokenService, never()).generateToken();
        verify(auditService, never()).appendRecord(any(), any(), any(), any());
    }

    @Test
    void disabledBootstrapDoesNothing() {
        BootstrapAdminSeeder disabled = new BootstrapAdminSeeder(userRepo, tokenService, auditService, false);
        disabled.run(null);
        verify(userRepo, never()).save(any(HsmUser.class));
        verify(userRepo, never()).count();
    }
}
