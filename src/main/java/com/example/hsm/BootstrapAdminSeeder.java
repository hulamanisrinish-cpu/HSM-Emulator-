package com.example.hsm;

import com.example.hsm.entity.AuditAction;
import com.example.hsm.entity.AuditOutcome;
import com.example.hsm.entity.HsmRole;
import com.example.hsm.entity.HsmUser;
import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.service.TokenService;
import com.example.hsm.service.audit.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates the first ADMIN user on an empty database so the API is usable after a fresh start
 * (only an Admin can create users — without a bootstrap there would be no way in).
 *
 * <p>The one-time token is printed to stdout exactly once, the same way Vault and other
 * secret managers surface an initial root token. It is never persisted in plaintext; only
 * its Argon2id hash and lookup prefix are stored. Subsequent startups do nothing because
 * the user table is no longer empty.
 *
 * <p>Disabled in the {@code test} profile: {@link TestDataSeeder} provides a deterministic
 * token for integration tests instead.
 */
@Component
@Profile("!test")
public class BootstrapAdminSeeder implements ApplicationRunner {

    public static final String BOOTSTRAP_ADMIN_USERNAME = "bootstrap-admin";

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdminSeeder.class);

    private final HsmUserRepository userRepo;
    private final TokenService tokenService;
    private final AuditService auditService;
    private final boolean enabled;

    public BootstrapAdminSeeder(HsmUserRepository userRepo,
                                TokenService tokenService,
                                AuditService auditService,
                                @Value("${hsm.bootstrap.enabled:true}") boolean enabled) {
        this.userRepo = userRepo;
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.enabled = enabled;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!enabled || userRepo.count() > 0) {
            return; // already initialized (or explicitly disabled)
        }
        String plainToken = tokenService.generateToken();
        HsmUser admin = new HsmUser(BOOTSTRAP_ADMIN_USERNAME,
                tokenService.hashToken(plainToken),
                tokenService.extractPrefix(plainToken),
                HsmRole.ADMIN);
        userRepo.save(admin);
        auditService.appendRecord(AuditAction.USER_CREATE, null, AuditOutcome.SUCCESS, null);

        log.warn("""
                \n
                ============================================================
                 BOOTSTRAP ADMIN TOKEN (shown once, not stored in plaintext):
                   {}
                 Store it in a secrets manager now — it will never be shown
                 again. Use it to create CryptoOfficer / AppClient / Auditor
                 users, then disable or delete bootstrap-admin.
                ============================================================
                """, plainToken);
    }
}
