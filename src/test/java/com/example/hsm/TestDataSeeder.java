package com.example.hsm;

import com.example.hsm.entity.HsmRole;
import com.example.hsm.entity.HsmUser;
import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.service.TokenService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Seeds a bootstrap admin user in the test profile so integration tests have a working token.
 * The token is stored as a system property so tests can read it.
 */
@Component
@Profile("test")
public class TestDataSeeder implements ApplicationRunner {

    public static final String BOOTSTRAP_ADMIN_TOKEN_PROP = "test.bootstrap.admin.token";

    private final HsmUserRepository userRepo;
    private final TokenService tokenService;

    public TestDataSeeder(HsmUserRepository userRepo, TokenService tokenService) {
        this.userRepo = userRepo;
        this.tokenService = tokenService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userRepo.findByUsername("bootstrap-admin").isEmpty()) {
            String token = tokenService.generateToken();
            String hash = tokenService.hashToken(token);
            String prefix = tokenService.extractPrefix(token);
            HsmUser admin = new HsmUser("bootstrap-admin", hash, prefix, HsmRole.ADMIN);
            userRepo.save(admin);
            System.setProperty(BOOTSTRAP_ADMIN_TOKEN_PROP, token);
        }
    }
}
