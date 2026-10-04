package com.example.hsm;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Base class for all integration tests.
 *
 * <p>Starts a single shared {@link PostgreSQLContainer} (postgres:15-alpine) for the entire
 * test suite. The container is started manually in a static initializer rather than via the
 * {@code @Testcontainers}/{@code @Container} JUnit extension on purpose: the extension runs
 * beforeAll/afterAll per test class, which stops and re-creates the shared container for every
 * class (a new random host port each time) while Spring's cached ApplicationContext keeps the
 * original JDBC URL — permanently losing the database after the first class. A manually started
 * static container lives for the whole JVM and is cleaned up by Ryuk on JVM exit.
 *
 * <p>The {@code HSM_MASTER_PASSPHRASE} property is injected via {@link DynamicPropertySource}
 * so the application context can start without requiring the environment variable to be set
 * externally. The value used here is safe for CI only and MUST NOT be used in production.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractIntegrationTest {

    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:15-alpine")
                    .withDatabaseName("hsm_test")
                    .withUsername("hsm")
                    .withPassword("hsm");

    static {
        // Started once per JVM: runs when this class is first loaded, before any
        // @DynamicPropertySource callback resolves the datasource properties.
        postgres.start();
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        // Provide a fixed test passphrase so the app context starts in CI without
        // the HSM_MASTER_PASSPHRASE environment variable being set externally.
        registry.add("hsm.master-key.passphrase", () -> "test-passphrase-for-ci-only");
    }
}
