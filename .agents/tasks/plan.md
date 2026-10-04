# Implementation Plan — Software HSM Emulator

> **Spec sources (all read in full before writing this plan):**
> - `g:\hsm\docs\requirements.md` — PRD, personas, FR/NFR
> - `g:\hsm\docs\design.md` — architecture, data model, API, threat model
> - `g:\hsm\docs\tasks.md` — 34-task ordered checklist (T01–T34)
> - `g:\hsm\README.md` — project readme

---

## Global Security Rules (apply to every task)

These rules are non-negotiable. Every code author must re-read them before writing any class:

1. **No key material in responses/logs.** Raw `byte[]` key bytes must NEVER appear in HTTP responses, log lines, MDC, or exception messages. `HsmKey.toString()` and `HsmUser.toString()` must explicitly exclude sensitive byte fields. Validate with grep: `grep -r "wrappedDek" src/main/` must only appear in entity and service files, never in DTOs or log statements.
2. **Zero byte arrays after use.** After any operation that holds a raw DEK or private key in memory, zero the array in a `finally` block: `Arrays.fill(rawKeyBytes, (byte) 0)`. This applies in `MasterKeyService.wrapKey()`, `MasterKeyService.unwrapKey()`, `CryptoEngine.encrypt()`, `CryptoEngine.decrypt()`, `CryptoEngine.sign()`, and `CryptoService` wherever a raw key is held.
3. **Identical 401 responses.** The Security filter must return the SAME response body (`{"status":401,"error":"Unauthorized","message":"Authentication required"}`) for ALL of: missing token, malformed token, unknown token, disabled user token. No oracle distinguishing user existence from bad credentials.
4. **Bouncy Castle only for Argon2id.** The import `org.bouncycastle.*` must appear ONLY in `TokenService.java`. Enforce with: `grep -r "bouncycastle" src/main/java --include="*.java" | grep -v TokenService`.
5. **Never custom cryptography.** All crypto uses JCA standard library (`javax.crypto`, `java.security`). No custom cipher implementations, no custom MACs, no custom key derivation.
6. **`@PreAuthorize` on service methods.** RBAC checks are on `@Service` methods, not `@Controller` methods. This prevents bypass via direct service calls from other services.
7. **Transactional audit.** Audit records for SUCCESS outcomes are written in the same `@Transactional` as the operation. Audit records for DENIED/ERROR outcomes use `@Transactional(propagation = REQUIRES_NEW)` so they always commit regardless of primary transaction rollback.

---

## Maven Coordinates (exact pinned versions — do not change)

```xml
<!-- Parent -->
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.2.5</version>
</parent>

<!-- Core dependencies -->
spring-boot-starter-web                         (via parent BOM)
spring-boot-starter-data-jpa                    (via parent BOM)
spring-boot-starter-security                    (via parent BOM)
spring-boot-starter-test                        (via parent BOM, scope=test)
spring-boot-starter-validation                  (via parent BOM)

springdoc-openapi-starter-webmvc-ui:2.5.0
org.postgresql:postgresql:42.7.3 (scope=runtime)
org.bouncycastle:bcprov-jdk18on:1.78.1
org.flywaydb:flyway-core:10.12.0
org.flywaydb:flyway-database-postgresql:10.12.0

<!-- Testcontainers BOM import -->
org.testcontainers:testcontainers-bom:1.19.8 (scope=import, type=pom)
org.testcontainers:postgresql (scope=test)
org.testcontainers:junit-jupiter (scope=test)

<!-- Build plugins -->
org.apache.maven.plugins:maven-compiler-plugin:3.13.0
org.apache.maven.plugins:maven-surefire-plugin:3.2.5
org.apache.maven.plugins:maven-failsafe-plugin:3.2.5
org.jacoco:jacoco-maven-plugin:0.8.12
org.apache.maven.plugins:maven-javadoc-plugin:3.7.0
org.owasp:dependency-check-maven:10.0.2
```

---

## Package Structure

```
com.example.hsm
├── HsmApplication.java                          # @SpringBootApplication
├── config/
│   ├── SecurityConfig.java                      # Spring Security filter chain, @EnableMethodSecurity
│   └── OpenApiConfig.java                       # Springdoc OpenAPI bean, bearer auth scheme
├── controller/
│   ├── KeyController.java                       # /api/v1/keys
│   ├── CryptoController.java                    # /api/v1/crypto
│   ├── AuditController.java                     # /api/v1/audit
│   └── UserController.java                      # /api/v1/users
├── service/
│   ├── KeyService.java                          # Key lifecycle, @PreAuthorize CRYPTO_OFFICER
│   ├── CryptoService.java                       # Encrypt/decrypt/sign/verify, @PreAuthorize APP_CLIENT
│   ├── UserService.java                         # User/role mgmt, @PreAuthorize ADMIN
│   ├── crypto/
│   │   ├── CryptoEngine.java                    # Stateless JCA wrapper
│   │   ├── MasterKeyService.java                # PBKDF2 key derivation, wrap/unwrap DEK
│   │   ├── WrappedKey.java                      # Value object: wrappedDek, iv, authTag
│   │   └── EncryptionResult.java                # Value object: iv, ciphertext, authTag
│   └── audit/
│       └── AuditService.java                    # Hash-chain append, verify, read
├── security/
│   ├── TokenAuthenticationFilter.java           # OncePerRequestFilter, token resolution
│   └── HsmPrincipal.java                        # Principal record: id, username, role
├── repository/
│   ├── HsmConfigRepository.java
│   ├── HsmUserRepository.java
│   ├── HsmKeyRepository.java
│   ├── HsmKeyAclRepository.java
│   └── AuditRecordRepository.java
├── entity/
│   ├── HsmConfig.java
│   ├── HsmUser.java                             # toString() EXCLUDES tokenHash
│   ├── HsmKey.java                              # toString() EXCLUDES wrappedDek/ivDek/authTagDek
│   ├── HsmKeyAcl.java
│   └── AuditRecord.java
├── dto/
│   ├── GenerateKeyRequest.java
│   ├── KeyMetadataDto.java                      # NO key bytes
│   ├── AclRequest.java
│   ├── EncryptRequest.java / EncryptResponse.java
│   ├── DecryptRequest.java / DecryptResponse.java
│   ├── SignRequest.java / SignResponse.java
│   ├── VerifyRequest.java / VerifyResponse.java
│   ├── AuditRecordDto.java
│   ├── AuditPageResponse.java
│   ├── AuditVerifyResult.java
│   ├── CreateUserRequest.java
│   ├── CreateUserResponse.java                  # token shown once
│   ├── UserDto.java                             # NO tokenHash
│   └── ErrorResponse.java
├── exception/
│   ├── HsmException.java                        # abstract base
│   ├── AuthenticationException.java             # → 401
│   ├── AccessDeniedException.java               # → 403
│   ├── KeyNotFoundException.java                # → 404
│   ├── KeyAlreadyExistsException.java           # → 409
│   ├── InvalidKeyStateException.java            # → 422
│   ├── DestroyedKeyException.java               # → 410 (extends InvalidKeyStateException)
│   ├── CryptographicOperationException.java     # → 400
│   ├── HsmInternalException.java                # → 500
│   └── GlobalExceptionHandler.java              # @RestControllerAdvice
└── service/
    └── TokenService.java                        # Argon2id via Bouncy Castle — ONLY BC usage
```

---

## Flyway Migration Files

All files in `src/main/resources/db/migration/`:

| File | Purpose | Key constraints |
|------|---------|-----------------|
| `V1__create_hsm_config.sql` | `hsm_config(config_key PK, config_value, created_at)` | Stores master key salt (Base64) |
| `V2__create_hsm_users.sql` | `hsm_users(id UUID PK, username UK, token_hash, token_prefix, role CHECK, created_at, enabled)` | `role IN ('ADMIN','CRYPTO_OFFICER','APP_CLIENT','AUDITOR')` |
| `V3__create_hsm_keys.sql` | `hsm_keys(id, name UK, algorithm, key_state CHECK, version, wrapped_dek BYTEA, iv_dek BYTEA, auth_tag_dek BYTEA, public_key_bytes BYTEA, key_type CHECK, created_by FK, timestamps)` | `key_state IN ('ACTIVE','DISABLED','DESTROYED')`; indexes on state, name |
| `V4__create_hsm_key_acls.sql` | `hsm_key_acls(id, key_id FK, principal_id FK, permission, granted_at, granted_by)` | Unique on `(key_id, principal_id)` |
| `V5__create_hsm_audit_log.sql` | `hsm_audit_log(sequence_number BIGSERIAL PK, id UUID UK, recorded_at TIMESTAMPTZ(9), principal_id UUID, action, key_id UUID, outcome CHECK, chain_hash VARCHAR(64))` | `outcome IN ('SUCCESS','DENIED','ERROR')`; indexes on recorded_at, principal_id, sequence_number |
| `V6__add_token_prefix.sql` | `ALTER TABLE hsm_users ADD COLUMN token_prefix VARCHAR(16); CREATE INDEX idx_users_token_prefix` | Enables O(1) token lookup without full-table Argon2 scan |

**Ordering constraint:** V1 must run before application start (MasterKeyService uses `hsm_config`). V2 must precede V3 (FK `created_by` references `hsm_users`). V3 must precede V4 (FK `key_id`). V6 must be applied before UserService creates users with token_prefix.

---

## Phase-by-Phase Plan (T01–T34)

---

- [ ] **1. T01–T03 — Project Scaffold**
      Create `pom.xml` with all pinned dependencies (see Maven Coordinates above). Create `HsmApplication.java`. Create `docker-compose.yml` (postgres:15-alpine, named volume). Create `src/main/resources/application.yml` (datasource, JPA validate, Flyway enabled). Create `src/main/resources/application-test.yml` (Flyway disabled, ddl-auto=create-drop). Create `AbstractIntegrationTest.java` (shared static `PostgreSQLContainer`, `@DynamicPropertySource` for datasource + `HSM_MASTER_PASSPHRASE=test-passphrase-for-ci-only`). Create `.github/workflows/ci.yml` (setup-java Temurin 17, Maven cache, `mvn verify`, JaCoCo artifact upload, dependency-check). Create `.gitignore`.
      Files: `pom.xml`, `src/main/java/com/example/hsm/HsmApplication.java`, `docker-compose.yml`, `src/main/resources/application.yml`, `src/main/resources/application-test.yml`, `src/test/java/com/example/hsm/AbstractIntegrationTest.java`, `.github/workflows/ci.yml`, `.gitignore`
      Verify: `mvn --batch-mode compile -DskipTests` → BUILD SUCCESS

---

- [ ] **2. T04 — MasterKeyService (PBKDF2 key derivation)**
      **Depends on:** Task 1 (pom.xml, HsmApplication, application.yml).
      Create Flyway migration `V1__create_hsm_config.sql`. Create `HsmConfig` JPA entity. Create `HsmConfigRepository`. Create `MasterKeyService` (`@Component`, `@PostConstruct` init): reads `HSM_MASTER_PASSPHRASE` env var (throws `HsmInternalException` with safe message if absent — never logs the passphrase); validates iterations ≥ 310,000; generates or loads 16-byte salt from `hsm_config`; derives AES-256 `SecretKey` via `PBKDF2WithHmacSHA256`; exposes `wrapKey(byte[])` → `WrappedKey` and `unwrapKey(WrappedKey)` → `byte[]`. Create `WrappedKey` value class. Zero passphrase char array and raw key byte arrays in `finally`.
      Files: `src/main/resources/db/migration/V1__create_hsm_config.sql`, `src/main/java/com/example/hsm/entity/HsmConfig.java`, `src/main/java/com/example/hsm/repository/HsmConfigRepository.java`, `src/main/java/com/example/hsm/service/crypto/MasterKeyService.java`, `src/main/java/com/example/hsm/service/crypto/WrappedKey.java`
      Tests: `MasterKeyServiceTest` — `samePassphraseAndSaltProducesSameKey`, `differentSaltProducesDifferentKey`, `missingPassphraseEnvVarFailsFast`, `iterationCountBelowMinimumFailsFast`
      Verify: `mvn --batch-mode test -Dtest=MasterKeyServiceTest` → 4 tests pass

---

- [ ] **3. T05 — CryptoEngine: AES-256-GCM**
      **Depends on:** Task 2 (`WrappedKey`, `MasterKeyService`).
      Create `EncryptionResult` value class. Create `CryptoEngine` (`@Component`, stateless). Implement: `generateSymmetricKey()` (32 bytes, `SecureRandom`), `encrypt(byte[] rawKey, byte[] plaintext)` (fresh 12-byte IV per call, `AES/GCM/NoPadding`, 128-bit tag — GCM appends the 16-byte tag to the ciphertext, split last 16 bytes as `authTag` in `EncryptionResult`), `decrypt(byte[] rawKey, byte[] iv, byte[] ciphertext, byte[] authTag)` (reassemble ciphertext+authTag, verify GCM tag; on `AEADBadTagException` throw `CryptographicOperationException`). Zero `rawKey` arrays in `finally` after every operation.
      Files: `src/main/java/com/example/hsm/service/crypto/EncryptionResult.java`, `src/main/java/com/example/hsm/service/crypto/CryptoEngine.java` (symmetric methods)
      Tests: `CryptoEngineTest` `@Tag("crypto")` — `aesEncryptDecryptRoundTrip`, `eachEncryptCallUsesUniqueIv`, `tamperedCiphertextThrowsCryptographicOperationException`, `tamperedAuthTagThrowsException`, `tamperedWrappedDekIsRejected` `@Tag("security")`
      Verify: `mvn --batch-mode test -Dtest=CryptoEngineTest -Dgroups=crypto` → 5 tests pass

---

- [ ] **4. T06 — CryptoEngine: RSA-2048 and EC P-256**
      **Depends on:** Task 3 (`CryptoEngine` symmetric).
      Add to `CryptoEngine`: `generateAsymmetricKeyPair(KeyAlgorithm)` (RSA-2048 or EC/secp256r1), `sign(byte[] privateKeyBytes, byte[] data, KeyAlgorithm)` (RSA→`SHA256withRSA`; EC→`SHA256withECDSA`), `verify(byte[] publicKeyBytes, byte[] data, byte[] signature, KeyAlgorithm)` (non-throwing; catch `SignatureException` → return `false`). Add key serialization helpers: `serializePublicKey(PublicKey)` → `byte[]` (X.509 `SubjectPublicKeyInfo`), `serializePrivateKey(PrivateKey)` → `byte[]` (PKCS#8), `deserializePublicKey(byte[], KeyAlgorithm)` → `PublicKey`, `deserializePrivateKey(byte[], KeyAlgorithm)` → `PrivateKey`.
      Files: `src/main/java/com/example/hsm/service/crypto/CryptoEngine.java` (asymmetric additions)
      Tests: `CryptoEngineTest` — `rsaSignVerifyRoundTrip`, `ecSignVerifyRoundTrip`, `invalidSignatureReturnsFalseNotException`, `symmetricKeyRejectedForSignOperation`
      Verify: `mvn --batch-mode test -Dtest=CryptoEngineTest` → all 9 tests pass

---

- [ ] **5. T07 — Database schema: Flyway migrations V2–V5**
      **Depends on:** Task 1 (Flyway configured), Task 2 (V1 already applied).
      Create: `V2__create_hsm_users.sql`, `V3__create_hsm_keys.sql`, `V4__create_hsm_key_acls.sql`, `V5__create_hsm_audit_log.sql`. Each migration applies FK constraints in dependency order (V2 before V3 before V4). V5 creates `BIGSERIAL` sequence for `sequence_number`. Add DB-level `CHECK` constraints: `key_state IN ('ACTIVE','DISABLED','DESTROYED')`, `outcome IN ('SUCCESS','DENIED','ERROR')`, `role IN ('ADMIN','CRYPTO_OFFICER','APP_CLIENT','AUDITOR')`. Add indexes on `hsm_audit_log(recorded_at)`, `hsm_audit_log(principal_id)`, `hsm_keys(name)`, `hsm_keys(key_state)`.
      Files: `src/main/resources/db/migration/V2__create_hsm_users.sql`, `V3__create_hsm_keys.sql`, `V4__create_hsm_key_acls.sql`, `V5__create_hsm_audit_log.sql`
      Tests: Integration test — context loads without errors; all tables exist (verified by `AbstractIntegrationTest` if it runs a simple health check, or via `@DataJpaTest` with Testcontainers)
      Verify: `mvn --batch-mode verify -Dtest=AbstractIntegrationTest` — context loads, no Flyway errors

---

- [ ] **6. T08 — JPA entities and repositories**
      **Depends on:** Task 5 (schema migrations).
      Create enums: `KeyAlgorithm` (AES_256, RSA_2048, EC_P256), `KeyState` (ACTIVE, DISABLED, DESTROYED), `KeyType` (SYMMETRIC, ASYMMETRIC_PAIR), `UserRole` (ADMIN, CRYPTO_OFFICER, APP_CLIENT, AUDITOR), `AuditAction` (all 17 constants from design section 6.3), `AuditOutcome` (SUCCESS, DENIED, ERROR).
      Create JPA entities: `HsmConfig`, `HsmUser` (override `toString()` to exclude `tokenHash`), `HsmKey` (override `toString()` to exclude `wrappedDek`, `ivDek`, `authTagDek`, `publicKeyBytes`; mark binary columns `@Column(columnDefinition="bytea")`), `HsmKeyAcl`, `AuditRecord` (sequenceNumber `@GeneratedValue(strategy=SEQUENCE)`).
      Create Spring Data JPA repositories with JPQL named queries: `HsmConfigRepository`, `HsmUserRepository` (`findByUsername`, `findByTokenPrefix`), `HsmKeyRepository` (`findByName`, `findByKeyState`), `HsmKeyAclRepository` (`findByKeyIdAndPrincipalId`, `findByPrincipalId`), `AuditRecordRepository` (`findTopByOrderBySequenceNumberDesc`, `findByRecordedAtBetween`, `findAllByOrderBySequenceNumberAsc`).
      Files: `src/main/java/com/example/hsm/entity/` (6 files), `src/main/java/com/example/hsm/repository/` (5 files)
      Tests: `HsmKeyRepositoryTest` — `findByNameReturnsKey`, `findByStateReturnsOnlyActiveKeys`; `HsmKeyAclRepositoryTest` — `findByKeyAndPrincipalReturnsAcl`; `AuditLogRepositoryTest` — `findByDateRangeReturnsPaginatedResults`
      Verify: `mvn --batch-mode test -Dtest=HsmKeyRepositoryTest,HsmKeyAclRepositoryTest,AuditLogRepositoryTest` → all pass

---

- [ ] **7. T09 — Exception hierarchy and global error handler**
      **Depends on:** Task 1 (Spring Boot application), Task 6 (entities for context).
      Create exception classes in `com.example.hsm.exception`: `HsmException` (abstract, `extends RuntimeException`), `AuthenticationException` (→ 401), `AccessDeniedException` (→ 403), `KeyNotFoundException` (→ 404), `KeyAlreadyExistsException` (→ 409), `InvalidKeyStateException` (→ 422), `DestroyedKeyException extends InvalidKeyStateException` (→ 410), `CryptographicOperationException` (→ 400), `HsmInternalException` (→ 500). All constructors take a `String message` — never a `byte[]` or raw key object.
      Create `ErrorResponse` DTO: fields `timestamp` (Instant), `status` (int), `error` (String), `message` (String), `path` (String).
      Create `GlobalExceptionHandler` (`@RestControllerAdvice`): map each exception to its HTTP status and `ErrorResponse`. Also handle Spring's `org.springframework.security.access.AccessDeniedException` → 403 and Spring's `org.springframework.security.core.AuthenticationException` → 401. NEVER serialize the stack trace. NEVER include raw key bytes.
      Files: `src/main/java/com/example/hsm/exception/` (10 files), `src/main/java/com/example/hsm/dto/ErrorResponse.java`
      Tests: `GlobalExceptionHandlerTest` — `accessDeniedReturns403WithStandardEnvelope`, `keyNotFoundReturns404`, `noStackTraceInResponse`, `genericInternalErrorHidesDetails`
      Verify: `mvn --batch-mode test -Dtest=GlobalExceptionHandlerTest` → 4 tests pass

---

- [ ] **8. T10 — API token generation and Argon2id hashing**
      **Depends on:** Task 1 (Bouncy Castle in pom.xml).
      Create `TokenService` (`@Component`). `generateToken()`: `"hsm_tk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(SecureRandom 32 bytes)`. `hashToken(String token)`: use Bouncy Castle `Argon2BytesGenerator` with `Argon2Parameters.ARGON2_id`, memory=65536 KB, iterations=3, parallelism=4, random 16-byte salt; encode output as `"$argon2id$v=19$m=65536,t=3,p=4$" + Base64(salt) + "$" + Base64(hash)` (or store as `salt_hex:hash_hex` — choose one consistent format). `verifyToken(String plainToken, String storedHash)`: extract salt from stored representation, re-derive with same params, compare with `MessageDigest.isEqual()` (constant-time). NEVER log plain tokens. BOUNCY CASTLE ONLY HERE.
      Files: `src/main/java/com/example/hsm/service/TokenService.java`
      Tests: `TokenServiceTest` — `generatedTokenHasExpectedPrefix`, `hashAndVerifyRoundTrip`, `differentTokensProduceDifferentHashes`, `timingAttackResistance`
      Verify: `mvn --batch-mode test -Dtest=TokenServiceTest` → 4 tests pass

---

- [ ] **9. T11 — Spring Security token authentication filter and SecurityConfig**
      **Depends on:** Tasks 7–8 (`HsmUser` entity, `HsmUserRepository`, `TokenService`).
      Create `HsmPrincipal` record: `UUID id, String username, UserRole role`.
      Create `TokenAuthenticationFilter extends OncePerRequestFilter`: (1) Extract `Authorization: Bearer <token>` header; (2) Extract token prefix (first 16 chars); (3) Call `HsmUserRepository.findByTokenPrefix(prefix)` for O(1) lookup; (4) Call `TokenService.verifyToken(token, user.tokenHash)`; (5) Check `user.enabled`; (6) On any failure: `response.sendError(401)` with generic body `{"status":401,"error":"Unauthorized","message":"Authentication required"}` — IDENTICAL for all failure modes; (7) On success: set `SecurityContextHolder` with `UsernamePasswordAuthenticationToken(new HsmPrincipal(user.id, user.username, user.role), null, List.of(new SimpleGrantedAuthority("ROLE_" + user.role.name())))`.
      Create `SecurityConfig` (`@Configuration @EnableMethodSecurity`): disable CSRF, stateless sessions, add `TokenAuthenticationFilter` before `UsernamePasswordAuthenticationFilter`, permit `/v3/api-docs/**`, `/swagger-ui/**`, `/swagger-ui.html`, `/actuator/health`; authenticate all others. Disable `formLogin` and `httpBasic`.
      Add `V6__add_token_prefix.sql`: `ALTER TABLE hsm_users ADD COLUMN token_prefix VARCHAR(16); CREATE INDEX idx_users_token_prefix ON hsm_users(token_prefix);`
      Files: `src/main/java/com/example/hsm/security/HsmPrincipal.java`, `src/main/java/com/example/hsm/security/TokenAuthenticationFilter.java`, `src/main/java/com/example/hsm/config/SecurityConfig.java`, `src/main/resources/db/migration/V6__add_token_prefix.sql`
      Tests: `SecurityFilterTest` `@Tag("security")` — `missingTokenReturns401`, `invalidTokenReturns401`, `validTokenPopulatesSecurityContext`, `unknownTokenReturnsGeneric401`
      Verify: `mvn --batch-mode test -Dtest=SecurityFilterTest` → all 4 `@Tag("security")` tests pass

---

- [ ] **10. T12 — Key generation endpoint**
      **Depends on:** Tasks 2–9 (all crypto and persistence infrastructure).
      Create DTOs: `GenerateKeyRequest` (`@NotBlank String name`, `@NotNull KeyAlgorithm algorithm`, `String description`), `KeyMetadataDto` (id, name, algorithm, keyType, state, version, createdAt, createdBy — NO key bytes).
      Create `AuditService` (minimal, complete implementation in T21 — but `appendRecord` must be working here): `@Service`. `appendRecord(AuditAction, UUID keyId, AuditOutcome, HsmPrincipal)` — REQUIRED propagation for SUCCESS, REQUIRES_NEW for DENIED/ERROR. Compute `chainHash` per design section 6.1 formula.
      Create `KeyService` (`@Service @Transactional`). `generateKey(GenerateKeyRequest, HsmPrincipal)`: `@PreAuthorize("hasRole('CRYPTO_OFFICER')")`. Steps: check name uniqueness → `KeyAlreadyExistsException`; generate raw bytes via `CryptoEngine`; for asymmetric, generate `KeyPair`, serialize private and public key; wrap private key via `MasterKeyService` (treating private key bytes as the "DEK"); store `publicKeyBytes` plaintext in entity; persist `HsmKey`; audit `KEY_GENERATE SUCCESS`; zero raw key bytes in `finally`; return `KeyMetadataDto`.
      Create `KeyController` (`@RestController @RequestMapping("/api/v1/keys")`): `POST /` → `generateKey` → 201.
      Files: `src/main/java/com/example/hsm/dto/GenerateKeyRequest.java`, `src/main/java/com/example/hsm/dto/KeyMetadataDto.java`, `src/main/java/com/example/hsm/service/audit/AuditService.java`, `src/main/java/com/example/hsm/service/KeyService.java`, `src/main/java/com/example/hsm/controller/KeyController.java`
      Tests: `KeyControllerIT` — `generateAesKeyReturns201WithMetadataNoKeyBytes`, `generateRsaKeyReturns201`, `generateEcKeyReturns201`, `duplicateKeyNameReturns409`, `appClientCannotGenerateKey` `@Tag("security")`, `auditorCannotGenerateKey` `@Tag("security")`, `unauthenticatedCannotGenerateKey` `@Tag("security")`
      Verify: `mvn --batch-mode verify -Dtest=KeyControllerIT#generateAesKeyReturns201*` → passes

---

- [ ] **11. T13 — Key list and metadata endpoints**
      **Depends on:** Task 10 (`KeyService`, `KeyController`).
      Add to `KeyService`: `listKeys(HsmPrincipal)` — CryptoOfficer sees all keys; AppClient sees only keys where `HsmKeyAclRepository.findByPrincipalId(caller.id())` has an entry. `getKeyById(UUID, HsmPrincipal)` — load or throw `KeyNotFoundException`.
      Add to `KeyController`: `GET /api/v1/keys` → `listKeys` → 200 (returns `List<KeyMetadataDto>`); `GET /api/v1/keys/{id}` → `getKeyById` → 200.
      Files: `src/main/java/com/example/hsm/service/KeyService.java` (additions), `src/main/java/com/example/hsm/controller/KeyController.java` (additions)
      Tests: `KeyControllerIT` — `listKeysReturnsCryptoOfficerView`, `listKeysReturnsAppClientViewOfOwnAcl`, `getKeyByIdReturnsMetadata`, `destroyedKeyReturns410`
      Verify: `mvn --batch-mode test -Dtest=KeyControllerIT` → all list/get tests pass

---

- [ ] **12. T14 — Key state transitions (disable, enable, destroy)**
      **Depends on:** Task 11 (`KeyService` with key management).
      Add to `KeyService`: `disableKey(UUID, HsmPrincipal)` — `@PreAuthorize("hasRole('CRYPTO_OFFICER')")`: load key; reject if DESTROYED (throw `DestroyedKeyException`); set state=DISABLED, `disabledAt`; audit `KEY_DISABLE`. `enableKey(UUID, HsmPrincipal)`: load key; reject if DESTROYED; set state=ACTIVE; audit `KEY_ENABLE`. `destroyKey(UUID, HsmPrincipal)`: load key; if already DESTROYED throw `DestroyedKeyException` (HTTP 410); set state=DESTROYED; **overwrite `wrappedDek`, `ivDek`, `authTagDek` with `new byte[original.length]` (all zeros)** before save; set `destroyedAt`; audit `KEY_DESTROY`.
      Add to `KeyController`: `PATCH /api/v1/keys/{id}/disable`, `PATCH /api/v1/keys/{id}/enable`, `DELETE /api/v1/keys/{id}`.
      Files: `src/main/java/com/example/hsm/service/KeyService.java` (additions), `src/main/java/com/example/hsm/controller/KeyController.java` (additions)
      Tests: `KeyControllerIT` — `disableActiveKeyReturns200`, `enableDisabledKeyReturns200`, `destroyKeyZerosWrappedDekInDb`, `destroyAlreadyDestroyedKeyReturns410`, `disableDestroyedKeyReturns422`, `appClientCannotDisableKey` `@Tag("security")`
      Verify: `mvn --batch-mode test -Dtest=KeyControllerIT` → all state-transition tests pass; `destroyKeyZerosWrappedDekInDb` asserts column value is all zeros

---

- [ ] **13. T15 — Key rotation**
      **Depends on:** Task 12 (key state, `KeyService`).
      Add to `KeyService`: `rotateKey(UUID keyId, HsmPrincipal)` — `@PreAuthorize("hasRole('CRYPTO_OFFICER')")`. Load old key; reject if DESTROYED (`DestroyedKeyException` → 422); generate new raw key bytes of the same algorithm; wrap via `MasterKeyService`; persist new `HsmKey` entity (same `name`, new UUID id, `version = old.version + 1`, state=ACTIVE); set old key's state to DISABLED; persist old; audit `KEY_ROTATE` with new key's id; zero raw bytes in `finally`.
      Add to `KeyController`: `POST /api/v1/keys/{id}/rotate`.
      Files: `src/main/java/com/example/hsm/service/KeyService.java`, `src/main/java/com/example/hsm/controller/KeyController.java`
      Tests: `KeyControllerIT` — `rotateActiveKeyIncrementsVersion`, `rotateKeyAuditRecordWritten`, `rotateDestroyedKeyReturns422`, `oldVersionRetainedAsDisabled`
      Verify: `mvn --batch-mode test -Dtest=KeyControllerIT` → all rotation tests pass

---

- [ ] **14. T16 — Per-key ACL management**
      **Depends on:** Task 13 (`KeyService`, `HsmKeyAclRepository`).
      Add `AclRequest` DTO: `@NotNull UUID principalId`.
      Add to `KeyService`: `grantAcl(UUID keyId, UUID principalId, HsmPrincipal caller)` — `@PreAuthorize("hasRole('CRYPTO_OFFICER')")`. Load key (throw `KeyNotFoundException`); load principal user (throw `KeyNotFoundException` — or a `UserNotFoundException extends KeyNotFoundException` with 404); upsert `HsmKeyAcl` entity; audit `ACL_GRANT`. `revokeAcl(UUID keyId, UUID principalId, HsmPrincipal caller)`: delete ACL entry; audit `ACL_REVOKE`.
      Add to `KeyController`: `POST /api/v1/keys/{id}/acl`, `DELETE /api/v1/keys/{id}/acl/{principalId}`.
      Files: `src/main/java/com/example/hsm/dto/AclRequest.java`, `src/main/java/com/example/hsm/service/KeyService.java`, `src/main/java/com/example/hsm/controller/KeyController.java`
      Tests: `KeyControllerIT` — `grantAclAllowsAppClientToEncrypt`, `revokeAclBlocksAppClientEncrypt` `@Tag("security")`, `appClientCannotGrantAcl` `@Tag("security")`, `grantAclForNonExistentPrincipalReturns404`
      Verify: `mvn --batch-mode test -Dtest=KeyControllerIT` → all ACL tests pass

---

- [ ] **15. T17–T20 — Cryptographic operations API (encrypt, decrypt, sign, verify)**
      **Depends on:** Tasks 10–14 (key entities, ACL, MasterKeyService, CryptoEngine, AuditService).
      Create DTOs: `EncryptRequest`, `EncryptResponse`, `DecryptRequest`, `DecryptResponse`, `SignRequest`, `SignResponse`, `VerifyRequest`, `VerifyResponse`. All base64 fields are `String`; all key IDs are `UUID`.
      Create `CryptoService` (`@Service @Transactional`). Helper `checkKeyAndAcl(UUID keyId, UUID principalId, AuditAction action, HsmPrincipal caller)`: load key (throw `KeyNotFoundException`); if DESTROYED throw `DestroyedKeyException`; if DISABLED throw `InvalidKeyStateException`; check ACL — if no entry, appendAudit(action, keyId, DENIED, caller) then throw `AccessDeniedException`.
      `encrypt(EncryptRequest, HsmPrincipal)` — `@PreAuthorize("hasRole('APP_CLIENT')")`: call checkKeyAndAcl; unwrap DEK via `MasterKeyService`; call `CryptoEngine.encrypt`; zero DEK bytes; audit ENCRYPT SUCCESS; return `EncryptResponse` (base64-encode iv, ciphertext, authTag).
      `decrypt` — similarly, reassemble ciphertext+authTag bytes, decrypt, return plaintext base64.
      `sign` — validate key is not SYMMETRIC (throw `InvalidKeyStateException` if so); unwrap private key; deserialize; sign; zero raw private key bytes.
      `verify` — load key, check ACL; deserialize public key from `publicKeyBytes` (no unwrapping needed for public key); verify; return `VerifyResponse(valid)` — NEVER throw on invalid signature.
      Create `CryptoController` (`@RestController @RequestMapping("/api/v1/crypto")`): POST /encrypt, /decrypt, /sign, /verify.
      Files: `src/main/java/com/example/hsm/dto/` (8 DTO files), `src/main/java/com/example/hsm/service/CryptoService.java`, `src/main/java/com/example/hsm/controller/CryptoController.java`
      Tests: `CryptoControllerIT` — all 18 named tests (see tasks.md T17–T20)
      Verify: `mvn --batch-mode verify -Dtest=CryptoControllerIT` → all 18 tests pass

---

- [ ] **16. T21 — AuditService with hash chain**
      **Depends on:** Tasks 7–8 (`AuditRecord` entity, `AuditRecordRepository`), Task 10 (AuditService stub).
      Finalize `AuditService` (located at `src/main/java/com/example/hsm/service/audit/AuditService.java`). Implement or verify `appendRecord`: (1) Load previous record's `chainHash` via `findTopByOrderBySequenceNumberDesc()`; use `"0000…0"` (64 zeros) if empty; (2) Assign `recordedAt = Instant.now()` (nanosecond precision); (3) Compute `chainHash = SHA-256(prevHash|seq|ts|principalId|action|keyId|outcome)` where fields are joined with `|` as delimiter — all fields converted to strings, `null` values rendered as `"null"`; hash as hex string; (4) Build and persist `AuditRecord`. Propagation: `@Transactional(REQUIRED)` for SUCCESS, `@Transactional(REQUIRES_NEW)` for DENIED/ERROR.
      Add `getRecords(Pageable, Instant from, Instant to)` → `Page<AuditRecord>` (internal use; `AuditController` wraps into `AuditPageResponse`). Add `verifyChain()` → `AuditVerifyResult`: load all records in sequence order, re-compute each hash, return `{valid, recordCount, firstTamperedSequence}`.
      Files: `src/main/java/com/example/hsm/service/audit/AuditService.java` (finalize), `src/main/java/com/example/hsm/dto/AuditVerifyResult.java`
      Tests: `AuditServiceTest` — `firstRecordUsesZeroHash`, `consecutiveRecordsFormValidChain`, `chainHashIsDetError`, `deniedOperationIsAuditedEvenWhenPrimaryTxRollsBack`
      Verify: `mvn --batch-mode test -Dtest=AuditServiceTest` → all 4 tests pass

---

- [ ] **17. T22 — Audit log read endpoint**
      **Depends on:** Task 16 (complete `AuditService`).
      Create DTOs `AuditRecordDto`, `AuditPageResponse`. Add to `AuditService`: `getRecords(Pageable, Instant from, Instant to, HsmPrincipal)` — `@PreAuthorize("hasRole('AUDITOR')")`: call repository; map to DTOs; also append `AUDIT_READ` audit record for the caller.
      Create `AuditController` (`@RestController @RequestMapping("/api/v1/audit")`): `GET /` with query params `page`, `size`, `from` (ISO-8601), `to` (ISO-8601) → `AuditPageResponse` 200.
      Files: `src/main/java/com/example/hsm/dto/AuditRecordDto.java`, `src/main/java/com/example/hsm/dto/AuditPageResponse.java`, `src/main/java/com/example/hsm/service/audit/AuditService.java` (getRecords addition), `src/main/java/com/example/hsm/controller/AuditController.java`
      Tests: `AuditControllerIT` — `auditorCanReadLog`, `appClientCannotReadLog` `@Tag("security")`, `paginationWorksCorrectly`, `dateRangeFilterReturnsCorrectRecords`, `auditReadEventIsItselfAudited`
      Verify: `mvn --batch-mode test -Dtest=AuditControllerIT#auditorCanReadLog+appClientCannotReadLog+paginationWorksCorrectly` → pass

---

- [ ] **18. T23 — Audit log integrity verification endpoint**
      **Depends on:** Task 17 (`AuditService.verifyChain()`, `AuditController`).
      Add `GET /api/v1/audit/verify` to `AuditController` → calls `AuditService.verifyChain()` → returns `AuditVerifyResult` 200.
      Files: `src/main/java/com/example/hsm/controller/AuditController.java` (addition), `src/main/java/com/example/hsm/dto/AuditVerifyResult.java` (if not created in T21)
      Tests: `AuditControllerIT` — `verifyIntactLogReturnsValid`, `verifyTamperedRecordDetected` (directly update `chain_hash` via JDBC template in test), `verifyTamperedFieldDetected` (update `action` field), `verifyEmptyLogReturnsValid`
      Verify: `mvn --batch-mode test -Dtest=AuditControllerIT` → all 9 tests pass

---

- [ ] **19. T24 — User creation and token issuance**
      **Depends on:** Tasks 8–9 (`HsmUser`, `TokenService`, exception hierarchy).
      Create DTOs: `CreateUserRequest`, `CreateUserResponse` (includes `token` and `warning` — token shown once), `UserDto` (no token).
      Create `UserService` (`@Service @Transactional`). `createUser(CreateUserRequest, HsmPrincipal)` — `@PreAuthorize("hasRole('ADMIN')")`: check username uniqueness; `generateToken()` → plain token; `hashToken(plain)` → stored hash; extract `tokenPrefix` (first 16 chars of plain token); persist `HsmUser(username, tokenHash, tokenPrefix, role, enabled=true)`; audit `USER_CREATE`; return `CreateUserResponse` with plain token (logged nowhere). `listUsers(HsmPrincipal)` — `@PreAuthorize("hasRole('ADMIN')")`: return `List<UserDto>` (no token).
      Create `UserController` (`@RestController @RequestMapping("/api/v1/users")`): `POST /` → `createUser` 201; `GET /` → `listUsers` 200.
      Files: DTOs, `src/main/java/com/example/hsm/service/UserService.java`, `src/main/java/com/example/hsm/controller/UserController.java`
      Tests: `UserControllerIT` — `adminCreatesUserAndReceivesOneTimeToken`, `tokenIsShownOnce`, `createdTokenCanAuthenticateImmediately`, `nonAdminCannotCreateUser` `@Tag("security")`, `duplicateUsernameReturns409`
      Verify: `mvn --batch-mode test -Dtest=UserControllerIT#adminCreatesUserAndReceivesOneTimeToken+tokenIsShownOnce+createdTokenCanAuthenticateImmediately` → pass

---

- [ ] **20. T25 — Role assignment and user disable**
      **Depends on:** Task 19 (`UserService`, `UserController`).
      Add to `UserService`: `assignRole(UUID userId, UserRole newRole, HsmPrincipal)` — `@PreAuthorize("hasRole('ADMIN')")`: load user; update role; audit `ROLE_ASSIGN`. `revokeRole(UUID userId, UserRole roleToRevoke, HsmPrincipal)`: for the single-role model, revoking a role disables the user or sets role to null (choose: set role=null and enabled=false to prevent login, audit `ROLE_REVOKE`). `disableUser(UUID userId, HsmPrincipal)`: set enabled=false; audit `USER_DISABLE`. Update `TokenAuthenticationFilter` to also check `user.enabled` at token resolution time.
      Add to `UserController`: `POST /api/v1/users/{id}/roles/{role}`, `DELETE /api/v1/users/{id}/roles/{role}`, `DELETE /api/v1/users/{id}`.
      Files: `src/main/java/com/example/hsm/service/UserService.java` (additions), `src/main/java/com/example/hsm/controller/UserController.java` (additions), `src/main/java/com/example/hsm/security/TokenAuthenticationFilter.java` (enabled check)
      Tests: `UserControllerIT` — `adminAssignsRole`, `adminRevokesRole`, `adminDisablesUser`, `nonAdminCannotRevokeRole` `@Tag("security")`
      Verify: `mvn --batch-mode test -Dtest=UserControllerIT` → all 9 tests pass

---

- [ ] **21. T26–T30 — Security hardening and threat-model tests**
      **Depends on:** Tasks 10–20 (all features complete).
      Write the following dedicated security test classes (all in `src/test/java/com/example/hsm/security/`):

      **T26** — `AuthenticationServiceTest` `@Tag("security")`: `falseTokenIsRejected`, `truncatedTokenReturns401`, `tokenForDisabledUserReturns401`, `noTokenReturns401`, `emptyBearerReturns401`. Assert all 5 cases return HTTP 401 with IDENTICAL response body. Verify `TokenAuthenticationFilter` uses `MessageDigest.isEqual` (constant-time comparison).

      **T27** — `AuditIntegrityTest` `@Tag("security")`: `tamperedRecordIsDetected` (update `chain_hash` column via JDBC → `GET /audit/verify` returns `valid=false`), `insertedRecordIsDetected` (insert record with forged hash into DB → chain breaks), `deletedRecordIsDetected` (delete a middle record via JDBC → chain breaks).

      **T28** — `CryptoServiceIT` `@Tag("security")`: `tamperedWrappedDekIsRejected` (unit — already in T05), `tamperedStoredDekCausesDecryptionFailure` (flip one byte in `hsm_keys.wrapped_dek` via JDBC, then call `POST /crypto/decrypt` → expect 400).

      **T29** — `RbacEnforcementTest` `@Tag("security")`: `appClientCannotGenerateKey`, `appClientCannotRotateKey`, `appClientCannotDestroyKey`, `appClientCannotGrantAcl`, `cryptoOfficerCannotEncrypt`, `cryptoOfficerCannotReadAuditLog`, `adminCannotGenerateKey`, `adminCannotEncrypt`, `auditorCannotGenerateKey`, `auditorCannotEncrypt`. Also `AclEnforcementTest`: `appClientWithoutAclIsRejected`, `appClientAfterAclRevocationIsRejected`.

      **T30** — `KeyStateGuardTest` `@Tag("security")`: `disabledKeyRejectsEncrypt`, `disabledKeyRejectsSign`, `destroyedKeyRejectsAllCryptoOps`, `destroyedKeyRejectsDisable`, `destroyedKeyRejectsRotate`.

      Files: `src/test/java/com/example/hsm/security/AuthenticationServiceTest.java`, `AuditIntegrityTest.java`, `CryptoServiceIT.java`, `RbacEnforcementTest.java`, `AclEnforcementTest.java`, `KeyStateGuardTest.java`
      Verify: `mvn --batch-mode verify -Dgroups=security` → all 25+ `@Tag("security")` tests pass

---

- [ ] **22. T31 — OpenAPI annotations and Swagger UI**
      **Depends on:** Tasks 10–20 (all controllers in place).
      Add `@Operation`, `@ApiResponse`, `@Parameter`, `@Schema` annotations to all controllers and DTOs. Create `OpenApiConfig` (`@Configuration`): `@Bean OpenAPI` with title "Software HSM Emulator API", version "0.1.0", disclaimer description, bearer auth security scheme. Add `springdoc.*` config to `application.yml`.
      Files: `src/main/java/com/example/hsm/config/OpenApiConfig.java`, all 4 controller files (add annotations), all DTO files (add `@Schema`)
      Tests: `OpenApiTest` — `allEndpointsAppearInApiDocs` (GET `/v3/api-docs`, assert paths present for all 8 endpoint groups)
      Verify: `mvn --batch-mode test -Dtest=OpenApiTest` → passes; `mvn spring-boot:run` → `http://localhost:8080/swagger-ui.html` loads

---

- [ ] **23. T32 — Javadoc on all public service and repository interfaces**
      **Depends on:** Task 22 (all classes exist).
      Add Javadoc to every `@Service` method and every `Repository` interface method. Key doc requirements: `MasterKeyService.wrapKey` — "Raw key bytes are zeroed after wrapping"; `CryptoEngine.decrypt` — "Throws CryptographicOperationException on GCM authentication tag failure; does not reveal which component failed"; `CryptoService.encrypt` — "Raw DEK bytes are zeroed immediately after use". Add `maven-javadoc-plugin` with `<failOnWarnings>true</failOnWarnings>` and `<doclint>all,-missing</doclint>` (allow missing on private methods, fail on public).
      Files: All service files, all repository files, `pom.xml` (javadoc plugin)
      Verify: `mvn javadoc:javadoc` → zero warnings

---

- [ ] **24. T33–T34 — Final CI gate and coverage verification**
      **Depends on:** All previous tasks.
      Run `mvn --batch-mode verify` and confirm: JaCoCo line ≥ 80%, branch ≥ 75%. If below threshold, add targeted tests for uncovered branches. Confirm all `@Tag("security")` tests run in Surefire/Failsafe. Run `mvn dependency-check:check` — zero HIGH/CRITICAL CVEs. Update `README.md` project structure section if needed. Add JaCoCo coverage badge. Create git tag `v0.1.0` on `main` after CI is green.
      Files: `README.md` (badge), `.github/workflows/ci.yml` (verify security-tag step added), possibly additional unit tests if coverage is below gate
      Verify: `mvn --batch-mode verify` → BUILD SUCCESS, JaCoCo gate passes, dependency-check passes

---

## Ordering Constraints Summary

```
T01 (scaffold) → T04 (MasterKeyService) → T05 (CryptoEngine AES) → T06 (CryptoEngine RSA/EC)
T01 → T07 (Flyway V2-V5)
T07 → T08 (entities + repos) → T09 (exceptions)
T01 → T10 (TokenService)
T07+T10 → T11 (SecurityConfig, TokenFilter)
T04+T05+T06+T08+T09+T11 → T12 (KeyService + KeyController generate)
T12 → T13 → T14 → T15 → T16 (key lifecycle)
T12 → T17–T20 (CryptoService + CryptoController)
T08+T12 → T21 (AuditService finalize) → T22 → T23 (audit endpoints)
T08+T10+T11 → T24 → T25 (UserService + UserController)
T12–T25 all done → T26–T30 (security hardening tests)
T26–T30 done → T31 (OpenAPI) → T32 (Javadoc) → T33–T34 (CI gate)
```

---

## FEAT Decomposition

The 34 tasks decompose into 5 sequentially-dependent FEATs under `g:\hsm\.agents\tasks\task-hsm-emulator\features\`:

| FEAT | Tasks | Description |
|------|-------|-------------|
| FEAT-001 | T01–T03 | Project scaffold — pom.xml, Docker Compose, AbstractIntegrationTest, CI |
| FEAT-002 | T04–T11 | Core crypto engine + persistence + authentication |
| FEAT-003 | T12–T20 | Key lifecycle API + cryptographic operations API |
| FEAT-004 | T21–T30 | Audit log + user/role management + security hardening tests |
| FEAT-005 | T31–T34 | OpenAPI docs, Javadoc, CI gate, README polish |

Each FEAT's full step-by-step detail, acceptance criteria, and verification commands are in the corresponding JSON file under `features/`.
