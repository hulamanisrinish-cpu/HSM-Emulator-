# Tasks — Software HSM Emulator
> Scope: ~2 calendar weeks, one student.
> Every task is traceable to a requirement in `requirements.md` and ships with
> at least one test. Tasks are ordered so each builds cleanly on the previous one.
> Mark tasks `[x]` as you complete them.

---

## Progress Snapshot

| Phase | Tasks | Estimated Days |
|-------|-------|----------------|
| 0 — Project Scaffold | T01–T03 | 0.5 |
| 1 — Core Crypto Engine | T04–T06 | 1.5 |
| 2 — Persistence Layer | T07–T09 | 1 |
| 3 — Authentication | T10–T11 | 1 |
| 4 — Key Lifecycle API | T12–T16 | 2 |
| 5 — Cryptographic Operations API | T17–T20 | 1.5 |
| 6 — Audit Log | T21–T23 | 1.5 |
| 7 — User & Role Management API | T24–T25 | 1 |
| 8 — Security Hardening & Threat-Model Tests | T26–T30 | 1.5 |
| 9 — Docs, CI, and Polish | T31–T34 | 1 |
| **Total** | **34 tasks** | **~13 days** |

---

## Phase 0 — Project Scaffold

### T01 — Initialize Maven project
**Requirement:** NFR-06 (build), NFR-03 (testability)  
**Test:** `mvn verify` on a fresh clone produces a successful build with zero test failures.

- [ ] Run Spring Initializr (or manually create `pom.xml`) with:
  - `spring-boot-starter-web`
  - `spring-boot-starter-data-jpa`
  - `spring-boot-starter-security`
  - `springdoc-openapi-starter-webmvc-ui:2.x`
  - `postgresql` driver
  - `bcprov-jdk18on` (Bouncy Castle — Argon2id only)
  - `testcontainers` BOM + `postgresql` module
  - `junit-jupiter`, `mockito-core`
  - `jacoco-maven-plugin`
  - `maven-failsafe-plugin` (integration tests)
- [ ] Set Java source/target to 17 in `pom.xml`.
- [ ] Pin all dependency versions; no open ranges.
- [ ] Configure JaCoCo `check` goal: line ≥ 80 %, branch ≥ 75 %.
- [ ] Add `.gitignore` (Maven targets, IDE files, `*.env`).

---

### T02 — Docker Compose and local database setup
**Requirement:** A1, A3, A6, NFR-06  
**Test:** `docker compose up -d db` starts Postgres; `mvn spring-boot:run` connects and logs "Started HsmApplication".

- [ ] Create `docker-compose.yml` with `postgres:15-alpine` service, named volume, and env vars (`POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`).
- [ ] Add `application.yml` with datasource pointing to `localhost:5432`, JPA `validate` DDL-auto, Flyway enabled.
- [ ] Add `application-test.yml` that disables Flyway (Testcontainers + `create-drop` for tests).
- [ ] Create `AbstractIntegrationTest` with `@Testcontainers` shared `PostgreSQLContainer` and `@DynamicPropertySource`.

---

### T03 — GitHub Actions CI skeleton
**Requirement:** NFR-06  
**Test:** Push to a branch triggers the workflow; it passes on a repo with only scaffold code.

- [ ] Create `.github/workflows/ci.yml`:
  - Trigger on `push` and `pull_request`.
  - `actions/setup-java@v4` with Temurin 17.
  - Maven cache on `pom.xml` hash.
  - `mvn --batch-mode verify` step.
  - Upload JaCoCo HTML report as artifact.
- [ ] Add OWASP Dependency-Check Maven plugin; add a CI step that fails on HIGH/CRITICAL CVEs (threshold configurable).

---

## Phase 1 — Core Crypto Engine

### T04 — MasterKeyService (PBKDF2 key derivation)
**Requirement:** FR-03, NFR-01  
**Tests:**
- `MasterKeyServiceTest#samePassphraseAndSaltProducesSameKey` — determinism.
- `MasterKeyServiceTest#differentSaltProducesDifferentKey` — salt uniqueness.
- `MasterKeyServiceTest#missingPassphraseEnvVarFailsFast` — startup guard.
- `MasterKeyServiceTest#iterationCountBelowMinimumFailsFast` — security guard.

- [ ] Create `MasterKeyService` (Spring `@Component`, `@PostConstruct` init).
  - Read passphrase from `HSM_MASTER_PASSPHRASE` env var; throw `HsmInternalException` with a safe message if absent.
  - Generate random 16-byte salt on first startup; persist to `hsm_config` table (key = `master_key_salt`).
  - Load existing salt on subsequent startups.
  - Derive 256-bit `SecretKey` using `PBKDF2WithHmacSHA256`, iterations ≥ 310,000.
  - Fail fast if configured iterations < 310,000.
  - Expose `wrapKey(byte[] rawKeyBytes)` → `WrappedKey(byte[] wrappedDek, byte[] iv, byte[] authTag)`.
  - Expose `unwrapKey(WrappedKey)` → `byte[]`; zeros input `wrappedDek` array after use.
- [ ] Create `HsmConfig` JPA entity and `HsmConfigRepository`.
- [ ] Apply Flyway migration `V1__create_hsm_config.sql`.

---

### T05 — CryptoEngine — symmetric (AES-256-GCM)
**Requirement:** FR-02 (AES-256), FR-04  
**Tests:**
- `CryptoEngineTest#aesEncryptDecryptRoundTrip` — correct plaintext recovered.
- `CryptoEngineTest#eachEncryptCallUsesUniqueIv` — IV randomness.
- `CryptoEngineTest#tamperedCiphertextThrowsCryptographicOperationException` — GCM auth.
- `CryptoEngineTest#tamperedAuthTagThrowsException` — GCM auth.
- `CryptoEngineTest#tamperedWrappedDekIsRejected` — wrapping integrity.

- [ ] Create `CryptoEngine` (Spring `@Component`, stateless).
- [ ] `generateSymmetricKey()` → `byte[]` 32 bytes via `KeyGenerator("AES", 256, SecureRandom)`.
- [ ] `encrypt(byte[] rawKey, byte[] plaintext)` → `EncryptionResult(byte[] iv, byte[] ciphertext, byte[] authTag)`.
  - Fresh 12-byte IV from `SecureRandom` per call.
  - `Cipher("AES/GCM/NoPadding")`.
  - GCM tag length 128 bits.
- [ ] `decrypt(byte[] rawKey, byte[] iv, byte[] ciphertext, byte[] authTag)` → `byte[]`.
  - On `AEADBadTagException` wrap in `CryptographicOperationException`.
- [ ] Zero all intermediate `byte[]` arrays (raw key, plaintext) after use in a `finally` block.

---

### T06 — CryptoEngine — asymmetric (RSA-2048, EC P-256)
**Requirement:** FR-02 (RSA, EC), FR-05  
**Tests:**
- `CryptoEngineTest#rsaSignVerifyRoundTrip`
- `CryptoEngineTest#ecSignVerifyRoundTrip`
- `CryptoEngineTest#invalidSignatureReturnsFalseNotException`
- `CryptoEngineTest#symmetricKeyRejectedForSignOperation`

- [ ] `generateAsymmetricKeyPair(algorithm)` → `KeyPair` (RSA-2048 or EC P-256).
- [ ] `sign(byte[] privateKeyBytes, byte[] data, String algorithm)` → `byte[]` signature.
  - RSA: `SHA256withRSA`; EC: `SHA256withECDSA`.
- [ ] `verify(byte[] publicKeyBytes, byte[] data, byte[] signature, String algorithm)` → `boolean`.
  - Catch `SignatureException`; return `false` (non-throwing).
- [ ] Helper: serialize/deserialize `PublicKey` / `PrivateKey` to/from `byte[]` using `X509EncodedKeySpec` / `PKCS8EncodedKeySpec`.

---

## Phase 2 — Persistence Layer

### T07 — Database schema (Flyway migrations)
**Requirement:** FR-01, FR-06, FR-08, A3  
**Test:** `AbstractIntegrationTest` application context loads without errors; all tables exist via `@DataJpaTest`.

- [ ] `V2__create_hsm_users.sql` — `hsm_users` table (id UUID PK, username UK, token_hash, role, created_at, enabled).
- [ ] `V3__create_hsm_keys.sql` — `hsm_keys` table (all columns from data model; `key_state` varchar with check constraint).
- [ ] `V4__create_hsm_key_acls.sql` — `hsm_key_acls` table (composite UK on `key_id, principal_id`).
- [ ] `V5__create_hsm_audit_log.sql` — `hsm_audit_log` table (sequence_number bigserial PK, indexes on `recorded_at` and `principal_id`).
- [ ] Add DB-level `NOT NULL` and `CHECK` constraints matching entity validation.

---

### T08 — JPA entities and repositories
**Requirement:** FR-01 through FR-09  
**Tests:**
- `HsmKeyRepositoryTest#findByNameReturnsKey`
- `HsmKeyRepositoryTest#findByStateReturnsOnlyActiveKeys`
- `HsmKeyAclRepositoryTest#findByKeyAndPrincipalReturnsAcl`
- `AuditLogRepositoryTest#findByDateRangeReturnsPaginatedResults`

- [ ] `HsmUser` entity: id, username, tokenHash, role (`@Enumerated STRING`), createdAt, enabled.
- [ ] `HsmKey` entity: id, name, algorithm, keyState, version, wrappedDek, ivDek, authTagDek, keyType, createdBy, createdAt, lastRotatedAt, disabledAt, destroyedAt.
  - `wrappedDek` field: `@Column(columnDefinition = "bytea")`.
  - Override `toString()` to exclude `wrappedDek`.
- [ ] `HsmKeyAcl` entity: id, key (ManyToOne), principal (ManyToOne), permission, grantedAt, grantedBy.
- [ ] `AuditRecord` entity: sequenceNumber (auto), id, recordedAt, principalId, action, keyId, outcome, chainHash.
- [ ] `HsmUserRepository`, `HsmKeyRepository`, `HsmKeyAclRepository`, `AuditRecordRepository` — Spring Data JPA interfaces with JPQL named queries.

---

### T09 — Exception hierarchy and global error handler
**Requirement:** FR-06, NFR-01 (no key material in responses), design section 7  
**Tests:**
- `GlobalExceptionHandlerTest#accessDeniedReturns403WithStandardEnvelope`
- `GlobalExceptionHandlerTest#keyNotFoundReturns404`
- `GlobalExceptionHandlerTest#noStackTraceInResponse`
- `GlobalExceptionHandlerTest#genericInternalErrorHidesDetails`

- [ ] Create exception classes: `HsmException`, `AuthenticationException`, `AccessDeniedException`, `KeyNotFoundException`, `KeyAlreadyExistsException`, `InvalidKeyStateException`, `CryptographicOperationException`, `HsmInternalException`.
- [ ] Create `ErrorResponse` DTO with `timestamp`, `status`, `error`, `message`, `path`.
- [ ] Create `@RestControllerAdvice GlobalExceptionHandler` — map each exception to HTTP status and `ErrorResponse`. Never serialize stack trace. Never include raw key bytes in message.

---

## Phase 3 — Authentication

### T10 — API token generation and Argon2id hashing
**Requirement:** FR-09, NFR-01, T1 (threat model)  
**Tests:**
- `TokenServiceTest#generatedTokenHasExpectedPrefix`
- `TokenServiceTest#hashAndVerifyRoundTrip`
- `TokenServiceTest#differentTokensProduceDifferentHashes`
- `TokenServiceTest#timingAttackResistance` — constant-time comparison (verify `MessageDigest.isEqual` or Bouncy Castle equivalent is used).

- [ ] Create `TokenService`:
  - `generateToken()` → `String` (prefix `hsm_tk_` + 32 random bytes base64url-encoded).
  - `hashToken(String token)` → `String` (Argon2id via Bouncy Castle, parameters: memory 65536 KB, iterations 3, parallelism 4 — OWASP 2024 defaults).
  - `verifyToken(String token, String hash)` → `boolean` (constant-time).
- [ ] Do NOT log plain-text tokens anywhere.

---

### T11 — Spring Security token authentication filter
**Requirement:** FR-06, FR-09, T1 (threat)  
**Tests:**
- `SecurityFilterTest#missingTokenReturns401`
- `SecurityFilterTest#invalidTokenReturns401`
- `SecurityFilterTest#validTokenPopulatesSecurityContext`
- `SecurityFilterTest#unknownTokenReturnsGeneric401` — no oracle (same response for "bad token" vs "unknown user").

- [ ] Create `TokenAuthenticationFilter extends OncePerRequestFilter`:
  - Extract `Authorization: Bearer <token>` header.
  - Look up user by resolving hash; on miss return 401.
  - Populate `SecurityContextHolder` with `UsernamePasswordAuthenticationToken` (principal, role as `GrantedAuthority`).
- [ ] Create `SecurityConfig (@Configuration)`:
  - Disable CSRF (stateless REST API).
  - Register filter before `UsernamePasswordAuthenticationFilter`.
  - Permit `GET /v3/api-docs/**`, `GET /swagger-ui/**` without auth.
  - All other paths require authentication.
- [ ] Enable method security: `@EnableMethodSecurity`.

---

## Phase 4 — Key Lifecycle API

### T12 — Key generation endpoint
**Requirement:** FR-02, FR-03, FR-06, US-01  
**Tests:**
- `KeyControllerIT#generateAesKeyReturns201WithMetadataNoKeyBytes`
- `KeyControllerIT#generateRsaKeyReturns201`
- `KeyControllerIT#generateEcKeyReturns201`
- `KeyControllerIT#duplicateKeyNameReturns409`
- `KeyControllerIT#appClientCannotGenerateKey` — `@Tag("security")`
- `KeyControllerIT#auditorCannotGenerateKey` — `@Tag("security")`
- `KeyControllerIT#unauthenticatedCannotGenerateKey` — `@Tag("security")`

- [ ] Create `GenerateKeyRequest` DTO (name, algorithm, description) with `@Valid` constraints.
- [ ] Create `KeyMetadataDto` (id, name, algorithm, keyType, state, version, createdAt, createdBy — **no wrappedDek**).
- [ ] Create `KeyService#generateKey(GenerateKeyRequest, HsmPrincipal)`:
  - `@PreAuthorize("hasRole('CRYPTO_OFFICER')")`.
  - Generate raw key bytes via `CryptoEngine`.
  - Wrap via `MasterKeyService`.
  - Persist `HsmKey` entity.
  - Append audit record (`KEY_GENERATE`, `SUCCESS`).
  - Zero raw key bytes in `finally`.
- [ ] Create `KeyController` with `POST /api/v1/keys`.

---

### T13 — Key list and metadata endpoints
**Requirement:** FR-01, US-01 (implied), role-permission matrix  
**Tests:**
- `KeyControllerIT#listKeysReturnsCryptoOfficerView`
- `KeyControllerIT#listKeysReturnsAppClientViewOfOwnAcl`
- `KeyControllerIT#getKeyByIdReturnsMetadata`
- `KeyControllerIT#destroyedKeyReturns410`

- [ ] `KeyService#listKeys(HsmPrincipal)` — CryptoOfficer sees all; AppClient sees only keys with an ACL entry.
- [ ] `KeyService#getKeyById(UUID, HsmPrincipal)`.
- [ ] `KeyController`: `GET /api/v1/keys`, `GET /api/v1/keys/{id}`.

---

### T14 — Key state transitions (disable, enable, destroy)
**Requirement:** FR-01, FR-03 (destroy zeroing), US-03, US-04  
**Tests:**
- `KeyControllerIT#disableActiveKeyReturns200`
- `KeyControllerIT#enableDisabledKeyReturns200`
- `KeyControllerIT#destroyKeyZerosWrappedDekInDb` — verify `wrappedDek` is all zeros after destroy.
- `KeyControllerIT#destroyAlreadyDestroyedKeyReturns410`
- `KeyControllerIT#disableDestroyedKeyReturns422`
- `KeyControllerIT#appClientCannotDisableKey` — `@Tag("security")`

- [ ] `KeyService#disableKey(UUID, HsmPrincipal)`, `enableKey`, `destroyKey`.
  - `destroyKey`: overwrite `wrappedDek`, `ivDek`, `authTagDek` with zero arrays before saving.
- [ ] `KeyController`: `PATCH /api/v1/keys/{id}/disable`, `PATCH /api/v1/keys/{id}/enable`, `DELETE /api/v1/keys/{id}`.
- [ ] Audit records for each transition.

---

### T15 — Key rotation
**Requirement:** FR-01, US-02  
**Tests:**
- `KeyControllerIT#rotateActiveKeyIncrementsVersion`
- `KeyControllerIT#rotateKeyAuditRecordWritten`
- `KeyControllerIT#rotateDestroyedKeyReturns422`
- `KeyControllerIT#oldVersionRetainedAsDisabled`

- [ ] `KeyService#rotateKey(UUID, HsmPrincipal)`:
  - Generate a new key of the same algorithm; set version = current + 1.
  - Set old key entity's state to `DISABLED` (retained for legacy decryption).
  - Persist new key entity (same `name`, new `id`).
  - Audit `KEY_ROTATE`.
- [ ] `KeyController`: `POST /api/v1/keys/{id}/rotate`.

---

### T16 — Per-key ACL management
**Requirement:** FR-07, US-09  
**Tests:**
- `KeyControllerIT#grantAclAllowsAppClientToEncrypt`
- `KeyControllerIT#revokeAclBlocksAppClientEncrypt` — `@Tag("security")`
- `KeyControllerIT#appClientCannotGrantAcl` — `@Tag("security")`
- `KeyControllerIT#grantAclForNonExistentPrincipalReturns404`

- [ ] `HsmKeyAcl` entity: permission field (`ALLOW`).
- [ ] `KeyService#grantAcl(UUID keyId, UUID principalId, HsmPrincipal caller)`.
- [ ] `KeyService#revokeAcl(UUID keyId, UUID principalId, HsmPrincipal caller)`.
- [ ] `KeyController`: `POST /api/v1/keys/{id}/acl`, `DELETE /api/v1/keys/{id}/acl/{principalId}`.
- [ ] Audit `ACL_GRANT` and `ACL_REVOKE`.

---

## Phase 5 — Cryptographic Operations API

### T17 — Encrypt endpoint
**Requirement:** FR-04, FR-07, US-05  
**Tests:**
- `CryptoControllerIT#encryptWithValidAclReturns200`
- `CryptoControllerIT#encryptWithoutAclReturns403` — `@Tag("security")`
- `CryptoControllerIT#encryptWithDisabledKeyReturns422`
- `CryptoControllerIT#encryptWithDestroyedKeyReturns410`
- `CryptoControllerIT#cryptoOfficerCannotEncrypt` — `@Tag("security")`
- `CryptoControllerIT#ivIsUniquePerEncryptCall`

- [ ] `EncryptRequest` DTO: `keyId` (UUID), `plaintext` (base64).
- [ ] `EncryptResponse` DTO: `keyId`, `keyVersion`, `algorithm`, `iv` (base64), `ciphertext` (base64), `authTag` (base64).
- [ ] `CryptoService#encrypt(EncryptRequest, HsmPrincipal)`:
  - `@PreAuthorize("hasRole('APP_CLIENT')")`.
  - Check key state; check ACL.
  - Unwrap DEK; encrypt; zero DEK bytes.
  - Audit `ENCRYPT SUCCESS` or `ENCRYPT DENIED`.
- [ ] `CryptoController`: `POST /api/v1/crypto/encrypt`.

---

### T18 — Decrypt endpoint
**Requirement:** FR-04, FR-07, US-06  
**Tests:**
- `CryptoControllerIT#decryptRoundTripRecoversMPlaintext`
- `CryptoControllerIT#tamperedCiphertextReturns400`
- `CryptoControllerIT#tamperedAuthTagReturns400`
- `CryptoControllerIT#decryptWithoutAclReturns403` — `@Tag("security")`
- `CryptoControllerIT#decryptWithDisabledKeyReturns422`

- [ ] `DecryptRequest` DTO: `keyId`, `iv` (base64), `ciphertext` (base64), `authTag` (base64).
- [ ] `DecryptResponse` DTO: `keyId`, `plaintext` (base64).
- [ ] `CryptoService#decrypt(DecryptRequest, HsmPrincipal)`.
- [ ] `CryptoController`: `POST /api/v1/crypto/decrypt`.

---

### T19 — Sign endpoint
**Requirement:** FR-05, FR-07, US-07  
**Tests:**
- `CryptoControllerIT#signWithRsaKeyReturns200`
- `CryptoControllerIT#signWithEcKeyReturns200`
- `CryptoControllerIT#signWithSymmetricKeyReturns422`
- `CryptoControllerIT#signWithoutAclReturns403` — `@Tag("security")`

- [ ] `SignRequest` DTO: `keyId`, `data` (base64).
- [ ] `SignResponse` DTO: `keyId`, `algorithm`, `signature` (base64).
- [ ] `CryptoService#sign(SignRequest, HsmPrincipal)`.
- [ ] `CryptoController`: `POST /api/v1/crypto/sign`.

---

### T20 — Verify endpoint
**Requirement:** FR-05, FR-07, US-08  
**Tests:**
- `CryptoControllerIT#verifyValidSignatureReturnsTrue`
- `CryptoControllerIT#verifyInvalidSignatureReturnsFalseNot4xx`
- `CryptoControllerIT#verifyWithoutAclReturns403` — `@Tag("security")`

- [ ] `VerifyRequest` DTO: `keyId`, `data` (base64), `signature` (base64).
- [ ] `VerifyResponse` DTO: `keyId`, `valid` (boolean).
- [ ] `CryptoService#verify(VerifyRequest, HsmPrincipal)`.
- [ ] `CryptoController`: `POST /api/v1/crypto/verify`.

---

## Phase 6 — Audit Log

### T21 — AuditService with hash chain
**Requirement:** FR-08, DD-05 (design decision)  
**Tests:**
- `AuditServiceTest#firstRecordUsesZeroHash`
- `AuditServiceTest#consecutiveRecordsFormValidChain`
- `AuditServiceTest#chainHashIsDetError` — change one field, verify hash changes.
- `AuditServiceTest#deniedOperationIsAuditedEvenWhenPrimaryTxRollsBack`

- [ ] `AuditService#appendRecord(String action, UUID keyId, String outcome, HsmPrincipal principal)`:
  - `@Transactional(propagation = REQUIRED)` for SUCCESS path (same TX as operation).
  - `@Transactional(propagation = REQUIRES_NEW)` for DENIED/ERROR path (own TX so it commits even when primary rolls back).
  - Compute `chainHash` as described in design section 6.
  - Assign `sequenceNumber` via DB sequence (atomic).
- [ ] `AuditRecord` hash computation utility: `SHA-256(prev | seq | ts | principal | action | keyId | outcome)`, fields joined with `|`.

---

### T22 — Audit log read endpoint
**Requirement:** FR-08, US-10  
**Tests:**
- `AuditControllerIT#auditorCanReadLog`
- `AuditControllerIT#appClientCannotReadLog` — `@Tag("security")`
- `AuditControllerIT#paginationWorksCorrectly`
- `AuditControllerIT#dateRangeFilterReturnsCorrectRecords`
- `AuditControllerIT#auditReadEventIsItselfAudited`

- [ ] `AuditService#getRecords(Pageable, Instant from, Instant to)` → `Page<AuditRecordDto>`.
- [ ] `AuditController`: `GET /api/v1/audit?page&size&from&to`.
  - `@PreAuthorize("hasRole('AUDITOR')")`.
  - Each read appends an `AUDIT_READ` record.

---

### T23 — Audit log integrity verification endpoint
**Requirement:** FR-08, US-11, T2 (threat)  
**Tests:**
- `AuditControllerIT#verifyIntactLogReturnsValid`
- `AuditControllerIT#verifyTamperedRecordDetected` — directly update a `chain_hash` in DB, then call verify.
- `AuditControllerIT#verifyTamperedFieldDetected` — update a non-hash field, then call verify.
- `AuditControllerIT#verifyEmptyLogReturnsValid`

- [ ] `AuditService#verifyChain()` → `AuditVerifyResult(valid, recordCount, firstTamperedSequence)`.
- [ ] `AuditController`: `GET /api/v1/audit/verify`.

---

## Phase 7 — User and Role Management API

### T24 — User creation and token issuance
**Requirement:** FR-09, US-12, FR-06  
**Tests:**
- `UserControllerIT#adminCreatesUserAndReceivesOneTimeToken`
- `UserControllerIT#tokenIsShownOnce` — second GET of user does not return token.
- `UserControllerIT#createdTokenCanAuthenticateImmediately`
- `UserControllerIT#nonAdminCannotCreateUser` — `@Tag("security")`
- `UserControllerIT#duplicateUsernameReturns409`

- [ ] `CreateUserRequest` DTO: `username`, `role`.
- [ ] `CreateUserResponse` DTO: `id`, `username`, `role`, `token`, `warning`.
- [ ] `UserService#createUser(CreateUserRequest, HsmPrincipal)`:
  - `@PreAuthorize("hasRole('ADMIN')")`.
  - Generate token via `TokenService#generateToken`.
  - Hash token via `TokenService#hashToken`.
  - Persist `HsmUser` with hashed token; return plain token once.
  - Audit `USER_CREATE`.
- [ ] `UserController`: `POST /api/v1/users`, `GET /api/v1/users`.

---

### T25 — Role assignment and user disable
**Requirement:** FR-06, US-12  
**Tests:**
- `UserControllerIT#adminAssignsRole`
- `UserControllerIT#adminRevokesRole` — user cannot use revoked-role endpoints.
- `UserControllerIT#adminDisablesUser` — disabled user's token returns 401.
- `UserControllerIT#nonAdminCannotRevokeRole` — `@Tag("security")`

- [ ] `UserService#assignRole`, `UserService#revokeRole`, `UserService#disableUser`.
- [ ] `UserController`: `POST /api/v1/users/{id}/roles/{role}`, `DELETE /api/v1/users/{id}/roles/{role}`, `DELETE /api/v1/users/{id}`.
- [ ] Security filter: reject tokens for disabled users (check `enabled` flag at resolve time).

---

## Phase 8 — Security Hardening and Threat-Model Tests

### T26 — Threat T1: token spoofing hardening
**Requirement:** T1 in threat model, FR-09  
**Tests:**
- `AuthenticationServiceTest#falseTokenIsRejected`
- `AuthenticationServiceTest#truncatedTokenReturns401`
- `AuthenticationServiceTest#tokenForDisabledUserReturns401`
- `AuthenticationServiceTest#noTokenReturns401`
- `AuthenticationServiceTest#emptyBearerReturns401`

- [ ] Verify `TokenAuthenticationFilter` uses constant-time comparison (not `String.equals`).
- [ ] Verify 401 response body is identical for all bad-token cases (no oracle).
- [ ] Write the tests above; they must all pass.

---

### T27 — Threat T2: audit log tamper detection
**Requirement:** T2 in threat model, FR-08  
**Tests:**
- `AuditIntegrityTest#tamperedRecordIsDetected` (reuse from T23 — also tag `@Tag("security")`).
- `AuditIntegrityTest#insertedRecordIsDetected` — insert a record with a forged hash, verify chain breaks.
- `AuditIntegrityTest#deletedRecordIsDetected` — delete a middle record, verify chain breaks.

- [ ] All three tests must be `@Tag("security")` and in the CI report.

---

### T28 — Threat T3: wrapped DEK tamper detection
**Requirement:** T3 in threat model, FR-03  
**Tests:**
- `CryptoEngineTest#tamperedWrappedDekIsRejected` (reuse from T05 — also tag `@Tag("security")`).
- `CryptoServiceIT#tamperedStoredDekCausesDecryptionFailure` — flip a byte in `hsm_keys.wrapped_dek` in the DB, then call decrypt; expect 400.

---

### T29 — Threat T9/T10: RBAC and ACL enforcement sweep
**Requirement:** T9, T10 in threat model, FR-06, FR-07  
**Tests (one per RBAC boundary — @Tag("security") on each):**
- `RbacEnforcementTest#appClientCannotGenerateKey`
- `RbacEnforcementTest#appClientCannotRotateKey`
- `RbacEnforcementTest#appClientCannotDestroyKey`
- `RbacEnforcementTest#appClientCannotGrantAcl`
- `RbacEnforcementTest#cryptoOfficerCannotEncrypt`
- `RbacEnforcementTest#cryptoOfficerCannotReadAuditLog`
- `RbacEnforcementTest#adminCannotGenerateKey`
- `RbacEnforcementTest#adminCannotEncrypt`
- `RbacEnforcementTest#auditorCannotGenerateKey`
- `RbacEnforcementTest#auditorCannotEncrypt`
- `AclEnforcementTest#appClientWithoutAclIsRejected`
- `AclEnforcementTest#appClientAfterAclRevocationIsRejected`

- [ ] All twelve tests pass and appear in JaCoCo report.

---

### T30 — Key state guard sweep
**Requirement:** FR-01, US-03, US-04  
**Tests (@Tag("security")):**
- `KeyStateGuardTest#disabledKeyRejectsEncrypt`
- `KeyStateGuardTest#disabledKeyRejectsSign`
- `KeyStateGuardTest#destroyedKeyRejectsAllCryptoOps`
- `KeyStateGuardTest#destroyedKeyRejectsDisable`
- `KeyStateGuardTest#destroyedKeyRejectsRotate`

---

## Phase 9 — Docs, CI, and Polish

### T31 — OpenAPI annotations and Swagger UI
**Requirement:** FR-10, NFR-05  
**Test:** `OpenApiTest#allEndpointsAppearInApiDocs` — call `GET /v3/api-docs`, parse JSON, assert each controller path is present.

- [ ] Add `@Operation`, `@ApiResponse`, `@Schema` annotations to all controllers and DTOs.
- [ ] Configure Springdoc: custom title "Software HSM Emulator API", version, description (with disclaimer).
- [ ] Verify Swagger UI loads at `/swagger-ui.html` with a local run.

---

### T32 — Javadoc on all public service and repository interfaces
**Requirement:** NFR-05  
**Test:** `mvn javadoc:javadoc` produces zero warnings on public APIs (configure `<failOnWarnings>true</failOnWarnings>` in `maven-javadoc-plugin`).

- [ ] Add Javadoc to every `@Service` class and every `Repository` interface.
- [ ] Add `maven-javadoc-plugin` to `pom.xml` with `failOnWarnings=true`.

---

### T33 — README.md
**Requirement:** NFR-05  
**Test:** A person unfamiliar with the project can follow README and reach Swagger UI within 5 minutes.

- [ ] Write `README.md` (see task T34 — done separately as the last file in this session).

---

### T34 — Final CI gate and coverage verification
**Requirement:** NFR-03, NFR-06  
**Test:** Clean GitHub Actions run with green badge.

- [ ] Run `mvn verify` locally; confirm JaCoCo reports ≥ 80 % line / ≥ 75 % branch.
- [ ] Confirm all `@Tag("security")` tests run (Surefire / Failsafe include them).
- [ ] Add coverage badge to `README.md` using the JaCoCo XML report and a badge service.
- [ ] Tag `v0.1.0` on `main` once all CI checks pass.
- [ ] Confirm OWASP Dependency-Check finds zero HIGH/CRITICAL CVEs.

---

## Appendix — Test Tag Reference

| Tag | Meaning |
|-----|---------|
| `@Tag("security")` | Tests an RBAC boundary, ACL boundary, or threat-model item. Required count: ≥ 1 per boundary. |
| `@Tag("crypto")` | Tests a cryptographic operation in isolation (CryptoEngine unit tests). |
| `@Tag("integration")` | Full-stack tests using Testcontainers. Run in `mvn verify` (Failsafe), not `mvn test` (Surefire). |

---

## Appendix — Requirement Traceability Matrix

| Task | Requirements | Threat Items |
|------|-------------|--------------|
| T04 | FR-03, NFR-01 | T7 (partial) |
| T05 | FR-02, FR-04 | T3 |
| T06 | FR-02, FR-05 | — |
| T10 | FR-09, NFR-01 | T1 |
| T11 | FR-06, FR-09 | T1, T9 |
| T12 | FR-02, FR-03, FR-06, US-01 | T9 |
| T14 | FR-01, FR-03, US-03, US-04 | — |
| T15 | FR-01, US-02 | — |
| T16 | FR-07, US-09 | T10 |
| T17–T20 | FR-04, FR-05, FR-07, US-05–08 | T9, T10 |
| T21 | FR-08 | T2, T4 |
| T22–T23 | FR-08, US-10, US-11 | T2, T4 |
| T24–T25 | FR-09, FR-06, US-12 | T1 |
| T26 | FR-09 | T1 |
| T27 | FR-08 | T2 |
| T28 | FR-03, FR-04 | T3 |
| T29 | FR-06, FR-07 | T9, T10 |
| T30 | FR-01 | — |
