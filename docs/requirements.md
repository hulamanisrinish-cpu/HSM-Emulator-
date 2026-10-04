# Requirements — Software HSM Emulator
> **Disclaimer:** This is an educational software emulator of a Hardware Security Module.
> It does NOT hold FIPS 140-2/3, Common Criteria, or any other certification.
> It does NOT protect keys with tamper-resistant hardware. All security properties
> are software-enforced and are intended to demonstrate secure-design principles,
> not to provide production-grade key protection.

---

## Table of Contents
1. [Problem Statement](#1-problem-statement)
2. [Goals and Non-Goals](#2-goals-and-non-goals)
3. [Personas and Role-Permission Matrix](#3-personas-and-role-permission-matrix)
4. [User Stories and Acceptance Criteria](#4-user-stories-and-acceptance-criteria)
5. [Functional Requirements](#5-functional-requirements)
6. [Non-Functional Requirements](#6-non-functional-requirements)
7. [Assumptions and Constraints](#7-assumptions-and-constraints)
8. [Risks](#8-risks)
9. [Out-of-Scope Items](#9-out-of-scope-items)
10. [Success Metrics](#10-success-metrics)

---

## 1. Problem Statement

Hardware Security Modules are dedicated physical devices that generate, store, and
perform cryptographic operations on secret keys, keeping those keys inaccessible to
host software. They are a cornerstone of PKI, payment systems, and secrets management.

Real HSMs are expensive, require specialised hardware, and have steep operational
complexity. This project builds a **software HSM emulator** that faithfully reproduces
the security abstractions of a real HSM — envelope-encrypted key storage, role-based
access control, and tamper-evident audit logging — using standard Java cryptographic
primitives and a Spring Boot REST API. The result is a testable, well-documented
reference for studying HSM design patterns.

---

## 2. Goals and Non-Goals

### Goals
- Provide a REST API that mirrors the functional surface of an HSM: key generation,
  encrypt/decrypt, sign/verify, key lifecycle management, and audit log retrieval.
- Protect stored keys at rest using envelope encryption (AES-256-GCM per-key DEK,
  wrapped with a master key derived via PBKDF2-HmacSHA256 from a startup passphrase).
- Enforce role-based access control (four roles: Admin, CryptoOfficer, AppClient,
  Auditor) including per-key ACLs for AppClient principals.
- Produce an append-only, hash-chained audit log that is verifiably tamper-evident.
- Ship with ≥ 80 % line and branch coverage (JaCoCo), a documented threat model,
  GitHub Actions CI, and an OpenAPI/Swagger UI.
- Be honest about every emulation limitation in code, comments, and documentation.

### Non-Goals
- Claiming or targeting any FIPS 140-2/3 or Common Criteria certification.
- Tamper-resistant hardware protection of keys.
- OS-keystore integration (Windows DPAPI, macOS Keychain, Linux kernel keyring).
- Multi-tenant SaaS deployment or horizontal scaling.
- Key-agreement protocols (Diffie–Hellman, ECDH).
- Certificate management (X.509 issuance, CRL/OCSP).
- High-availability or clustering.

---

## 3. Personas and Role-Permission Matrix

### Persona Descriptions

| Persona | Description |
|---------|-------------|
| **Admin** | Manages users and role assignments. Does not perform crypto operations directly. |
| **CryptoOfficer** | Full key lifecycle: generate, rotate, disable, destroy. Cannot read plaintext key material. |
| **AppClient** | Application principal that uses keys for encrypt/decrypt/sign/verify. Restricted to keys it has been explicitly granted via ACL. |
| **Auditor** | Read-only access to audit logs. No key or user management rights. |

### Role-Permission Matrix

| Operation | Admin | CryptoOfficer | AppClient | Auditor |
|-----------|:-----:|:-------------:|:---------:|:-------:|
| Create user | ✅ | ❌ | ❌ | ❌ |
| Assign / revoke role | ✅ | ❌ | ❌ | ❌ |
| Generate key | ❌ | ✅ | ❌ | ❌ |
| List keys (metadata only) | ❌ | ✅ | ✅ (own ACL) | ❌ |
| Rotate key | ❌ | ✅ | ❌ | ❌ |
| Disable key | ❌ | ✅ | ❌ | ❌ |
| Destroy key | ❌ | ✅ | ❌ | ❌ |
| Encrypt (with key) | ❌ | ❌ | ✅ (ACL) | ❌ |
| Decrypt (with key) | ❌ | ❌ | ✅ (ACL) | ❌ |
| Sign (with key) | ❌ | ❌ | ✅ (ACL) | ❌ |
| Verify signature | ❌ | ❌ | ✅ (ACL) | ❌ |
| Grant / revoke key ACL | ❌ | ✅ | ❌ | ❌ |
| Read audit log | ❌ | ❌ | ❌ | ✅ |
| Verify audit log integrity | ❌ | ❌ | ❌ | ✅ |

> **Note:** `Admin` cannot perform cryptographic operations. `CryptoOfficer` cannot
> read plaintext key material — only manages the key lifecycle. This separation of
> duties mirrors real HSM operational security policies.

---

## 4. User Stories and Acceptance Criteria

### US-01 — Key Generation (CryptoOfficer)
**As a** CryptoOfficer, **I want to** generate a new named AES-256 key,
**so that** AppClients can use it for encryption without ever seeing the raw key bytes.

**Acceptance Criteria (EARS):**
- WHEN a CryptoOfficer sends a valid `POST /api/v1/keys` request with a unique key
  name and algorithm, THE SYSTEM SHALL generate a cryptographically random AES-256
  key, wrap it under the master key using AES-256-GCM, persist the wrapped key and
  its metadata, and return the new key ID and metadata (never the raw key bytes).
- WHEN the key name already exists, THE SYSTEM SHALL reject the request with
  HTTP 409 Conflict.
- WHEN the caller does not have the CryptoOfficer role, THE SYSTEM SHALL reject the
  request with HTTP 403 Forbidden and record the attempt in the audit log.

### US-02 — Key Rotation (CryptoOfficer)
**As a** CryptoOfficer, **I want to** rotate an existing key,
**so that** the blast radius of key compromise is limited over time.

**Acceptance Criteria:**
- WHEN a CryptoOfficer sends `POST /api/v1/keys/{id}/rotate`, THE SYSTEM SHALL
  generate a new key version, retain the previous version in a DISABLED state
  (for decryption of old ciphertext), and return the new version metadata.
- WHEN the key is already in DESTROYED state, THE SYSTEM SHALL reject the request
  with HTTP 422 Unprocessable Entity.

### US-03 — Key Disable (CryptoOfficer)
**As a** CryptoOfficer, **I want to** disable a key without destroying it,
**so that** I can suspend its use while preserving the option to re-enable it.

**Acceptance Criteria:**
- WHEN a CryptoOfficer sends `PATCH /api/v1/keys/{id}/disable`, THE SYSTEM SHALL
  set the key state to DISABLED and reject all subsequent encrypt/decrypt/sign/verify
  requests for that key with HTTP 422.
- WHEN an AppClient attempts to use a DISABLED key, THE SYSTEM SHALL reject the
  request with HTTP 422 and record the attempt in the audit log.

### US-04 — Key Destroy (CryptoOfficer)
**As a** CryptoOfficer, **I want to** permanently destroy a key,
**so that** data protected by that key becomes permanently inaccessible.

**Acceptance Criteria:**
- WHEN a CryptoOfficer sends `DELETE /api/v1/keys/{id}`, THE SYSTEM SHALL set the
  key state to DESTROYED, overwrite the wrapped key material in the database with
  zeros, and reject all future operations on that key ID with HTTP 410 Gone.
- WHEN the key state is already DESTROYED, THE SYSTEM SHALL return HTTP 410.

### US-05 — Encrypt (AppClient)
**As an** AppClient, **I want to** encrypt plaintext with a named key,
**so that** I can store or transmit data that only an authorised party can decrypt.

**Acceptance Criteria:**
- WHEN an AppClient sends `POST /api/v1/crypto/encrypt` with a valid key ID and
  base64-encoded plaintext, AND the AppClient has an ALLOW ACL entry for that key,
  THE SYSTEM SHALL return a base64-encoded ciphertext (AES-256-GCM with a random IV)
  and the key version used.
- WHEN the AppClient does not have an ACL entry for the key, THE SYSTEM SHALL
  reject with HTTP 403 and audit the attempt.
- WHEN the key is DISABLED or DESTROYED, THE SYSTEM SHALL reject with HTTP 422.

### US-06 — Decrypt (AppClient)
**As an** AppClient, **I want to** decrypt ciphertext I previously encrypted,
**so that** I can recover the original plaintext.

**Acceptance Criteria:**
- WHEN an AppClient sends `POST /api/v1/crypto/decrypt` with a valid key ID,
  ciphertext, IV, and auth tag, THE SYSTEM SHALL unwrap the DEK from storage, perform
  AES-256-GCM decryption, and return the plaintext.
- WHEN the GCM authentication tag fails to verify, THE SYSTEM SHALL return HTTP 400
  Bad Request (authentication failure — ciphertext may have been tampered with).
- WHEN the AppClient lacks ACL permission, THE SYSTEM SHALL return HTTP 403.

### US-07 — Sign (AppClient)
**As an** AppClient, **I want to** produce a digital signature over data,
**so that** recipients can verify its authenticity and integrity.

**Acceptance Criteria:**
- WHEN an AppClient sends `POST /api/v1/crypto/sign` with a valid RSA-2048 or
  EC P-256 key ID and base64-encoded data, THE SYSTEM SHALL return a base64-encoded
  signature and the algorithm used.
- WHEN the key type does not support signing (e.g., AES symmetric key), THE SYSTEM
  SHALL reject with HTTP 422.

### US-08 — Verify (AppClient)
**As an** AppClient, **I want to** verify a digital signature,
**so that** I can confirm data integrity and origin.

**Acceptance Criteria:**
- WHEN an AppClient sends `POST /api/v1/crypto/verify` with a key ID, data, and
  signature, THE SYSTEM SHALL return `{ "valid": true }` or `{ "valid": false }`.
- Invalid signatures SHALL NOT cause an error response; they return `valid: false`.

### US-09 — Per-Key ACL Grant / Revoke (CryptoOfficer)
**As a** CryptoOfficer, **I want to** grant or revoke an AppClient's access to a
specific key, **so that** key usage is limited to authorised consumers.

**Acceptance Criteria:**
- WHEN a CryptoOfficer sends `POST /api/v1/keys/{id}/acl` with a principal ID and
  permission type, THE SYSTEM SHALL create or update the ACL entry.
- WHEN a CryptoOfficer sends `DELETE /api/v1/keys/{id}/acl/{principalId}`, THE SYSTEM
  SHALL remove the ACL entry and subsequent use by that principal SHALL be rejected.

### US-10 — Audit Log Read (Auditor)
**As an** Auditor, **I want to** read the audit log with pagination and filters,
**so that** I can investigate events without requiring access to key material.

**Acceptance Criteria:**
- WHEN an Auditor sends `GET /api/v1/audit?page=0&size=50&from=...&to=...`, THE SYSTEM
  SHALL return a paginated list of audit records ordered by timestamp ascending.
- WHEN any other role attempts to read the audit log, THE SYSTEM SHALL reject with
  HTTP 403.

### US-11 — Audit Log Integrity Verification (Auditor)
**As an** Auditor, **I want to** verify the audit log has not been tampered with,
**so that** I can trust the log as a forensic record.

**Acceptance Criteria:**
- WHEN an Auditor sends `GET /api/v1/audit/verify`, THE SYSTEM SHALL re-compute the
  hash chain over all records and return `{ "valid": true, "recordCount": N }` if
  the chain is intact, or `{ "valid": false, "firstTamperedSequence": N }` if a
  break is detected.

### US-12 — User and Role Management (Admin)
**As an** Admin, **I want to** create users and assign roles,
**so that** I can onboard new CryptoOfficers, AppClients, and Auditors.

**Acceptance Criteria:**
- WHEN an Admin sends `POST /api/v1/users` with a username and role, THE SYSTEM SHALL
  create the user, generate a hashed API token, and return the plain-text token once
  (it cannot be retrieved again).
- WHEN an Admin sends `DELETE /api/v1/users/{id}/roles/{role}`, THE SYSTEM SHALL
  revoke that role; subsequent requests using that principal's token SHALL be rejected
  for operations requiring that role.

---

## 5. Functional Requirements

### FR-01 — Key Lifecycle States
Keys shall follow the state machine: `ACTIVE → DISABLED → ACTIVE | DESTROYED`.
From `DESTROYED` there is no transition. Each state change shall be recorded in the
audit log.

```
ACTIVE ──disable──▶ DISABLED ──enable──▶ ACTIVE
  │                     │
  └──destroy────────────┘
              ▼
          DESTROYED (terminal)
```

### FR-02 — Key Generation
The system shall support generating:
- AES-256 symmetric keys (for encrypt/decrypt).
- RSA-2048 asymmetric key pairs (for sign/verify).
- EC P-256 asymmetric key pairs (for sign/verify).

Each generated key shall be assigned a UUID key ID and an initial version counter of 1.

### FR-03 — Envelope Encryption at Rest
Each key's raw material shall be encrypted with a unique per-key Data Encryption Key
(DEK). The DEK shall itself be wrapped (AES-256-GCM) using the master key. Only the
wrapped DEK is persisted. The master key shall never be persisted; it shall be derived
at startup from a passphrase using PBKDF2-HmacSHA256 (iteration count ≥ 310,000,
per OWASP 2024 recommendations; random 16-byte salt stored separately).

### FR-04 — Encryption and Decryption
Symmetric encryption/decryption shall use AES-256-GCM. Each encrypt call shall
generate a fresh random 12-byte IV. The GCM authentication tag shall be verified
during decryption; failure shall return an error without revealing whether the
key or the ciphertext was wrong.

### FR-05 — Signing and Verification
Signing shall use SHA-256 with RSA (RSASSA-PKCS1-v1_5) for RSA keys, and
ECDSA with SHA-256 for EC keys. Verification shall be non-throwing: invalid
signatures return `valid: false`.

### FR-06 — RBAC Enforcement
Every API endpoint shall require a valid API token. The token shall be resolved to a
principal and role before the request is processed. Requests that fail role checks
shall be rejected before any key material is accessed, and the attempt shall be
written to the audit log.

### FR-07 — Per-Key ACLs
AppClient operations (encrypt, decrypt, sign, verify) shall require both:
1. The caller has the AppClient role.
2. An explicit ACL entry exists for `(principalId, keyId)` in the `ALLOW` state.

### FR-08 — Audit Log
Every security-relevant event shall produce an immutable audit record containing:
`sequenceNumber`, `timestamp` (UTC, nanosecond precision), `principalId`, `action`,
`keyId` (nullable), `outcome` (SUCCESS | DENIED | ERROR), and `chainHash`.

`chainHash` = SHA-256(`chainHash(n-1)` ∥ `sequenceNumber` ∥ `timestamp` ∥
`principalId` ∥ `action` ∥ `keyId` ∥ `outcome`).

The first record uses a zero-hash as the previous hash.

### FR-09 — Authentication
API tokens shall be stored as Argon2id hashes (via Bouncy Castle). Plain-text tokens
shall be generated once and never stored or logged. Each request shall supply the
token in the `Authorization: Bearer <token>` header.

### FR-10 — OpenAPI Documentation
The application shall expose a Swagger UI at `/swagger-ui.html` and a machine-readable
OpenAPI 3.0 spec at `/v3/api-docs`. All endpoints, request bodies, response schemas,
and error codes shall be documented.

---

## 6. Non-Functional Requirements

### NFR-01 — Security
- All cryptographic operations shall use JCA standard algorithms via the Java standard
  library; no custom cryptographic implementations.
- Bouncy Castle shall be used only for Argon2id (token hashing); its use shall be
  limited to that single concern.
- No key material (raw or wrapped) shall appear in HTTP responses, log lines, or
  exception messages.
- HTTP responses for authentication failures shall not distinguish between "unknown
  user" and "wrong token" (generic 401).
- Dependencies shall be pinned to exact versions in `pom.xml`.

### NFR-02 — Reliability and Correctness
- All database writes shall be transactional; partial key-generation failures shall
  not leave orphaned records.
- Audit log records shall be written in the same transaction as the operation they
  record, or in a compensating transaction if the primary transaction fails.

### NFR-03 — Testability
- JaCoCo line coverage: ≥ 80 % (target; measured by CI, not invented).
- JaCoCo branch coverage: ≥ 75 % (target; measured by CI).
- All tests shall run without a network or a pre-installed database (Testcontainers
  manages the PostgreSQL instance).
- Negative test cases shall exist for every RBAC boundary, every key state transition
  guard, and every tampered-log scenario.

### NFR-04 — Performance
- All performance targets are **to be measured** after implementation using a load
  tool (e.g., Apache JMeter or `k6`). No numbers are invented here.
- The design shall not introduce unnecessary synchronisation bottlenecks
  (e.g., no global lock on the key store).

### NFR-05 — Documentation
- `README.md` shall include: project purpose (with emulation disclaimer), architecture
  summary, prerequisites, quick-start instructions, API overview, security design
  summary, and known limitations.
- All public service and repository interfaces shall have Javadoc.
- `design.md` shall be kept in sync with implementation decisions.

### NFR-06 — Build and CI
- `mvn verify` shall run the full build, all tests, and JaCoCo reporting without
  manual steps beyond `docker compose up -d db` (or Testcontainers for tests).
- GitHub Actions shall: build, test, enforce coverage gates, and upload the JaCoCo
  report as an artifact on every push and pull request.

---

## 7. Assumptions and Constraints

| # | Item |
|---|------|
| A1 | The startup passphrase is supplied via an environment variable (`HSM_MASTER_PASSPHRASE`). Protecting this variable is the operator's responsibility, as with a real HSM's PIN. |
| A2 | A single instance is deployed; no clustering or distributed key management is required. |
| A3 | PostgreSQL 15+ is the only supported database; in-memory H2 is not used (Testcontainers provides real Postgres in CI). |
| A4 | Java 17 LTS is the minimum runtime; no Java 21 features are required (can be added later). |
| A5 | Maven 3.9+ is the build tool. |
| A6 | Docker and Docker Compose are available in the development environment. |
| C1 | The project scope is two calendar weeks for one student; features are prioritised accordingly. |
| C2 | No frontend UI is in scope; Swagger UI is the sole interactive interface. |
| C3 | No HSM-to-HSM key synchronisation or replication protocol is in scope. |

---

## 8. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Master key derivation parameters (iteration count, salt) are misconfigured and too weak | Medium | High | Fail fast on startup if parameters fall below OWASP minimums; test this check |
| R2 | Audit log grows unbounded and degrades query performance | Low | Medium | Add pagination and a database index on `sequence_number` and `timestamp` |
| R3 | Testcontainers startup time makes CI slow | Medium | Low | Use a shared PostgreSQL container per test suite (not per test) |
| R4 | Key material leaks in an exception message or log line | Medium | High | Custom exception hierarchy with sanitised messages; no raw key logging anywhere |
| R5 | Dependency vulnerability in a pinned version | Medium | Medium | Dependabot alerts on GitHub; reviewed in CI |
| R6 | GCM IV reuse with the same key (birthday problem at high volume) | Low | High | Document the emulation limit; for production, use a counter-based IV or key rotation |

---

## 9. Out-of-Scope Items

- FIPS 140-2/3 or Common Criteria certification.
- Hardware tamper resistance or secure enclaves (Intel SGX, ARM TrustZone).
- OS keystore integration.
- Key export / import (PKCS#12, PKCS#8).
- Certificate issuance or management (X.509, CRL, OCSP).
- Key agreement (ECDH, DH).
- Multi-tenancy or tenant isolation.
- Mutual TLS between client and server.
- Secrets rotation automation (e.g., Vault integration).
- A web or desktop UI.

---

## 10. Success Metrics

All metrics are measured by tooling; no numbers are hand-crafted.

| Metric | Tool | Target |
|--------|------|--------|
| Line coverage | JaCoCo (enforced in `mvn verify`) | ≥ 80 % |
| Branch coverage | JaCoCo | ≥ 75 % |
| STRIDE threat items mitigated | Documented in `design.md` threat model table | All HIGH items have a mitigation and a corresponding test |
| Build passes on clean checkout | GitHub Actions | 100 % of pushes to `main` |
| Zero HIGH/CRITICAL CVEs in dependencies | OWASP Dependency-Check plugin (or Dependabot) | Zero at merge time |
| API documented | Springdoc OpenAPI — all endpoints appear in `/v3/api-docs` | 100 % of public endpoints |
| Negative test cases | JUnit 5 — count of `@Tag("security")` tests | At least one per RBAC boundary and key state guard |
