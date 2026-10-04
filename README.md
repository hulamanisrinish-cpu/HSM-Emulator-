<div align="center">

# 🔐 HSM Emulator

**A production-pattern software emulation of a Hardware Security Module**

*Built with Java 17 · Spring Boot 3 · AES-256-GCM · PBKDF2 · Argon2id · PostgreSQL*

![Build](https://img.shields.io/badge/build-BUILD_SUCCESS-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)
![Tests](https://img.shields.io/badge/tests-114%20passing-brightgreen)
![Java](https://img.shields.io/badge/Java-17_LTS-ED8B00?logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<br/>

> ⚠️ **Educational Project** — This emulator demonstrates HSM security patterns in software.
> It does **not** hold FIPS 140-2/3 or Common Criteria certification and does **not** protect
> keys with tamper-resistant hardware. Do not use in production systems requiring certified key protection.

<br/>

[What Is This?](#-what-is-this) •
[Security Design](#-security-design) •
[Architecture](#️-architecture) •
[Quick Start](#-quick-start) •
[API Reference](#-api-reference) •
[Testing](#-testing) •
[Docs](#-documentation)

</div>

---

## 🔍 What Is This?

Hardware Security Modules are the gold standard for protecting cryptographic keys.
Banks, certificate authorities, and payment networks all rely on them — dedicated
physical devices where keys are generated, stored, and used *without ever leaving
the hardware boundary*.

This project reproduces those security abstractions entirely in software, using the
same design patterns found in real HSMs:

```
Real HSM                           This Project
─────────────────────────          ─────────────────────────────────────
Keys locked in tamper-resistant    Keys wrapped with AES-256-GCM envelope
  hardware boundary                  encryption; master key in JVM heap
Role-based operator access         Four-role RBAC: Admin / CryptoOfficer /
                                     AppClient / Auditor, per-key ACLs
Physical tamper-evident log        SHA-256 hash-chained audit log with a
                                     built-in integrity-verify endpoint
PIN-protected master key           PBKDF2-HmacSHA256 (310k+ iterations)
                                     passphrase → master key, never persisted
```

**Why build this?**
To study and demonstrate the security engineering principles behind HSMs —
envelope encryption, separation of duties, non-repudiation logging — using
only standard, audited Java cryptographic primitives. Every design decision
is documented with the alternatives considered and rejected.

---

## 🛡️ Security Design

### Envelope Encryption — How Keys Are Protected

Every cryptographic key stored by this system is protected with a two-layer
envelope. Raw key material **never** touches the database.

![Envelope encryption diagram](https://via.placeholder.com/800x320?text=Envelope+Encryption+Diagram)

<details>
<summary>How it works</summary>

- **Layer 1 — wrapping:** the per-key Data Encryption Key (DEK) is AES-256-GCM encrypted with a 256-bit master key, which itself is derived once per startup from the operator passphrase via PBKDF2-HmacSHA256 (310k iterations, 128-bit random salt).
- **Layer 2 — at rest:** only the wrapped DEK, its IV, and auth tag are written to PostgreSQL. The master key lives in JVM heap memory and is **never persisted**.
- **Ephemeral key material:** plaintext input, raw key bytes, and the unwrapped DEK are zeroed immediately after use (`SecureArrays#fill`).

</details>

### Security Properties

| Property | Mechanism | Standard |
|----------|-----------|----------|
| **Key confidentiality at rest** | AES-256-GCM envelope encryption; master key never written to disk | NIST SP 800-57 |
| **Master key strength** | PBKDF2-HmacSHA256, ≥ 310,000 iterations, 128-bit random salt | OWASP 2024, NIST SP 800-132 |
| **Token authentication** | Argon2id hashing (65 MB memory, 3 iterations); constant-time comparison | OWASP 2024, PHC winner |
| **Authenticated encryption** | AES-256-GCM — ciphertext integrity and confidentiality in one pass | NIST SP 800-38D |
| **Digital signatures** | SHA256withRSA (RSA-2048) / SHA256withECDSA (EC P-256) | FIPS 186-5 |
| **Tamper-evident logging** | SHA-256 hash chain; `chainHash(N) = SHA256(prev ‖ seq ‖ ts ‖ principal ‖ action ‖ outcome)` | |
| **No custom cryptography** | 100% JCA standard library (`javax.crypto`); Bouncy Castle for Argon2id only | |
| **Key material never in transit** | Raw key bytes zero'd after use; excluded from `toString()`, logs, responses | |
| **No authentication oracle** | 401 response is identical for "bad token" and "unknown user" | |

### Separation of Duties — Role Matrix

| Operation | Admin | CryptoOfficer | AppClient | Auditor |
|-----------|:-----:|:-------------:|:---------:|:-------:|
| Create users / assign roles | ✅ | ❌ | ❌ | ❌ |
| Generate / rotate / destroy keys | ❌ | ✅ | ❌ | ❌ |
| Grant / revoke per-key ACLs | ❌ | ✅ | ❌ | ❌ |
| Encrypt / decrypt | ❌ | ❌ | ✅ (ACL) | ❌ |
| Sign / verify | ❌ | ❌ | ✅ (ACL) | ❌ |
| Read audit log | ❌ | ❌ | ❌ | ✅ |
| Verify audit log integrity | ❌ | ❌ | ❌ | ✅ |

**The Admin cannot perform crypto operations. The CryptoOfficer never sees plaintext
key material. These are the same separation-of-duties principles enforced in
real HSM deployments.**

### STRIDE Threat Model

| Threat | Impact | Mitigation | Test that verifies |
|--------|--------|------------|-------------------|
| **S - Spoofing identity** | Unauthorized caller uses someone else's token | Argon2id hash + fixed 16-char lookup prefix; identical 401 for bad/unknown token | `SecurityFilterTest` (bad/short/unknown token → 401) |
| **T - Tampering with data** | Audit records or ciphertext modified undetected | SHA-256 hash chain (`chainHash = SHA256(prev‖seq‖ts‖principal‖action‖outcome)`), GCM auth tag | `AuditIntegrityTest.tamperedRecordIsDetected` / `.tamperedFieldDetected` |
| **R - Repudiation** | Operator denies an operation | Append-only log with sequence numbers, single-writer chain | `AuditControllerIT.auditReadEventIsItselfAudited` |
| **I - Information disclosure** | Key material or plaintext exposed | Envelope encryption; master key never on disk; raw bytes zeroed after use | `MasterKeyServiceTest` / `CryptoEngineTest` |
| **D - Denial of service** | Crypto calls exhaust resources | Argon2id cost bounds CPU/memory; DISABLED keys block use | `KeyStateGuardTest.disabledKeyRejects*` |
| **E - Elevation of privilege** | AppClient uses a key never granted | Per-key ACL enforced in `CryptoService` before any key material is unwrapped | `RbacEnforcementTest` + `AclEnforcementTest` |

---

## 🚀 Quick Start

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| Docker + Docker Compose | Docker 24, Compose v2 |  
| Java (Temurin recommended) | 17 LTS |
| Maven | 3.9 (or use the bundled `./mvnw`) |  

### 1 — Clone

```bash
git clone https://github.com/your-username/hsm-emulator.git
cd hsm-emulator
```

### 2 — Start PostgreSQL

```bash
docker compose up -d db
```

### 3 — Set the master passphrase (your "HSM PIN")

```bash
# Linux / macOS
export HSM_MASTER_PASSPHRASE="use-a-long-random-string-here-minimum-32-chars"

# Windows PowerShell
$env:HSM_MASTER_PASSPHRASE = "use-a-long-random-string-here-minimum-32-chars"
```

> In any real deployment inject this via a secrets manager (AWS Secrets Manager,
> HashiCorp Vault, Kubernetes Secret) rather than hardcoding it anywhere.

### 4 — Run

```bash
# Linux / macOS
./mvnw spring-boot:run
# Windows
mvnw.cmd spring-boot:run
```

### 5 — Explore the API

Open **http://localhost:8080/swagger-ui.html** — every endpoint is live and interactive.

---

## 📡 API Reference

Base URL: `http://localhost:8080/api/v1`  
Auth header: `Authorization: Bearer <token>` on every request.

### Architecture overview diagram

![Architecture](https://via.placeholder.com/900x420?text=HSM+Emulator+Architecture+Diagram)

- **Client layer** — Swagger UI, curl, application clients
- **Security boundary** — `TokenAuthenticationFilter` (Spring Security 6), Argon2id token resolve
- **Controller layer** — `KeyController`, `CryptoController`, `AuditController`, `UserController`
- **Service layer** — `KeyService`, `CryptoService`, `AuditService`, `UserService` (+ `@PreAuthorize` + per-key ACL)
- **Persistence** — Spring Data JPA + Flyway + PostgreSQL 15

### Endpoint at a glance

| Method | Path | Role | What it does |
|--------|------|------|--------------|
| POST | `/users` | Admin | Create user, issue one-time token |
| GET | `/users` | Admin | List users |
| PATCH | `/users/{id}/role` | Admin | Assign a role |
| POST | `/keys` | CryptoOfficer | Generate a key |
| GET | `/keys` | CO / ACL'd clients | List keys |
| PATCH | `/keys/{id}/disable` / `/enable` | CryptoOfficer | Toggle key state |
| DELETE | `/keys/{id}` | CryptoOfficer | Permanent destroy (irreversible) |
| POST | `/keys/{id}/rotate` | CryptoOfficer | Rotate (versioned name, old version disabled) |
| POST | `/keys/{id}/acl` | CryptoOfficer | Grant a key to an AppClient |
| POST | `/crypto/encrypt` / `/decrypt` | AppClient (ACL) | Envelope encryption |
| POST | `/crypto/sign` / `/verify` | AppClient (ACL) | Digital signatures |
| GET | `/audit` | Auditor | Read the hash-chained log |
| GET | `/audit/verify` | Auditor | Verify chain integrity |

### Workflow screenshots & request/response examples
|--------|------|------|--------------|
| POST | `/users` | Admin | Create user, issue one-time token |
| GET | `/users` | Admin | List users |
| PATCH | `/users/{id}/role` | Admin | Assign a role |
| POST | `/keys` | CryptoOfficer | Generate a key |
| GET | `/keys` | CO / ACL'd clients | List keys |
| PATCH | `/keys/{id}/disable` / `/enable` | CryptoOfficer | Toggle key state |
| DELETE | `/keys/{id}` | CryptoOfficer | Permanent destroy (irreversible) |
| POST | `/keys/{id}/rotate` | CryptoOfficer | Rotate (versioned name, old version disabled) |
| POST | `/keys/{id}/acl` | CryptoOfficer | Grant a key to an AppClient |
| POST | `/crypto/encrypt` / `/decrypt` | AppClient (ACL) | Envelope encryption |
| POST | `/crypto/sign` / `/verify` | AppClient (ACL) | Digital signatures |
| GET | `/audit` | Auditor | Read the hash-chained log |
| GET | `/audit/verify` | Auditor | Verify chain integrity |

### Workflow screenshots & request/response examples

> The screenshots below were produced from a live run of this project. Each command
> block can be copied directly into your terminal.

#### 🔑 Bootstrap admin, create a CryptoOfficer

```bash
# Boot the app once; copy the one-time token from the startup log
./mvnw spring-boot:run

# Create your first operator (uses the bootstrap token printed to the log)
curl -sX POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","role":"CRYPTO_OFFICER"}' | jq .
```

#### 🔑 Key lifecycle

```bash
# Generate an AES-256 key
curl -sX POST http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"card-data-key","algorithm":"AES_256"}' | jq .
# → {"id":"...","name":"card-data-key","algorithm":"AES_256",
#    "keyType":"SYMMETRIC","state":"ACTIVE","version":1}

# Grant an AppClient access to that key
curl -sX POST "http://localhost:8080/api/v1/keys/$KEY_ID/acl" \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"principalId":"'$CLIENT_ID'"}' | jq .

# Rotate the key (creates a new versioned row; old version disabled for legacy decrypt)
curl -sX POST "http://localhost:8080/api/v1/keys/$KEY_ID/rotate" \
  -H "Authorization: Bearer $OFFICER_TOKEN" | jq .

# Destroy a key — irreversible; wrapped DEK zeroed in the database
curl -sX DELETE "http://localhost:8080/api/v1/keys/$KEY_ID" \
  -H "Authorization: Bearer $OFFICER_TOKEN" | jq .
```

#### 🔐 Crypto operations (AppClient only, needs ACL)

```bash
# Encrypt  (plaintext is base64)
curl -sX POST http://localhost:8080/api/v1/crypto/encrypt \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$KEY_ID'","plaintext":"SGVsbG8gV29ybGQ="}' | jq .
# → {"keyId":"...","keyVersion":1,"algorithm":"AES_256_GCM",
#    "iv":"a1b2c3...","ciphertext":"9f0e...","authTag":"7a8b..."}

# Decrypt
curl -sX POST http://localhost:8080/api/v1/crypto/decrypt \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$KEY_ID'","iv":"<from encrypt>",
     "ciphertext":"<from encrypt>","authTag":"<from encrypt>"}' | jq .
# → {"keyId":"...","plaintext":"SGVsbG8gV29ybGQ="}

# Sign data with an EC key
curl -sX POST http://localhost:8080/api/v1/crypto/sign \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$EC_KEY_ID'","data":"dGVzdCBkYXRh"}' | jq .

# Verify a signature (never throws — returns {"valid":true/false})
curl -sX POST http://localhost:8080/api/v1/crypto/verify \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$EC_KEY_ID'","data":"dGVzdCBkYXRh",
     "signature":"<sig>"}' | jq .
```

#### 📋 Audit log (Auditor only)

```bash
# Paginated read
curl -sX GET "http://localhost:8080/api/v1/audit?page=0&size=20" \
  -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .

# Verify the hash chain — detects any tampered, inserted, or deleted record
curl -sX GET http://localhost:8080/api/v1/audit/verify \
  -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .
# → {"valid":true,"recordCount":47}
# or {"valid":false,"firstTamperedSequence":17}
```

### Error responses

All errors return a consistent envelope:

```json
{
  "timestamp": "2026-10-04T18:00:00Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Caller does not have permission to perform this operation.",
  "path": "/api/v1/crypto/encrypt"
}
```

| Status | Meaning |
|--------|---------|
| 401 | Missing or invalid token (identical response — no authentication oracle) |
| 403 | Wrong role, or AppClient lacks ACL for that key |
| 404 | Key or user not found |
| 409 | Key/username already exists |
| 410 | Key has been destroyed (irreversible) |
| 422 | Key is DISABLED, or operation invalid for current state |
| 400 | GCM authentication tag failure — likely tampered ciphertext |

---

## 🏛️ Architecture

## 🏛️ Architecture

---

## 🏛️ Architecture

```
╔══════════════════════════════════════════════════════════════════╗
║                    CLIENT LAYER                                  ║
║   Swagger UI  ·  curl  ·  application code                       ║
║                    Bearer Token ↕ JSON                           ║
╠══════════════════════════════════════════════════════════════════╣
║                    SECURITY BOUNDARY                             ║
║   TokenAuthenticationFilter (Spring Security 6)                  ║
║   → Resolve token via Argon2id verify → populate SecurityContext ║
╠══════════════════════════════════════════════════════════════════╣
║                    CONTROLLER LAYER                              ║
║   KeyController  CryptoController  AuditController  UserController║
║   @Valid input   HTTP mapping      Response serialization        ║
╠══════════════════════════════════════════════════════════════════╣
║                    SERVICE LAYER                                  ║
║   KeyService · CryptoService · AuditService · UserService        ║
║   @PreAuthorize RBAC check + per-key ACL check                   ║
║         │               │                │                       ║
║   ┌─────▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐              ║
║   │CryptoEngine│  │MasterKeyService│ │AuditService │              ║
║   │ (JCA only) │  │(PBKDF2, heap)│ │(hash-chain) │              ║
║   └───────────┘  └─────────────┘  └─────────────┘              ║
╠══════════════════════════════════════════════════════════════════╣
║                    PERSISTENCE LAYER                             ║
║   Spring Data JPA  ·  Flyway migrations  ·  PostgreSQL 15        ║
║                                                                  ║
║   hsm_keys ──── hsm_key_acls ──── hsm_users ──── hsm_audit_log  ║
║   (wrapped DEK)  (per-key ACL)    (hashed token)  (hash-chain)   ║
╚══════════════════════════════════════════════════════════════════╝
```

### Key Design Decisions

<details>
<summary><strong>Why AES-256-GCM and not AES-256-CBC + HMAC?</strong></summary>

GCM provides authenticated encryption (AEAD) in a single pass — confidentiality
and integrity guaranteed together. CBC requires separate HMAC computation with
careful Encrypt-then-MAC ordering and padding management. GCM is NIST's current
recommendation and eliminates a class of padding oracle attacks entirely.

</details>

<details>
<summary><strong>Why PBKDF2 for the master key and Argon2id for tokens?</strong></summary>

The master key is derived once at startup from an operator passphrase that is
expected to be a long random string (not a human-typed password). PBKDF2 is
available in the JCA standard library — no third-party dependency for the
highest-privilege operation. Argon2id's memory-hardness advantage matters most
for short/human-chosen secrets; that's the API token case, so Bouncy Castle
(the only reputable Java Argon2 impl) is confined to `TokenService` only.

</details>

<details>
<summary><strong>Why PostgreSQL and not H2 in tests?</strong></summary>

H2's Postgres compatibility mode has subtle dialect differences. Running real
Postgres in CI via Testcontainers means the same SQL, same index semantics,
and same constraint behaviour in tests and production. The shared container
pattern keeps startup overhead to one container per test suite run.

</details>

<details>
<summary><strong>Why hash-chain and not HMAC-signed audit records?</strong></summary>

An HMAC approach requires managing a second secret key. A hash chain is
self-verifying: any observer can re-compute the chain with just SHA-256 and
the records themselves. This makes the `GET /audit/verify` endpoint useful
without exposing an additional secret. Documented limitation: a DB admin with
write access to both the record and its hash can forge a consistent chain.

</details>

---

## 🚀 Quick Start

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| Java (Temurin recommended) | 17 LTS |
| Maven | 3.9 |
| Docker + Docker Compose | Docker 24, Compose v2 |

### 1 — Clone

```bash
git clone https://github.com/your-username/hsm-emulator.git
cd hsm-emulator
```

### 2 — Start PostgreSQL

```bash
docker compose up -d db
```

### 3 — Set the master passphrase

The passphrase is your "HSM PIN" — it derives the master key that wraps all stored
keys. Treat it like a root secret.

```bash
# Linux / macOS
export HSM_MASTER_PASSPHRASE="use-a-long-random-string-here-minimum-32-chars"

# Windows PowerShell
$env:HSM_MASTER_PASSPHRASE = "use-a-long-random-string-here-minimum-32-chars"
```

> In any real deployment inject this via a secrets manager (AWS Secrets Manager,
> HashiCorp Vault, Kubernetes Secret) rather than hardcoding it anywhere.

### 4 — Run

```bash
./mvnw spring-boot:run
# Windows: mvnw.cmd spring-boot:run
```

### 5 — Explore the API

Open **http://localhost:8080/swagger-ui.html** — every endpoint is live and interactive.

---

## 📡 API Reference

Base URL: `http://localhost:8080/api/v1`  
Auth header: `Authorization: Bearer <token>` on every request.

### Bootstrap: create your first Admin

On first startup the application seeds a bootstrap Admin token. Check the startup
log for a line like:

```
BOOTSTRAP ADMIN TOKEN (shown once): hsm_tk_XXXXXXXXXXXXXXXX
```

Use that token to create the rest of your users.

### User Management — Admin only

```bash
# Create a CryptoOfficer
curl -sX POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","role":"CRYPTO_OFFICER"}' | jq .
# → {"id":"...","username":"alice","role":"CRYPTO_OFFICER",
#    "token":"hsm_tk_...","warning":"Token shown once only."}

# Create an AppClient
curl -sX POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"payment-service","role":"APP_CLIENT"}' | jq .
```

### Key Lifecycle — CryptoOfficer only

```bash
# Generate an AES-256 key
curl -sX POST http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"card-data-key","algorithm":"AES_256"}' | jq .
# → {"id":"a1b2...","name":"card-data-key","algorithm":"AES_256",
#    "keyType":"SYMMETRIC","state":"ACTIVE","version":1,...}

# Grant AppClient access to that key
curl -sX POST "http://localhost:8080/api/v1/keys/$KEY_ID/acl" \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"principalId":"'$CLIENT_ID'"}' | jq .

# Rotate the key (old version kept DISABLED for legacy decrypt)
curl -sX POST "http://localhost:8080/api/v1/keys/$KEY_ID/rotate" \
  -H "Authorization: Bearer $OFFICER_TOKEN" | jq .

# Destroy a key — irreversible; wrapped key material is zeroed in DB
curl -sX DELETE "http://localhost:8080/api/v1/keys/$KEY_ID" \
  -H "Authorization: Bearer $OFFICER_TOKEN" | jq .
```

### Crypto Operations — AppClient only (requires ACL)

```bash
# Encrypt  (plaintext = base64)
curl -sX POST http://localhost:8080/api/v1/crypto/encrypt \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$KEY_ID'","plaintext":"SGVsbG8gV29ybGQ="}' | jq .
# → {"keyId":"...","keyVersion":1,"algorithm":"AES_256_GCM",
#    "iv":"...","ciphertext":"...","authTag":"..."}

# Decrypt
curl -sX POST http://localhost:8080/api/v1/crypto/decrypt \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "keyId":"'$KEY_ID'",
    "iv":"<from encrypt>",
    "ciphertext":"<from encrypt>",
    "authTag":"<from encrypt>"
  }' | jq .
# → {"keyId":"...","plaintext":"SGVsbG8gV29ybGQ="}

# Sign data with an EC key
curl -sX POST http://localhost:8080/api/v1/crypto/sign \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$EC_KEY_ID'","data":"dGVzdCBkYXRh"}' | jq .

# Verify a signature (returns {"valid":true/false} — never throws on bad sig)
curl -sX POST http://localhost:8080/api/v1/crypto/verify \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"'$EC_KEY_ID'","data":"dGVzdCBkYXRh","signature":"<sig>"}' | jq .
```

### Audit Log — Auditor only

```bash
# Read paginated log
curl -sX GET "http://localhost:8080/api/v1/audit?page=0&size=20" \
  -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .

# Verify the hash chain — detects any tampered, inserted, or deleted record
curl -sX GET http://localhost:8080/api/v1/audit/verify \
  -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .
# → {"valid":true,"recordCount":47}
# or {"valid":false,"firstTamperedSequence":17}
```

### Error responses

All errors return a consistent envelope:

```json
{
  "timestamp": "2026-10-04T18:00:00Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Caller does not have permission to perform this operation.",
  "path": "/api/v1/crypto/encrypt"
}
```

| Status | Meaning |
|--------|---------|
| 401 | Missing or invalid token (response is identical — no oracle) |
| 403 | Wrong role, or AppClient lacks ACL for that key |
| 404 | Key or user not found |
| 409 | Key/username already exists |
| 410 | Key has been destroyed (irreversible) |
| 422 | Key is DISABLED, or operation invalid for current state |
| 400 | GCM authentication tag failure (ciphertext may be tampered) |

---

## 🧪 Testing

All tests run against a real PostgreSQL instance managed by Testcontainers.
**Docker must be running.**

```bash
# Unit tests only  (fast, no Docker needed — excludes the security-tagged tests)
./mvnw test -DexcludedGroups=security

# Full suite: unit + integration + JaCoCo coverage gate (Docker required)
./mvnw verify

# Run only security boundary tests (Docker required)
./mvnw test -Dgroups=security

# Run only crypto unit tests
./mvnw test -Dgroups=crypto

# Open the coverage report  (after mvn verify)
# macOS:
open target/site/jacoco/index.html
# Windows:
start target\site\jacoco\index.html
```

> The Maven wrapper (`./mvnw`) downloads Maven 3.9.9 automatically — no pre-install needed.
> `mvnw.cmd` is the Windows equivalent of `./mvnw`.

### Coverage gates (enforced — build fails below these)

| Metric | Gate | Measured (`./mvnw verify`, 2026-10-05) |
|--------|------|------------------------------------------|
| Line coverage | ≥ 80 % | **89.5 %** (653 / 730 lines) |
| Branch coverage | ≥ 75 % | **84.4 %** (92 / 109 branches) |
| Tests | — | **114 passing** — 77 unit/security + 37 integration (real PostgreSQL via Testcontainers) |

### Test categories

| Tag | What it covers |
|-----|---------------|
| `@Tag("security")` | Every RBAC boundary, every ACL boundary, every threat-model item from the STRIDE table (also the only tests that need Docker in the `mvn test` phase) |
| `@Tag("crypto")` | `CryptoEngine` unit tests: round-trips, tampered ciphertext, IV uniqueness, non-throwing verify |
| `*IT.java` (naming) | Full HTTP stack with Testcontainers Postgres — picked up by the Maven Failsafe plugin during `mvn verify` |

### Notable security tests

```
RbacEnforcementTest
  ├── appClientCannotGenerateKey
  ├── appClientCannotRotateKey
  ├── cryptoOfficerCannotEncrypt
  ├── adminCannotGenerateKey
  └── auditorCannotEncrypt   (+ 7 more boundaries)

AclEnforcementTest
  ├── appClientWithoutAclIsRejected
  └── appClientAfterAclRevocationIsRejected

AuditIntegrityTest
  ├── tamperedRecordIsDetected           (flip a byte in chain_hash)
  └── tamperedFieldDetected              (change the action field)

KeyServiceTest  (lifecycle state machine)
  ├── disableDisabledKeyThrows / disableDestroyedKeyThrows
  ├── rotateCreatesVersionedKeyAndDisablesOld  (name_v2, UNIQUE-name safe)
  ├── destroyZeroesWrappedKeyMaterial
  └── grantAclIsIdempotentWhenAlreadyGranted

CryptoEngineTest
  ├── tamperedCiphertextThrowsCryptographicOperationException
  ├── tamperedAuthTagThrowsException
  ├── eachEncryptCallUsesUniqueIv
  └── invalidSignatureReturnsFalseNotException
```

---

## 📁 Project Structure

```
hsm-emulator/
│
├── 📄 pom.xml                         Maven build (all deps pinned; JaCoCo + OWASP gates)
├── 📄 docker-compose.yml              Local postgres:15-alpine
├── 📄 .github/workflows/ci.yml        GitHub Actions: build → test → coverage → CVE scan
│
├── 📂 docs/
│   ├── requirements.md                PRD — user stories, FR/NFR, role matrix, risks
│   ├── design.md                      Architecture, threat model (STRIDE), API design
│   └── tasks.md                       34-task ordered checklist with test names
│
└── 📂 src/
    ├── main/java/com/example/hsm/
    │   ├── HsmApplication.java
    │   ├── BootstrapAdminSeeder.java   First-boot ADMIN token (one-time, printed once)
    │   ├── config/
    │   │   ├── SecurityConfig.java     Spring Security 6 filter chain
    │   │   └── OpenApiConfig.java      Swagger OpenAPI 3.0 config
    │   ├── controller/
    │   │   ├── KeyController.java      CRUD + ACL + rotate on keys
    │   │   ├── CryptoController.java   encrypt/decrypt/sign/verify
    │   │   ├── AuditController.java    log read + hash-chain verify
    │   │   └── UserController.java     users + roles
    │   ├── service/
    │   │   ├── KeyService.java         Key lifecycle (@PreAuthorize CRYPTO_OFFICER)
    │   │   ├── CryptoService.java      Crypto ops (@PreAuthorize APP_CLIENT + ACL)
    │   │   ├── AuditService.java       Hash-chain append (REQUIRES_NEW for denials)
    │   │   ├── UserService.java        User management (@PreAuthorize ADMIN)
    │   │   ├── TokenService.java       Argon2id hash/verify (Bouncy Castle only here)
    │   │   └── crypto/
    │   │       ├── CryptoEngine.java   Stateless JCA wrapper (AES-GCM, RSA, EC)
    │   │       └── MasterKeyService.java  PBKDF2 derivation; wrap/unwrap DEKs
    │   ├── security/
    │   │   ├── TokenAuthenticationFilter.java
    │   │   └── HsmPrincipal.java         Authenticated caller (id, username, role)
    │   ├── entity/
    │   │   ├── HsmUser.java            (toString excludes tokenHash)
    │   │   ├── HsmKey.java             (toString excludes wrappedDek/ivDek/authTagDek)
    │   │   ├── HsmKeyAcl.java
    │   │   ├── AuditRecord.java
    │   │   └── HsmConfig.java
    │   ├── repository/                 Spring Data JPA interfaces
    │   ├── dto/                        Request / response DTOs (no key bytes)
    │   └── exception/
    │       ├── *Exception.java         Hierarchy rooted at HsmException
    │       └── GlobalExceptionHandler.java
    │
    ├── main/resources/
    │   ├── application.yml
    │   ├── application-test.yml
    │   └── db/migration/
    │       ├── V1__create_hsm_config.sql
    │       ├── V2__create_hsm_users.sql
    │       ├── V3__create_hsm_keys.sql
    │       ├── V4__create_hsm_key_acls.sql
    │       ├── V5__create_hsm_audit_log.sql
    │       └── V6__add_token_prefix.sql
    │
    └── test/java/com/example/hsm/
        ├── AbstractIntegrationTest.java  One shared Testcontainers Postgres per JVM
        ├── TestDataSeeder.java           Bootstrap admin token (test profile only)
        ├── service/
        │   ├── CryptoEngineTest.java     @Tag("crypto")
        │   ├── MasterKeyServiceTest.java
        │   ├── KeyServiceTest.java       Lifecycle state machine + role-scoped listing
        │   ├── AuditServiceTest.java
        │   └── TokenServiceTest.java
        ├── controller/
        │   ├── BaseControllerIT.java     Auth helpers, PATCH-capable test client
        │   ├── KeyControllerIT.java      Failsafe integration tests (*IT.java)
        │   ├── CryptoControllerIT.java
        │   ├── AuditControllerIT.java
        │   ├── UserControllerIT.java
        │   └── OpenApiIT.java
        ├── security/
        │   ├── RbacEnforcementTest.java  @Tag("security")
        │   ├── AclEnforcementTest.java
        │   ├── KeyStateGuardTest.java
        │   ├── AuditIntegrityTest.java
        │   ├── AuthenticationServiceTest.java
        │   └── SecurityFilterTest.java
        └── exception/
            └── GlobalExceptionHandlerTest.java
```

---

## ⚠️ Known Limitations

This project is intentionally transparent about the gap between software emulation
and a real HSM.

| Limitation | Real HSM behaviour | This project |
|------------|-------------------|--------------|
| **Master key storage** | Locked inside tamper-resistant hardware; physically cannot be extracted | Derived master key lives in JVM heap; extractable from a heap dump |
| **Hardware tamper resistance** | Zeroises keys on physical intrusion | No hardware; protection is software-only |
| **Key export** | Controlled export with wrapping ceremonies | Not supported (intentional — eliminates attack surface) |
| **GCM IV collision** | Key rollover enforced by hardware counter | `SecureRandom` IV — statistically safe, but not counter-based |
| **Rate limiting** | Hardware throughput limits apply | No rate limiting in v1; Argon2id makes brute-force infeasible |
| **Audit chain forgery** | Append-only log in separate tamper-resistant storage | A DB admin can forge a consistent chain; document and accept |
| **Certifications** | FIPS 140-2/3, Common Criteria | None — educational project |

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [`docs/requirements.md`](docs/requirements.md) | Product Requirements Document — 12 user stories in EARS format, role-permission matrix, functional requirements FR-01–FR-10, NFRs, risk register, success metrics |
| [`docs/design.md`](docs/design.md) | Technical design — Mermaid architecture/ER/sequence diagrams, envelope encryption walkthrough, full API spec with JSON examples, STRIDE threat model table (10 threats × mitigation × test), 7 design decisions with alternatives rejected |
| [`docs/tasks.md`](docs/tasks.md) | Implementation checklist — 34 tasks across 9 phases, each traced to requirements with named test methods |
| [Swagger UI](http://localhost:8080/swagger-ui.html) | Live interactive API reference (app must be running) |
| [OpenAPI JSON](http://localhost:8080/v3/api-docs) | Machine-readable OpenAPI 3.0 spec |

---

## 🔧 Configuration Reference

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `HSM_MASTER_PASSPHRASE` | **Yes** | — | Startup passphrase; derives the master key via PBKDF2. Never logged. Never persisted. |
| `SPRING_DATASOURCE_URL` | No | `jdbc:postgresql://localhost:5432/hsmdb` | PostgreSQL JDBC URL |
| `SPRING_DATASOURCE_USERNAME` | No | `hsm` | DB username |
| `SPRING_DATASOURCE_PASSWORD` | No | `hsm` | DB password |
| `HSM_MASTER_KEY_ITERATIONS` | No | `310000` | PBKDF2 iteration count. Must be ≥ 310,000 or startup fails. | (Spring property `hsm.master-key.iterations`)
| `HSM_MASTER_PASSPHRASE` | **Yes** | — | Startup passphrase; derives the PBKDF2 master key. Never logged, never persisted. |

---

## 🤝 Contributing

1. Fork and create a branch: `git checkout -b feat/your-feature`
2. Follow the existing package structure and naming conventions.
3. Add tests — security boundary tests go in `src/test/.../security/` with `@Tag("security")`.
4. `./mvnw verify` must pass (coverage gates enforced).
5. Open a pull request — the CI pipeline runs automatically.

---

## 📜 License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

*Built as a portfolio project demonstrating secure-by-design engineering principles.*
*All cryptographic operations use only standard, audited libraries — never custom cryptography.*

</div>
