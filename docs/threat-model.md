# TrustGuard Threat Model

## 1. Protected Assets & Security Properties

| Asset | Security Property | Storage & Mechanism |
| --- | --- | --- |
| Protected Resource Bodies (`resources` & adapter `contents`) | Confidentiality & Authorization Integrity | Encrypted at rest in DB with AES-256-GCM under active key DEK; adapter protects state via `0600` file perms, HMAC integrity envelope, and strict deny-without-disclosure. |
| Device & Key-Version Private Keys (`ML-KEM-768`, `ML-DSA-65`) | Confidentiality & Non-Exportability | Stored outside ordinary DB columns in `ProtectedKeyStore` (`0600` + `AES-256-GCM` at-rest encryption via `TRUSTGUARD_KEYSTORE_MASTER_KEY`, required outside `local`/`test`); adapter never persists raw `key_material` or shared secrets. |
| Ephemeral Messaging Session Keys | Forward Secrecy (within stated RAM/GC limits) | Fresh one-time ephemeral ML-KEM-768 keypairs generated per message, deleted from `ProtectedKeyStore` upon verified receipt (`consumeAndErase`), and zeroized in byte arrays. |
| Identity, Device & Revocation State | Integrity & Monotonic Enforcement | Transactional updates across `devices`, `revocations`, `users.token_version`, and `simulated_nodes`; revocation version and `tokenVersion` invalidate active sessions/JWTs immediately. |
| Security Audit Trail (`audit_logs`) | Tamper Evidence & Injection Containment | Canonical JSON + SHA-256 hash chain from genesis (`seq_number`, `prev_hash`, `current_hash`) persisted in an isolated HikariCP pool so rolled-back business rejects still log security alerts/events. |
| Backup Snapshots (`backup_records`) | Integrity & Authenticity Before Restore | SHA-256 canonical digest + keyed `HMAC-SHA-256` (`hmac_sha256`) verified prior to any restore action (`ADMIN`-only). |

## 2. Adversaries

1. **Unauthorized External or Peer Caller**: Attempts cross-owner reads (`alice` reading `ledger-bob`), accesses without valid JWT, or calls `protected_read` with invalid/tampered keys.
2. **Compromised / Lost Enrolled Device**: Presents a previously valid device credential after the owner or administrator revokes it.
3. **Compromised Service / Lateral-Movement Actor**: Attempts multi-hop unexpected service edges (`reports -> billing -> archive -> identity`) or unauthorized role escalation (`user-blair` without `approvals.json`).
4. **Network / Replay / Tamper Adversary**: Replays captured `message_id` or `request_id`, modifies recipient identity or ciphertext, corrupts backup payloads, or alters single audit rows in storage.
5. **Privileged Database Compromise (Out-of-Scope Limit)**: Adversary with full write access to both the primary database and the local keystore/checkpoints.

## 3. Trust Boundaries

- **Client ↔ Spring Security API Boundary**: Bearer JWT enforces `alg == "HS256"`, `typ == "JWT"`, non-future `iat <= now + 60s`, DB authority lookup, and `tokenVersion`; `/api/v1/auth/login` applies composite `(username, clientIp)` lockout + per-IP spray throttling (`429`); `/auth/logout` bumps `tokenVersion`; admin-only endpoints (`/keys/**`, `/nodes/**`, `/backups/**`, `/audit/verify`, `/detection/evaluate`, `/sessions/run-tests`, `/crypto/verify-shor-resilience`) enforce `@PreAuthorize("hasRole('ADMIN')")` while read endpoints are strictly caller-scoped.
- **Node Enforcement Boundary (`simulated_nodes`)**: Policy check verifies node `currentRevocationVersion`, `device.status == ACTIVE`, committed key `cutoffTime`, FIPS 203 `ML-KEM-768` modulus (`< q = 3329`, non-zero), owner/service scope, and role permissions before releasing plaintext or computing `protected_read` proof.
- **Adapter Process Boundary (`track4_service.py`)**: Isolated per-process stdin/stdout JSON contract; `TRACK4_STATE_DIR` locks and HMAC-verifies state before every operation.
- **Detector ↔ Ground-Truth Boundary**: `DeterministicDetectionEngine` accepts only `events.csv` + `approvals.json`; `labels.csv` resides solely in `PracticeEvaluator` post-detection.

## 4. Assumptions

- Host OS and container isolate `TRACK4_STATE_DIR` and `0600` `ProtectedKeyStore` permissions from unprivileged users.
- Administrators act honestly when approving `approvals.json` changes and verifying backups/audit exports.
- Source clock offsets (`source_clock_offset_ms`) provided to the detector are known/calibrated; unmeasured clock skew remains an uncertainty interval.
- Simulated nodes run inside the same modular monolith process and model distributed state transitions rather than true asynchronous WAN partitions.

## 5. Defenses & Evidence Mapping

- **Unauthorized & Lost-Device Access**: Enforced in `team_app.py`, `DeviceService`, and `AccessControlService`; verified by `Track-4-Toolkit/validate.py` (`21/21`), `test_adapter.py` (`6/6`), `TrustGuardIntegrationTests` (`6/6`), and `SecurityHardeningRegressionTests` (`20/20`).
- **Key Rotation Quorum, Cutoff & Crash Recovery**: Enforced in `KeyManagementService` (`60 s` default grace period); verified for both committed `v2` persistence and interrupted uncommitted-rotation rollback by `CrashRecoveryIntegrationTest` (`2/2`).
- **Post-Quantum & Classical-Downgrade Resistance**: Enforced via `pqcrypto==0.4.0` (`ML-KEM-768`) and BouncyCastle `1.80` (`ML-KEM-768`, `ML-DSA-65`, `HKDF-SHA-256`, `AES-256-GCM`), FIPS 203 modulus validation, HS256 JWT algorithm pinning, and AES-256-GCM at-rest `ProtectedKeyStore`; verified by `PostQuantumCryptoServiceTest` (`4/4`) and `SecurityHardeningRegressionTests`.
- **Replay & Recipient Binding**: Enforced via `consumed_messages` unique constraint, inactive sender/recipient gates, and AES-GCM AAD + ML-DSA-65 verification before `consumeAndErase`; verified by `SessionService` and `SecurityHardeningRegressionTests`.
- **Tamper-Evident Audit, Log-Injection Containment & Backups**: Enforced via isolated `AuditLogService` hash chaining, keyed HMAC-SHA-256 `BackupRecoveryService`, and escaped single-entry logging; verified by `TrustGuardIntegrationTests`, `SecurityHardeningRegressionTests`, and `test_adapter.py`.

## 6. Exclusions and Remaining Risks

- **Same-Database Audit Chain Limit**: If an attacker gains full write control of MySQL and rewrites the entire chain + checkpoints, an in-DB hash chain cannot detect it without external anchoring/WORM storage.
- **JVM Memory Residency**: While byte arrays are zeroized (`Arrays.fill`), Java GC/JIT copies of strings/objects in heap memory are not strictly lockable without native `mlock` memory.
- **Sample Size Caveat**: The 22-event `practice/events.csv` dataset demonstrates functional rule behavior only and does not establish production precision/recall or throughput.
- **Simulated Nodes**: Nodes are database-backed state machines inside one Spring Boot monolith, not geographically distributed consensus replicas.
