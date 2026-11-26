# Trust, but verify — Two-Page Project Brief

## Page 1: USP, architecture, and fallback video

**Project:** TrustGuard  
**Team:** TheLastCommit  
**Repository and commit:** https://github.com/Aryan1i/TrustGuard (main branch)  
**Demo entry point:** `python validate.py --entry ../TrustGuard/track4_service.py` (adapter) | `http://localhost:5173` (UI)

### Unique selling proposition (USP)

TrustGuard protects sensitive organizational documents, device identities, and inter-device communications against lost devices, key staleness, and noisy alert triage for zero-trust security teams. Unlike practice mocks that trust caller-supplied identities or store plaintext keys, TrustGuard enforces server-authenticated JWT identity, keeps post-quantum private keys out of ordinary database columns, requires multi-node quorum acknowledgements before committing rotated keys, and runs an independent deterministic threat detector that never reads ground-truth labels. Every access decision, revocation propagation latency, hash-chain verification mismatch, and ML-KEM-768 proof is directly measured and reproducible.

### Architecture

```text
[React/Vite UI] --JWT/HTTPS--> [Spring Boot Monolith] <--> [MySQL / H2-MySQL Mode (16 tables)]
                                   |         |
                  [ProtectedKeyStore 0600]  [3 Simulated Nodes: alpha/beta/gamma]
[Track 4 Worker] --stdin/stdout--> [track4_service.py + team_app.py (pqcrypto 0.4.0 ML-KEM-768)]
```

TrustGuard combines a standalone Python 3.12 compatibility adapter (`track4_service.py`, `team_app.py`) with a Java 21 Spring Boot 3.4.5 modular monolith and a React 18 + Vite console. The Python adapter persists locked, HMAC-sealed state in `TRACK4_STATE_DIR` and implements `setup`, `read`, `revoke`, `audit`, and `protected_read` using `pqcrypto==0.4.0` (`ML-KEM-768`, FIPS 203 modulus-checked 1184B key) + `HMAC-SHA-256`. The backend uses BouncyCastle `1.80` (`ML-KEM-768`, `ML-DSA-65`, `HKDF-SHA-256`, `AES-256-GCM`), hardened JWT auth (`alg=HS256`, `typ=JWT`, `tokenVersion`, `(username, clientIp)` rate limiting, `/api/v1/auth/logout`, env-configured secrets/demo passphrase), `ProtectedKeyStore` (`0600` + AES-256-GCM at-rest `TRUSTGUARD_KEYSTORE_MASTER_KEY`), `AuditLogService` (isolated HikariCP pool SHA-256 hash chain + log-injection safety), `BackupRecoveryService` (SHA-256 + keyed `HMAC-SHA-256`), `KeyManagementService` (`PREPARED→DISTRIBUTED→ACKNOWLEDGED→COMMITTED`, default `60 s` grace), and `DeterministicDetectionEngine` (zero AI/ML; `±30,000 ms` clock window; slow-and-low `24h` correlation). Working controls cover both `USER` and `ADMIN` scoping across all 9 UI views; simulated nodes run in one JVM/DB rather than WAN hosts.

### Accessible five-minute fallback video link

**Video link:** `[INSERT PUBLIC 5-MIN DEMO VIDEO URL — confirm anonymous viewer access before final upload]`  
**Duration:** 5 minutes (follows `docs/demo-script.md`)  
**Access checked:** Verify anonymous viewing without login prior to Track 4 portal upload.

The walkthrough demonstrates: (1) `validate.py` passing `21/21` checks + `test_adapter.py` (`6/6`, `1.993 s`) verifying `ML-KEM-768` `protected_read` and log-injection containment; (2) device revocation across `3/3` nodes (`7–11 ms` measured live propagation) + immediate `tokenVersion` JWT invalidation while preserving peer `bob`; (3) blocked key commit during simulated outage, quorum commit (`60 s` default grace / `0 s` cutoff test), and crash-recovery persistence for both committed `v2` and uncommitted-rotation rollback (`2.430 s`); (4) deterministic detection scoring `22/22` in `0.006 s` (`F1=1.0`, `falseAlertsPer1000Benign=0.0`, `n=22` caveat, `±30,000 ms` clock-skew bounds, slow-and-low probes); and (5) audit tamper mismatch detection, HMAC+SHA-256 backup rejection, and replay/recipient/inactive-sender blocking.

**Observed outcome:** `21/21` `validate.py` checks (`+ 7/7` toolkit unit tests), `6/6` Python `ML-KEM-768` tests, `35/35` Spring Boot JUnit 5 tests (`58.379 s`), and Vite build (`1.11 s`) passed cleanly. See `docs/evidence-matrix.md`.

<div style="page-break-before: always;"></div>

## Page 2: One-page threat model

### Assets

1. **Protected Resource Bodies (`resources`, adapter `contents`)**: Require confidentiality and owner/policy authorization; encrypted in DB with `AES-256-GCM` under versioned DEKs.
2. **Device & Key-Version Private Keys (`ML-KEM-768`, `ML-DSA-65`)**: Require confidentiality; stored in isolated `0600` `ProtectedKeyStore` encrypted via `AES-256-GCM` (`TRUSTGUARD_KEYSTORE_MASTER_KEY`).
3. **Ephemeral Session Keys**: Require forward secrecy via one-time prekey deletion (`consumeAndErase`) only after recipient/signature checks pass.
4. **Revocation, Key Version & Session State**: Require monotonic persistence (`revocationVersion`, `tokenVersion`) across crashes/restarts.
5. **Audit Logs & Backups**: Require tamper-evidence (`SHA-256` hash chain, injection containment) and keyed authenticity (`SHA-256` + `HMAC-SHA-256`) before restore.

### Adversaries

- **Unauthorized External / Peer Caller**: Attempts cross-owner reads, unauthenticated API calls, or actor-name spoofing.
- **Lost / Compromised Device Holder**: Attempts reads or session resumption after device revocation.
- **Compromised Service / Lateral-Movement Actor**: Attempts unapproved role escalation or multi-edge probing (`reports→billing→archive→identity`).
- **Network / Replay / Tamper Adversary**: Replays `message_id`/`request_id`, alters intended AAD recipient or ciphertext, or corrupts backups/single audit rows.
- **Full-DB Compromiser (Excluded Limit)**: Attacker with root DB + filesystem write privileges able to rewrite hashes and checkpoints simultaneously.

### Trust boundaries

1. **Client ↔ Spring Security JWT Boundary**: Enforces `alg=HS256`, `typ=JWT`, non-future `iat`, DB roles, `tokenVersion`, `(username, clientIp)` throttling, `ADMIN` RBAC on `/keys/**`/`/nodes/**`/`/backups/**`/`/audit/verify`, and caller-scoped reads.
2. **Enforcement Node Boundary (`simulated_nodes`)**: Verifies node `currentRevocationVersion`, `device.status=ACTIVE`, committed key `cutoffTime`, FIPS 203 `< q=3329` modulus check, and role permissions before releasing plaintext or `protected_read` proof.
3. **Python Adapter Boundary (`track4_service.py`)**: Per-process JSON `stdin`/`stdout`, `fcntl.flock`, atomic `fsync` + rename, HMAC-sealed state, zero secret logging.
4. **Detector ↔ Ground-Truth Boundary**: `DeterministicDetectionEngine` consumes only `events.csv` + `approvals.json`; `labels.csv` is strictly post-detection.

### Assumptions

- Host OS/container enforces `0600` filesystem isolation for `TRACK4_STATE_DIR` and `ProtectedKeyStore`.
- Administrators faithfully manage `approvals.json` and review audit verification failures.
- Supplied `source_clock_offset_ms` values reflect calibrated drift; unmeasured skew remains bounded uncertainty.

### Defenses

- **Lost Device & Cross-Owner Access** → `AccessControlService`, `DeviceService`, `team_app.py` (`validate.py` `21/21`, `test_adapter.py` `6/6`, `TrustGuardIntegrationTests` `6/6`).
- **Premature Rotation, Stale Keys & Crash Recovery** → `KeyManagementService` (`60 s` grace, 3-node ack quorum, `CrashRecoveryIntegrationTest` `2/2` covering committed `v2` & uncommitted rollback).
- **Replay, Recipient Swap, & Shor/Downgrade Resistance** → `consumed_messages`, `ML-DSA-65` + `AES-256-GCM` AAD, inactive-sender/recipient blocks, `ML-KEM-768` FIPS 203 check, HS256 JWT pinning (`PostQuantumCryptoServiceTest` `4/4`, `SecurityHardeningRegressionTests` `20/20`).
- **Ephemeral Forward Secrecy & Session Control** → One-time `ML-KEM-768` prekeys erased on verified receipt + byte-array zeroization; active-device session open/resume enforcement.
- **Audit, Injection & Backup Tampering** → Isolated-pool `AuditLogService` hash chain + single-entry log-injection containment and keyed `HMAC-SHA-256` `BackupRecoveryService`.

### Exclusions and remaining risks

Largest remaining risk: **single-host storage trust** — an adversary with full DB and local `0600` keystore access can rewrite audit chains or steal static keys, requiring external WORM audit anchoring and HSMs in production. Additionally, JVM garbage-collected copies cannot guarantee `mlock`-grade RAM erasure, simulated nodes do not model WAN network partitions, and the 22-event practice dataset demonstrates rule logic only without establishing production precision or scale throughput.
