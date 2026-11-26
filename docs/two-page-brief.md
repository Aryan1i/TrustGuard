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

TrustGuard combines a standalone Python 3.12 compatibility adapter (`track4_service.py`, `team_app.py`) with a Java 21 Spring Boot 3.4.5 modular monolith and a React 18 + Vite console. The Python adapter persists locked, HMAC-sealed state in `TRACK4_STATE_DIR` and implements `setup`, `read`, `revoke`, `audit`, and `protected_read` using `pqcrypto==0.4.0` (`ML-KEM-768`, raw 1184-byte key) + `HMAC-SHA-256`. The backend uses BouncyCastle `1.80` (`ML-KEM-768` FIPS 203, `ML-DSA-65` FIPS 204, `HKDF-SHA-256`, `AES-256-GCM`), Spring Security JWT authentication, `AuditLogService` (canonical JSON SHA-256 hash chaining), `BackupRecoveryService` (SHA-256 snapshot checks), `KeyManagementService` (`PREPARED→DISTRIBUTED→ACKNOWLEDGED→COMMITTED` with grace/cutoff enforcement), and `DeterministicDetectionEngine` (zero AI/ML; ingests `events.csv` + `approvals.json`). Working components include all adapter operations, quorum key rotation, cross-node revocation, messaging, backups, and crash recovery; simulated multi-node topology runs inside one JVM/DB rather than WAN hosts.

### Accessible five-minute fallback video link

**Video link:** `[INSERT PUBLIC 5-MIN DEMO VIDEO URL — confirm anonymous viewer access before final upload]`  
**Duration:** 5 minutes (follows `docs/demo-script.md`)  
**Access checked:** Verify anonymous viewing without login prior to Track 4 portal upload.

The walkthrough demonstrates: (1) official `validate.py` passing all 21 checks + `test_adapter.py` verifying real `ML-KEM-768` `protected_read`; (2) device revocation propagating across 3 simulated nodes in 7–11 ms while preserving peer `bob` and enrolling a replacement device; (3) blocked key commit on simulated node failure followed by quorum commit and post-cutoff `v1` rejection; (4) deterministic detection scoring 22/22 on `practice/events.csv` (`DENIED_ATTEMPT` for `evt-010..012`, `+2000 ms` clock-offset fix on `evt-015`); and (5) audit tamper mismatch detection, replay/recipient-binding rejection, and corrupted backup rejection.

**Observed outcome:** All 21 `validate.py` checks passed, 2/2 Python `ML-KEM-768` adapter tests passed, and 11/11 Spring Boot JUnit 5/Mockito tests (including crash-recovery restart) passed cleanly. See `docs/evidence-matrix.md`.

<div style="page-break-before: always;"></div>

## Page 2: One-page threat model

### Assets

1. **Protected Resource Bodies (`resources`, adapter `contents`)**: Require confidentiality and owner/policy authorization; encrypted in DB with `AES-256-GCM` under versioned DEKs.
2. **Device & Key-Version Private Keys (`ML-KEM-768`, `ML-DSA-65`)**: Require confidentiality; stored in isolated `0600` `ProtectedKeyStore` outside DB columns (`keystore://` references only).
3. **Ephemeral Session Keys**: Require forward secrecy via one-time prekey deletion on receipt.
4. **Revocation, Key Version & Session State**: Require integrity and monotonic version persistence across restarts.
5. **Audit Logs & Backups**: Require tamper-evidence (`SHA-256` hash chain) and integrity verification before restore.

### Adversaries

- **Unauthorized External / Peer Caller**: Attempts cross-owner reads, unauthenticated API calls, or actor-name spoofing.
- **Lost / Compromised Device Holder**: Attempts reads or session resumption after device revocation.
- **Compromised Service / Lateral-Movement Actor**: Attempts unapproved role escalation or multi-edge probing (`reports→billing→archive→identity`).
- **Network / Replay / Tamper Adversary**: Replays `message_id`/`request_id`, alters intended AAD recipient or ciphertext, or corrupts backups/single audit rows.
- **Full-DB Compromiser (Excluded Limit)**: Attacker with root DB + filesystem write privileges able to rewrite hashes and checkpoints simultaneously.

### Trust boundaries

1. **Client ↔ Spring Security JWT Boundary**: `JwtAuthenticationFilter` enforces verified bearer identity; non-admin actor overrides are rejected (`403`), and admin simulations are explicitly marked `demoSimulation=true`.
2. **Enforcement Node Boundary (`simulated_nodes`)**: Verifies node `currentRevocationVersion`, `device.status`, key `cutoffTime`, and role permissions before releasing plaintext or `protected_read` proof.
3. **Python Adapter Boundary (`track4_service.py`)**: Per-process JSON `stdin`/`stdout`, `fcntl.flock`, atomic `fsync` + rename, HMAC-sealed state, zero secret logging.
4. **Detector ↔ Ground-Truth Boundary**: `DeterministicDetectionEngine` consumes only `events.csv` + `approvals.json`; `labels.csv` is strictly post-detection.

### Assumptions

- Host OS/container enforces `0600` filesystem isolation for `TRACK4_STATE_DIR` and `ProtectedKeyStore`.
- Administrators faithfully manage `approvals.json` and review audit verification failures.
- Supplied `source_clock_offset_ms` values reflect calibrated drift; unmeasured skew remains bounded uncertainty.

### Defenses

- **Lost Device & Cross-Owner Access** → `AccessControlService`, `DeviceService`, and `team_app.py` deny without disclosing content (`validate.py`, `TrustGuardIntegrationTests`).
- **Premature Rotation & Stale Keys** → `KeyManagementService` enforces 3-node ack quorum and post-cutoff key rejection.
- **Replay, Tamper & Recipient Swap** → `consumed_messages` unique constraint, `ML-DSA-65` signatures, and `AES-256-GCM` AAD binding (`SessionService` 7/7 tests).
- **Ephemeral Forward Secrecy** → One-time ephemeral `ML-KEM-768` prekeys erased on receipt + byte-array zeroization (`PostQuantumCryptoServiceTest`).
- **Audit & Backup Tampering** → `AuditLogService` first-mismatch detection and `BackupRecoveryService` `SHA-256` verification before restore.

### Exclusions and remaining risks

Largest remaining risk: **single-host storage trust** — an adversary with full DB and local `0600` keystore access can rewrite audit chains or steal static keys, requiring external WORM audit anchoring and HSMs in production. Additionally, JVM garbage-collected copies cannot guarantee `mlock`-grade RAM erasure, simulated nodes do not model WAN network partitions, and the 22-event practice dataset demonstrates rule logic only without establishing production precision or scale throughput.
