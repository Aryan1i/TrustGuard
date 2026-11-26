# TrustGuard Architecture

**Track 4: Trust, but verify — Yugaantar DevForge Hackathon**

## 1. System Overview

TrustGuard is a modular-monolith post-quantum identity, access control, key lifecycle, secure messaging, tamper-evident audit, backup recovery, and deterministic threat detection platform. It consists of three coordinated components inside a single repository:

1. **Standalone Track 4 Compatibility Adapter (`track4_service.py` + `team_app.py`)**
   - Runs as a fresh Python 3.12 subprocess per JSON request (`stdin` → `stdout`, diagnostics to `stderr`).
   - Persists state atomically (`fsync` + `os.replace`, `0600` file permissions, `fcntl.flock` concurrency lock) under `TRACK4_STATE_DIR` (falling back to OS temp directory).
   - Protects persisted state with an HMAC-SHA-256 envelope tag and SHA-256 hash-chained audit records.
   - Implements `setup`, `read`, `revoke`, `audit`, and `protected_read` using `pqcrypto==0.4.0` (`pqcrypto.kem.ml_kem_768`) and `HMAC-SHA-256` challenge proofs without ever disclosing `key_material`, shared secrets, or denied resource bodies.

2. **Java 21 / Spring Boot Core Platform (`backend/`)**
   - Modular package architecture: `config`, `controller`, `dto`, `entity`, `repository`, `service`, `security`, `crypto`, `detection`, `audit`, `recovery`, `messaging`, `metrics`, `exception`, `util`.
   - **Authentication & Identity (`security`)**: Stateless Bearer JWT (`HMAC-SHA-256` signed via `ProtectedKeyStore`), BCrypt password verification for synthetic users (`alice`, `bob`, `charlie`, `admin`), and strict server-side principal enforcement (`SecurityContextHolder`).
   - **Post-Quantum Crypto (`crypto`)**: BouncyCastle `1.80` (`ML-KEM-768` FIPS 203, `ML-DSA-65` FIPS 204, `HKDF-SHA-256`, `AES-256-GCM`). Raw private keys and DEKs are stored in an isolated `0600` keystore (`ProtectedKeyStore`) referenced via opaque `keystore://...` identifiers rather than ordinary database columns.
   - **Key Lifecycle (`KeyManagementService`)**: Enforces `PREPARED → DISTRIBUTED → ACKNOWLEDGED → COMMITTED` across three simulated nodes (`node-alpha`, `node-beta`, `node-gamma`), blocks commit if any node fails or has not acknowledged, enforces explicit grace windows and hard cutoff rejection on retired key versions, and re-wraps protected resources on commit.
   - **Device & Revocation Lifecycle (`DeviceService`)**: Enrolls replacement/new devices with `ML-KEM-768` + `ML-DSA-65` keypairs, records monotonic `revocations` versions, propagates revocations across all simulated nodes, measures propagation latency, and preserves unaffected peers.
   - **Deterministic Threat Detection (`detection`)**: Purely deterministic rules (no AI/ML). Consumes `events.csv` + `approvals.json` without reading `labels.csv`, adjusts `source_clock_offset_ms`, preserves receipt vs event ordering, distinguishes denied lateral-movement candidates from confirmed compromise and isolated denials, and evaluates confusion metrics strictly post-detection.
   - **Tamper-Evident Audit & Backup Recovery (`audit`, `recovery`)**: Canonical JSON + SHA-256 hash-chained `audit_logs` with first-mismatch chain verification, plus SHA-256-verified snapshot backups (`backup_records`, `backup_items`) that reject corrupted restores and monotonically retain committed keys and revocations.

3. **React + Vite Security Operations Console (`frontend/`)**
   - Clean white-surface enterprise dashboard with a dark navy left sidebar (`Dashboard`, `Devices`, `Key Management`, `Access Monitor`, `Threat Detection`, `Audit Logs`, `Secure Messaging`, `Backup & Recovery`, `Settings`).
   - Uses Axios (`src/api.js`) against live `/api/v1/*` endpoints.

## 2. Data Model & Persistence

Normalized MySQL 8+ schema (`database/schema.sql`) with 16 tables (`users`, `devices`, `resources`, `role_permissions`, `access_events`, `key_versions`, `simulated_nodes`, `node_key_acknowledgements`, `revocations`, `audit_logs`, `security_alerts`, `secure_messages`, `consumed_messages`, `backup_records`, `backup_items`, `session_records`), foreign keys, unique constraints (`request_id`, `message_id`, `seq_number`, `(key_alias, version_number)`), and millisecond UTC timestamps. Local runs also support file-persistent H2 in MySQL compatibility mode via `--spring.profiles.active=local`.
