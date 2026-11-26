# TrustGuard — Post-Quantum Security, Access Control, Key Lifecycle & Threat Detection

**Yugaantar DevForge Hackathon | Track 4: Trust, but verify**

TrustGuard is a modular-monolith security platform combining:
- A standalone **Track 4 Python 3.12 compatibility adapter** (`track4_service.py` + `team_app.py`) with `ML-KEM-768` (`pqcrypto==0.4.0`) + `HMAC-SHA-256` `protected_read`, atomic `TRACK4_STATE_DIR` persistence, HMAC-verified state integrity, and SHA-256 hash-chained audit logs.
- A **Java 21 + Spring Boot** backend (`backend/`) enforcing authenticated JWT identity, `ML-KEM-768` / `ML-DSA-65` / `HKDF-SHA-256` / `AES-256-GCM` cryptography (BouncyCastle 1.80), isolated `0600` private key storage (`ProtectedKeyStore`), quorum-gated key rotation with cutoff enforcement, cross-node device revocation, deterministic rule-based threat detection (zero AI/ML), SHA-256 hash-chained audit logging, and checksum-verified backup/crash recovery.
- A **React + Vite** security operations dashboard (`frontend/`) connected via Axios to live `/api/v1/*` REST APIs.

---

## Repository Structure

```text
TrustGuard/
├── track4_service.py          # Official Track 4 Python CLI JSON entry point
├── team_app.py                # Standalone Track 4 application dispatch & ML-KEM-768 logic
├── requirements.txt           # Python runtime dependency (pqcrypto==0.4.0)
├── threat-model.json          # Root-level Track 4 asset/boundary metadata
├── database/
│   └── schema.sql             # Normalized MySQL 8+ DDL (16 tables)
├── backend/                   # Java 21 + Spring Boot 3.4.5 modular monolith
│   ├── pom.xml
│   └── src/
├── frontend/                  # React 18 + Vite 5 + Axios dashboard
├── tests/
│   └── test_adapter.py        # Python adapter & ML-KEM-768 subprocess tests
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── evidence-matrix.md     # 12 Track 4 security goals with measured/partial statuses
│   ├── demo-script.md         # Five-minute walkthrough script
│   ├── two-page-brief.md      # Two-page submission brief source
│   └── two-page-brief.pdf     # Rendered two-page brief PDF (<= 2 pages)
└── README.md
```

---

## Prerequisites

- **Python 3.12** with `pqcrypto==0.4.0`
- **Java 21+** and **Maven 3.9+**
- **Node.js 20+ / 22+** and **npm**
- **MySQL 8+/9+** (or use Spring Boot `local` profile for file-backed MySQL-compatible H2 persistence without a local MySQL password)

---

## 1. Python Compatibility Adapter Setup & Validator

Create a Python 3.12 virtual environment and install `pqcrypto==0.4.0`:

```sh
cd TrustGuard
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Run the Python adapter integration tests (tests `setup`, `read`, `revoke`, `audit`, `protected_read` with real `ML-KEM-768` decapsulation + `HMAC-SHA-256` verification, replay rejection, and tamper rejection):

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Run the official Track 4 public lost-device validator from the separate `Track-4-Toolkit` directory:

```sh
cd ../Track-4-Toolkit
../TrustGuard/.venv/bin/python validate.py --entry ../TrustGuard/track4_service.py
```

---

## 2. Database Setup (MySQL)

Initialize the normalized schema in MySQL:

```sh
mysql -u root -p < TrustGuard/database/schema.sql
```

Configure MySQL connection variables (or use defaults in `backend/src/main/resources/application.yml`):

```sh
export DB_URL="jdbc:mysql://localhost:3306/trustguard?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&createDatabaseIfNotExist=true"
export DB_USERNAME="root"
export DB_PASSWORD="<your-mysql-password>"
```

> **Quick Local Mode (no MySQL server credentials required):** Pass `--spring.profiles.active=local` when starting Spring Boot to use persistent file-backed H2 in `MODE=MySQL` (`./data/trustguard-local-db`).

---

## 3. Run the Backend (Spring Boot)

First run the full JUnit 5 suite (35 tests across 5 suites: unit, integration, crash recovery, PQC, and security regression):

```sh
cd TrustGuard/backend
mvn clean test
```

Configure required security secrets before running outside `local`/`test` profiles (`prod`):

```sh
export TRUSTGUARD_JWT_SECRET="<at-least-32-bytes-random-secret>"
export TRUSTGUARD_KEYSTORE_MASTER_KEY="<at-least-32-bytes-aes-256-gcm-master-key>"
# Demo seeding is disabled outside local/test unless explicitly opted in with >=12 char passphrase:
# export TRUSTGUARD_DEMO_SEED_ENABLED=true
# export TRUSTGUARD_DEMO_PASSWORD="<strong-demo-passphrase>"
```

Start the backend server (MySQL default profile):

```sh
cd TrustGuard/backend
mvn spring-boot:run
```

Or run with persistent file-backed local MySQL-compatibility mode (sets `TRUSTGUARD_DEMO_PASSWORD` or generates an ephemeral 24-character passphrase logged at startup):

```sh
cd TrustGuard/backend
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

Backend runs on `http://localhost:8080`. Defaults include a `60 s` key rotation grace period (`trustguard.demo.default-grace-seconds: 60`) and `±30,000 ms` (`±30 s`) detector clock-offset plausibility bounds.

---

## 4. Run the Frontend (React + Vite)

```sh
cd TrustGuard/frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api/*` directly to `http://localhost:8080`.

### Deploying Frontend to Vercel

[frontend/vercel.json](frontend/vercel.json) is configured for Vite SPA routing (`dist/`). Set Vercel's **Root Directory** to `frontend` (Framework Preset: `Vite`).
- If `VITE_API_BASE_URL` is **not** set on Vercel (static frontend only), the app automatically activates browser persistence and WebCrypto security evaluation so authentication and all 9 views work immediately.
- To connect the full Java 21 / Spring Boot / BouncyCastle `ML-KEM-768` & `ML-DSA-65` backend, deploy `backend/` to a JVM host (Render, Railway, Fly.io, or Docker) and set `VITE_API_BASE_URL` in Vercel environment variables.

### Synthetic Demo Identities & Security Hardening

In `local` profile (`-Dspring-boot.run.profiles=local`), `DataInitializer` seeds four synthetic accounts (`alice`, `bob`, `charlie`, `admin`) using `TRUSTGUARD_DEMO_PASSWORD` (or a generated ephemeral 24-character password printed to the local startup log—no hardcoded password literals exist in application or UI source code). Outside `local`/`test`, demo seeding is disabled unless `trustguard.demo.seed-enabled=true` and an explicit `TRUSTGUARD_DEMO_PASSWORD` (`>= 12` bytes) are supplied. In `frontend/` standalone offline mode, an ephemeral passphrase is stored per-session in `sessionStorage` (overridable at build time via `VITE_DEMO_PASSWORD`).

---

## 5. Key REST API Endpoints (`/api/v1`)

| Endpoint | Role / Scope | Purpose | Example Payload |
| --- | --- | --- | --- |
| `POST /api/v1/auth/login` | Public (rate-limited `(username, IP)` + IP spray) | Issue HS256 `typ=JWT` bearer token | `{"username":"admin","password":"<configured-passphrase>"}` |
| `POST /api/v1/auth/logout` | Authenticated | Increment `tokenVersion` & invalidate JWT | — |
| `GET /api/v1/dashboard` | Scoped (`ADMIN` global / `USER` caller) | Dashboard telemetry & metrics | — |
| `GET /api/v1/users` / `GET /api/v1/users/recipients` | Scoped (`USER` sees self on `/users`, minimal usernames on `/recipients`) | User directory & messaging recipients | — |
| `GET /api/v1/devices` / `enrol` / `{id}/revoke` | Scoped (`USER` replacement-only + bumps `tokenVersion`) | PQ device lifecycle & 3-node revocation | `{"ownerUsername":"alice","deviceName":"Alice Laptop","replacesDeviceId":1}` |
| `GET /api/v1/resources` / `POST /api/v1/access/check` / `events` | Scoped (`USER` own resources/events) | Policy evaluation + FIPS 203 `protectedRead` | `{"sourceService":"portal","targetService":"vault","resourceKey":"brief-alice","action":"read"}` |
| `GET /api/v1/nodes` / `GET/POST /api/v1/keys/**` | `ADMIN` only | Cluster nodes & quorum key rotation (`gracePeriodSeconds`) | `{"keyAlias":"trustguard-data-key","gracePeriodSeconds":60}` |
| `GET /api/v1/audit` / `POST /api/v1/audit/verify` | `/audit` scoped; `/verify` `ADMIN` only | Hash-chained audit log & integrity check | — |
| `GET /api/v1/detection/latest` / `POST /evaluate` / `GET /alerts` | `/evaluate` `ADMIN`; `/alerts` caller-scoped | Deterministic detector (`n=22`) & live alerts | — |
| `GET/POST /api/v1/messages` / `{id}/receive` | Caller-scoped (sender/recipient) | Ephemeral `ML-KEM-768` + `HKDF` + `AES-GCM` + `ML-DSA-65` | `{"recipientUsername":"bob","plaintext":"Hello Bob"}` |
| `GET/POST /api/v1/backups/**` | `ADMIN` only | SHA-256 + HMAC-SHA-256 verified snapshot & restore | — |
| `GET/POST /api/v1/sessions/**` / `run-tests` | Caller-scoped; `/run-tests` `ADMIN` | Session open/close/resume & 7 verification checks | — |
| `GET /api/v1/crypto/pqc-status` / `POST /verify-shor-resilience` | `/pqc-status` Auth; `/verify-shor-resilience` `ADMIN` | PQC algorithm inventory & live Shor-resistance checks | — |

---

## 6. Known Limitations

1. **Single-Database Hash Chain**: `audit_logs` hash chaining detects partial row tampering by non-privileged actors but cannot stop an adversary with full database write access who rewrites all rows and external checkpoints.
2. **Practice Dataset Scope**: `practice/events.csv` contains 22 synthetic events for functional verification only and cannot establish production precision, recall, false-positive rate, or throughput.
3. **Simulated Enforcement Nodes**: `node-alpha`, `node-beta`, and `node-gamma` are database-backed simulated nodes within one modular monolith, not independent distributed processes over a partitionable WAN.
4. **JVM Memory Residency**: Ephemeral keys are removed from `ProtectedKeyStore` upon message receipt and byte arrays are zeroized, but JVM GC/JIT copies cannot be hardware-locked (`mlock`) in pure Java.
5. **Python Compatibility Adapter Scope**: The root `track4_service.py` adapter uses `TRACK4_STATE_DIR` with `0600` file permissions and HMAC-SHA-256 integrity sealing; it relies on OS/container filesystem isolation for confidentiality of `contents`.
