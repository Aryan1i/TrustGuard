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
│   └── two-page-brief.pdf     # Rendered two-page brief PDF
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

First run the full JUnit 5 & Mockito test suite:

```sh
cd TrustGuard/backend
mvn test
```

Start the backend server (MySQL default profile):

```sh
cd TrustGuard/backend
mvn spring-boot:run
```

Or run with persistent file-backed local MySQL-compatibility mode:

```sh
cd TrustGuard/backend
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

Backend runs on `http://localhost:8080`.

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

### Synthetic Demo Identities

The application seeds four synthetic hackathon users (`alice`, `bob`, `charlie`, `admin`) with BCrypt-hashed credentials. The synthetic demo password defaults to `TrustGuard!Demo2026` (overridable via `TRUSTGUARD_DEMO_PASSWORD`) and can be entered directly or triggered via the one-click synthetic identity buttons on the sign-in screen (which perform a real `POST /api/v1/auth/login` JWT exchange).

---

## 5. Key REST API Endpoints (`/api/v1`)

| Endpoint | Purpose | Example Payload |
| --- | --- | --- |
| `POST /api/v1/auth/login` | Issue JWT bearer token | `{"username":"admin","password":"TrustGuard!Demo2026"}` |
| `GET /api/v1/dashboard` | Live dashboard telemetry & metrics | — |
| `GET /api/v1/users` / `GET /api/v1/devices` | List synthetic users & devices | — |
| `POST /api/v1/devices/enrol` | Enroll or replace device with ML-KEM-768 + ML-DSA-65 | `{"ownerUsername":"alice","deviceName":"Alice Replacement"}` |
| `POST /api/v1/devices/{id}/revoke` | Revoke device & propagate to 3 simulated nodes | `{"reason":"Lost laptop"}` |
| `GET /api/v1/resources` / `POST /api/v1/access/check` | Policy check + optional ML-KEM-768 `protectedRead` | `{"sourceService":"portal","targetService":"vault","resourceKey":"brief-alice","action":"read"}` |
| `POST /api/v1/keys/prepare` / `acknowledge` / `commit` | Quorum-gated key lifecycle (`gracePeriodSeconds`) | `{"keyAlias":"trustguard-data-key","gracePeriodSeconds":60}` |
| `GET /api/v1/audit` / `POST /api/v1/audit/verify` | Hash-chained audit log & first-mismatch check | — |
| `POST /api/v1/detection/evaluate` / `GET /api/v1/alerts` | Deterministic rule engine on 22 practice events | — |
| `POST /api/v1/messages` / `POST /api/v1/messages/{id}/receive` | Ephemeral ML-KEM-768 + HKDF + AES-GCM + ML-DSA-65 | `{"recipientUsername":"bob","plaintext":"Hello Bob"}` |
| `POST /api/v1/backups/create` / `verify` / `restore` | SHA-256 checksum snapshot & verified restore | — |
| `POST /api/v1/sessions/run-tests` | Run 7 repeatable session & delivery checks | — |

---

## 6. Known Limitations

1. **Single-Database Hash Chain**: `audit_logs` hash chaining detects partial row tampering by non-privileged actors but cannot stop an adversary with full database write access who rewrites all rows and external checkpoints.
2. **Practice Dataset Scope**: `practice/events.csv` contains 22 synthetic events for functional verification only and cannot establish production precision, recall, false-positive rate, or throughput.
3. **Simulated Enforcement Nodes**: `node-alpha`, `node-beta`, and `node-gamma` are database-backed simulated nodes within one modular monolith, not independent distributed processes over a partitionable WAN.
4. **JVM Memory Residency**: Ephemeral keys are removed from `ProtectedKeyStore` upon message receipt and byte arrays are zeroized, but JVM GC/JIT copies cannot be hardware-locked (`mlock`) in pure Java.
5. **Python Compatibility Adapter Scope**: The root `track4_service.py` adapter uses `TRACK4_STATE_DIR` with `0600` file permissions and HMAC-SHA-256 integrity sealing; it relies on OS/container filesystem isolation for confidentiality of `contents`.
