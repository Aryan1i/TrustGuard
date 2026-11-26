# TrustGuard 5-Minute Demo Script

**Total Runtime:** ~5:00 minutes

## Minute 0:00 – 0:45 | Problem & Official Track 4 Adapter Validation
1. **Narrate the problem**: Lost devices, stale keys, replayed messages, and noisy SOC logs that conflate denied probing with actual compromise.
2. **Terminal demonstration**:
   - Run the official toolkit validator against the root-level Python compatibility adapter:
     ```sh
     cd Track-4-Toolkit
     ../TrustGuard/.venv/bin/python validate.py --entry ../TrustGuard/track4_service.py
     ```
   - Point out that each request spawns a fresh process, persists state atomically under `TRACK4_STATE_DIR`, hides `key_material`, denies the revoked owner without disclosing content, preserves peer access, and correlates `audit` by `request_id`.
   - Run `../TrustGuard/.venv/bin/python -m unittest discover -s ../TrustGuard/tests -v` to show real `ML-KEM-768` (`pqcrypto==0.4.0`) encapsulation + `HMAC-SHA-256` proof verification in `protected_read`.

## Minute 0:45 – 1:45 | Dashboard, Authentication & Lost-Device Flow
1. Open the React UI (`http://localhost:5173`) and sign in via the Spring Security JWT login screen (`admin`).
2. **Dashboard**: Highlight active users (`4`), active devices (`4`), active key version (`v1` `ML-KEM-768 + AES-256-GCM`), 3/3 simulated nodes, audit chain `Verified`, and measured metrics with explicit `n = 22` dataset caveat.
3. **Devices (`/devices`)**:
   - Revoke `dev-alice-01` with reason `"Lost commuter laptop"`.
   - Show the recorded revocation version, `3/3` simulated nodes enforced, measured propagation latency (`ms`), and enroll a replacement device for Alice (`Alice Replacement Laptop`) linking `replacedByDeviceId`.
4. **Access Monitor (`/access`)**:
   - Test **Revoked Device** on `node-beta`: returns `DENY` with zero content disclosure and logs a `revoked_identity_activity` alert.
   - Test **Correct Owner** for `bob` (`ledger-bob`): returns `ALLOW`, confirming unaffected peer access.

## Minute 1:45 – 2:45 | Post-Quantum Key Rotation & Cutoff Enforcement
1. Navigate to **Key Management (`/keys`)**.
2. Click **Simulate Ack Failure** on `node-gamma` (`DEGRADED`).
3. Click **Prepare & Distribute New Key** (`gracePeriodSeconds = 0`).
4. Click **Acknowledge All** → `node-gamma` shows `FAILED`. Click **Commit Key** → demonstrate **409 Conflict (`ACK_QUORUM_NOT_MET`)** blocking premature commit.
5. Recover `node-gamma`, click **Acknowledge All** (`3/3 ACKNOWLEDGED`), and **Commit Key** → `v2` becomes `COMMITTED`, `v1` becomes `RETIRED` with exact `cutoffTime`.
6. Return to **Access Monitor**, enter `Key Version Override = 1`, and verify old key `v1` is **rejected after cutoff**.

## Minute 2:45 – 3:45 | Deterministic Threat Detection (22 Practice Events)
1. Navigate to **Threat Detection (`/threats`)** and click **Re-run Deterministic Evaluation**.
2. Highlight that **zero AI/ML** is used and `labels.csv` is excluded from detection logic.
3. Walk through key detections:
   - `evt-003` & `evt-004`: Approved role change matching `approvals.json` (`change-100`).
   - `evt-008` & `evt-009`: Unauthorized role change for `user-blair` + follow-up allowed read (`CRITICAL`).
   - `evt-010`–`evt-012`: Candidate lateral movement grouped by `sess-worker` / `flow-005` and explicitly tagged `DENIED_ATTEMPT` (not confirmed compromise).
   - `evt-020`: Isolated denial (not lateral movement).
   - `evt-013` / `evt-014` & `evt-015`: Out-of-order receipt preserved and `+2000 ms` clock offset corrected to `09:06:01Z` (`200 ms` delay).

## Minute 3:45 – 4:30 | Secure Messaging, Audit Logs & Backup Recovery
1. **Secure Messaging (`/messaging`)**:
   - Send an `ML-KEM-768` + `HKDF-SHA-256` + `AES-256-GCM` + `ML-DSA-65` message, then click **Run 7 Verification Tests** to display live `MEASURED_PASS` results for replay rejection, AAD recipient binding, ciphertext tamper rejection, forward-secrecy ephemeral key erasure, session resumption, and reordering.
2. **Audit Logs (`/audit`)**:
   - Click **Simulate Row Tamper** → click **Verify Chain** → show exact `firstMismatchSeq: #1` detected → click **Revert Tamper** and note the single-DB trust limitation.
3. **Backup & Recovery (`/recovery`)**:
   - Click **Create Verified Backup**, click **Corrupt Test**, click **Restore** → show `BACKUP_CORRUPTED` rejection, then create a clean verified backup and restore while retaining `v2` key and revoked device state.

## Minute 4:30 – 5:00 | Wrap-Up & Honest Limitations
- Summarize JUnit 5 crash-recovery verification (`CrashRecoveryIntegrationTest`), `n = 22` sample scope caveat, simulated single-JVM nodes, and in-DB audit hash-chain limitations.
