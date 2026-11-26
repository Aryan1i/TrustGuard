"""Unit and subprocess integration tests for TrustGuard Track 4 compatibility adapter."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from pqcrypto.kem import ml_kem_768

import team_app


TRUSTGUARD_ROOT = Path(__file__).resolve().parent.parent
ADAPTER_ENTRY = TRUSTGUARD_ROOT / "track4_service.py"


class AdapterIntegrationTests(unittest.TestCase):
    def invoke(self, state_dir: str, payload: dict) -> tuple[int, dict | None, bytes, bytes]:
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = state_dir
        proc = subprocess.run(
            [sys.executable, "-B", str(ADAPTER_ENTRY)],
            cwd=str(TRUSTGUARD_ROOT),
            env=env,
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        parsed = json.loads(proc.stdout.decode("utf-8")) if proc.stdout.strip() else None
        return proc.returncode, parsed, proc.stdout, proc.stderr

    def test_full_lost_device_and_protected_read_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="tg-adapter-test-") as state_dir:
            secret_marker = "synthetic-master-key-do-not-leak-99182"
            asset_body = "confidential-brief-\u2713-utf8"
            peer_body = "peer-isolated-document"

            rc, res, out, err = self.invoke(
                state_dir,
                {
                    "op": "setup",
                    "owners": {"brief": "alice", "ledger": "bob"},
                    "contents": {"brief": asset_body, "ledger": peer_body},
                    "disabled": ["charlie"],
                    "key_material": secret_marker,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"ready": True})
            self.assertNotIn(secret_marker.encode(), out + err)

            # Verify key_material is not stored in plaintext in persisted state files
            for p in Path(state_dir).iterdir():
                if p.is_file():
                    self.assertNotIn(secret_marker.encode(), p.read_bytes())

            # Authorized read
            rc, res, _, _ = self.invoke(
                state_dir,
                {"op": "read", "actor": "alice", "asset": "brief", "request_id": "req-001"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"decision": "allow", "body": asset_body})

            # Disabled actor denied
            rc, res, out, err = self.invoke(
                state_dir,
                {"op": "read", "actor": "charlie", "asset": "brief", "request_id": "req-002"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"decision": "deny"})
            self.assertNotIn(asset_body.encode(), out + err)

            # Replay same request_id denied without disclosure
            rc, res, out, err = self.invoke(
                state_dir,
                {"op": "read", "actor": "alice", "asset": "brief", "request_id": "req-001"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"decision": "deny"})
            self.assertNotIn(asset_body.encode(), out + err)

            # Authorized protected_read with real ML-KEM-768
            pk, sk = ml_kem_768.generate_keypair()
            pk_b64 = base64.b64encode(pk).decode("ascii")
            challenge = "chal-2026-xyz-\u03bb"

            rc, res, out, err = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "alice",
                    "asset": "brief",
                    "challenge": challenge,
                    "public_key": pk_b64,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res["decision"], "allow")
            self.assertNotIn("body", res)
            self.assertNotIn(asset_body.encode(), out + err)

            ct = base64.b64decode(res["ciphertext"], validate=True)
            shared_secret = ml_kem_768.decrypt(sk, ct)
            expected_proof = hmac.new(
                shared_secret,
                (challenge + asset_body).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(res["proof"], expected_proof)
            self.assertEqual(res["proof"], res["proof"].lower())

            # Wrong owner protected_read must deny without ciphertext or proof
            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "bob",
                    "asset": "brief",
                    "challenge": challenge,
                    "public_key": pk_b64,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"decision": "deny"})

            # Revoke alice, verify protected_read and read deny, peer stays allowed
            rc, res, _, _ = self.invoke(state_dir, {"op": "revoke", "actor": "alice"})
            self.assertEqual(rc, 0)
            self.assertTrue(res["revoked"])

            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "alice",
                    "asset": "brief",
                    "challenge": challenge,
                    "public_key": pk_b64,
                    "request_id": "req-pr-denied",
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"decision": "deny"})

            rc, res, _, _ = self.invoke(
                state_dir,
                {"op": "audit", "request_id": "req-pr-denied"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res["request_id"], "req-pr-denied")
            self.assertEqual(res["decision"], "deny")
            self.assertTrue(res["chain_verified"])

            rc, res, _, _ = self.invoke(
                state_dir,
                {"op": "read", "actor": "bob", "asset": "ledger", "request_id": "req-peer"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"decision": "allow", "body": peer_body})

    def test_tampered_state_rejected(self):
        with tempfile.TemporaryDirectory(prefix="tg-tamper-test-") as state_dir:
            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "setup",
                    "owners": {"doc": "alice"},
                    "contents": {"doc": "secret"},
                    "disabled": ["alice"],
                    "key_material": "km",
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"ready": True})

            state_file = Path(state_dir) / "trustguard-adapter-state.json"
            data = json.loads(state_file.read_text(encoding="utf-8"))
            data["payload"]["revoked"] = []
            state_file.write_text(json.dumps(data), encoding="utf-8")

            rc, _, out, err = self.invoke(
                state_dir,
                {"op": "read", "actor": "alice", "asset": "doc", "request_id": "req-tamper"},
            )
            self.assertNotEqual(rc, 0)
            self.assertEqual(out, b"")
            self.assertIn(b"Request failed", err)

    def test_protected_read_replay_rejected_without_overwriting_state_events(self):
        with tempfile.TemporaryDirectory(prefix="tg-pr-replay-") as state_dir:
            asset_body = "protected-doc-secret-99881"
            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "setup",
                    "owners": {"doc": "alice"},
                    "contents": {"doc": asset_body},
                    "disabled": [],
                    "key_material": "km-pr-replay",
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res, {"ready": True})

            pk, sk = ml_kem_768.generate_keypair()
            pk_b64 = base64.b64encode(pk).decode("ascii")
            challenge = "chal-replay-check-1"
            req_id = "pr-unique-001"

            rc, res1, out1, err1 = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "alice",
                    "asset": "doc",
                    "challenge": challenge,
                    "public_key": pk_b64,
                    "request_id": req_id,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res1["decision"], "allow")
            self.assertNotIn(asset_body.encode(), out1 + err1)
            ss = ml_kem_768.decrypt(sk, base64.b64decode(res1["ciphertext"], validate=True))
            expected_proof = hmac.new(ss, (challenge + asset_body).encode("utf-8"), hashlib.sha256).hexdigest()
            self.assertEqual(res1["proof"], expected_proof)

            # Audit entry before replay
            rc, audit_before, _, _ = self.invoke(state_dir, {"op": "audit", "request_id": req_id})
            self.assertEqual(rc, 0)
            self.assertEqual(audit_before["decision"], "allow")

            # Replay exact request_id in protected_read (even with another actor or same actor) must be denied
            rc, res2, out2, err2 = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "bob",
                    "asset": "doc",
                    "challenge": challenge,
                    "public_key": pk_b64,
                    "request_id": req_id,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res2, {"decision": "deny"})
            self.assertNotIn(asset_body.encode(), out2 + err2)

            # Replay with original owner & same request_id must also deny without overwriting state["events"][req_id]
            rc, res3, out3, err3 = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "alice",
                    "asset": "doc",
                    "challenge": challenge,
                    "public_key": pk_b64,
                    "request_id": req_id,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res3, {"decision": "deny"})
            self.assertNotIn(asset_body.encode(), out3 + err3)

            rc, audit_after, _, _ = self.invoke(state_dir, {"op": "audit", "request_id": req_id})
            self.assertEqual(rc, 0)
            self.assertEqual(audit_after["decision"], "allow")
            self.assertEqual(audit_after["entry_hash"], audit_before["entry_hash"])
            self.assertEqual(audit_after["prev_hash"], audit_before["prev_hash"])
            self.assertTrue(audit_after["chain_verified"])

    def test_state_dir_enforces_0700_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="tg-dir-hardening-") as tmp:
            tmp_path = Path(tmp)
            target_dir = tmp_path / "loose-state"
            target_dir.mkdir(mode=0o755)
            os.chmod(target_dir, 0o755)

            old_env = os.environ.get("TRACK4_STATE_DIR")
            try:
                os.environ["TRACK4_STATE_DIR"] = str(target_dir)
                resolved = team_app._state_dir()
                self.assertEqual(resolved, target_dir)
                self.assertEqual(stat.S_IMODE(os.lstat(resolved).st_mode), 0o700)

                symlink_dir = tmp_path / "symlink-state"
                symlink_dir.symlink_to(target_dir)
                os.environ["TRACK4_STATE_DIR"] = str(symlink_dir)
                with self.assertRaises(team_app.AdapterError):
                    team_app._state_dir()
            finally:
                if old_env is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = old_env

    def test_fips203_rejects_classical_zero_and_out_of_range_kem_keys(self):
        with tempfile.TemporaryDirectory(prefix="tg-fips203-") as state_dir:
            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "setup",
                    "owners": {"doc": "alice"},
                    "contents": {"doc": "pqc-secret"},
                    "disabled": [],
                },
            )
            self.assertEqual(rc, 0)
            self.assertTrue(res["ready"])

            bad_keys = [
                b"\x00" * 294,       # RSA-sized
                b"\x00" * 1184,      # All-zero degenerate 1184B
                b"\xff" * 1184,      # Out-of-range coefficients >= q=3329
            ]
            for i, key_bytes in enumerate(bad_keys):
                rc, _, out, err = self.invoke(
                    state_dir,
                    {
                        "op": "protected_read",
                        "actor": "alice",
                        "asset": "doc",
                        "challenge": f"chal-bad-{i}",
                        "public_key": base64.b64encode(key_bytes).decode("ascii"),
                        "request_id": f"bad-kem-{i}",
                    },
                )
                self.assertNotEqual(rc, 0)
                self.assertEqual(out, b"")
                self.assertIn(b"Request failed", err)

    def test_log_injection_challenge_is_escaped_inside_single_valid_audit_entry(self):
        with tempfile.TemporaryDirectory(prefix="tg-loginj-") as state_dir:
            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "setup",
                    "owners": {"doc": "alice"},
                    "contents": {"doc": "pqc-secret"},
                    "disabled": [],
                },
            )
            self.assertEqual(rc, 0)
            self.assertTrue(res["ready"])

            pk, _ = ml_kem_768.generate_keypair()
            malicious_challenge = 'chal\n{"seq":999,"actor":"root","decision":"forged"}|END\r\n'
            req_id = "req-log-inj-1"
            rc, res, _, _ = self.invoke(
                state_dir,
                {
                    "op": "protected_read",
                    "actor": "alice",
                    "asset": "doc",
                    "challenge": malicious_challenge,
                    "public_key": base64.b64encode(pk).decode("ascii"),
                    "request_id": req_id,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(res["decision"], "allow")

            rc, audit_res, _, _ = self.invoke(
                state_dir,
                {"op": "audit", "request_id": req_id},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(audit_res["request_id"], req_id)
            self.assertEqual(audit_res["decision"], "allow")
            self.assertTrue(audit_res["chain_verified"])

            raw_lines = (Path(state_dir) / team_app.STATE_FILENAME).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(raw_lines), 1)
            envelope = json.loads(raw_lines[0])
            chain = envelope["payload"]["audit_chain"]
            self.assertEqual(len(chain), 2)
            self.assertEqual(chain[1]["request_id"], req_id)
            self.assertEqual(chain[1]["actor"], "alice")
            self.assertEqual(chain[1]["decision"], "allow")
            self.assertTrue(all(entry["actor"] != "root" for entry in chain))


if __name__ == "__main__":
    unittest.main()
