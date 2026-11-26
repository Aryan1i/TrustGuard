"""Unit and subprocess integration tests for TrustGuard Track 4 compatibility adapter."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pqcrypto.kem import ml_kem_768


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


if __name__ == "__main__":
    unittest.main()
