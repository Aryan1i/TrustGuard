"""TrustGuard Track 4 compatibility adapter application module.

Implements the standalone Track 4 adapter contract (setup, read, revoke, audit,
protected_read) with atomic persistence in TRACK4_STATE_DIR (or OS temp dir),
file-level locking, SHA-256 hash-chained audit records, state integrity MAC,
and post-quantum ML-KEM-768 encapsulation + HMAC-SHA-256 proof generation.

Security invariants:
- Never emit key_material, shared secrets, or protected bodies to stdout/stderr.
- Never disclose protected content on denied reads.
- Persist state via fsync + atomic rename before returning acknowledgements.
"""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any


STATE_FILENAME = "trustguard-adapter-state.json"
HMAC_KEY_FILENAME = ".trustguard-state-hmac.key"
LOCK_FILENAME = ".trustguard-adapter.lock"
DEFAULT_SUBDIR = "trustguard-track4-state"
GENESIS_HASH = "0" * 64


class AdapterError(ValueError):
    """Safe, secret-free error for invalid adapter state or requests."""


def _state_dir() -> Path:
    configured = os.environ.get("TRACK4_STATE_DIR")
    if configured:
        base = Path(configured)
    else:
        base = Path(tempfile.gettempdir()) / DEFAULT_SUBDIR

    if base.exists() or os.path.islink(base):
        st = os.lstat(base)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise AdapterError("Unsafe state directory")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise AdapterError("State directory owned by unexpected user")
    else:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)

    os.chmod(base, 0o700)
    final_stat = os.lstat(base)
    if stat.S_ISLNK(final_stat.st_mode) or not stat.S_ISDIR(final_stat.st_mode):
        raise AdapterError("Unsafe state directory")
    if hasattr(os, "geteuid") and final_stat.st_uid != os.geteuid():
        raise AdapterError("State directory owned by unexpected user")
    if stat.S_IMODE(final_stat.st_mode) & 0o077:
        raise AdapterError("Unsafe state directory permissions")
    return base


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _require_non_empty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdapterError(f"Invalid {field}")
    return value


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AdapterError(f"Invalid {field}")
    return value


def _validate_ml_kem_768_pk(pk_bytes: bytes) -> None:
    """Enforce NIST FIPS 203 Section 7.2 encapsulation key checks (< q=3329, non-zero)."""
    if len(pk_bytes) != 1184:
        raise AdapterError("Invalid ML-KEM-768 public_key size")
    t_bytes = pk_bytes[:1152]
    if not any(t_bytes):
        raise AdapterError("Degenerate all-zero ML-KEM-768 public_key")
    for idx in range(0, 1152, 3):
        b0 = t_bytes[idx]
        b1 = t_bytes[idx + 1]
        b2 = t_bytes[idx + 2]
        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 >= 3329 or d2 >= 3329:
            raise AdapterError("Invalid ML-KEM-768 public_key modulus check")


def _compute_entry_hash(prev_hash: str, record: dict[str, Any]) -> str:
    material = {
        "prev_hash": prev_hash,
        "seq": record["seq"],
        "op": record["op"],
        "request_id": record["request_id"],
        "actor": record["actor"],
        "asset": record["asset"],
        "decision": record["decision"],
        "rule": record["rule"],
        "timestamp_utc": record["timestamp_utc"],
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def _verify_audit_chain(chain: list[dict[str, Any]]) -> bool:
    prev = GENESIS_HASH
    for idx, entry in enumerate(chain):
        if entry.get("seq") != idx + 1:
            return False
        if entry.get("prev_hash") != prev:
            return False
        expected = _compute_entry_hash(prev, entry)
        if not hmac.compare_digest(str(entry.get("entry_hash", "")), expected):
            return False
        prev = expected
    return True


@contextmanager
def _locked_state_dir(state_dir: Path):
    lock_path = state_dir / LOCK_FILENAME
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(lock_path), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _atomic_write_bytes(target: Path, data: bytes, mode: int = 0o600) -> None:
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".tg-tmp-", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(tmp_fd, mode)
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp_path), str(target))
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def _load_or_create_hmac_key(state_dir: Path, reset: bool = False) -> bytes:
    key_path = state_dir / HMAC_KEY_FILENAME
    if key_path.exists() or os.path.islink(key_path):
        st = os.lstat(key_path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise AdapterError("Unsafe state integrity key file")
    if reset or not key_path.exists():
        raw_key = secrets.token_bytes(32)
        _atomic_write_bytes(key_path, raw_key, mode=0o600)
        return raw_key
    raw_key = key_path.read_bytes()
    if len(raw_key) != 32:
        raise AdapterError("Corrupted state integrity key")
    return raw_key


def _save_state(state_dir: Path, payload: dict[str, Any], hmac_key: bytes) -> None:
    payload_bytes = _canonical_json(payload)
    mac_hex = hmac.new(hmac_key, payload_bytes, hashlib.sha256).hexdigest()
    envelope = json.dumps(
        {"version": 1, "payload": payload, "mac": mac_hex},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    _atomic_write_bytes(state_dir / STATE_FILENAME, envelope, mode=0o600)


def _load_state(state_dir: Path) -> tuple[dict[str, Any], bytes]:
    state_path = state_dir / STATE_FILENAME
    if os.path.islink(state_path):
        raise AdapterError("Unsafe persisted state file")
    if not state_path.exists():
        raise AdapterError("Adapter state is not initialized")
    hmac_key = _load_or_create_hmac_key(state_dir, reset=False)
    envelope = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict) or "payload" not in envelope or "mac" not in envelope:
        raise AdapterError("Malformed persisted state")
    payload = envelope["payload"]
    expected_mac = hmac.new(hmac_key, _canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(envelope["mac"]), expected_mac):
        raise AdapterError("Persisted state failed integrity verification")
    if not _verify_audit_chain(payload.get("audit_chain", [])):
        raise AdapterError("Persisted audit log failed hash-chain verification")
    return payload, hmac_key


def _append_audit_event(
    state: dict[str, Any],
    *,
    op: str,
    request_id: str,
    actor: str,
    asset: str,
    decision: str,
    rule: str,
) -> dict[str, Any]:
    chain: list[dict[str, Any]] = state["audit_chain"]
    prev_hash = chain[-1]["entry_hash"] if chain else GENESIS_HASH
    entry: dict[str, Any] = {
        "seq": len(chain) + 1,
        "op": op,
        "request_id": request_id,
        "actor": actor,
        "asset": asset,
        "decision": decision,
        "rule": rule,
        "timestamp_utc": _utc_now_iso(),
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = _compute_entry_hash(prev_hash, entry)
    chain.append(entry)
    return entry


def _evaluate_access(state: dict[str, Any], actor: str, asset: str) -> tuple[bool, str]:
    if actor in state["revoked"]:
        return False, "identity_revoked"
    owners = state["owners"]
    contents = state["contents"]
    if asset not in owners or asset not in contents:
        return False, "asset_not_found"
    if owners[asset] != actor:
        return False, "owner_required"
    return True, "owner_allowed"


def _handle_setup(state_dir: Path, request: dict[str, Any]) -> dict[str, Any]:
    owners = request.get("owners")
    contents = request.get("contents")
    disabled = request.get("disabled", [])
    key_material = request.get("key_material", "")

    if not isinstance(owners, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in owners.items()
    ):
        raise AdapterError("Invalid owners mapping")
    if not isinstance(contents, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in contents.items()
    ):
        raise AdapterError("Invalid contents mapping")
    if not isinstance(disabled, list) or not all(isinstance(a, str) for a in disabled):
        raise AdapterError("Invalid disabled list")
    if not isinstance(key_material, str):
        raise AdapterError("Invalid key_material")

    # Never persist raw key_material in plaintext state or logs; keep only salted fingerprint.
    km_salt = secrets.token_hex(16)
    km_digest = hashlib.sha256(f"{km_salt}:{key_material}".encode("utf-8")).hexdigest()
    del key_material

    revoked_sorted = sorted(set(disabled))
    state = {
        "owners": dict(owners),
        "contents": dict(contents),
        "revoked": revoked_sorted,
        "revocation_version": len(revoked_sorted),
        "key_material_salt": km_salt,
        "key_material_digest": km_digest,
        "events": {},
        "audit_chain": [],
    }
    _append_audit_event(
        state,
        op="setup",
        request_id="setup-init",
        actor="system",
        asset="*",
        decision="allow",
        rule="setup_initialized",
    )

    hmac_key = _load_or_create_hmac_key(state_dir, reset=True)
    _save_state(state_dir, state, hmac_key)
    return {"ready": True}


def _handle_read(state_dir: Path, request: dict[str, Any]) -> dict[str, Any]:
    actor = _require_non_empty_str(request.get("actor"), "actor")
    asset = _require_non_empty_str(request.get("asset"), "asset")
    request_id = _require_non_empty_str(request.get("request_id"), "request_id")

    state, hmac_key = _load_state(state_dir)

    if request_id in state["events"]:
        # Reject replayed request_id without disclosing content or mutating original audit record.
        _append_audit_event(
            state,
            op="read_replay",
            request_id=f"{request_id}:replay:{secrets.token_hex(4)}",
            actor=actor,
            asset=asset,
            decision="deny",
            rule="duplicate_request_id",
        )
        _save_state(state_dir, state, hmac_key)
        return {"decision": "deny"}

    allowed, rule = _evaluate_access(state, actor, asset)
    decision = "allow" if allowed else "deny"
    entry = _append_audit_event(
        state,
        op="read",
        request_id=request_id,
        actor=actor,
        asset=asset,
        decision=decision,
        rule=rule,
    )
    state["events"][request_id] = {
        "request_id": request_id,
        "decision": decision,
        "rule": rule,
        "entry_hash": entry["entry_hash"],
        "prev_hash": entry["prev_hash"],
    }
    _save_state(state_dir, state, hmac_key)

    if allowed:
        return {"decision": "allow", "body": state["contents"][asset]}
    return {"decision": "deny"}


def _handle_revoke(state_dir: Path, request: dict[str, Any]) -> dict[str, Any]:
    actor = _require_non_empty_str(request.get("actor"), "actor")
    state, hmac_key = _load_state(state_dir)

    revoked_set = set(state["revoked"])
    if actor not in revoked_set:
        revoked_set.add(actor)
        state["revoked"] = sorted(revoked_set)
        state["revocation_version"] = int(state.get("revocation_version", 0)) + 1

    _append_audit_event(
        state,
        op="revoke",
        request_id=f"revoke-{state['revocation_version']}-{secrets.token_hex(4)}",
        actor=actor,
        asset="*",
        decision="allow",
        rule="actor_revoked",
    )
    _save_state(state_dir, state, hmac_key)
    return {
        "revoked": True,
        "revocation_version": state["revocation_version"],
    }


def _handle_audit(state_dir: Path, request: dict[str, Any]) -> dict[str, Any]:
    request_id = _require_non_empty_str(request.get("request_id"), "request_id")
    state, _ = _load_state(state_dir)

    record = state["events"].get(request_id)
    if record is None:
        return {"request_id": request_id, "error": "unknown_request"}

    return {
        "request_id": record["request_id"],
        "decision": record["decision"],
        "rule": record["rule"],
        "entry_hash": record["entry_hash"],
        "prev_hash": record["prev_hash"],
        "chain_verified": True,
    }


def _handle_protected_read(state_dir: Path, request: dict[str, Any]) -> dict[str, Any]:
    actor = _require_non_empty_str(request.get("actor"), "actor")
    asset = _require_non_empty_str(request.get("asset"), "asset")
    challenge = _require_str(request.get("challenge"), "challenge")
    public_key_b64 = _require_non_empty_str(request.get("public_key"), "public_key")
    request_id = request.get("request_id")
    if request_id is None:
        request_id = f"pr-{secrets.token_hex(12)}"
    else:
        request_id = _require_non_empty_str(request_id, "request_id")

    state, hmac_key = _load_state(state_dir)

    if request_id in state["events"]:
        # Reject replayed request_id without disclosing content or mutating original event record.
        _append_audit_event(
            state,
            op="protected_read_replay",
            request_id=f"{request_id}:replay:{secrets.token_hex(4)}",
            actor=actor,
            asset=asset,
            decision="deny",
            rule="duplicate_request_id",
        )
        _save_state(state_dir, state, hmac_key)
        return {"decision": "deny"}

    allowed, rule = _evaluate_access(state, actor, asset)

    if not allowed:
        entry = _append_audit_event(
            state,
            op="protected_read",
            request_id=request_id,
            actor=actor,
            asset=asset,
            decision="deny",
            rule=rule,
        )
        state["events"][request_id] = {
            "request_id": request_id,
            "decision": "deny",
            "rule": rule,
            "entry_hash": entry["entry_hash"],
            "prev_hash": entry["prev_hash"],
        }
        _save_state(state_dir, state, hmac_key)
        return {"decision": "deny"}

    # Validate raw ML-KEM-768 public key before encapsulating.
    try:
        pk_bytes = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AdapterError("Malformed Base64 public_key") from exc

    from pqcrypto.kem import ml_kem_768  # Vetted NIST FIPS 203 implementation (pqcrypto==0.4.0)

    if len(pk_bytes) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise AdapterError("Invalid ML-KEM-768 public_key size")

    _validate_ml_kem_768_pk(pk_bytes)

    ciphertext_bytes, shared_secret = ml_kem_768.encrypt(pk_bytes)
    try:
        stored_body = state["contents"][asset]
        proof_input = (challenge + stored_body).encode("utf-8")
        proof_hex = hmac.new(shared_secret, proof_input, hashlib.sha256).hexdigest()
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
    finally:
        # Remove references to sensitive shared secret material promptly.
        del shared_secret

    entry = _append_audit_event(
        state,
        op="protected_read",
        request_id=request_id,
        actor=actor,
        asset=asset,
        decision="allow",
        rule=rule,
    )
    state["events"][request_id] = {
        "request_id": request_id,
        "decision": "allow",
        "rule": rule,
        "entry_hash": entry["entry_hash"],
        "prev_hash": entry["prev_hash"],
    }
    _save_state(state_dir, state, hmac_key)

    return {
        "decision": "allow",
        "ciphertext": ciphertext_b64,
        "proof": proof_hex,
    }


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a single Track 4 adapter request with persistent locked state."""
    if not isinstance(request, dict):
        raise AdapterError("Request must be a JSON object")
    op = request.get("op")
    state_dir = _state_dir()

    with _locked_state_dir(state_dir):
        if op == "setup":
            return _handle_setup(state_dir, request)
        if op == "read":
            return _handle_read(state_dir, request)
        if op == "revoke":
            return _handle_revoke(state_dir, request)
        if op == "audit":
            return _handle_audit(state_dir, request)
        if op == "protected_read":
            return _handle_protected_read(state_dir, request)
        return {"error": "unsupported_operation"}
