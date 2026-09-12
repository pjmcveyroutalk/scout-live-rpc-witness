#!/usr/bin/env python3
"""Read-only Ghost G0 locked-target acquisition sensor.

This file acquires evidence only. It cannot sign, build, submit, or broadcast a
transaction and it never emits G0_READY. A successful capture is handed to the
canonical Ghost V0.8 offline admission gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ghost_g0_common import (
    G0Error,
    RAYDIUM_CPMM_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    classify_raydium_swap_base_input,
    decode_account_data,
    decode_pool_identity,
    exact_transaction_match,
    extract_raw_transaction_bytes,
    sha256_bytes,
    snapshot_body,
    writable_target_overlap,
    write_json,
)

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
DEFAULT_POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
ALLOWED = {
    "getGenesisHash",
    "getAccountInfo",
    "getMultipleAccounts",
    "getSignaturesForAddress",
    "getTransaction",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class RPC:
    def __init__(self, endpoint: str, out: Path, timeout: float) -> None:
        self.endpoint = endpoint
        self.path = out / "rpc_evidence.ndjson"
        self.timeout = timeout
        self.seq = 0

    def call(self, method: str, params: list[Any]) -> tuple[Any, str]:
        if method not in ALLOWED:
            raise G0Error(f"method not allowed: {method}")
        self.seq += 1
        evidence_id = f"rpc-{self.seq:08d}"
        obj = {"jsonrpc": "2.0", "id": self.seq, "method": method, "params": params}
        body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
        started = now()
        mono = time.monotonic_ns()
        status = None
        raw = b""
        error = None
        try:
            req = urllib.request.Request(
                self.endpoint,
                data=body,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "accept": "application/json",
                    "user-agent": "Ghost-G0-Target-Evidence/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = int(response.status)
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            raw = exc.read()
            error = f"HTTPError:{exc.code}"
        except Exception as exc:
            error = f"{type(exc).__name__}:{exc}"
        record = {
            "schema": "ghost_g0_rpc_evidence_v1",
            "evidence_id": evidence_id,
            "method": method,
            "endpoint": self.endpoint,
            "request_body": body.decode(),
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "response_body": raw.decode("utf-8", errors="replace"),
            "response_sha256": hashlib.sha256(raw).hexdigest(),
            "started_at": started,
            "completed_at": now(),
            "elapsed_ms": round((time.monotonic_ns() - mono) / 1_000_000, 3),
            "http_status": status,
            "transport_success": status == 200 and error is None,
            "error": error,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
        if status != 200 or error:
            raise G0Error(f"{method} transport failure: {error or status}")
        payload = json.loads(raw)
        if not isinstance(payload, Mapping) or payload.get("error") is not None:
            raise G0Error(f"{method} RPC failure: {payload.get('error') if isinstance(payload, Mapping) else 'shape'}")
        return payload.get("result"), evidence_id


def account_info(rpc: RPC, key: str) -> tuple[Mapping[str, Any], int, str]:
    result, eid = rpc.call("getAccountInfo", [key, {"encoding": "base64", "commitment": "finalized"}])
    if not isinstance(result, Mapping) or not isinstance(result.get("context"), Mapping):
        raise G0Error("invalid getAccountInfo shape")
    value = result.get("value")
    if not isinstance(value, Mapping):
        raise G0Error("target pool account missing")
    return value, int(result["context"]["slot"]), eid


def snapshot(rpc: RPC, keys: list[str], min_slot: int | None = None) -> tuple[dict[str, Any], str]:
    cfg: dict[str, Any] = {"encoding": "base64", "commitment": "finalized"}
    if min_slot is not None:
        cfg["minContextSlot"] = min_slot
    result, eid = rpc.call("getMultipleAccounts", [keys, cfg])
    if not isinstance(result, Mapping) or not isinstance(result.get("context"), Mapping):
        raise G0Error("invalid getMultipleAccounts shape")
    values = result.get("value")
    if not isinstance(values, list) or len(values) != 6 or any(not isinstance(v, Mapping) for v in values):
        raise G0Error("six-account bundle incomplete")
    return snapshot_body(
        int(result["context"]["slot"]),
        keys,
        values,
        continuity_epoch=0,
        captured_at_unix_ns=time.time_ns(),
        rpc_evidence_id=eid,
        transport_interruption_count=0,
    ), eid


def signatures(rpc: RPC, key: str, commitment: str, limit: int = 100) -> tuple[list[Mapping[str, Any]], str]:
    result, eid = rpc.call("getSignaturesForAddress", [key, {"commitment": commitment, "limit": limit}])
    if not isinstance(result, list):
        raise G0Error("invalid signature history shape")
    return [x for x in result if isinstance(x, Mapping)], eid


def tx(rpc: RPC, sig: str, commitment: str, encoding: str) -> tuple[Mapping[str, Any] | None, str]:
    result, eid = rpc.call(
        "getTransaction",
        [sig, {"commitment": commitment, "encoding": encoding, "maxSupportedTransactionVersion": 0}],
    )
    if result is None:
        return None, eid
    if not isinstance(result, Mapping):
        raise G0Error("invalid transaction shape")
    return result, eid


def wait_finalized(rpc: RPC, sig: str, encoding: str, seconds: float) -> tuple[Mapping[str, Any], list[str]]:
    deadline = time.monotonic() + seconds
    eids: list[str] = []
    while time.monotonic() <= deadline:
        result, eid = tx(rpc, sig, "finalized", encoding)
        eids.append(eid)
        if result is not None:
            return result, eids
        time.sleep(1)
    raise G0Error("candidate did not finalize before timeout")


def static_equal(s0: Mapping[str, Any], s1: Mapping[str, Any]) -> bool:
    for i in (1, 4, 5):
        a, b = s0["accounts"][i], s1["accounts"][i]
        for field in ("pubkey", "owner", "lamports", "executable", "data_len", "data_sha256"):
            if a.get(field) != b.get(field):
                return False
    return True


def conflict_audit(rpc: RPC, mutable: list[str], target_sig: str, s0_slot: int, s1_slot: int) -> tuple[dict[str, Any], list[str]]:
    eids: list[str] = []
    seen: dict[str, int] = {}
    for key in mutable:
        rows, eid = signatures(rpc, key, "finalized", 100)
        eids.append(eid)
        if rows and min(int(r.get("slot", 0)) for r in rows) > s0_slot:
            return {"status": "REJECT", "reason": "finalized_history_did_not_cover_s0_boundary", "address": key}, eids
        for row in rows:
            sig = row.get("signature")
            slot = int(row.get("slot", -1))
            if isinstance(sig, str) and s0_slot < slot <= s1_slot:
                seen[sig] = slot
    conflicts = []
    for sig, slot in sorted(seen.items(), key=lambda x: x[1]):
        result, eid = tx(rpc, sig, "finalized", "json")
        eids.append(eid)
        if result is None:
            return {"status": "REJECT", "reason": "window_transaction_unavailable", "signature": sig}, eids
        overlap = sorted(writable_target_overlap(result, set(mutable)))
        if sig != target_sig and overlap:
            conflicts.append({"signature": sig, "slot": slot, "writable_overlap": overlap})
    if conflicts:
        return {"status": "REJECT", "reason": "competing_mutable_write", "conflicts": conflicts}, eids
    return {"status": "PASS", "window": {"s0": s0_slot, "s1": s1_slot}, "signatures": seen}, eids


def manifest(root: Path) -> None:
    rows = []
    for p in sorted(x for x in root.rglob("*") if x.is_file() and x.name != "MANIFEST.sha256"):
        rows.append(f"{sha256_bytes(p.read_bytes())}  {p.relative_to(root).as_posix()}")
    (root / "MANIFEST.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


def reject(root: Path, n: int, value: Mapping[str, Any]) -> None:
    write_json(root / "rejections" / f"candidate-{n:04d}.json", dict(value), canonical=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-url", default=DEFAULT_RPC)
    ap.add_argument("--pool-id", default=DEFAULT_POOL)
    ap.add_argument("--output-dir", default="ghost-g0-evidence")
    ap.add_argument("--max-runtime-seconds", type=int, default=600)
    ap.add_argument("--poll-seconds", type=float, default=2.5)
    ap.add_argument("--request-timeout-seconds", type=float, default=20)
    ap.add_argument("--finalization-timeout-seconds", type=float, default=120)
    args = ap.parse_args()
    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "authority_boundary.json", {
        "read_only": True,
        "wallet": False,
        "private_key": False,
        "transaction_builder": False,
        "signing": False,
        "submission": False,
        "broadcast": False,
        "capital_movement": False,
        "production_scout_mutation": False,
    }, canonical=True)
    rpc = RPC(args.rpc_url, root, args.request_timeout_seconds)
    try:
        genesis, genesis_eid = rpc.call("getGenesisHash", [])
        pool, pool_slot, pool_eid = account_info(rpc, args.pool_id)
        if pool.get("owner") != RAYDIUM_CPMM_PROGRAM_ID:
            raise G0Error("target account is not owned by Raydium CPMM")
        ident = decode_pool_identity(decode_account_data(pool, "target_pool"))
        if ident["token_0_program"] != SPL_TOKEN_PROGRAM_ID or ident["token_1_program"] != SPL_TOKEN_PROGRAM_ID:
            raise G0Error("first G0 truth case requires SPL Token on both sides")
        keys = [args.pool_id, ident["amm_config"], ident["token_0_vault"], ident["token_1_vault"], ident["token_0_mint"], ident["token_1_mint"]]
        mutable = [args.pool_id, ident["token_0_vault"], ident["token_1_vault"]]
        write_json(root / "pool_identity.json", {
            "target_pool": args.pool_id,
            "genesis_hash": genesis,
            "bootstrap_pool_slot": pool_slot,
            "six_account_bundle": keys,
            "mutable_quote_state": mutable,
            "decoded_pool_identity": ident,
            "bootstrap_evidence": [genesis_eid, pool_eid],
        }, canonical=True)
        first, _ = snapshot(rpc, keys)
        ring = [first]
        baseline, _ = signatures(rpc, args.pool_id, "confirmed", 100)
        seen = {str(r["signature"]) for r in baseline if isinstance(r.get("signature"), str)}
        started = time.monotonic()
        count = 0
        while time.monotonic() - started < args.max_runtime_seconds:
            time.sleep(args.poll_seconds)
            try:
                snap, _ = snapshot(rpc, keys)
                if snap["snapshot_sha256"] != ring[-1]["snapshot_sha256"]:
                    ring.append(snap)
                    ring = ring[-128:]
                rows, discovery_eid = signatures(rpc, args.pool_id, "confirmed", 100)
            except G0Error as exc:
                write_json(root / "last_acquisition_warning.json", {"at": now(), "error": str(exc)}, canonical=True)
                continue
            fresh = [r for r in rows if isinstance(r.get("signature"), str) and str(r["signature"]) not in seen]
            fresh.sort(key=lambda r: int(r.get("slot", 0)))
            for row in fresh:
                sig = str(row["signature"])
                seen.add(sig)
                count += 1
                slot = int(row.get("slot", -1))
                if row.get("err") is not None:
                    reject(root, count, {"signature": sig, "slot": slot, "reason": "failed_at_discovery"})
                    continue
                prior = [s for s in ring if int(s["context_slot"]) < slot]
                if not prior:
                    reject(root, count, {"signature": sig, "slot": slot, "reason": "no_finalized_s0_before_transaction"})
                    continue
                s0 = max(prior, key=lambda s: int(s["context_slot"]))
                try:
                    cj, cj_eid = tx(rpc, sig, "confirmed", "json")
                    cb, cb_eid = tx(rpc, sig, "confirmed", "base64")
                    if cj is None or cb is None:
                        raise G0Error("confirmed transaction unavailable")
                    classified = classify_raydium_swap_base_input(cj, args.pool_id)
                    writable = {r["pubkey"] for r in classified["resolved_accounts"] if r.get("is_writable")}
                    if not set(mutable).issubset(writable):
                        raise G0Error("pool and both vaults were not writable")
                    raw_confirmed = extract_raw_transaction_bytes(cb)
                    fj, fj_wait = wait_finalized(rpc, sig, "json", args.finalization_timeout_seconds)
                    fb, fb_wait = wait_finalized(rpc, sig, "base64", args.finalization_timeout_seconds)
                    final_class = classify_raydium_swap_base_input(fj, args.pool_id)
                    raw_final = extract_raw_transaction_bytes(fb)
                    if not exact_transaction_match(raw_confirmed, raw_final):
                        raise G0Error("confirmed/finalized signed transaction bytes differ")
                    if int(fj.get("slot", -1)) != slot:
                        raise G0Error("transaction slot changed between acquisition and finalization")
                    s1, s1_eid = snapshot(rpc, keys, slot)
                    if int(s1["context_slot"]) < slot:
                        raise G0Error("S1 context below transaction slot")
                    if not static_equal(s0, s1):
                        raise G0Error("static config/mint dependency changed")
                    audit, audit_eids = conflict_audit(rpc, mutable, sig, int(s0["context_slot"]), int(s1["context_slot"]))
                    if audit["status"] != "PASS":
                        reject(root, count, {"signature": sig, "slot": slot, "reason": audit["reason"], "conflict_audit": audit})
                        continue
                    write_json(root / "s0.json", s0, canonical=True)
                    write_json(root / "s1.json", s1, canonical=True)
                    write_json(root / "transaction_confirmed_json.json", cj, canonical=True)
                    write_json(root / "transaction_finalized_json.json", fj, canonical=True)
                    write_json(root / "transaction_confirmed_base64.json", cb, canonical=True)
                    write_json(root / "transaction_finalized_base64.json", fb, canonical=True)
                    write_json(root / "classification.json", final_class, canonical=True)
                    write_json(root / "conflict_audit.json", audit, canonical=True)
                    (root / "signed_transaction.bin").write_bytes(raw_final)
                    write_json(root / "READY_FOR_OFFLINE_ADMISSION.json", {
                        "status": "EVIDENCE_READY_FOR_GHOST_V0_8_OFFLINE_ADMISSION",
                        "target_pool": args.pool_id,
                        "transaction_signature": sig,
                        "transaction_slot": slot,
                        "s0_slot": s0["context_slot"],
                        "s1_slot": s1["context_slot"],
                        "signed_transaction_sha256": sha256_bytes(raw_final),
                        "instruction_kind": final_class["instruction_kind"],
                        "rpc_evidence_file": "rpc_evidence.ndjson",
                        "evidence_ids": {
                            "discovery": discovery_eid,
                            "confirmed_json": cj_eid,
                            "confirmed_base64": cb_eid,
                            "finalized_json": fj_wait,
                            "finalized_base64": fb_wait,
                            "s1": s1_eid,
                            "conflict_audit": audit_eids,
                        },
                        "note": "Acquisition only; canonical Ghost V0.8 admission remains separate.",
                    }, canonical=True)
                    manifest(root)
                    print(f"EVIDENCE_READY signature={sig} slot={slot}", flush=True)
                    return 0
                except G0Error as exc:
                    reject(root, count, {"signature": sig, "slot": slot, "reason": str(exc)})
        write_json(root / "NOT_FOUND.json", {
            "status": "NO_ADMISSIBLE_TARGET_CASE_IN_WINDOW",
            "target_pool": args.pool_id,
            "runtime_seconds": args.max_runtime_seconds,
            "candidates_seen": count,
            "snapshot_count": len(ring),
        }, canonical=True)
        manifest(root)
        print("NO_ADMISSIBLE_TARGET_CASE_IN_WINDOW", flush=True)
        return 3
    except Exception as exc:
        write_json(root / "FATAL.json", {"status": "FATAL", "at": now(), "error": f"{type(exc).__name__}: {exc}"}, canonical=True)
        manifest(root)
        print(f"FATAL {type(exc).__name__}: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
