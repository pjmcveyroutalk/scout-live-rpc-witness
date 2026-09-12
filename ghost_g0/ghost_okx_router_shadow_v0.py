#!/usr/bin/env python3
"""Read-only Ghost shadow test for signed OKX -> Raydium CPMM projections.

This sensor watches the locked Raydium pool for a fresh transaction whose
SIGNED outer OKX SwapTob route deterministically exposes a direct-root Raydium
CPMM share. It commits a projected six-account S1 from S0 before requesting
post-transaction truth, then scores exact account parity.

The prediction path never reads innerInstructions, logMessages, token balance
deltas, or S1. `jsonParsed` is used only for transaction.message, which is a
deterministic resolution of signed message + address lookup tables.

No wallet, signing, submission, broadcasting, or capital movement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ghost_okx_raydium_router_probe_v0 import (
    OKX_ROUTER,
    ProbeError,
    b58decode,
    derive_direct_root_raydium_leg,
)
from ghost_ray_cpmm_state_transition_v0 import TransitionError, project_rpc_bundle

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
TARGET_POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
SIX_KEYS = [
    TARGET_POOL,
    "FMmwToGqT9iwDgsqvzLg65vcKSzKme4szbWqX1kyCBCJ",
    "v3YN4d7JRhKFcwtex7qNtyg2r5hKYW96Cayb6GivSvY",
    "HG2WgeYsjqQhnjhwHj7QdTVvjyWpFRk6VREAQ8MURv2u",
    "So11111111111111111111111111111111111111112",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
]
MUTABLE_KEYS = [SIX_KEYS[0], SIX_KEYS[2], SIX_KEYS[3]]
ALLOWED = {
    "getGenesisHash",
    "getMultipleAccounts",
    "getSignaturesForAddress",
    "getTransaction",
    "getSignatureStatuses",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(value)
    with path.open("wb") as fh:
        fh.write(data)
        fh.flush()
        try:
            import os
            os.fsync(fh.fileno())
        except OSError:
            pass


class RpcError(RuntimeError):
    pass


class RPC:
    def __init__(self, endpoint: str, root: Path, timeout: float) -> None:
        self.endpoint = endpoint
        self.path = root / "rpc_evidence.ndjson"
        self.timeout = timeout
        self.seq = 0

    def call(self, method: str, params: list[Any]) -> tuple[Any, str]:
        if method not in ALLOWED:
            raise RpcError(f"method not allowed: {method}")
        self.seq += 1
        evidence_id = f"rpc-{self.seq:08d}"
        request_obj = {"jsonrpc": "2.0", "id": self.seq, "method": method, "params": params}
        request = json.dumps(request_obj, separators=(",", ":"), ensure_ascii=False).encode()
        started = now()
        t0 = time.monotonic_ns()
        status = None
        raw = b""
        error = None
        try:
            req = urllib.request.Request(
                self.endpoint,
                data=request,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "accept": "application/json",
                    "user-agent": "Ghost-OKX-Ray-Shadow/0",
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
            "schema": "ghost_router_shadow_rpc_v0",
            "evidence_id": evidence_id,
            "endpoint": self.endpoint,
            "method": method,
            "request_body": request.decode(),
            "request_sha256": sha256(request),
            "response_body": raw.decode("utf-8", errors="replace"),
            "response_sha256": sha256(raw),
            "started_at": started,
            "completed_at": now(),
            "elapsed_ms": round((time.monotonic_ns() - t0) / 1_000_000, 3),
            "http_status": status,
            "transport_success": status == 200 and error is None,
            "error": error,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")

        if status != 200 or error:
            raise RpcError(f"{method} transport failure: {error or status}")
        payload = json.loads(raw)
        if not isinstance(payload, Mapping) or payload.get("error") is not None:
            raise RpcError(
                f"{method} RPC failure: "
                f"{payload.get('error') if isinstance(payload, Mapping) else 'shape'}"
            )
        return payload.get("result"), evidence_id


def snapshot(rpc: RPC, min_slot: int | None = None) -> dict[str, Any]:
    cfg: dict[str, Any] = {"encoding": "base64", "commitment": "finalized"}
    if min_slot is not None:
        cfg["minContextSlot"] = min_slot
    result, evidence_id = rpc.call("getMultipleAccounts", [SIX_KEYS, cfg])
    if not isinstance(result, Mapping) or not isinstance(result.get("context"), Mapping):
        raise RpcError("invalid getMultipleAccounts shape")
    values = result.get("value")
    if not isinstance(values, list) or len(values) != 6 or any(not isinstance(v, Mapping) for v in values):
        raise RpcError("incomplete six-account snapshot")
    return {
        "context_slot": int(result["context"]["slot"]),
        "values": values,
        "rpc_evidence_id": evidence_id,
        "captured_at": now(),
    }


def signatures(rpc: RPC, key: str, commitment: str = "confirmed") -> list[Mapping[str, Any]]:
    result, _ = rpc.call(
        "getSignaturesForAddress",
        [key, {"commitment": commitment, "limit": 100}],
    )
    if not isinstance(result, list):
        raise RpcError("invalid signature history shape")
    return [row for row in result if isinstance(row, Mapping)]


def transaction_message_surface(rpc: RPC, signature: str) -> tuple[dict[str, Any] | None, str]:
    result, evidence_id = rpc.call(
        "getTransaction",
        [
            signature,
            {
                "commitment": "confirmed",
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0,
            },
        ],
    )
    if result is None:
        return None, evidence_id
    if not isinstance(result, Mapping):
        raise RpcError("invalid getTransaction shape")

    transaction = result.get("transaction")
    if not isinstance(transaction, Mapping):
        raise RpcError("transaction field missing")
    message = transaction.get("message")
    if not isinstance(message, Mapping):
        raise RpcError("message field missing")
    slot = int(result.get("slot", -1))
    return {"slot": slot, "message": message}, evidence_id


def raw_okx_instructions(surface: Mapping[str, Any]) -> list[dict[str, Any]]:
    message = surface.get("message")
    if not isinstance(message, Mapping):
        raise ProbeError("message missing")
    instructions = message.get("instructions")
    if not isinstance(instructions, list):
        raise ProbeError("message instructions missing")

    out: list[dict[str, Any]] = []
    for index, instruction in enumerate(instructions):
        if not isinstance(instruction, Mapping):
            continue
        if instruction.get("programId") != OKX_ROUTER:
            continue
        data = instruction.get("data")
        accounts = instruction.get("accounts")
        if not isinstance(data, str) or not isinstance(accounts, list):
            continue
        if not all(isinstance(x, str) for x in accounts):
            continue
        out.append({"index": index, "data": data, "accounts": list(accounts)})
    return out


def derive_leg(surface: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    successes: list[tuple[dict[str, Any], dict[str, Any]]] = []
    errors: list[str] = []
    for instruction in raw_okx_instructions(surface):
        try:
            leg = derive_direct_root_raydium_leg(
                b58decode(instruction["data"]),
                instruction["accounts"],
                TARGET_POOL,
            )
            successes.append((instruction, leg))
        except ProbeError as exc:
            errors.append(str(exc))
    if len(successes) != 1:
        raise ProbeError(
            f"expected one projectable OKX instruction, got {len(successes)}; "
            f"rejections={errors[:4]}"
        )
    return successes[0]


def wait_finalized(rpc: RPC, signature: str, timeout: float) -> list[str]:
    deadline = time.monotonic() + timeout
    evidence: list[str] = []
    while time.monotonic() <= deadline:
        result, evidence_id = rpc.call(
            "getSignatureStatuses",
            [[signature], {"searchTransactionHistory": True}],
        )
        evidence.append(evidence_id)
        if isinstance(result, Mapping):
            values = result.get("value")
            if isinstance(values, list) and values and isinstance(values[0], Mapping):
                status = values[0]
                if status.get("err") is not None:
                    raise RpcError("candidate failed before finalization")
                if status.get("confirmationStatus") == "finalized":
                    return evidence
        time.sleep(1)
    raise RpcError("candidate did not finalize before timeout")


def conservative_conflict_audit(
    rpc: RPC, signature: str, s0_slot: int, s1_slot: int
) -> dict[str, Any]:
    seen: dict[str, int] = {}
    coverage: dict[str, int] = {}
    for key in MUTABLE_KEYS:
        rows = signatures(rpc, key, "finalized")
        if not rows:
            raise RpcError(f"no finalized history for mutable account {key}")
        min_slot = min(int(row.get("slot", 0)) for row in rows)
        coverage[key] = min_slot
        if min_slot > s0_slot:
            raise RpcError(f"history did not cover S0 for mutable account {key}")
        for row in rows:
            sig = row.get("signature")
            slot = int(row.get("slot", -1))
            if isinstance(sig, str) and row.get("err") is None and s0_slot < slot <= s1_slot:
                seen[sig] = slot

    others = {sig: slot for sig, slot in seen.items() if sig != signature}
    return {
        "status": "PASS" if not others and signature in seen else "REJECT",
        "target_signature_present": signature in seen,
        "other_successful_signatures": others,
        "window": {"s0_slot": s0_slot, "s1_slot": s1_slot},
        "history_min_slots": coverage,
    }


def score(predicted: list[Mapping[str, Any]], actual: list[Mapping[str, Any]]) -> dict[str, Any]:
    if len(predicted) != 6 or len(actual) != 6:
        raise RpcError("score requires six accounts")
    rows = []
    for key, p, a in zip(SIX_KEYS, predicted, actual):
        p_bytes = canonical_bytes(p)
        a_bytes = canonical_bytes(a)
        rows.append({
            "pubkey": key,
            "exact": p == a,
            "predicted_sha256": sha256(p_bytes),
            "actual_sha256": sha256(a_bytes),
            "predicted_lamports": p.get("lamports"),
            "actual_lamports": a.get("lamports"),
        })
    return {
        "exact_account_count": sum(1 for row in rows if row["exact"]),
        "all_six_exact": all(row["exact"] for row in rows),
        "accounts": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-url", default=DEFAULT_RPC)
    ap.add_argument("--output-dir", default="ghost-okx-router-shadow")
    ap.add_argument("--max-runtime-seconds", type=int, default=900)
    ap.add_argument("--poll-seconds", type=float, default=2.5)
    ap.add_argument("--request-timeout-seconds", type=float, default=20)
    ap.add_argument("--finalization-timeout-seconds", type=float, default=120)
    args = ap.parse_args()

    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    write_json(
        root / "authority_boundary.json",
        {
            "read_only": True,
            "wallet": False,
            "private_key": False,
            "signing": False,
            "submission": False,
            "broadcast": False,
            "capital_movement": False,
            "production_scout_mutation": False,
            "prediction_forbids": [
                "innerInstructions",
                "logMessages",
                "preTokenBalances",
                "postTokenBalances",
                "S1 before prediction commit",
            ],
        },
    )

    rpc = RPC(args.rpc_url, root, args.request_timeout_seconds)
    rejected = Counter()
    prediction_committed = False

    try:
        genesis, genesis_eid = rpc.call("getGenesisHash", [])
        write_json(
            root / "network.json",
            {"genesis_hash": genesis, "evidence_id": genesis_eid, "target_pool": TARGET_POOL},
        )

        first = snapshot(rpc)
        ring = [first]
        baseline = signatures(rpc, TARGET_POOL, "confirmed")
        seen = {
            str(row["signature"])
            for row in baseline
            if isinstance(row.get("signature"), str)
        }

        started = time.monotonic()
        while time.monotonic() - started < args.max_runtime_seconds:
            time.sleep(args.poll_seconds)
            try:
                snap = snapshot(rpc)
                if snap["context_slot"] != ring[-1]["context_slot"]:
                    ring.append(snap)
                    ring = ring[-256:]
                rows = signatures(rpc, TARGET_POOL, "confirmed")
            except RpcError:
                rejected["rpc_poll_error"] += 1
                continue

            fresh = [
                row
                for row in rows
                if isinstance(row.get("signature"), str)
                and str(row["signature"]) not in seen
            ]
            fresh.sort(key=lambda row: int(row.get("slot", 0)))

            for row in fresh:
                signature = str(row["signature"])
                seen.add(signature)
                tx_slot = int(row.get("slot", -1))
                if row.get("err") is not None:
                    rejected["failed_at_discovery"] += 1
                    continue

                prior = [item for item in ring if int(item["context_slot"]) < tx_slot]
                if not prior:
                    rejected["no_s0"] += 1
                    continue
                s0 = max(prior, key=lambda item: int(item["context_slot"]))

                try:
                    surface, tx_evidence_id = transaction_message_surface(rpc, signature)
                    if surface is None:
                        rejected["transaction_unavailable"] += 1
                        continue
                    if int(surface["slot"]) != tx_slot:
                        raise ProbeError("transaction slot mismatch")
                    instruction, leg = derive_leg(surface)
                    predicted_values, transition = project_rpc_bundle(
                        s0["values"], SIX_KEYS, leg, tx_slot
                    )
                except (RpcError, ProbeError, TransitionError) as exc:
                    rejected[f"not_projectable:{type(exc).__name__}"] += 1
                    continue

                signed_surface = {
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "message_only": surface["message"],
                    "selected_okx_instruction_index": instruction["index"],
                    "selected_okx_instruction_data": instruction["data"],
                    "selected_okx_instruction_accounts": instruction["accounts"],
                    "get_transaction_evidence_id": tx_evidence_id,
                }
                signed_surface_hash = sha256(canonical_bytes(signed_surface))
                prediction = {
                    "schema": "ghost_okx_router_shadow_prediction_v0",
                    "committed_at": now(),
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "s0_slot": int(s0["context_slot"]),
                    "s0_evidence_id": s0["rpc_evidence_id"],
                    "signed_surface_sha256": signed_surface_hash,
                    "causal_leg": leg,
                    "transition": transition,
                    "predicted_values": predicted_values,
                }
                prediction_hash = sha256(canonical_bytes(prediction))
                write_json(root / "signed_surface.json", signed_surface)
                write_json(root / "prediction.json", prediction)
                write_json(
                    root / "PREDICTION_COMMIT.json",
                    {
                        "schema": "ghost_prediction_commit_v0",
                        "committed_at": now(),
                        "prediction_sha256": prediction_hash,
                        "signed_surface_sha256": signed_surface_hash,
                        "truth_requested_after_this_commit": True,
                    },
                )
                prediction_committed = True

                finalization_evidence = wait_finalized(
                    rpc, signature, args.finalization_timeout_seconds
                )
                s1 = snapshot(rpc, tx_slot)
                audit = conservative_conflict_audit(
                    rpc,
                    signature,
                    int(s0["context_slot"]),
                    int(s1["context_slot"]),
                )
                result = score(predicted_values, s1["values"])
                truth = {
                    "schema": "ghost_okx_router_shadow_truth_v0",
                    "captured_at": now(),
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "s1_slot": int(s1["context_slot"]),
                    "s1_evidence_id": s1["rpc_evidence_id"],
                    "finalization_evidence_ids": finalization_evidence,
                    "conflict_audit": audit,
                    "score": result,
                    "actual_values": s1["values"],
                }
                write_json(root / "truth_and_score.json", truth)

                passed = audit["status"] == "PASS" and result["all_six_exact"]
                write_json(
                    root / ("SHADOW_PASS.json" if passed else "SHADOW_REJECT.json"),
                    {
                        "status": "PASS" if passed else "REJECT",
                        "signature": signature,
                        "transaction_slot": tx_slot,
                        "s0_slot": int(s0["context_slot"]),
                        "s1_slot": int(s1["context_slot"]),
                        "prediction_sha256": prediction_hash,
                        "exact_account_count": result["exact_account_count"],
                        "all_six_exact": result["all_six_exact"],
                        "conflict_audit": audit["status"],
                    },
                )
                return 0 if passed else 3

        write_json(
            root / "NOT_FOUND.json",
            {
                "status": "NO_PROJECTABLE_FRESH_OKX_ROOT_RAYDIUM_CASE",
                "runtime_seconds": args.max_runtime_seconds,
                "rejections": dict(rejected),
                "prediction_committed": prediction_committed,
            },
        )
        return 4

    except Exception as exc:
        write_json(
            root / "FATAL.json",
            {
                "status": "FATAL",
                "type": type(exc).__name__,
                "error": str(exc),
                "prediction_committed": prediction_committed,
            },
        )
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
