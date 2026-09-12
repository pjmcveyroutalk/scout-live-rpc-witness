#!/usr/bin/env python3
"""Near-tip Ghost shadow sensor for signed OKX -> Raydium CPMM projection.

V1 keeps the frozen causal projector unchanged but improves observation quality:
- S0 is captured at `confirmed` near tip instead of `finalized` lag.
- S1 is captured only after the target signature finalizes, at `finalized`.
- conflict-contaminated candidates are sealed and skipped rather than ending the run.
- if all mismatches are accounts marked read-only in the signed message, the
  candidate is classified as external/static drift and skipped.
- any conflict-free mismatch in a target-writable projected account remains a
  hard projector rejection.

Read-only research only. No signing, submission, broadcasting, or capital movement.
"""
from __future__ import annotations

import argparse
import time
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from ghost_okx_raydium_router_probe_v0 import ProbeError
from ghost_okx_router_shadow_v0 import (
    RPC,
    RpcError,
    SIX_KEYS,
    TARGET_POOL,
    canonical_bytes,
    conservative_conflict_audit,
    derive_leg,
    now,
    score,
    sha256,
    signatures,
    transaction_message_surface,
    wait_finalized,
    write_json,
)
from ghost_ray_cpmm_state_transition_v0 import TransitionError, project_rpc_bundle


def snapshot(rpc: RPC, commitment: str, min_slot: int | None = None) -> dict[str, Any]:
    if commitment not in {"confirmed", "finalized"}:
        raise RpcError(f"unsupported snapshot commitment {commitment}")
    cfg: dict[str, Any] = {"encoding": "base64", "commitment": commitment}
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
        "commitment": commitment,
    }


def writable_map(message: Mapping[str, Any]) -> dict[str, bool]:
    keys = message.get("accountKeys")
    if not isinstance(keys, list):
        raise RpcError("jsonParsed message accountKeys missing")
    out: dict[str, bool] = {}
    for item in keys:
        if isinstance(item, Mapping) and isinstance(item.get("pubkey"), str):
            out[str(item["pubkey"])] = bool(item.get("writable"))
        elif isinstance(item, str):
            out[item] = True
    return out


def mismatch_classification(result: Mapping[str, Any], message: Mapping[str, Any]) -> dict[str, Any]:
    writes = writable_map(message)
    mismatches = [row for row in result["accounts"] if not bool(row["exact"])]
    details = []
    for row in mismatches:
        key = str(row["pubkey"])
        details.append({
            "pubkey": key,
            "target_message_writable": writes.get(key),
        })
    all_read_only = bool(details) and all(
        item["target_message_writable"] is False for item in details
    )
    any_writable_or_unknown = any(
        item["target_message_writable"] is not False for item in details
    )
    return {
        "mismatches": details,
        "all_mismatches_target_read_only": all_read_only,
        "any_mismatch_target_writable_or_unknown": any_writable_or_unknown,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-url", default="https://api.mainnet-beta.solana.com")
    ap.add_argument("--output-dir", default="ghost-okx-router-shadow-v1")
    ap.add_argument("--max-runtime-seconds", type=int, default=900)
    ap.add_argument("--poll-seconds", type=float, default=1.5)
    ap.add_argument("--request-timeout-seconds", type=float, default=20)
    ap.add_argument("--finalization-timeout-seconds", type=float, default=120)
    args = ap.parse_args()

    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "authority_boundary.json", {
        "read_only": True,
        "wallet": False,
        "private_key": False,
        "signing": False,
        "submission": False,
        "broadcast": False,
        "capital_movement": False,
        "production_scout_mutation": False,
        "projector_changed": False,
        "s0_commitment": "confirmed",
        "s1_commitment": "finalized_after_target_finalization",
        "prediction_forbids": [
            "innerInstructions",
            "logMessages",
            "preTokenBalances",
            "postTokenBalances",
            "S1 before prediction commit",
        ],
    })

    rpc = RPC(args.rpc_url, root, args.request_timeout_seconds)
    rejected = Counter()
    candidate_count = 0
    prediction_committed = False

    try:
        genesis, genesis_eid = rpc.call("getGenesisHash", [])
        write_json(root / "network.json", {
            "genesis_hash": genesis,
            "evidence_id": genesis_eid,
            "target_pool": TARGET_POOL,
        })

        first = snapshot(rpc, "confirmed")
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
                snap = snapshot(rpc, "confirmed")
                if snap["context_slot"] != ring[-1]["context_slot"]:
                    ring.append(snap)
                    ring = ring[-512:]
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
                    rejected["no_confirmed_s0"] += 1
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

                candidate_count += 1
                candidate_dir = root / "candidates" / f"candidate-{candidate_count:04d}"
                candidate_dir.mkdir(parents=True, exist_ok=True)
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
                    "schema": "ghost_okx_router_shadow_prediction_v1",
                    "committed_at": now(),
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "s0_slot": int(s0["context_slot"]),
                    "s0_commitment": s0["commitment"],
                    "s0_evidence_id": s0["rpc_evidence_id"],
                    "signed_surface_sha256": signed_surface_hash,
                    "causal_leg": leg,
                    "transition": transition,
                    "predicted_values": predicted_values,
                }
                prediction_hash = sha256(canonical_bytes(prediction))
                write_json(candidate_dir / "signed_surface.json", signed_surface)
                write_json(candidate_dir / "prediction.json", prediction)
                write_json(candidate_dir / "PREDICTION_COMMIT.json", {
                    "schema": "ghost_prediction_commit_v1",
                    "committed_at": now(),
                    "prediction_sha256": prediction_hash,
                    "signed_surface_sha256": signed_surface_hash,
                    "truth_requested_after_this_commit": True,
                })
                prediction_committed = True

                try:
                    finalization_evidence = wait_finalized(
                        rpc, signature, args.finalization_timeout_seconds
                    )
                    s1 = snapshot(rpc, "finalized", tx_slot)
                    audit = conservative_conflict_audit(
                        rpc,
                        signature,
                        int(s0["context_slot"]),
                        int(s1["context_slot"]),
                    )
                    result = score(predicted_values, s1["values"])
                    mismatch = mismatch_classification(result, surface["message"])
                except RpcError as exc:
                    write_json(candidate_dir / "CANDIDATE_ERROR.json", {
                        "status": "EVIDENCE_ERROR",
                        "error": str(exc),
                    })
                    rejected["candidate_evidence_error"] += 1
                    continue

                write_json(candidate_dir / "truth_and_score.json", {
                    "schema": "ghost_okx_router_shadow_truth_v1",
                    "captured_at": now(),
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "s1_slot": int(s1["context_slot"]),
                    "s1_evidence_id": s1["rpc_evidence_id"],
                    "finalization_evidence_ids": finalization_evidence,
                    "conflict_audit": audit,
                    "score": result,
                    "mismatch_classification": mismatch,
                    "actual_values": s1["values"],
                })

                if audit["status"] != "PASS":
                    write_json(candidate_dir / "CANDIDATE_CONTAMINATED.json", {
                        "status": "CONFLICT_CONTAMINATED",
                        "prediction_sha256": prediction_hash,
                        "conflict_audit": audit,
                    })
                    rejected["conflict_contaminated"] += 1
                    continue

                if result["all_six_exact"]:
                    write_json(candidate_dir / "CANDIDATE_PASS.json", {
                        "status": "PASS",
                        "prediction_sha256": prediction_hash,
                        "exact_account_count": 6,
                    })
                    write_json(root / "SHADOW_PASS.json", {
                        "status": "PASS",
                        "candidate": candidate_count,
                        "signature": signature,
                        "transaction_slot": tx_slot,
                        "s0_slot": int(s0["context_slot"]),
                        "s1_slot": int(s1["context_slot"]),
                        "prediction_sha256": prediction_hash,
                        "exact_account_count": 6,
                        "all_six_exact": True,
                        "conflict_audit": "PASS",
                    })
                    return 0

                if mismatch["all_mismatches_target_read_only"]:
                    write_json(candidate_dir / "CANDIDATE_CONTAMINATED.json", {
                        "status": "READ_ONLY_ACCOUNT_DRIFT",
                        "prediction_sha256": prediction_hash,
                        "mismatch_classification": mismatch,
                    })
                    rejected["read_only_account_drift"] += 1
                    continue

                write_json(candidate_dir / "CANDIDATE_PROJECTOR_REJECT.json", {
                    "status": "PROJECTOR_MISMATCH",
                    "prediction_sha256": prediction_hash,
                    "exact_account_count": result["exact_account_count"],
                    "mismatch_classification": mismatch,
                })
                write_json(root / "SHADOW_REJECT.json", {
                    "status": "PROJECTOR_MISMATCH",
                    "candidate": candidate_count,
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "s0_slot": int(s0["context_slot"]),
                    "s1_slot": int(s1["context_slot"]),
                    "prediction_sha256": prediction_hash,
                    "exact_account_count": result["exact_account_count"],
                    "all_six_exact": False,
                    "conflict_audit": "PASS",
                    "mismatch_classification": mismatch,
                })
                return 3

        write_json(root / "NOT_FOUND.json", {
            "status": "NO_CLEAN_PROJECTABLE_FRESH_OKX_ROOT_RAYDIUM_CASE",
            "runtime_seconds": args.max_runtime_seconds,
            "candidate_count": candidate_count,
            "rejections": dict(rejected),
            "prediction_committed": prediction_committed,
        })
        return 4

    except Exception as exc:
        write_json(root / "FATAL.json", {
            "status": "FATAL",
            "type": type(exc).__name__,
            "error": str(exc),
            "candidate_count": candidate_count,
            "prediction_committed": prediction_committed,
        })
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
