#!/usr/bin/env python3
"""Classify Shadow-v1 intervening writers for burst-projection feasibility.

Read-only historical witness. Uses finalized transaction.message only for
predictive classification; no inner instructions, logs, token deltas, signing,
submission, broadcasting, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ghost_g0.ghost_okx_raydium_router_probe_v0 import (
    OKX_ROUTER,
    RAYDIUM_CPMM,
    ProbeError,
    b58decode,
    decode_swap_tob,
)
from ghost_g0.ghost_okx_raydium_router_probe_v1 import derive_direct_root_raydium_leg_v1

RPC_URL = "https://api.mainnet-beta.solana.com"
TARGET_POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
RAY_SWAP_BASE_INPUT = bytes([0x8F, 0xBE, 0x5A, 0xDA, 0xC4, 0x1E, 0x33, 0xDE])

SIGNATURES = [
    "5pgvTKLrJNPToAv5DuxPptkFPqt7emvGPugVXLg28zbvEwfxz4971HuKDuBJLDEbRYovybqhJF6JDRW6sAxGdTvi",
    "5wVFPSLYJzo13Zkagmjb92yY4NJ2Ekz6C1jLR84peVZLBiaY8yKVghRLf1nVEu7WwG1a9JsJnXiqoZTPqQQtqnyt",
    "2vZyLd2WWArweYKTPbVWXt45CbJyqktejLgqjn5QvSTuczBqJjTiBv875fwox5Jdw7qMcbPhixD958bALuN5mtYP",
    "3tBMwopBHWKX3kUkiQVmCncu91t8iemdQcqhNSAvbNeomaoMdJ5xczU4v86PaThQkbTKAYfNVUU32XZBktpK6ZJe",
    "4MJ1V3fL5Er69BCBSctyPr886aPEpArycnzSwp64DDQkJSNEnjQncfKueRCxiQFX4y1heHTbKXzk5UBH3PphqkAE",
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rpc(method: str, params: list[Any]) -> tuple[Any, dict[str, Any]]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
    delay = 0.5
    last = None
    for attempt in range(6):
        started = now()
        try:
            req = urllib.request.Request(
                RPC_URL,
                data=body,
                method="POST",
                headers={"content-type": "application/json", "user-agent": "Ghost-Burst-Census/0"},
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
                status = int(response.status)
            payload = json.loads(raw)
            evidence = {
                "endpoint": RPC_URL,
                "method": method,
                "request_body": body.decode(),
                "request_sha256": sha256(body),
                "response_sha256": sha256(raw),
                "http_status": status,
                "started_at": started,
                "completed_at": now(),
            }
            if not isinstance(payload, Mapping) or payload.get("error") is not None:
                raise RuntimeError(str(payload.get("error") if isinstance(payload, Mapping) else "invalid shape"))
            return payload.get("result"), evidence
        except Exception as exc:
            last = exc
            if attempt == 5:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 8)
    raise RuntimeError(str(last))


def classify_message(message: Mapping[str, Any]) -> dict[str, Any]:
    instructions = message.get("instructions")
    if not isinstance(instructions, list):
        return {"kind": "NO_MESSAGE_INSTRUCTIONS", "projectable_now": False}

    top_level_ray = []
    okx_rows = []
    for idx, ix in enumerate(instructions):
        if not isinstance(ix, Mapping):
            continue
        program = ix.get("programId")
        accounts = ix.get("accounts")
        data = ix.get("data")
        if program == RAYDIUM_CPMM and isinstance(accounts, list) and TARGET_POOL in accounts and isinstance(data, str):
            raw = b58decode(data)
            amount = None
            if len(raw) >= 24 and raw[:8] == RAY_SWAP_BASE_INPUT:
                amount = int.from_bytes(raw[8:16], "little")
            top_level_ray.append({"instruction_index": idx, "swap_base_input": amount is not None, "amount_in": amount})
        if program == OKX_ROUTER and isinstance(accounts, list) and isinstance(data, str) and all(isinstance(x, str) for x in accounts):
            row: dict[str, Any] = {"instruction_index": idx}
            try:
                raw = b58decode(data)
                decoded = decode_swap_tob(raw)
                row["routes"] = decoded["routes"]
                row["outer_amount_in"] = decoded["amount_in"]
                try:
                    leg = derive_direct_root_raydium_leg_v1(raw, list(accounts), TARGET_POOL)
                    row["direct_root_projectable"] = True
                    row["derived_raydium_amount_in"] = leg["derived_raydium_amount_in"]
                except ProbeError as exc:
                    row["direct_root_projectable"] = False
                    row["projector_rejection"] = str(exc)
                okx_rows.append(row)
            except ProbeError as exc:
                row["decode_error"] = str(exc)
                okx_rows.append(row)

    if any(row.get("direct_root_projectable") for row in okx_rows):
        return {"kind": "OKX_DIRECT_ROOT_PROJECTABLE", "projectable_now": True, "okx": okx_rows, "top_level_raydium": top_level_ray}
    if top_level_ray and any(row.get("swap_base_input") for row in top_level_ray):
        return {"kind": "TOP_LEVEL_RAYDIUM_PROJECTABLE", "projectable_now": True, "okx": okx_rows, "top_level_raydium": top_level_ray}
    if okx_rows:
        return {"kind": "OKX_PRESENT_NOT_CURRENTLY_PROJECTABLE", "projectable_now": False, "okx": okx_rows, "top_level_raydium": top_level_ray}
    return {"kind": "NON_OKX_OR_UNKNOWN_WRITER", "projectable_now": False, "okx": [], "top_level_raydium": top_level_ray}


def main() -> int:
    stamp = now().replace(":", "").replace("-", "").replace(".", "_")
    out_dir = Path("live-evidence") / f"ghost-conflict-writer-census-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    rpc_records = []
    for signature in SIGNATURES:
        result, evidence = rpc(
            "getTransaction",
            [signature, {"commitment": "finalized", "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
        )
        evidence["signature"] = signature
        rpc_records.append(evidence)
        if not isinstance(result, Mapping):
            rows.append({"signature": signature, "status": "UNAVAILABLE", "projectable_now": False})
            continue
        tx = result.get("transaction")
        message = tx.get("message") if isinstance(tx, Mapping) else None
        if not isinstance(message, Mapping):
            rows.append({"signature": signature, "slot": result.get("slot"), "status": "MESSAGE_MISSING", "projectable_now": False})
            continue
        classification = classify_message(message)
        rows.append({
            "signature": signature,
            "slot": int(result.get("slot", -1)),
            "status": "OK",
            **classification,
        })

    projectable = sum(1 for row in rows if row.get("projectable_now") is True)
    evidence = {
        "schema": "ghost.conflict_writer_census.v0",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "target_pool": TARGET_POOL,
        "predictive_surface": "finalized signed transaction.message only",
        "forbidden_for_classification": ["innerInstructions", "logMessages", "preTokenBalances", "postTokenBalances"],
        "writer_count": len(rows),
        "projectable_now_count": projectable,
        "projectable_now_fraction": projectable / len(rows) if rows else 0.0,
        "writers": rows,
        "rpc_evidence": rpc_records,
        "safety": {
            "wallet": False,
            "signer": False,
            "approval": False,
            "transaction_builder": False,
            "transaction_serialization": False,
            "transaction_simulation": False,
            "transaction_submission": False,
            "broadcast": False,
            "bridge_execution": False,
            "capital_movement": False,
        },
    }
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out_dir / "evidence.json").write_bytes(raw)
    (out_dir / "evidence.sha256").write_text(sha256(raw) + "  evidence.json\n")
    print(json.dumps({"writer_count": len(rows), "projectable_now_count": projectable, "kinds": [row.get("kind") for row in rows]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
