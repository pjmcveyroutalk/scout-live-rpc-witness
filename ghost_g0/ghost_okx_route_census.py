#!/usr/bin/env python3
"""Signed-message-only Ghost census for OKX routes touching the locked Raydium pool.

Discovery instrument only. It decodes finalized transaction.message surfaces and
never reads innerInstructions, logMessages, token balance deltas, or post-state.
No signing, submission, broadcasting, or capital movement.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ghost_okx_raydium_router_probe_v0 import (
    OKX_ROUTER,
    RAYDIUM_ADAPTER_BLOCK_LEN,
    RAYDIUM_CPMM,
    RAYDIUM_CPMM_DEX_TAG,
    SWAP_TOB_FIXED_ACCOUNT_COUNT,
    ProbeError,
    b58decode,
    decode_swap_tob,
)

RPC_URL = "https://api.mainnet-beta.solana.com"
TARGET_POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def rpc(method: str, params: list[Any], retries: int = 6) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
    delay = 0.5
    for attempt in range(retries):
        req = urllib.request.Request(
            RPC_URL,
            data=body,
            method="POST",
            headers={"content-type": "application/json", "user-agent": "Ghost-OKX-Route-Census/0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read())
            if not isinstance(payload, Mapping) or payload.get("error") is not None:
                raise RuntimeError(f"RPC failure {method}: {payload.get('error') if isinstance(payload, Mapping) else 'shape'}")
            return payload.get("result")
        except Exception:
            if attempt + 1 == retries:
                raise
            time.sleep(delay)
            delay = min(delay * 2.0, 8.0)
    raise RuntimeError("unreachable")


def okx_instructions(message: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = message.get("instructions")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for ix_index, ix in enumerate(rows):
        if not isinstance(ix, Mapping) or ix.get("programId") != OKX_ROUTER:
            continue
        data = ix.get("data")
        accounts = ix.get("accounts")
        if isinstance(data, str) and isinstance(accounts, list) and all(isinstance(x, str) for x in accounts):
            out.append({"ix_index": ix_index, "data": data, "accounts": list(accounts)})
    return out


def ray_blocks(accounts: list[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for start in range(SWAP_TOB_FIXED_ACCOUNT_COUNT, len(accounts)):
        if accounts[start] != RAYDIUM_CPMM:
            continue
        end = start + RAYDIUM_ADAPTER_BLOCK_LEN
        if end > len(accounts):
            continue
        block = accounts[start:end]
        found.append({
            "start": start,
            "pool": block[6],
            "amm_config": block[5],
            "input_vault": block[7],
            "output_vault": block[8],
            "input_mint": block[11],
            "output_mint": block[12],
        })
    return found


def stage_shape(routes: list[dict[str, int]]) -> dict[str, Any]:
    by_source: dict[int, list[dict[str, int]]] = defaultdict(list)
    for route in routes:
        by_source[int(route["source_node"])].append(route)
    return {
        str(source): {
            "branch_count": len(items),
            "weight_sum": sum(int(x["weight"]) for x in items),
            "destinations": [int(x["destination_node"]) for x in items],
            "dex_tags": [int(x["dex_tag"]) for x in items],
            "weights": [int(x["weight"]) for x in items],
        }
        for source, items in sorted(by_source.items())
    }


def classify_target(decoded: Mapping[str, Any], accounts: list[str]) -> dict[str, Any]:
    routes = list(decoded["routes"])
    ray_routes = [r for r in routes if int(r["dex_tag"]) == RAYDIUM_CPMM_DEX_TAG]
    blocks = ray_blocks(accounts)
    if len(ray_routes) != len(blocks):
        return {"status": "RAY_ROUTE_BLOCK_MISMATCH", "ray_routes": len(ray_routes), "ray_blocks": len(blocks)}
    pairs = list(zip(ray_routes, blocks))
    matches = [(route, block) for route, block in pairs if block["pool"] == TARGET_POOL]
    if len(matches) != 1:
        return {"status": "TARGET_BLOCK_COUNT", "target_matches": len(matches), "ray_routes": len(ray_routes)}
    target_route, target_block = matches[0]
    src = int(target_route["source_node"])
    dst = int(target_route["destination_node"])
    immediate_upstream = [dict(r) for r in routes if int(r["destination_node"]) == src]
    immediate_downstream = [dict(r) for r in routes if int(r["source_node"]) == dst]

    direct_root_allocation = None
    root_rounding_residual = None
    root_routes = [r for r in routes if int(r["source_node"]) == 0]
    if src == 0 and root_routes and sum(int(r["weight"]) for r in root_routes) == 10_000:
        amount = int(decoded["amount_in"])
        allocations: list[int] = []
        allocated = 0
        for i, route in enumerate(root_routes):
            if i + 1 == len(root_routes):
                value = amount - allocated
            else:
                value = amount * int(route["weight"]) // 10_000
                allocated += value
            allocations.append(value)
        for route, value in zip(root_routes, allocations):
            if route is target_route:
                direct_root_allocation = value
        floors = [amount * int(route["weight"]) // 10_000 for route in root_routes]
        root_rounding_residual = amount - sum(floors)

    return {
        "status": "OK",
        "target_route": dict(target_route),
        "target_block": target_block,
        "target_is_direct_root": src == 0 and dst == 1,
        "target_source_node": src,
        "target_destination_node": dst,
        "direct_root_allocation": direct_root_allocation,
        "root_rounding_residual": root_rounding_residual,
        "immediate_upstream": immediate_upstream,
        "immediate_downstream": immediate_downstream,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--output", default="ghost-okx-route-census/CENSUS.json")
    args = ap.parse_args()

    rows = rpc("getSignaturesForAddress", [TARGET_POOL, {"commitment": "finalized", "limit": max(1, min(args.limit, 1000))}])
    if not isinstance(rows, list):
        raise RuntimeError("invalid signature history")

    records: list[dict[str, Any]] = []
    counters = Counter()
    upstream_tags = Counter()
    downstream_tags = Counter()
    target_source_nodes = Counter()
    route_counts = Counter()
    root_branch_counts = Counter()
    rounding_residuals = Counter()

    for row in rows:
        if not isinstance(row, Mapping) or row.get("err") is not None or not isinstance(row.get("signature"), str):
            counters["skipped_failed_or_invalid"] += 1
            continue
        signature = str(row["signature"])
        tx = rpc("getTransaction", [signature, {"commitment": "finalized", "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
        if not isinstance(tx, Mapping):
            counters["transaction_unavailable"] += 1
            continue
        transaction = tx.get("transaction")
        message = transaction.get("message") if isinstance(transaction, Mapping) else None
        if not isinstance(message, Mapping):
            counters["message_missing"] += 1
            continue

        for ix in okx_instructions(message):
            counters["okx_instruction_seen"] += 1
            try:
                decoded = decode_swap_tob(b58decode(ix["data"]))
            except ProbeError as exc:
                counters[f"decode_reject:{str(exc)[:80]}"] += 1
                continue
            target = classify_target(decoded, ix["accounts"])
            if target.get("status") != "OK":
                counters[f"target_reject:{target.get('status')}"] += 1
                continue

            routes = list(decoded["routes"])
            root_routes = [r for r in routes if int(r["source_node"]) == 0]
            route_counts[len(routes)] += 1
            root_branch_counts[len(root_routes)] += 1
            target_source_nodes[int(target["target_source_node"])] += 1
            if target.get("root_rounding_residual") is not None:
                rounding_residuals[int(target["root_rounding_residual"])] += 1
            for r in target["immediate_upstream"]:
                upstream_tags[int(r["dex_tag"])] += 1
            for r in target["immediate_downstream"]:
                downstream_tags[int(r["dex_tag"])] += 1

            records.append({
                "signature": signature,
                "slot": int(tx.get("slot", row.get("slot", -1))),
                "outer_amount_in": int(decoded["amount_in"]),
                "outer_expect_amount_out": int(decoded["expect_amount_out"]),
                "slippage": int(decoded["slippage"]),
                "platform_fee_rate": int(decoded["platform_fee_rate"]),
                "trim_rate": int(decoded["trim_rate"]),
                "commission_info": int(decoded["commission_info"]),
                "route_count": len(routes),
                "routes": routes,
                "stage_shape": stage_shape(routes),
                "target": target,
            })
            counters["decoded_target_case"] += 1

    summary = {
        "schema": "ghost_okx_route_census_v0",
        "captured_at": now(),
        "authority": {"read_only": True, "signing": False, "submission": False, "capital_movement": False},
        "prediction_surface": "signed transaction.message only",
        "forbidden_execution_surfaces": ["innerInstructions", "logMessages", "preTokenBalances", "postTokenBalances", "S1"],
        "target_pool": TARGET_POOL,
        "requested_signature_limit": args.limit,
        "counts": dict(counters),
        "target_source_nodes": {str(k): v for k, v in target_source_nodes.most_common()},
        "route_counts": {str(k): v for k, v in route_counts.most_common()},
        "root_branch_counts": {str(k): v for k, v in root_branch_counts.most_common()},
        "immediate_upstream_dex_tags": {str(k): v for k, v in upstream_tags.most_common()},
        "immediate_downstream_dex_tags": {str(k): v for k, v in downstream_tags.most_common()},
        "root_rounding_residuals": {str(k): v for k, v in rounding_residuals.most_common()},
        "records": records,
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps({k: summary[k] for k in ["counts", "target_source_nodes", "route_counts", "root_branch_counts", "immediate_upstream_dex_tags", "root_rounding_residuals"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
