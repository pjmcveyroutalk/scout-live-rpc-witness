#!/usr/bin/env python3
"""Blind-corpus collector for OKX BisonFi -> Raydium CPMM multi-stage routes.

Research-only and read-only. The collector keeps a rolling confirmed snapshot of
known BisonFi WSOL/USDT market state plus Scout's locked Raydium six-account
quote bundle. When a fresh signed OKX SwapTob message commits the proven route
shape BisonFi 0->1 followed by a stage-1 Raydium CPMM leg into the locked pool,
it seals the signed message + nearest pre-transaction snapshot before fetching
any post-execution truth.

It does not sign, submit, broadcast, or move capital. It does not use inner
instructions, logs, token deltas, or post-state before the input commit.
"""
from __future__ import annotations

import argparse
import time
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from ghost_okx_raydium_router_probe_v0 import (
    OKX_ROUTER,
    ProbeError,
    RAYDIUM_CPMM,
    RAYDIUM_CPMM_DEX_TAG,
    RAYDIUM_ADAPTER_BLOCK_LEN,
    SPL_TOKEN,
    SWAP_TOB_FIXED_ACCOUNT_COUNT,
    b58decode,
    decode_swap_tob,
)
from ghost_okx_router_shadow_v0 import (
    RPC,
    RpcError,
    canonical_bytes,
    now,
    sha256,
    wait_finalized,
    write_json,
)

TARGET_POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
BISON_PROGRAM = "BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi"
BISON_MARKET = "FJnaiidSLXFweWkgbinxEHRykVHsnkzDcYbNDR3RF5LN"
BISON_WSOL_VAULT = "C9jjhzojE16zJ296tEPinA35rB1okyMVspE7FnR4idMf"
BISON_USDT_VAULT = "F2zDmA4GLsHtSDtEAFo9wWr5VBHLXtZjYzhRoGybWsFM"
SYSVAR_INSTRUCTIONS = "Sysvar1nstructions1111111111111111111111111"
BISON_WITH_SIG_TAG = 120

RAY_SIX = [
    TARGET_POOL,
    "FMmwToGqT9iwDgsqvzLg65vcKSzKme4szbWqX1kyCBCJ",
    "v3YN4d7JRhKFcwtex7qNtyg2r5hKYW96Cayb6GivSvY",
    "HG2WgeYsjqQhnjhwHj7QdTVvjyWpFRk6VREAQ8MURv2u",
    "So11111111111111111111111111111111111111112",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
]
BISON_STATE = [BISON_MARKET, BISON_WSOL_VAULT, BISON_USDT_VAULT]
SNAPSHOT_KEYS = BISON_STATE + RAY_SIX


def snapshot(rpc: RPC, min_slot: int | None = None) -> dict[str, Any]:
    cfg: dict[str, Any] = {"encoding": "base64", "commitment": "confirmed"}
    if min_slot is not None:
        cfg["minContextSlot"] = min_slot
    result, evidence_id = rpc.call("getMultipleAccounts", [SNAPSHOT_KEYS, cfg])
    if not isinstance(result, Mapping) or not isinstance(result.get("context"), Mapping):
        raise RpcError("invalid getMultipleAccounts shape")
    values = result.get("value")
    if not isinstance(values, list) or len(values) != len(SNAPSHOT_KEYS):
        raise RpcError("incomplete multi-stage dependency snapshot")
    if any(not isinstance(value, Mapping) for value in values):
        raise RpcError("missing multi-stage dependency account")
    return {
        "context_slot": int(result["context"]["slot"]),
        "keys": list(SNAPSHOT_KEYS),
        "values": values,
        "rpc_evidence_id": evidence_id,
        "captured_at": now(),
    }


def signatures(rpc: RPC) -> list[Mapping[str, Any]]:
    result, _ = rpc.call(
        "getSignaturesForAddress",
        [TARGET_POOL, {"commitment": "confirmed", "limit": 100}],
    )
    if not isinstance(result, list):
        raise RpcError("invalid target signature history")
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
    return {"slot": int(result.get("slot", -1)), "message": message}, evidence_id


def raw_okx_instructions(surface: Mapping[str, Any]) -> list[dict[str, Any]]:
    message = surface.get("message")
    if not isinstance(message, Mapping):
        raise ProbeError("message missing")
    instructions = message.get("instructions")
    if not isinstance(instructions, list):
        raise ProbeError("instructions missing")
    out: list[dict[str, Any]] = []
    for index, instruction in enumerate(instructions):
        if not isinstance(instruction, Mapping) or instruction.get("programId") != OKX_ROUTER:
            continue
        data = instruction.get("data")
        accounts = instruction.get("accounts")
        if (
            isinstance(data, str)
            and isinstance(accounts, list)
            and all(isinstance(x, str) for x in accounts)
        ):
            out.append({"index": index, "data": data, "accounts": list(accounts)})
    return out


def find_bison_block(accounts: list[str]) -> dict[str, Any]:
    starts = [i for i, key in enumerate(accounts) if key == BISON_PROGRAM]
    matches: list[tuple[int, list[str]]] = []
    for start in starts:
        end = start + 10
        if end > len(accounts):
            continue
        block = accounts[start:end]
        if (
            block[4] == BISON_MARKET
            and block[5] == BISON_WSOL_VAULT
            and block[6] == BISON_USDT_VAULT
            and block[7] == SPL_TOKEN
            and block[8] == SPL_TOKEN
            and block[9] == SYSVAR_INSTRUCTIONS
        ):
            matches.append((start, block))
    if len(matches) != 1:
        raise ProbeError(f"expected one known BisonFi block, got {len(matches)}")
    start, block = matches[0]
    return {
        "start": start,
        "program": block[0],
        "authority": block[1],
        "user_account_a": block[2],
        "user_account_b": block[3],
        "market": block[4],
        "market_wsol_vault": block[5],
        "market_usdt_vault": block[6],
        "token_program_a": block[7],
        "token_program_b": block[8],
        "sysvar_instructions": block[9],
    }


def find_target_ray_block(accounts: list[str]) -> dict[str, Any]:
    matches: list[tuple[int, list[str]]] = []
    for start in range(SWAP_TOB_FIXED_ACCOUNT_COUNT, len(accounts)):
        if accounts[start] != RAYDIUM_CPMM:
            continue
        end = start + RAYDIUM_ADAPTER_BLOCK_LEN
        if end > len(accounts):
            continue
        block = accounts[start:end]
        if block[6] == TARGET_POOL and block[9] == SPL_TOKEN and block[10] == SPL_TOKEN:
            matches.append((start, block))
    if len(matches) != 1:
        raise ProbeError(f"expected one locked-pool Raydium block, got {len(matches)}")
    start, block = matches[0]
    return {
        "start": start,
        "program": block[0],
        "payer": block[1],
        "user_input": block[2],
        "user_output": block[3],
        "authority": block[4],
        "amm_config": block[5],
        "pool": block[6],
        "input_vault": block[7],
        "output_vault": block[8],
        "input_token_program": block[9],
        "output_token_program": block[10],
        "input_mint": block[11],
        "output_mint": block[12],
        "observation_state": block[13],
    }


def classify_multistage(instruction_data: bytes, accounts: list[str]) -> dict[str, Any]:
    decoded = decode_swap_tob(instruction_data)
    routes = list(decoded["routes"])
    root = [
        route
        for route in routes
        if int(route["source_node"]) == 0 and int(route["destination_node"]) == 1
    ]
    if (
        len(root) != 1
        or int(root[0]["weight"]) != 10_000
        or int(root[0]["dex_tag"]) != BISON_WITH_SIG_TAG
    ):
        raise ProbeError("root is not the proven 100% BisonFi-WithSig edge")
    stage = [
        route
        for route in routes
        if int(route["source_node"]) == 1 and int(route["destination_node"]) == 2
    ]
    if not stage or sum(int(route["weight"]) for route in stage) != 10_000:
        raise ProbeError("stage 1->2 is not a complete deterministic split")
    ray_routes = [
        route for route in stage if int(route["dex_tag"]) == RAYDIUM_CPMM_DEX_TAG
    ]
    if not ray_routes:
        raise ProbeError("stage 1->2 has no Raydium CPMM route")
    return {
        "decoded_swap_tob": decoded,
        "root_route": root[0],
        "stage_1_to_2_routes": stage,
        "bison_block": find_bison_block(accounts),
        "target_raydium_block": find_target_ray_block(accounts),
    }


def derive_candidate(surface: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    successes: list[tuple[dict[str, Any], dict[str, Any]]] = []
    errors: list[str] = []
    for instruction in raw_okx_instructions(surface):
        try:
            classification = classify_multistage(
                b58decode(instruction["data"]), instruction["accounts"]
            )
            successes.append((instruction, classification))
        except ProbeError as exc:
            errors.append(str(exc))
    if len(successes) != 1:
        raise ProbeError(
            f"expected one multi-stage OKX candidate, got {len(successes)}; "
            f"rejections={errors[:4]}"
        )
    return successes[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-url", default="https://api.mainnet-beta.solana.com")
    ap.add_argument("--output-dir", default="ghost-okx-bison-ray-multistage")
    ap.add_argument("--max-runtime-seconds", type=int, default=900)
    ap.add_argument("--poll-seconds", type=float, default=2.0)
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
            "input_commit_forbids": [
                "innerInstructions",
                "logMessages",
                "preTokenBalances",
                "postTokenBalances",
                "post-state before commit",
            ],
        },
    )

    rpc = RPC(args.rpc_url, root, args.request_timeout_seconds)
    rejected = Counter()
    input_committed = False
    try:
        genesis, genesis_eid = rpc.call("getGenesisHash", [])
        write_json(
            root / "network.json",
            {
                "genesis_hash": genesis,
                "evidence_id": genesis_eid,
                "target_pool": TARGET_POOL,
                "bison_market": BISON_MARKET,
                "snapshot_keys": SNAPSHOT_KEYS,
            },
        )

        first = snapshot(rpc)
        ring = [first]
        baseline = signatures(rpc)
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
                    ring = ring[-512:]
                rows = signatures(rpc)
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
                    rejected["no_pre_tx_dependency_snapshot"] += 1
                    continue
                s0 = max(prior, key=lambda item: int(item["context_slot"]))
                try:
                    surface, tx_eid = transaction_message_surface(rpc, signature)
                    if surface is None:
                        rejected["transaction_unavailable"] += 1
                        continue
                    if int(surface["slot"]) != tx_slot:
                        raise ProbeError("transaction slot mismatch")
                    instruction, classification = derive_candidate(surface)
                except (RpcError, ProbeError) as exc:
                    rejected[f"not_candidate:{type(exc).__name__}"] += 1
                    continue

                sealed_input = {
                    "schema": "ghost_okx_bison_raydium_multistage_input_v0",
                    "committed_at": now(),
                    "signature": signature,
                    "transaction_slot": tx_slot,
                    "s0_slot": int(s0["context_slot"]),
                    "s0_evidence_id": s0["rpc_evidence_id"],
                    "snapshot_keys": list(s0["keys"]),
                    "s0_values": s0["values"],
                    "message_only": surface["message"],
                    "selected_okx_instruction_index": instruction["index"],
                    "selected_okx_instruction_data": instruction["data"],
                    "selected_okx_instruction_accounts": instruction["accounts"],
                    "get_transaction_evidence_id": tx_eid,
                    "classification": classification,
                }
                input_hash = sha256(canonical_bytes(sealed_input))
                write_json(root / "sealed_input.json", sealed_input)
                write_json(
                    root / "INPUT_COMMIT.json",
                    {
                        "schema": "ghost_multistage_input_commit_v0",
                        "committed_at": now(),
                        "input_sha256": input_hash,
                        "truth_requested_after_this_commit": True,
                    },
                )
                input_committed = True

                finalization_eids = wait_finalized(
                    rpc, signature, args.finalization_timeout_seconds
                )
                truth, truth_eid = rpc.call(
                    "getTransaction",
                    [
                        signature,
                        {
                            "commitment": "finalized",
                            "encoding": "jsonParsed",
                            "maxSupportedTransactionVersion": 0,
                        },
                    ],
                )
                s1 = snapshot(rpc, tx_slot)
                write_json(
                    root / "truth_after_commit.json",
                    {
                        "schema": "ghost_okx_bison_raydium_multistage_truth_v0",
                        "captured_at": now(),
                        "signature": signature,
                        "transaction_slot": tx_slot,
                        "truth_get_transaction_evidence_id": truth_eid,
                        "finalization_evidence_ids": finalization_eids,
                        "s1_slot": int(s1["context_slot"]),
                        "s1_evidence_id": s1["rpc_evidence_id"],
                        "s1_values": s1["values"],
                        "finalized_transaction": truth,
                    },
                )
                write_json(
                    root / "CORPUS_CAPTURED.json",
                    {
                        "status": "CAPTURED",
                        "signature": signature,
                        "transaction_slot": tx_slot,
                        "s0_slot": int(s0["context_slot"]),
                        "s1_slot": int(s1["context_slot"]),
                        "input_sha256": input_hash,
                    },
                )
                return 0

        write_json(
            root / "NOT_FOUND.json",
            {
                "status": "NO_FRESH_BISON_TO_LOCKED_RAYDIUM_MULTISTAGE_CASE",
                "runtime_seconds": args.max_runtime_seconds,
                "rejections": dict(rejected),
                "input_committed": input_committed,
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
                "input_committed": input_committed,
            },
        )
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
