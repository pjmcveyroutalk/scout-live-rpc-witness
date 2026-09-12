#!/usr/bin/env python3
"""Read-only signed-surface census for recent successful writers touching Ghost's locked Raydium pool.

The witness deliberately classifies only transaction.message/top-level instruction data.
It does not use inner instructions, logs, token deltas, post-state, wallets, signing,
simulation, transaction construction, submission, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

RPC_URL = "https://api.mainnet-beta.solana.com"
TARGET_POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
OKX = "proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u"
TITAN = "T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT"
DRSW = "DRSw8uSW9De7eCKSM9qXm7aD2QKrvcJnA7Hf4Uu3ezYM"
RAYDIUM_CPMM = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
OKX_SWAP_TOB = bytes([170, 41, 85, 177, 132, 80, 31, 53])
OKX_SWAP_TOB_ENHANCED = bytes([190, 156, 169, 176, 149, 154, 161, 108])
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def b58decode(value: str) -> bytes:
    n = 0
    for ch in value:
        n = n * 58 + B58_INDEX[ch]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def rpc(method: str, params: list[Any], retries: int = 7) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
    delay = 0.6
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(
            RPC_URL,
            data=body,
            method="POST",
            headers={"content-type": "application/json", "user-agent": "Ghost-Target-Writer-Census/1"},
        )
        try:
            with urllib.request.urlopen(req, timeout=35) as response:
                obj = json.loads(response.read())
            if not isinstance(obj, Mapping) or obj.get("error") is not None:
                raise RuntimeError(f"RPC {method}: {obj.get('error') if isinstance(obj, Mapping) else 'invalid shape'}")
            return obj.get("result")
        except Exception as exc:
            last = exc
            if attempt + 1 >= retries:
                raise
            time.sleep(delay)
            delay = min(delay * 2.0, 8.0)
    raise RuntimeError(str(last) if last else "RPC failed")


def family(program_id: str, raw: bytes) -> str:
    if program_id == OKX:
        if raw.startswith(OKX_SWAP_TOB):
            return "okx_swap_tob"
        if raw.startswith(OKX_SWAP_TOB_ENHANCED):
            return "okx_swap_tob_enhanced"
        return "okx_other"
    if program_id == TITAN:
        if raw[:1] == b"\x2a":
            return "titan_swap_route_v3"
        return "titan_other"
    if program_id == DRSW:
        if len(raw) == 33 and raw[:1] == b"\x03":
            return "drsw_03_len33"
        return "drsw_other"
    if program_id == RAYDIUM_CPMM:
        return "raydium_cpmm_top_level"
    return "other"


def signed_header(program_id: str, fam: str, raw: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if fam in {"okx_swap_tob", "okx_swap_tob_enhanced"} and len(raw) >= 34:
        # Both observed families use the same concrete SwapArgs prefix:
        # disc(8), order_id(8), amount_in(8), expected_out(8), slippage(2).
        out = {
            "order_id": int.from_bytes(raw[8:16], "little"),
            "amount_in": int.from_bytes(raw[16:24], "little"),
            "expected_amount_out": int.from_bytes(raw[24:32], "little"),
            "slippage": int.from_bytes(raw[32:34], "little"),
        }
    elif fam == "titan_swap_route_v3" and len(raw) >= 24:
        out = {
            "config": raw[1],
            "amount": int.from_bytes(raw[2:10], "little"),
            "expected_amount_out": int.from_bytes(raw[10:18], "little"),
            "slippage_threshold_bps": int.from_bytes(raw[18:20], "little"),
            "mints": raw[20],
            "fee_centi_bps": int.from_bytes(raw[21:23], "little"),
            "mesh_size": raw[23],
        }
    elif fam == "drsw_03_len33":
        out = {"candidate_amount_at_1_8": int.from_bytes(raw[1:9], "little")}
    elif fam == "raydium_cpmm_top_level" and len(raw) >= 24:
        out = {"amount_or_arg_8_16": int.from_bytes(raw[8:16], "little")}
    return out


def main() -> int:
    started = utc_now()
    history = rpc("getSignaturesForAddress", [TARGET_POOL, {"commitment": "finalized", "limit": 500}])
    if not isinstance(history, list):
        raise RuntimeError("signature history is not a list")

    records: list[dict[str, Any]] = []
    counts = Counter()
    successful_rows = [r for r in history if isinstance(r, Mapping) and r.get("err") is None and isinstance(r.get("signature"), str)]

    # Cap transaction fetches so the public endpoint remains a passive research source.
    for row in successful_rows[:60]:
        signature = str(row["signature"])
        tx = rpc("getTransaction", [signature, {"commitment": "finalized", "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
        if not isinstance(tx, Mapping):
            counts["transaction_unavailable"] += 1
            continue
        transaction = tx.get("transaction")
        message = transaction.get("message") if isinstance(transaction, Mapping) else None
        if not isinstance(message, Mapping):
            counts["message_missing"] += 1
            continue
        instructions = message.get("instructions")
        if not isinstance(instructions, list):
            counts["instruction_list_missing"] += 1
            continue

        target_outer: list[dict[str, Any]] = []
        for ix_index, ix in enumerate(instructions):
            if not isinstance(ix, Mapping):
                continue
            program_id = ix.get("programId")
            accounts = ix.get("accounts")
            data = ix.get("data")
            if not isinstance(program_id, str) or not isinstance(accounts, list) or not all(isinstance(x, str) for x in accounts):
                continue
            if TARGET_POOL not in accounts:
                continue
            raw = b""
            if isinstance(data, str):
                try:
                    raw = b58decode(data)
                except Exception:
                    raw = b""
            fam = family(program_id, raw)
            counts[fam] += 1
            target_outer.append({
                "ix_index": ix_index,
                "program_id": program_id,
                "family": fam,
                "account_count": len(accounts),
                "target_account_index": accounts.index(TARGET_POOL),
                "raydium_program_explicit": RAYDIUM_CPMM in accounts,
                "data_len": len(raw),
                "data_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                "discriminator_hex": raw[:8].hex() if raw else None,
                "signed_header": signed_header(program_id, fam, raw),
            })

        if target_outer:
            records.append({
                "signature": signature,
                "slot": int(tx.get("slot", row.get("slot", -1))),
                "block_time": tx.get("blockTime"),
                "outer_target_instructions": target_outer,
            })
            counts["successful_transactions_with_explicit_target"] += 1
        else:
            counts["successful_transactions_without_explicit_target_outer"] += 1

    stamp = started.replace(":", "").replace("-", "").replace(".", "_")
    bundle = Path("live-evidence") / f"ghost-target-writer-census-{stamp}"
    bundle.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema": "ghost.target_writer_census.v1",
        "accepted": True,
        "captured_at_utc": started,
        "completed_at_utc": utc_now(),
        "observation_only": True,
        "execution_authority": False,
        "target_pool": TARGET_POOL,
        "rpc_url": RPC_URL,
        "requested_signature_limit": 500,
        "history_rows": len(history),
        "successful_history_rows": len(successful_rows),
        "fetched_successful_transactions": min(len(successful_rows), 60),
        "classification_surface": "signed transaction.message top-level instructions only",
        "forbidden_surfaces_not_used": [
            "meta.innerInstructions",
            "meta.logMessages",
            "preTokenBalances",
            "postTokenBalances",
            "S1 account truth",
        ],
        "family_counts": dict(counts),
        "records": records,
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
    (bundle / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "accepted": True,
        "history_rows": len(history),
        "successful_history_rows": len(successful_rows),
        "records": len(records),
        "family_counts": dict(counts),
        "evidence": str(bundle / "evidence.json"),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
