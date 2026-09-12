#!/usr/bin/env python3
"""Batched excluded-signature holdout for the narrow Titan 36-byte single-Ray fee rule.

This is the same precommitted rule as T898, evaluated more efficiently over finalized
pool history by batching getTransaction reads. The four T897 discovery signatures are
excluded. Unsupported shapes/configs fail closed and are not scored.

Rule:
- finalized only, at least 128 slots behind finalized tip;
- exactly one top-level Titan instruction naming the locked Raydium pool/program;
- payload exactly 36 bytes, discriminator 0x2a, route field 1, venue 10,
  source 0, destination 1, full route weight 1_000_000_000, tail 14, fee 8100;
- config 0 => gross signed amount reaches Raydium;
- config 2 => gross minus floor(amount * 8100 / 1_000_000);
- otherwise fail closed.

No pending monitoring, wallet, signer, simulation, transaction construction,
serialization, submission, broadcast, bridge execution, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

RPC = "https://api.mainnet-beta.solana.com"
POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
TITAN = "T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT"
RAY = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
SWAP_IN = hashlib.sha256(b"global:swap_base_input").digest()[:8]
EXCLUDED = {
    "2R9EZsXZrQgjw8gJgQkFaAkLEBih3QG88Rx5JPdqNFXeFutL4ohdSKKashEscmHmcNnczrQkEKJYxRkce53Kx8CN",
    "5qLLJHzbv98s9sif33S41UfPHTqJm7Li6ReSymunb2MUiQoo3UVt9Su78sjBfNAhvT5GHzorSUetRo2R2rr2G6RN",
    "4ntz9zfeDQb4ZfGEjRCQq16LtSP8mF2BCtnARsoVzyK835qczZiFZXCsWLLBLemc51xGA11eSBsmSRYP65p5pzGc",
    "2wSUV82ydrEvATJ5kyjfwFAgrUP1HMkwdzcMKeZoNA621uLSzo1FC73ngVk5GnLyteyWgnqzWDJ5EuQLpyRCptnV",
}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58)}


def b58decode(value: str) -> bytes:
    n = 0
    for ch in value:
        n = n * 58 + B58_MAP[ch]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def post(payload: Any) -> Any:
    body = json.dumps(payload, separators=(",", ":")).encode()
    delay = 0.7
    for attempt in range(8):
        try:
            req = urllib.request.Request(
                RPC,
                data=body,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "user-agent": "Ghost-Titan-Config-Batch-Holdout/1",
                },
            )
            with urllib.request.urlopen(req, timeout=45) as response:
                return json.loads(response.read())
        except Exception:
            if attempt == 7:
                raise
            time.sleep(delay)
            delay = min(delay * 1.8, 8)
    raise AssertionError("unreachable")


def rpc(method: str, params: list[Any]) -> Any:
    obj = post({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if not isinstance(obj, Mapping) or obj.get("error") is not None:
        raise RuntimeError(str(obj.get("error") if isinstance(obj, Mapping) else obj))
    return obj.get("result")


def rpc_transactions(signatures: list[str]) -> list[Any]:
    requests = [
        {
            "jsonrpc": "2.0",
            "id": i,
            "method": "getTransaction",
            "params": [
                sig,
                {
                    "commitment": "finalized",
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        }
        for i, sig in enumerate(signatures)
    ]
    obj = post(requests)
    if not isinstance(obj, list):
        raise RuntimeError(f"batch response not list: {type(obj).__name__}")
    by_id = {int(row.get("id")): row for row in obj if isinstance(row, Mapping) and isinstance(row.get("id"), int)}
    out: list[Any] = []
    for i in range(len(signatures)):
        row = by_id.get(i)
        if not isinstance(row, Mapping) or row.get("error") is not None:
            out.append(None)
        else:
            out.append(row.get("result"))
    return out


def message(tx: Mapping[str, Any]) -> Mapping[str, Any]:
    tr = tx.get("transaction")
    msg = tr.get("message") if isinstance(tr, Mapping) else None
    if not isinstance(msg, Mapping):
        raise RuntimeError("message missing")
    return msg


def target_outer(tx: Mapping[str, Any]) -> tuple[bytes, list[str]] | None:
    matches: list[tuple[bytes, list[str]]] = []
    instructions = message(tx).get("instructions")
    if not isinstance(instructions, list):
        return None
    for ix in instructions:
        if not isinstance(ix, Mapping) or ix.get("programId") != TITAN:
            continue
        accounts, data = ix.get("accounts"), ix.get("data")
        if not isinstance(accounts, list) or POOL not in accounts or RAY not in accounts or not isinstance(data, str):
            continue
        try:
            matches.append((b58decode(data), [str(x) for x in accounts]))
        except Exception:
            continue
    return matches[0] if len(matches) == 1 else None


def predict(raw: bytes) -> tuple[int, int] | None:
    if len(raw) != 36 or raw[0] != 0x2A:
        return None
    if int.from_bytes(raw[24:28], "little") != 1:
        return None
    if raw[28:31] != bytes([10, 0, 1]):
        return None
    if int.from_bytes(raw[31:35], "little") != 1_000_000_000 or raw[35] != 14:
        return None
    fee = int.from_bytes(raw[21:23], "little")
    if fee != 8100:
        return None
    config = raw[1]
    amount = int.from_bytes(raw[2:10], "little")
    if amount <= 0:
        return None
    if config == 0:
        return config, amount
    if config == 2:
        return config, amount - amount * fee // 1_000_000
    return None


def truth_amounts(tx: Mapping[str, Any]) -> list[int]:
    rows: list[Mapping[str, Any]] = []
    top = message(tx).get("instructions")
    if isinstance(top, list):
        rows.extend(x for x in top if isinstance(x, Mapping))
    meta = tx.get("meta")
    inner = meta.get("innerInstructions") if isinstance(meta, Mapping) else None
    if isinstance(inner, list):
        for group in inner:
            instructions = group.get("instructions") if isinstance(group, Mapping) else None
            if isinstance(instructions, list):
                rows.extend(x for x in instructions if isinstance(x, Mapping))
    values: list[int] = []
    for ix in rows:
        if ix.get("programId") != RAY:
            continue
        accounts, data = ix.get("accounts"), ix.get("data")
        if not isinstance(accounts, list) or len(accounts) != 13 or accounts[3] != POOL or not isinstance(data, str):
            continue
        try:
            raw = b58decode(data)
        except Exception:
            continue
        if len(raw) == 24 and raw[:8] == SWAP_IN:
            values.append(int.from_bytes(raw[8:16], "little"))
    return values


def main() -> int:
    started = now()
    tip = int(rpc("getSlot", [{"commitment": "finalized"}]))
    cutoff = tip - 128
    history = rpc("getSignaturesForAddress", [POOL, {"commitment": "finalized", "limit": 1000}])
    if not isinstance(history, list):
        raise RuntimeError("signature history missing")

    candidates: list[tuple[str, int]] = []
    for row in history:
        if not isinstance(row, Mapping) or row.get("err") is not None:
            continue
        sig, slot = row.get("signature"), row.get("slot")
        if not isinstance(sig, str) or not isinstance(slot, int) or slot > cutoff or sig in EXCLUDED:
            continue
        candidates.append((sig, slot))
        if len(candidates) >= 360:
            break

    results: list[dict[str, Any]] = []
    batch_failures = 0
    tx_missing = 0
    unsupported = 0
    truth_not_unique = 0

    for start in range(0, len(candidates), 12):
        if len(results) >= 24:
            break
        chunk = candidates[start : start + 12]
        sigs = [sig for sig, _ in chunk]
        try:
            txs = rpc_transactions(sigs)
        except Exception:
            batch_failures += 1
            continue
        for (sig, historical_slot), tx in zip(chunk, txs):
            if len(results) >= 24:
                break
            if not isinstance(tx, Mapping):
                tx_missing += 1
                continue
            outer = target_outer(tx)
            if outer is None:
                unsupported += 1
                continue
            raw, accounts = outer
            pred = predict(raw)
            if pred is None:
                unsupported += 1
                continue
            config, predicted = pred
            truths = truth_amounts(tx)
            if len(truths) != 1:
                truth_not_unique += 1
                continue
            actual = truths[0]
            results.append(
                {
                    "signature": sig,
                    "slot": int(tx.get("slot", historical_slot)),
                    "config": config,
                    "amount": int.from_bytes(raw[2:10], "little"),
                    "fee_centi_bps": int.from_bytes(raw[21:23], "little"),
                    "predicted_raydium_amount_in": predicted,
                    "actual_raydium_amount_in": actual,
                    "exact": predicted == actual,
                    "payload_sha256": sha256(raw),
                    "account_count": len(accounts),
                    "target_account_index": accounts.index(POOL),
                    "raydium_program_index": accounts.index(RAY),
                }
            )
        time.sleep(0.15)

    exact = sum(1 for row in results if row["exact"])
    counts: dict[str, int] = {}
    exact_counts: dict[str, int] = {}
    for row in results:
        key = str(row["config"])
        counts[key] = counts.get(key, 0) + 1
        if row["exact"]:
            exact_counts[key] = exact_counts.get(key, 0) + 1

    evidence = {
        "schema": "ghost.titan_config_batch_holdout.v1",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "started_at": started,
        "completed_at": now(),
        "finalized_tip_at_start": tip,
        "eligibility_cutoff_slot": cutoff,
        "minimum_tip_distance_slots": 128,
        "history_limit": 1000,
        "eligible_candidates_considered": len(candidates),
        "batch_size": 12,
        "max_supported_scored": 24,
        "discovery_signatures_excluded": sorted(EXCLUDED),
        "sample_count": len(results),
        "exact_count": exact,
        "all_exact": bool(results) and exact == len(results),
        "config_counts": counts,
        "config_exact_counts": exact_counts,
        "results": results,
        "rejections": {
            "batch_failures": batch_failures,
            "transaction_missing": tx_missing,
            "unsupported_shape_or_nonunique_outer": unsupported,
            "truth_not_unique": truth_not_unique,
        },
        "precommitted_rule": {
            "payload_len": 36,
            "discriminator": 42,
            "field_24_27_u32": 1,
            "venue_tag": 10,
            "source_node": 0,
            "destination_node": 1,
            "weight_nanos": 1_000_000_000,
            "tail_byte": 14,
            "fee_centi_bps": 8100,
            "config_0": "gross signed amount",
            "config_2": "gross minus floor(amount * 8100 / 1_000_000)",
        },
        "interpretation": (
            "This is an excluded-signature settled holdout for one narrow signed-wire family. "
            "Even perfect exactness does not establish a Titan-wide ABI; all other shapes/configs "
            "remain fail-closed until separately validated."
        ),
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
    stamp = started.replace(":", "").replace("-", "").replace(".", "_")
    out = Path("live-evidence") / f"titan-config-batch-holdout-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out / "evidence.json").write_bytes(raw)
    (out / "evidence.sha256").write_text(f"{sha256(raw)}  evidence.json\n")
    print(json.dumps({
        "sample_count": len(results),
        "exact_count": exact,
        "all_exact": bool(results) and exact == len(results),
        "config_counts": counts,
        "config_exact_counts": exact_counts,
        "rejections": evidence["rejections"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
