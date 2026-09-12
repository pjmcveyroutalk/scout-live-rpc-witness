#!/usr/bin/env python3
"""Excluded-signature settled holdout for the Titan 36-byte single-Ray fee rule.

Rule frozen before corpus discovery for this witness:
- Only finalized transactions at least 128 slots behind finalized tip.
- Only one top-level Titan instruction that names the locked Raydium CPMM pool/program.
- Payload must be exactly 36 bytes with the observed single-Ray shape:
  discriminator 0x2a, field_24_27 == 1, venue 10, source 0, destination 1,
  full route weight 1_000_000_000, tail byte 14, and fee field 8100.
- config 0 predicts gross signed amount reaches Raydium.
- config 2 predicts signed amount minus floor(amount * 8100 / 1_000_000).
- Any other config/shape fails closed and is not scored.

The four T897 discovery signatures are explicitly excluded. Truth is read only after the
prediction from the signed top-level message is fixed. This is retrospective finalized-state
research only: no pending monitoring, wallet, signer, simulation, transaction construction,
serialization, submission, broadcast, bridge execution, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import time
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
    for char in value:
        n = n * 58 + B58_MAP[char]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    delay = 0.45
    for attempt in range(8):
        try:
            request = urllib.request.Request(
                RPC,
                data=body,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "user-agent": "Ghost-Titan-Config-Holdout/1",
                },
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read())
            if not isinstance(payload, Mapping) or payload.get("error") is not None:
                raise RuntimeError(str(payload.get("error") if isinstance(payload, Mapping) else payload))
            return payload.get("result")
        except Exception:
            if attempt == 7:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 7)
    raise AssertionError("unreachable")


def message(tx: Mapping[str, Any]) -> Mapping[str, Any]:
    transaction = tx.get("transaction")
    msg = transaction.get("message") if isinstance(transaction, Mapping) else None
    if not isinstance(msg, Mapping):
        raise RuntimeError("message missing")
    return msg


def target_titan_outers(tx: Mapping[str, Any]) -> list[tuple[bytes, list[str]]]:
    out: list[tuple[bytes, list[str]]] = []
    instructions = message(tx).get("instructions")
    if not isinstance(instructions, list):
        return out
    for ix in instructions:
        if not isinstance(ix, Mapping) or ix.get("programId") != TITAN:
            continue
        accounts = ix.get("accounts")
        data = ix.get("data")
        if not isinstance(accounts, list) or POOL not in accounts or RAY not in accounts or not isinstance(data, str):
            continue
        try:
            raw = b58decode(data)
        except Exception:
            continue
        out.append((raw, [str(x) for x in accounts]))
    return out


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
        accounts = ix.get("accounts")
        data = ix.get("data")
        if not isinstance(accounts, list) or len(accounts) != 13 or accounts[3] != POOL or not isinstance(data, str):
            continue
        try:
            raw = b58decode(data)
        except Exception:
            continue
        if len(raw) == 24 and raw[:8] == SWAP_IN:
            values.append(int.from_bytes(raw[8:16], "little"))
    return values


def predict(raw: bytes) -> tuple[int, int] | None:
    if len(raw) != 36 or raw[0] != 0x2A:
        return None
    if int.from_bytes(raw[24:28], "little") != 1:
        return None
    if raw[28] != 10 or raw[29] != 0 or raw[30] != 1:
        return None
    if int.from_bytes(raw[31:35], "little") != 1_000_000_000 or raw[35] != 14:
        return None
    fee_centi_bps = int.from_bytes(raw[21:23], "little")
    if fee_centi_bps != 8100:
        return None
    config = raw[1]
    amount = int.from_bytes(raw[2:10], "little")
    if amount <= 0:
        return None
    if config == 0:
        return config, amount
    if config == 2:
        return config, amount - amount * fee_centi_bps // 1_000_000
    return None


def main() -> int:
    started = now()
    tip = int(rpc("getSlot", [{"commitment": "finalized"}]))
    cutoff = tip - 128
    history = rpc("getSignaturesForAddress", [POOL, {"commitment": "finalized", "limit": 500}])
    if not isinstance(history, list):
        raise RuntimeError("signature history missing")

    results: list[dict[str, Any]] = []
    rejections: dict[str, int] = {}
    scanned = 0
    for row in history:
        if len(results) >= 24:
            break
        if not isinstance(row, Mapping) or row.get("err") is not None:
            continue
        slot = int(row.get("slot", 10**18))
        signature = row.get("signature")
        if slot > cutoff or not isinstance(signature, str):
            continue
        if signature in EXCLUDED:
            rejections["t897_discovery_signature"] = rejections.get("t897_discovery_signature", 0) + 1
            continue
        scanned += 1
        try:
            tx = rpc(
                "getTransaction",
                [signature, {"commitment": "finalized", "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
            )
        except Exception:
            rejections["rpc"] = rejections.get("rpc", 0) + 1
            continue
        if not isinstance(tx, Mapping):
            rejections["missing_tx"] = rejections.get("missing_tx", 0) + 1
            continue
        outers = target_titan_outers(tx)
        if len(outers) != 1:
            rejections["target_titan_outer_not_unique"] = rejections.get("target_titan_outer_not_unique", 0) + 1
            continue
        raw, accounts = outers[0]
        pred = predict(raw)
        if pred is None:
            rejections["shape_or_config_not_supported"] = rejections.get("shape_or_config_not_supported", 0) + 1
            continue
        truths = truth_amounts(tx)
        if len(truths) != 1:
            rejections["truth_not_unique"] = rejections.get("truth_not_unique", 0) + 1
            continue
        config, predicted = pred
        actual = truths[0]
        results.append(
            {
                "signature": signature,
                "slot": int(tx.get("slot", -1)),
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

    exact_count = sum(1 for row in results if row["exact"])
    config_counts: dict[str, int] = {}
    config_exact: dict[str, int] = {}
    for row in results:
        key = str(row["config"])
        config_counts[key] = config_counts.get(key, 0) + 1
        if row["exact"]:
            config_exact[key] = config_exact.get(key, 0) + 1

    evidence = {
        "schema": "ghost.titan_config_holdout.v1",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "started_at": started,
        "completed_at": now(),
        "finalized_tip_at_start": tip,
        "eligibility_cutoff_slot": cutoff,
        "minimum_tip_distance_slots": 128,
        "discovery_signatures_excluded": sorted(EXCLUDED),
        "history_limit": 500,
        "eligible_history_rows_scanned_until_stop": scanned,
        "sample_count": len(results),
        "exact_count": exact_count,
        "all_exact": bool(results) and exact_count == len(results),
        "config_counts": config_counts,
        "config_exact_counts": config_exact,
        "results": results,
        "rejections": rejections,
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
            "This scores only the precommitted 36-byte single-Ray family and excludes all four T897 "
            "discovery signatures. Exactness supports this narrow observed family only; unsupported "
            "shapes/configs remain fail-closed and no Titan-wide ABI is inferred."
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
    out = Path("live-evidence") / f"titan-config-holdout-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out / "evidence.json").write_bytes(raw)
    (out / "evidence.sha256").write_text(f"{sha256(raw)}  evidence.json\n")
    print(
        json.dumps(
            {
                "sample_count": len(results),
                "exact_count": exact_count,
                "all_exact": bool(results) and exact_count == len(results),
                "config_counts": config_counts,
                "config_exact_counts": config_exact,
                "rejections": rejections,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
