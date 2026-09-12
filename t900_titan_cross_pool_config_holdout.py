#!/usr/bin/env python3
"""Cross-pool excluded-signature holdout for the narrow Titan 36-byte single-Ray rule.

This witness freezes the T897/T899 rule and widens only the corpus: instead of one
Raydium pool, it samples finalized Titan-router history and scores any transaction
that has exactly one supported 36-byte Titan route plus exactly one finalized
Raydium CPMM swap_base_input truth amount.

Precommitted rule (unchanged):
- payload len 36, discriminator 0x2a;
- route_count/field_24_27 == 1;
- venue tag 10, source node 0, destination node 1;
- route weight 1_000_000_000, tail byte 14;
- fee field 8100 centi-bps;
- config 0 => gross signed amount reaches Raydium;
- config 2 => gross - floor(amount * 8100 / 1_000_000) reaches Raydium;
- all other shapes/configs fail closed.

All T897 discovery signatures and the first T899 excluded-signature holdout are
explicitly excluded. Truth is read only after prediction is fixed from the signed
outer bytes. Finalized retrospective research only: no pending monitoring, wallet,
signer, simulation, transaction construction/serialization/submission, broadcast,
bridge execution, or capital movement.
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
TITAN = "T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT"
RAY = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
SWAP_IN = hashlib.sha256(b"global:swap_base_input").digest()[:8]
EXCLUDED = {
    "2R9EZsXZrQgjw8gJgQkFaAkLEBih3QG88Rx5JPdqNFXeFutL4ohdSKKashEscmHmcNnczrQkEKJYxRkce53Kx8CN",
    "5qLLJHzbv98s9sif33S41UfPHTqJm7Li6ReSymunb2MUiQoo3UVt9Su78sjBfNAhvT5GHzorSUetRo2R2rr2G6RN",
    "4ntz9zfeDQb4ZfGEjRCQq16LtSP8mF2BCtnARsoVzyK835qczZiFZXCsWLLBLemc51xGA11eSBsmSRYP65p5pzGc",
    "2wSUV82ydrEvATJ5kyjfwFAgrUP1HMkwdzcMKeZoNA621uLSzo1FC73ngVk5GnLyteyWgnqzWDJ5EuQLpyRCptnV",
    "3woAvca24p7JhdSwPPdRW86nHszRTJHryBWKKLkVCjoCfysgVjGrRYWX3KkvSVXS2cT819v7Nzz8ySNg5kpmGMqg",
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
    delay = 0.5
    for attempt in range(8):
        try:
            req = urllib.request.Request(
                RPC,
                data=body,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "user-agent": "Ghost-Titan-Cross-Pool-Config-Holdout/1",
                },
            )
            with urllib.request.urlopen(req, timeout=40) as response:
                return json.loads(response.read())
        except Exception:
            if attempt == 7:
                raise
            time.sleep(delay)
            delay = min(delay * 1.8, 7)
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
        raise RuntimeError("batch response not list")
    by_id = {
        int(row.get("id")): row
        for row in obj
        if isinstance(row, Mapping) and isinstance(row.get("id"), int)
    }
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


def titan_payloads(tx: Mapping[str, Any]) -> list[bytes]:
    rows = message(tx).get("instructions")
    out: list[bytes] = []
    if not isinstance(rows, list):
        return out
    for ix in rows:
        if not isinstance(ix, Mapping) or ix.get("programId") != TITAN:
            continue
        data = ix.get("data")
        if not isinstance(data, str):
            continue
        try:
            out.append(b58decode(data))
        except Exception:
            continue
    return out


def predict(raw: bytes) -> tuple[int, int, int] | None:
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
        return config, amount, amount
    if config == 2:
        return config, amount, amount - amount * fee // 1_000_000
    return None


def ray_truths(tx: Mapping[str, Any]) -> list[dict[str, Any]]:
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
    out: list[dict[str, Any]] = []
    for ix in rows:
        if ix.get("programId") != RAY:
            continue
        accounts, data = ix.get("accounts"), ix.get("data")
        if not isinstance(accounts, list) or len(accounts) != 13 or not isinstance(data, str):
            continue
        try:
            raw = b58decode(data)
        except Exception:
            continue
        if len(raw) == 24 and raw[:8] == SWAP_IN:
            out.append(
                {
                    "amount_in": int.from_bytes(raw[8:16], "little"),
                    "minimum_amount_out": int.from_bytes(raw[16:24], "little"),
                    "pool": str(accounts[3]),
                }
            )
    return out


def main() -> int:
    started = now()
    tip = int(rpc("getSlot", [{"commitment": "finalized"}]))
    cutoff = tip - 128
    history = rpc(
        "getSignaturesForAddress",
        [TITAN, {"commitment": "finalized", "limit": 1000}],
    )
    if not isinstance(history, list):
        raise RuntimeError("Titan signature history missing")

    candidates: list[tuple[str, int]] = []
    for row in history:
        if not isinstance(row, Mapping) or row.get("err") is not None:
            continue
        sig, slot = row.get("signature"), row.get("slot")
        if not isinstance(sig, str) or not isinstance(slot, int):
            continue
        if slot > cutoff or sig in EXCLUDED:
            continue
        candidates.append((sig, slot))
        if len(candidates) >= 720:
            break

    results: list[dict[str, Any]] = []
    missing = unsupported = truth_nonunique = batch_failures = 0
    config_counts: dict[str, int] = {}

    for start in range(0, len(candidates), 10):
        if sum(1 for x in results if x["config"] == 0) >= 10 and sum(1 for x in results if x["config"] == 2) >= 10:
            break
        chunk = candidates[start : start + 10]
        try:
            txs = rpc_transactions([sig for sig, _ in chunk])
        except Exception:
            batch_failures += 1
            continue
        for (sig, slot), tx in zip(chunk, txs):
            if not isinstance(tx, Mapping):
                missing += 1
                continue
            payloads = titan_payloads(tx)
            supported: list[tuple[bytes, tuple[int, int, int]]] = []
            for raw in payloads:
                pred = predict(raw)
                if pred is not None:
                    supported.append((raw, pred))
            if len(supported) != 1:
                unsupported += 1
                continue
            raw, (config, amount, predicted) = supported[0]
            truths = ray_truths(tx)
            if len(truths) != 1:
                truth_nonunique += 1
                continue
            truth = truths[0]
            actual = int(truth["amount_in"])
            results.append(
                {
                    "signature": sig,
                    "slot": int(tx.get("slot", slot)),
                    "config": config,
                    "amount": amount,
                    "predicted_raydium_amount_in": predicted,
                    "actual_raydium_amount_in": actual,
                    "exact": predicted == actual,
                    "pool": truth["pool"],
                    "minimum_amount_out": truth["minimum_amount_out"],
                    "payload_sha256": sha256(raw),
                }
            )
            key = str(config)
            config_counts[key] = config_counts.get(key, 0) + 1
        time.sleep(0.12)

    exact_count = sum(1 for row in results if row["exact"])
    exact_by_config: dict[str, int] = {}
    for row in results:
        if row["exact"]:
            key = str(row["config"])
            exact_by_config[key] = exact_by_config.get(key, 0) + 1

    evidence = {
        "schema": "ghost.titan_cross_pool_config_holdout.v1",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "started_at": started,
        "completed_at": now(),
        "finalized_tip_at_start": tip,
        "eligibility_cutoff_slot": cutoff,
        "minimum_tip_distance_slots": 128,
        "history_address": TITAN,
        "history_limit": 1000,
        "eligible_candidates_considered": len(candidates),
        "discovery_and_prior_holdout_signatures_excluded": sorted(EXCLUDED),
        "sample_count": len(results),
        "exact_count": exact_count,
        "all_exact": bool(results) and exact_count == len(results),
        "config_counts": config_counts,
        "config_exact_counts": exact_by_config,
        "distinct_pool_count": len({row["pool"] for row in results}),
        "results": results,
        "rejections": {
            "batch_failures": batch_failures,
            "transaction_missing": missing,
            "unsupported_shape_or_nonunique_supported_titan_outer": unsupported,
            "raydium_truth_not_unique": truth_nonunique,
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
            "Corpus widening does not widen the rule. This scores only the exact frozen 36-byte "
            "single-Ray family against finalized Raydium CPMM CPI truth. Any other Titan shape, "
            "venue, fee, route layout, or config remains fail-closed."
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
    out = Path("live-evidence") / f"titan-cross-pool-config-holdout-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out / "evidence.json").write_bytes(raw)
    (out / "evidence.sha256").write_text(f"{sha256(raw)}  evidence.json\n")
    print(json.dumps({
        "sample_count": len(results),
        "exact_count": exact_count,
        "all_exact": bool(results) and exact_count == len(results),
        "config_counts": config_counts,
        "config_exact_counts": exact_by_config,
        "distinct_pool_count": len({row["pool"] for row in results}),
        "rejections": evidence["rejections"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
