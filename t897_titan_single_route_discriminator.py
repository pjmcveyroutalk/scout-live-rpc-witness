#!/usr/bin/env python3
"""Retrospective discriminator probe for four settled Titan single-route Raydium cases.

The witness compares two finalized cases where the Raydium input equals the Titan
signed amount with two finalized cases where the Raydium input equals the signed
amount minus floor(amount * fee_centi_bps / 1_000_000). It reads only finalized
transaction messages plus already-finalized Raydium CPI truth, and reports signed
wire/account-layout positions that separate the observed behaviors.

No pending/unfinalized monitoring, wallet, signing, simulation, transaction
construction/serialization/submission, broadcast, bridge execution, or capital movement.
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

CASES = {
    "2R9EZsXZrQgjw8gJgQkFaAkLEBih3QG88Rx5JPdqNFXeFutL4ohdSKKashEscmHmcNnczrQkEKJYxRkce53Kx8CN": "gross_truth_a",
    "5qLLJHzbv98s9sif33S41UfPHTqJm7Li6ReSymunb2MUiQoo3UVt9Su78sjBfNAhvT5GHzorSUetRo2R2rr2G6RN": "gross_truth_b",
    "4ntz9zfeDQb4ZfGEjRCQq16LtSP8mF2BCtnARsoVzyK835qczZiFZXCsWLLBLemc51xGA11eSBsmSRYP65p5pzGc": "floor_fee_truth_a",
    "2wSUV82ydrEvATJ5kyjfwFAgrUP1HMkwdzcMKeZoNA621uLSzo1FC73ngVk5GnLyteyWgnqzWDJ5EuQLpyRCptnV": "floor_fee_truth_b",
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
    delay = 0.5
    for attempt in range(7):
        try:
            request = urllib.request.Request(
                RPC,
                data=body,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "user-agent": "Ghost-Titan-Single-Route-Discriminator/1",
                },
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read())
            if not isinstance(payload, Mapping) or payload.get("error") is not None:
                raise RuntimeError(str(payload.get("error") if isinstance(payload, Mapping) else payload))
            return payload.get("result")
        except Exception:
            if attempt == 6:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 6)
    raise AssertionError("unreachable")


def message(tx: Mapping[str, Any]) -> Mapping[str, Any]:
    transaction = tx.get("transaction")
    msg = transaction.get("message") if isinstance(transaction, Mapping) else None
    if not isinstance(msg, Mapping):
        raise RuntimeError("message missing")
    return msg


def titan_outer(tx: Mapping[str, Any]) -> tuple[bytes, list[str]]:
    found: list[tuple[bytes, list[str]]] = []
    instructions = message(tx).get("instructions")
    if not isinstance(instructions, list):
        return b"", []
    for ix in instructions:
        if not isinstance(ix, Mapping) or ix.get("programId") != TITAN:
            continue
        accounts = ix.get("accounts")
        data = ix.get("data")
        if not isinstance(accounts, list) or POOL not in accounts or RAY not in accounts or not isinstance(data, str):
            continue
        found.append((b58decode(data), [str(x) for x in accounts]))
    if len(found) != 1:
        raise RuntimeError(f"expected one target Titan outer instruction, got {len(found)}")
    return found[0]


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
        raw = b58decode(data)
        if len(raw) == 24 and raw[:8] == SWAP_IN:
            values.append(int.from_bytes(raw[8:16], "little"))
    return values


def parse_case(signature: str, label: str, cutoff: int) -> dict[str, Any]:
    tx = rpc(
        "getTransaction",
        [signature, {"commitment": "finalized", "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
    )
    if not isinstance(tx, Mapping):
        raise RuntimeError(f"transaction unavailable: {signature}")
    slot = int(tx.get("slot", -1))
    if slot > cutoff:
        raise RuntimeError(f"case is not at least 128 slots behind finalized tip: {signature}")
    raw, accounts = titan_outer(tx)
    truths = truth_amounts(tx)
    if len(truths) != 1:
        raise RuntimeError(f"Raydium truth is not unique: {signature}: {truths}")
    if len(raw) < 24 or raw[0] != 0x2A:
        raise RuntimeError(f"unexpected Titan payload: {signature}")

    amount = int.from_bytes(raw[2:10], "little")
    expected_out = int.from_bytes(raw[10:18], "little")
    slippage_bps = int.from_bytes(raw[18:20], "little")
    fee_centi_bps = int.from_bytes(raw[21:23], "little")
    fee_floor = amount * fee_centi_bps // 1_000_000
    net_floor = amount - fee_floor
    truth = truths[0]
    if truth == amount:
        behavior = "gross_equals_raydium_input"
    elif truth == net_floor:
        behavior = "floor_fee_subtracted"
    else:
        behavior = "other"

    route = None
    if len(raw) == 36:
        route = {
            "field_24_27_u32": int.from_bytes(raw[24:28], "little"),
            "venue_tag": raw[28],
            "source_node": raw[29],
            "destination_node": raw[30],
            "weight_nanos": int.from_bytes(raw[31:35], "little"),
            "tail_byte_35": raw[35],
        }

    return {
        "label": label,
        "signature": signature,
        "slot": slot,
        "payload_len": len(raw),
        "payload_hex": raw.hex(),
        "payload_sha256": sha256(raw),
        "bytes": list(raw),
        "header": {
            "discriminator": raw[0],
            "config": raw[1] if len(raw) > 1 else None,
            "amount": amount,
            "expected_amount_out": expected_out,
            "slippage_threshold_bps": slippage_bps,
            "mints": raw[20] if len(raw) > 20 else None,
            "fee_centi_bps": fee_centi_bps,
            "mesh_size": raw[23] if len(raw) > 23 else None,
        },
        "route": route,
        "account_count": len(accounts),
        "target_account_index": accounts.index(POOL),
        "raydium_program_index": accounts.index(RAY),
        "fee_floor": fee_floor,
        "net_after_floor_fee": net_floor,
        "actual_raydium_amount_in": truth,
        "observed_fee_behavior": behavior,
    }


def stable_group_discriminators(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gross = [c for c in cases if c["observed_fee_behavior"] == "gross_equals_raydium_input"]
    fee = [c for c in cases if c["observed_fee_behavior"] == "floor_fee_subtracted"]
    if len(gross) != 2 or len(fee) != 2:
        return []
    lengths = {c["payload_len"] for c in cases}
    if len(lengths) != 1:
        return []
    n = next(iter(lengths))
    excluded = set(range(2, 18))
    rows: list[dict[str, Any]] = []
    for offset in range(n):
        if offset in excluded:
            continue
        gv = {c["bytes"][offset] for c in gross}
        fv = {c["bytes"][offset] for c in fee}
        if len(gv) == 1 and len(fv) == 1 and gv != fv:
            rows.append(
                {
                    "offset": offset,
                    "gross_value": next(iter(gv)),
                    "floor_fee_value": next(iter(fv)),
                }
            )
    return rows


def layout_discriminators(cases: list[dict[str, Any]]) -> dict[str, Any]:
    gross = [c for c in cases if c["observed_fee_behavior"] == "gross_equals_raydium_input"]
    fee = [c for c in cases if c["observed_fee_behavior"] == "floor_fee_subtracted"]
    out: dict[str, Any] = {}
    for key in ("payload_len", "account_count", "target_account_index", "raydium_program_index"):
        gv = sorted({c[key] for c in gross})
        fv = sorted({c[key] for c in fee})
        out[key] = {"gross_values": gv, "floor_fee_values": fv, "separates_groups": bool(gv and fv and set(gv).isdisjoint(fv))}
    return out


def main() -> int:
    started = now()
    tip = int(rpc("getSlot", [{"commitment": "finalized"}]))
    cutoff = tip - 128
    cases = [parse_case(signature, label, cutoff) for signature, label in CASES.items()]
    wire = stable_group_discriminators(cases)
    layouts = layout_discriminators(cases)

    evidence = {
        "schema": "ghost.titan_single_route_discriminator.v1",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "started_at": started,
        "completed_at": now(),
        "finalized_tip_at_start": tip,
        "eligibility_cutoff_slot": cutoff,
        "minimum_tip_distance_slots": 128,
        "cases": cases,
        "stable_signed_byte_discriminators_excluding_amount_expected_out": wire,
        "layout_discriminators": layouts,
        "interpretation": (
            "A reported discriminator is only an observed four-case separator. It must not be promoted "
            "to a Titan-wide ABI rule without additional out-of-sample settled validation. If no stable "
            "separator is found, the fee behavior remains fail-closed."
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
    out = Path("live-evidence") / f"titan-single-route-discriminator-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out / "evidence.json").write_bytes(raw)
    (out / "evidence.sha256").write_text(f"{sha256(raw)}  evidence.json\n")
    print(
        json.dumps(
            {
                "behaviors": [
                    {
                        "label": c["label"],
                        "slot": c["slot"],
                        "payload_len": c["payload_len"],
                        "account_count": c["account_count"],
                        "amount": c["header"]["amount"],
                        "fee_centi_bps": c["header"]["fee_centi_bps"],
                        "truth": c["actual_raydium_amount_in"],
                        "behavior": c["observed_fee_behavior"],
                    }
                    for c in cases
                ],
                "stable_wire_discriminators": wire,
                "layout_discriminators": layouts,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
