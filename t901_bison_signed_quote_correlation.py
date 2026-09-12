#!/usr/bin/env python3
"""Correlate settled BisonFiWithSig payload fields with finalized swap truth.

Uses four already-settled transactions, including the sealed Ghost Bison specimen and
three independent public finalized specimens. It reads the inner Bison instruction,
extracts finalized OKX SwapEvent truth from transaction logs, and records structural
fields/occurrences without assuming a pricing formula.

Purpose: determine whether Bison amount_out is directly embedded, ratio/price encoded,
or instead dependent on signed quote material plus market state. Retrospective only:
no pending monitoring, wallet, signer, simulation, transaction construction,
serialization, submission, broadcast, bridge execution, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

RPC = "https://api.mainnet-beta.solana.com"
BISON = "BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi"
CASES = {
    "3DhDBbxDaENVui8f7vjmmzygBMQnnGoNnfpTtqszuHhYLycZK8KYH5bje79hgpuWTyUCuH8HkTzzCRgTat1iyuhJ": "sealed_ghost",
    "26aKhuit1vWNyimWjCcvMY3mzoTk297PCup5pTiamxXDf6G57Lkq878nnPSzRhGRTma66LyFuWPW8AbpxVSHZVqP": "public_a",
    "2roTgE7GxgW7KwPLTkmmMARH9RpoPLa2kLTnH4mnLMWw2yTWUULzheAQPJHyqcyGsYLpZyi7GkuPvbAR8kQGjkDa": "public_b",
    "31rpu29NYFhHpwkXVgVvLWa9sL51JQddtq8YmyGeP3paCbqp9A9AbuWuWxorGiMJ9pkSRtp49rcmmHcokuPBS1nE": "public_c",
}
EVENT_RE = re.compile(r"SwapEvent \{ dex: BisonFiWithSig, amount_in: (\d+), amount_out: (\d+) \}")
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


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    delay = 0.5
    for attempt in range(7):
        try:
            req = urllib.request.Request(
                RPC,
                data=body,
                method="POST",
                headers={
                    "content-type": "application/json",
                    "user-agent": "Ghost-Bison-Signed-Quote-Correlation/1",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                obj = json.loads(response.read())
            if not isinstance(obj, Mapping) or obj.get("error") is not None:
                raise RuntimeError(str(obj.get("error") if isinstance(obj, Mapping) else obj))
            return obj.get("result")
        except Exception:
            if attempt == 6:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 6)
    raise AssertionError("unreachable")


def bison_inner(tx: Mapping[str, Any]) -> list[tuple[bytes, list[str]]]:
    meta = tx.get("meta")
    inner = meta.get("innerInstructions") if isinstance(meta, Mapping) else None
    out: list[tuple[bytes, list[str]]] = []
    if not isinstance(inner, list):
        return out
    for group in inner:
        instructions = group.get("instructions") if isinstance(group, Mapping) else None
        if not isinstance(instructions, list):
            continue
        for ix in instructions:
            if not isinstance(ix, Mapping) or ix.get("programId") != BISON:
                continue
            data, accounts = ix.get("data"), ix.get("accounts")
            if not isinstance(data, str) or not isinstance(accounts, list):
                continue
            try:
                out.append((b58decode(data), [str(x) for x in accounts]))
            except Exception:
                continue
    return out


def truth_from_logs(tx: Mapping[str, Any]) -> list[tuple[int, int]]:
    meta = tx.get("meta")
    logs = meta.get("logMessages") if isinstance(meta, Mapping) else None
    out: list[tuple[int, int]] = []
    if not isinstance(logs, list):
        return out
    for line in logs:
        if not isinstance(line, str):
            continue
        m = EVENT_RE.search(line)
        if m:
            out.append((int(m.group(1)), int(m.group(2))))
    return out


def occurrences(raw: bytes, value: int) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for size in (4, 8):
        if value >= (1 << (8 * size)):
            continue
        for endian in ("little", "big"):
            needle = value.to_bytes(size, endian)
            offsets = [i for i in range(0, len(raw) - size + 1) if raw[i : i + size] == needle]
            if offsets:
                found[f"u{size * 8}_{endian}"] = offsets
    return found


def parse_segments(raw: bytes, block_time: int, slot: int) -> dict[str, Any]:
    segments: dict[str, Any] = {
        "opcode": raw[0] if raw else None,
        "u64_at_1": int.from_bytes(raw[1:9], "little") if len(raw) >= 9 else None,
        "u64_at_9": int.from_bytes(raw[9:17], "little") if len(raw) >= 17 else None,
        "u64_at_17": int.from_bytes(raw[17:25], "little") if len(raw) >= 25 else None,
        "u64_at_25": int.from_bytes(raw[25:33], "little") if len(raw) >= 33 else None,
        "u64_at_33": int.from_bytes(raw[33:41], "little") if len(raw) >= 41 else None,
        "bytes_41_72_hex": raw[41:73].hex() if len(raw) >= 73 else None,
        "u64_at_73": int.from_bytes(raw[73:81], "little") if len(raw) >= 81 else None,
        "bytes_81_144_hex": raw[81:145].hex() if len(raw) >= 145 else None,
        "u64_at_145": int.from_bytes(raw[145:153], "little") if len(raw) >= 153 else None,
    }
    ts_candidates = []
    slot_candidates = []
    for offset in range(0, max(0, len(raw) - 7)):
        value = int.from_bytes(raw[offset : offset + 8], "little")
        if abs(value - block_time) <= 600:
            ts_candidates.append({"offset": offset, "value": value, "delta_seconds": value - block_time})
        if abs(value - slot) <= 2000:
            slot_candidates.append({"offset": offset, "value": value, "delta_slots": value - slot})
    segments["timestamp_candidates"] = ts_candidates
    segments["slot_candidates"] = slot_candidates
    return segments


def main() -> int:
    started = now()
    rows: list[dict[str, Any]] = []
    for signature, label in CASES.items():
        tx = rpc(
            "getTransaction",
            [signature, {"commitment": "finalized", "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
        )
        if not isinstance(tx, Mapping):
            raise RuntimeError(f"transaction unavailable: {signature}")
        inners = bison_inner(tx)
        truths = truth_from_logs(tx)
        if len(inners) != 1:
            raise RuntimeError(f"expected one Bison inner instruction, got {len(inners)}: {signature}")
        if len(truths) != 1:
            raise RuntimeError(f"expected one Bison SwapEvent truth, got {len(truths)}: {signature}")
        raw, accounts = inners[0]
        amount_in, amount_out = truths[0]
        slot = int(tx.get("slot", -1))
        block_time = int(tx.get("blockTime", -1))
        rows.append(
            {
                "label": label,
                "signature": signature,
                "slot": slot,
                "block_time": block_time,
                "amount_in": amount_in,
                "amount_out": amount_out,
                "payload_len": len(raw),
                "payload_sha256": sha256(raw),
                "payload_hex": raw.hex(),
                "account_count": len(accounts),
                "accounts": accounts,
                "amount_in_occurrences": occurrences(raw, amount_in),
                "amount_out_occurrences": occurrences(raw, amount_out),
                "segments": parse_segments(raw, block_time, slot),
                "derived": {
                    "u64_at_25_div_1000": (int.from_bytes(raw[25:33], "little") / 1000) if len(raw) >= 33 else None,
                    "u64_at_25_to_amount_in": (int.from_bytes(raw[25:33], "little") / amount_in) if len(raw) >= 33 and amount_in else None,
                    "output_per_input": amount_out / amount_in if amount_in else None,
                },
            }
        )

    lengths = sorted({row["payload_len"] for row in rows})
    opcodes = sorted({row["segments"]["opcode"] for row in rows})
    direct_out_cases = sum(1 for row in rows if row["amount_out_occurrences"])
    direct_in_cases = sum(1 for row in rows if row["amount_in_occurrences"])
    timestamp_at_9 = sum(1 for row in rows if abs(row["segments"]["u64_at_9"] - row["block_time"]) <= 600)
    slot_at_73 = sum(1 for row in rows if abs(row["segments"]["u64_at_73"] - row["slot"]) <= 2000)

    evidence = {
        "schema": "ghost.bison_signed_quote_correlation.v1",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "started_at": started,
        "completed_at": now(),
        "case_count": len(rows),
        "payload_lengths": lengths,
        "opcodes": opcodes,
        "amount_in_directly_embedded_cases": direct_in_cases,
        "amount_out_directly_embedded_cases": direct_out_cases,
        "timestamp_like_u64_at_9_cases": timestamp_at_9,
        "slot_like_u64_at_73_cases": slot_at_73,
        "cases": rows,
        "interpretation": (
            "This is structural correlation only. Exact output absence is evidence against a simple "
            "literal amount_out field, not proof of a pricing formula. Signature-like and timing "
            "segments remain opaque until independently verified."
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
    out = Path("live-evidence") / f"bison-signed-quote-correlation-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out / "evidence.json").write_bytes(raw)
    (out / "evidence.sha256").write_text(f"{sha256(raw)}  evidence.json\n")
    print(json.dumps({
        "case_count": len(rows),
        "payload_lengths": lengths,
        "opcodes": opcodes,
        "amount_in_directly_embedded_cases": direct_in_cases,
        "amount_out_directly_embedded_cases": direct_out_cases,
        "timestamp_like_u64_at_9_cases": timestamp_at_9,
        "slot_like_u64_at_73_cases": slot_at_73,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
