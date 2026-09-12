#!/usr/bin/env python3
"""Correlate settled BisonFiWithSig payloads after fail-closed inner-instruction selection.

T901 correctly failed because one settled transaction contained two Bison inner
instructions. This witness does not choose by order. For each finalized Bison SwapEvent,
it selects a Bison instruction only when exactly one candidate payload contains that
settled event amount_in as a little-endian u64. If selection is ambiguous or absent,
the case is rejected rather than guessed.

The selected payload is then inspected structurally for direct amount_out presence,
timestamp/slot-like fields, and stable fixed-offset values. No pricing formula is
assumed. Retrospective finalized-state research only; no pending monitoring, wallet,
signer, simulation, transaction construction/serialization/submission, broadcast,
bridge execution, or capital movement.
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
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}, separators=(",", ":")).encode()
    delay = 0.5
    for attempt in range(7):
        try:
            req = urllib.request.Request(RPC, data=body, method="POST", headers={"content-type":"application/json","user-agent":"Ghost-Bison-Signed-Quote-Correlation-V2/1"})
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


def bison_inners(tx: Mapping[str, Any]) -> list[dict[str, Any]]:
    meta = tx.get("meta")
    inner = meta.get("innerInstructions") if isinstance(meta, Mapping) else None
    out: list[dict[str, Any]] = []
    if not isinstance(inner, list):
        return out
    for group in inner:
        if not isinstance(group, Mapping):
            continue
        parent_index = group.get("index")
        instructions = group.get("instructions")
        if not isinstance(instructions, list):
            continue
        for child_index, ix in enumerate(instructions):
            if not isinstance(ix, Mapping) or ix.get("programId") != BISON:
                continue
            data, accounts = ix.get("data"), ix.get("accounts")
            if not isinstance(data, str) or not isinstance(accounts, list):
                continue
            try:
                raw = b58decode(data)
            except Exception:
                continue
            out.append({"raw": raw, "accounts": [str(x) for x in accounts], "parent_index": parent_index, "child_index": child_index})
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


def u64_offsets(raw: bytes, value: int) -> list[int]:
    if value < 0 or value >= 1 << 64:
        return []
    needle = value.to_bytes(8, "little")
    return [i for i in range(len(raw) - 7) if raw[i:i+8] == needle]


def generic_occurrences(raw: bytes, value: int) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for size in (4, 8):
        if value >= 1 << (8 * size):
            continue
        for endian in ("little", "big"):
            needle = value.to_bytes(size, endian)
            offsets = [i for i in range(len(raw) - size + 1) if raw[i:i+size] == needle]
            if offsets:
                found[f"u{size*8}_{endian}"] = offsets
    return found


def fixed_fields(raw: bytes, block_time: int, slot: int) -> dict[str, Any]:
    def ule(off: int) -> int | None:
        return int.from_bytes(raw[off:off+8], "little") if len(raw) >= off + 8 else None
    ts_candidates = []
    slot_candidates = []
    for offset in range(max(0, len(raw) - 7)):
        value = int.from_bytes(raw[offset:offset+8], "little")
        if block_time >= 0 and abs(value - block_time) <= 600:
            ts_candidates.append({"offset": offset, "value": value, "delta_seconds": value - block_time})
        if slot >= 0 and abs(value - slot) <= 2000:
            slot_candidates.append({"offset": offset, "value": value, "delta_slots": value - slot})
    return {
        "opcode": raw[0] if raw else None,
        "u64_at_1": ule(1),
        "u64_at_9": ule(9),
        "u64_at_17": ule(17),
        "u64_at_25": ule(25),
        "u64_at_33": ule(33),
        "bytes_41_72_hex": raw[41:73].hex() if len(raw) >= 73 else None,
        "u64_at_73": ule(73),
        "bytes_81_144_hex": raw[81:145].hex() if len(raw) >= 145 else None,
        "u64_at_145": ule(145),
        "timestamp_candidates": ts_candidates,
        "slot_candidates": slot_candidates,
    }


def main() -> int:
    started = now()
    accepted_rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    for signature, label in CASES.items():
        tx = rpc("getTransaction", [signature, {"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
        if not isinstance(tx, Mapping):
            rejected_rows.append({"label":label,"signature":signature,"reason":"transaction_unavailable"})
            continue
        truths = truth_from_logs(tx)
        inners = bison_inners(tx)
        if len(truths) != 1:
            rejected_rows.append({"label":label,"signature":signature,"reason":"truth_not_unique","truth_count":len(truths),"bison_inner_count":len(inners)})
            continue
        amount_in, amount_out = truths[0]
        matching = []
        for row in inners:
            offsets = u64_offsets(row["raw"], amount_in)
            if offsets:
                matching.append((row, offsets))
        if len(matching) != 1:
            rejected_rows.append({
                "label":label,
                "signature":signature,
                "reason":"amount_in_payload_match_not_unique",
                "truth_amount_in":amount_in,
                "truth_amount_out":amount_out,
                "bison_inner_count":len(inners),
                "matching_payload_count":len(matching),
                "candidate_lengths":[len(x["raw"]) for x in inners],
            })
            continue
        selected, input_offsets = matching[0]
        raw = selected["raw"]
        slot = int(tx.get("slot", -1))
        block_time = int(tx.get("blockTime", -1))
        fields = fixed_fields(raw, block_time, slot)
        accepted_rows.append({
            "label":label,
            "signature":signature,
            "slot":slot,
            "block_time":block_time,
            "truth_amount_in":amount_in,
            "truth_amount_out":amount_out,
            "bison_inner_count":len(inners),
            "selected_parent_index":selected["parent_index"],
            "selected_child_index":selected["child_index"],
            "selected_payload_len":len(raw),
            "selected_payload_sha256":sha256(raw),
            "selected_payload_hex":raw.hex(),
            "selected_account_count":len(selected["accounts"]),
            "selected_accounts":selected["accounts"],
            "amount_in_u64_le_offsets":input_offsets,
            "amount_out_occurrences":generic_occurrences(raw, amount_out),
            "fields":fields,
            "derived":{
                "output_per_input": amount_out / amount_in if amount_in else None,
                "u64_at_25_div_input": fields["u64_at_25"] / amount_in if amount_in and fields["u64_at_25"] is not None else None,
                "u64_at_25_div_output": fields["u64_at_25"] / amount_out if amount_out and fields["u64_at_25"] is not None else None,
            },
        })

    lengths = sorted({r["selected_payload_len"] for r in accepted_rows})
    opcodes = sorted({r["fields"]["opcode"] for r in accepted_rows})
    out_direct = sum(1 for r in accepted_rows if r["amount_out_occurrences"])
    input_offsets_sets = sorted({tuple(r["amount_in_u64_le_offsets"]) for r in accepted_rows})
    timestamp9 = sum(1 for r in accepted_rows if r["fields"]["u64_at_9"] is not None and abs(r["fields"]["u64_at_9"] - r["block_time"]) <= 600)
    slot73 = sum(1 for r in accepted_rows if r["fields"]["u64_at_73"] is not None and abs(r["fields"]["u64_at_73"] - r["slot"]) <= 2000)

    evidence = {
        "schema":"ghost.bison_signed_quote_correlation.v2",
        "accepted":True,
        "observation_only":True,
        "execution_authority":False,
        "started_at":started,
        "completed_at":now(),
        "requested_case_count":len(CASES),
        "accepted_case_count":len(accepted_rows),
        "rejected_case_count":len(rejected_rows),
        "payload_lengths":lengths,
        "opcodes":opcodes,
        "amount_in_u64_le_offset_patterns":[list(x) for x in input_offsets_sets],
        "amount_out_directly_embedded_cases":out_direct,
        "timestamp_like_u64_at_9_cases":timestamp9,
        "slot_like_u64_at_73_cases":slot73,
        "cases":accepted_rows,
        "rejections":rejected_rows,
        "interpretation":(
            "Selection is fail-closed by finalized event amount_in, not instruction order. "
            "Absence of literal amount_out is evidence against a simple direct output field only. "
            "Any candidate timestamp, slot, signer key, signature, ratio, or quote-price semantics "
            "remain provisional until independently verified."
        ),
        "safety":{
            "wallet":False,"signer":False,"approval":False,"transaction_builder":False,
            "transaction_serialization":False,"transaction_simulation":False,
            "transaction_submission":False,"broadcast":False,"bridge_execution":False,
            "capital_movement":False,
        },
    }
    stamp = started.replace(":","").replace("-","").replace(".","_")
    out = Path("live-evidence") / f"bison-signed-quote-correlation-v2-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out/"evidence.json").write_bytes(raw)
    (out/"evidence.sha256").write_text(f"{sha256(raw)}  evidence.json\n")
    print(json.dumps({
        "accepted_case_count":len(accepted_rows),
        "rejected_case_count":len(rejected_rows),
        "payload_lengths":lengths,
        "opcodes":opcodes,
        "amount_in_u64_le_offset_patterns":[list(x) for x in input_offsets_sets],
        "amount_out_directly_embedded_cases":out_direct,
        "timestamp_like_u64_at_9_cases":timestamp9,
        "slot_like_u64_at_73_cases":slot73,
        "rejections":rejected_rows,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
