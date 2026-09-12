#!/usr/bin/env python3
"""Shared primitives for the isolated Ghost G0 Raydium evidence collector.

Standard library only. No signing, submission, broadcast, or capital movement.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}

RAYDIUM_CPMM_PROGRAM_ID = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

POOL_STATE_LEN = 637
POOL_STATE_DISCRIMINATOR = bytes([247, 237, 227, 245, 215, 195, 222, 70])
TOKEN_ACCOUNT_MIN_LEN = 165
TOKEN_ACCOUNT_AMOUNT_OFFSET = 64


class G0Error(RuntimeError):
    pass


def unix_ns() -> int:
    return time.time_ns()


def monotonic_ns() -> int:
    return time.monotonic_ns()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    # V0 hash contract: UTF-8, recursively sorted keys, compact separators,
    # ensure_ascii=False, no NaN/Infinity, and one trailing LF.
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def write_json(path: Path, value: Any, *, canonical: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json_bytes(value) if canonical else (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")
    path.write_bytes(data)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text("utf-8"))


def b58encode(data: bytes) -> str:
    if not data:
        return ""
    zeroes = 0
    for byte in data:
        if byte == 0:
            zeroes += 1
        else:
            break
    number = int.from_bytes(data, "big")
    encoded = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(B58_ALPHABET[remainder])
    core = "".join(reversed(encoded))
    return "1" * zeroes + core


def b58decode(text: str) -> bytes:
    if not text:
        return b""
    number = 0
    for char in text:
        if char not in B58_INDEX:
            raise G0Error(f"invalid base58 character: {char!r}")
        number = number * 58 + B58_INDEX[char]
    full = b"" if number == 0 else number.to_bytes((number.bit_length() + 7) // 8, "big")
    zeroes = len(text) - len(text.lstrip("1"))
    return b"\x00" * zeroes + full


def require_pubkey_bytes(text: str) -> bytes:
    raw = b58decode(text)
    if len(raw) != 32:
        raise G0Error(f"pubkey {text} decoded to {len(raw)} bytes, expected 32")
    return raw


def decode_account_data(account: Mapping[str, Any], label: str) -> bytes:
    data = account.get("data")
    if not isinstance(data, list) or len(data) < 2 or data[1] != "base64":
        raise G0Error(f"{label} does not contain [data, 'base64']")
    if not isinstance(data[0], str):
        raise G0Error(f"{label} base64 payload is not a string")
    try:
        return base64.b64decode(data[0], validate=True)
    except Exception as exc:
        raise G0Error(f"{label} has invalid base64: {exc}") from exc


def decode_pool_identity(pool_data: bytes) -> dict[str, str]:
    if len(pool_data) != POOL_STATE_LEN:
        raise G0Error(
            f"unexpected Raydium PoolState length: expected {POOL_STATE_LEN}, got {len(pool_data)}"
        )
    if pool_data[:8] != POOL_STATE_DISCRIMINATOR:
        raise G0Error("unexpected Raydium PoolState discriminator")

    # Mirrors the current Scout Raydium PoolState prefix layout.
    offset = 8

    def pubkey() -> str:
        nonlocal offset
        end = offset + 32
        if end > len(pool_data):
            raise G0Error("Raydium PoolState pubkey read exceeded account data")
        value = b58encode(pool_data[offset:end])
        offset = end
        return value

    amm_config = pubkey()
    _pool_creator = pubkey()
    token_0_vault = pubkey()
    token_1_vault = pubkey()
    _lp_mint = pubkey()
    token_0_mint = pubkey()
    token_1_mint = pubkey()
    token_0_program = pubkey()
    token_1_program = pubkey()
    observation_key = pubkey()

    return {
        "amm_config": amm_config,
        "token_0_vault": token_0_vault,
        "token_1_vault": token_1_vault,
        "token_0_mint": token_0_mint,
        "token_1_mint": token_1_mint,
        "token_0_program": token_0_program,
        "token_1_program": token_1_program,
        "observation_key": observation_key,
    }


def redact_endpoint(url: str) -> dict[str, str]:
    parts = urlsplit(url)
    host = parts.hostname or "unknown"
    port = f":{parts.port}" if parts.port is not None else ""
    origin = f"{parts.scheme}://{host}{port}"
    return {
        "origin": origin,
        "endpoint_sha256": sha256_bytes(url.encode("utf-8")),
    }


def account_record(pubkey: str, account: Mapping[str, Any]) -> dict[str, Any]:
    raw = decode_account_data(account, pubkey)
    return {
        "pubkey": pubkey,
        "owner": account.get("owner"),
        "lamports": account.get("lamports"),
        "executable": account.get("executable"),
        "rent_epoch": account.get("rentEpoch"),
        "space": account.get("space"),
        "data_base64": base64.b64encode(raw).decode("ascii"),
        "data_len": len(raw),
        "data_sha256": sha256_bytes(raw),
    }


def token_account_amount_raw(record: Mapping[str, Any]) -> int:
    raw = base64.b64decode(record["data_base64"], validate=True)
    end = TOKEN_ACCOUNT_AMOUNT_OFFSET + 8
    if len(raw) < max(TOKEN_ACCOUNT_MIN_LEN, end):
        raise G0Error(f"token account {record.get('pubkey')} is too short")
    return int.from_bytes(raw[TOKEN_ACCOUNT_AMOUNT_OFFSET:end], "little")


def snapshot_body(
    context_slot: int,
    pubkeys: list[str],
    accounts: list[Mapping[str, Any]],
    *,
    continuity_epoch: int,
    captured_at_unix_ns: int,
    rpc_evidence_id: str,
    transport_interruption_count: int = 0,
) -> dict[str, Any]:
    if len(pubkeys) != 6 or len(accounts) != 6:
        raise G0Error("G0 Raydium quote-state snapshot requires exactly six accounts")
    if any(account is None for account in accounts):
        raise G0Error("G0 Raydium quote-state snapshot contains a null account")

    records = [account_record(pubkey, account) for pubkey, account in zip(pubkeys, accounts)]
    body = {
        "schema_version": "raydium_g0_snapshot_v1",
        "context_slot": int(context_slot),
        "continuity_epoch": int(continuity_epoch),
        "transport_interruption_count": int(transport_interruption_count),
        "captured_at_unix_ns": int(captured_at_unix_ns),
        "rpc_evidence_id": rpc_evidence_id,
        "accounts": records,
    }
    body["snapshot_sha256"] = sha256_bytes(canonical_json_bytes(body))
    return body


def snapshot_account_map(snapshot: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {entry["pubkey"]: entry for entry in snapshot["accounts"]}


def resolve_transaction_accounts(tx_result: Mapping[str, Any]) -> list[dict[str, Any]]:
    transaction = tx_result.get("transaction")
    meta = tx_result.get("meta")
    if not isinstance(transaction, Mapping) or not isinstance(meta, Mapping):
        raise G0Error("JSON transaction response is missing transaction/meta objects")
    message = transaction.get("message")
    if not isinstance(message, Mapping):
        raise G0Error("transaction message is missing")

    static_keys = message.get("accountKeys")
    header = message.get("header")
    if not isinstance(static_keys, list) or not all(isinstance(x, str) for x in static_keys):
        raise G0Error("transaction JSON must use raw/json static accountKeys")
    if not isinstance(header, Mapping):
        raise G0Error("transaction message header is missing")

    required = int(header.get("numRequiredSignatures", 0))
    ro_signed = int(header.get("numReadonlySignedAccounts", 0))
    ro_unsigned = int(header.get("numReadonlyUnsignedAccounts", 0))
    signed_writable_end = required - ro_signed
    unsigned_writable_end = len(static_keys) - ro_unsigned

    resolved: list[dict[str, Any]] = []
    for idx, key in enumerate(static_keys):
        signer = idx < required
        if signer:
            writable = idx < signed_writable_end
        else:
            writable = idx < unsigned_writable_end
        resolved.append({
            "index": idx,
            "pubkey": key,
            "is_signer": signer,
            "is_writable": writable,
            "key_source": "static",
        })

    loaded = meta.get("loadedAddresses") or {"writable": [], "readonly": []}
    if not isinstance(loaded, Mapping):
        raise G0Error("transaction loadedAddresses has invalid shape")
    for key in loaded.get("writable", []) or []:
        resolved.append({
            "index": len(resolved),
            "pubkey": key,
            "is_signer": False,
            "is_writable": True,
            "key_source": "alt_writable",
        })
    for key in loaded.get("readonly", []) or []:
        resolved.append({
            "index": len(resolved),
            "pubkey": key,
            "is_signer": False,
            "is_writable": False,
            "key_source": "alt_readonly",
        })
    return resolved


def flatten_compiled_instructions(tx_result: Mapping[str, Any]) -> list[dict[str, Any]]:
    transaction = tx_result["transaction"]
    message = transaction["message"]
    output: list[dict[str, Any]] = []
    for i, ix in enumerate(message.get("instructions", []) or []):
        if isinstance(ix, Mapping) and "programIdIndex" in ix:
            item = dict(ix)
            item["_origin"] = f"top:{i}"
            output.append(item)
    meta = tx_result.get("meta") or {}
    for group in meta.get("innerInstructions", []) or []:
        parent = group.get("index")
        for i, ix in enumerate(group.get("instructions", []) or []):
            if isinstance(ix, Mapping) and "programIdIndex" in ix:
                item = dict(ix)
                item["_origin"] = f"inner:{parent}:{i}"
                output.append(item)
    return output


def classify_raydium_swap_base_input(
    tx_result: Mapping[str, Any],
    target_pool: str,
) -> dict[str, Any]:
    meta = tx_result.get("meta")
    if not isinstance(meta, Mapping):
        raise G0Error("transaction metadata is missing")
    if meta.get("err") is not None:
        raise G0Error("transaction failed")

    accounts = resolve_transaction_accounts(tx_result)
    keys = [item["pubkey"] for item in accounts]
    raydium_ixs = []
    for ix in flatten_compiled_instructions(tx_result):
        pidx = int(ix["programIdIndex"])
        if pidx < 0 or pidx >= len(keys):
            raise G0Error("instruction programIdIndex exceeds resolved account list")
        if keys[pidx] != RAYDIUM_CPMM_PROGRAM_ID:
            continue
        ix_accounts = []
        for index in ix.get("accounts", []) or []:
            index = int(index)
            if index < 0 or index >= len(keys):
                raise G0Error("instruction account index exceeds resolved account list")
            ix_accounts.append(keys[index])
        if target_pool in ix_accounts:
            raydium_ixs.append({
                "origin": ix["_origin"],
                "accounts": ix_accounts,
                "data": ix.get("data"),
            })

    logs = meta.get("logMessages") or []
    base_input_logs = [
        line for line in logs
        if isinstance(line, str) and "Instruction: SwapBaseInput" in line
    ]
    if len(raydium_ixs) != 1:
        raise G0Error(
            f"expected exactly one target-pool Raydium CPMM instruction, got {len(raydium_ixs)}"
        )
    if len(base_input_logs) != 1:
        raise G0Error(
            f"expected exactly one SwapBaseInput log, got {len(base_input_logs)}"
        )
    return {
        "instruction_kind": "swap_base_input",
        "raydium_instruction": raydium_ixs[0],
        "resolved_accounts": accounts,
        "log_evidence": base_input_logs[0],
    }


def writable_target_overlap(
    tx_result: Mapping[str, Any],
    target_pubkeys: set[str],
) -> set[str]:
    resolved = resolve_transaction_accounts(tx_result)
    return {
        item["pubkey"]
        for item in resolved
        if item["is_writable"] and item["pubkey"] in target_pubkeys
    }


def extract_raw_transaction_bytes(base64_result: Mapping[str, Any]) -> bytes:
    transaction = base64_result.get("transaction")
    encoded = None
    if isinstance(transaction, list) and transaction:
        encoded = transaction[0]
    elif isinstance(transaction, str):
        encoded = transaction
    if not isinstance(encoded, str):
        raise G0Error("base64 getTransaction result does not contain encoded transaction bytes")
    try:
        return base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise G0Error(f"invalid base64 transaction bytes: {exc}") from exc



def exact_transaction_match(discovered: bytes, sealed: bytes) -> bool:
    """Return True only when both serialized signed transaction byte strings are identical."""
    return discovered == sealed and sha256_bytes(discovered) == sha256_bytes(sealed)

def copy_rpc_evidence(evidence_root: Path, ids: Iterable[str], destination: Path) -> list[str]:
    destination.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for evidence_id in sorted(set(ids)):
        source_dir = evidence_root / evidence_id
        if not source_dir.exists():
            raise G0Error(f"missing RPC evidence directory {evidence_id}")
        dest_dir = destination / evidence_id
        shutil.copytree(source_dir, dest_dir)
        copied.append(evidence_id)
    return copied


def hash_tree(root: Path, *, exclude_names: set[str] | None = None) -> dict[str, str]:
    exclude_names = exclude_names or set()
    hashes: dict[str, str] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.name in exclude_names:
            continue
        rel = path.relative_to(root).as_posix()
        hashes[rel] = sha256_bytes(path.read_bytes())
    return hashes


def verify_hash_tree(root: Path, hashes: Mapping[str, str]) -> None:
    for rel, expected in hashes.items():
        path = root / rel
        if not path.is_file():
            raise G0Error(f"sealed artifact missing file: {rel}")
        actual = sha256_bytes(path.read_bytes())
        if actual != expected:
            raise G0Error(f"hash mismatch for {rel}: expected {expected}, got {actual}")


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    http_status: int | None
    continuity_epoch: int
