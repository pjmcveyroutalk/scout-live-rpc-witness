#!/usr/bin/env python3
"""Verify the BisonFiWithSig cryptographic quote envelope on settled transactions.

Independent evidence combined before this witness:
- T902 established a stable 153-byte Bison payload family, amount_in-based fail-closed
  selection, timestamp-like u64 at raw[9:17], caller pubkey at raw[41:73], slot-like
  u64 at raw[73:81], 64 opaque bytes at raw[81:145], and recovery-like byte raw[145].
- The previously captured finalized Bison executable has SHA-256
  3b204a28ed7c7de1cba5781fd6f3a207804d6d8d9482246c37d1086ae7faad54.
  Static SBF inspection shows sol_keccak256 and sol_secp256k1_recover imports and a
  hard-coded compressed verifier pubkey at executable virtual/file offset 0x33610:
  033c9fde8fface4e866f2978823ed1d2353d0c380085fcb29962ee0f25bbc4182b.
  The verification path hashes a 72-byte message and recovers from a 64-byte signature
  plus one-byte recovery id.

This witness tests, without fitting per case, the exact envelope implied by that code:
  message = raw[9:81]
  digest = Keccak-256(message)
  compact secp256k1 signature = raw[81:145]
  recovery id = raw[145]
  recovered compressed key must equal the executable's frozen verifier key.
It also requires raw[41:73] to equal the selected Bison instruction's account[0],
binding the signed message to the router/caller pubkey.

Finalized retrospective research only. No pending monitoring, wallet, signer,
simulation, transaction construction/serialization/submission, broadcast,
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
PROGRAM_ELF_SHA256 = "3b204a28ed7c7de1cba5781fd6f3a207804d6d8d9482246c37d1086ae7faad54"
VERIFIER_COMPRESSED_PUBKEY = bytes.fromhex(
    "033c9fde8fface4e866f2978823ed1d2353d0c380085fcb29962ee0f25bbc4182b"
)
CASES = {
    "3DhDBbxDaENVui8f7vjmmzygBMQnnGoNnfpTtqszuHhYLycZK8KYH5bje79hgpuWTyUCuH8HkTzzCRgTat1iyuhJ": "sealed_ghost",
    "26aKhuit1vWNyimWjCcvMY3mzoTk297PCup5pTiamxXDf6G57Lkq878nnPSzRhGRTma66LyFuWPW8AbpxVSHZVqP": "public_a",
    "2roTgE7GxgW7KwPLTkmmMARH9RpoPLa2kLTnH4mnLMWw2yTWUULzheAQPJHyqcyGsYLpZyi7GkuPvbAR8kQGjkDa": "public_b",
    "31rpu29NYFhHpwkXVgVvLWa9sL51JQddtq8YmyGeP3paCbqp9A9AbuWuWxorGiMJ9pkSRtp49rcmmHcokuPBS1nE": "public_c",
}
EVENT_RE = re.compile(r"SwapEvent \{ dex: BisonFiWithSig, amount_in: (\d+), amount_out: (\d+) \}")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58)}

MASK64 = (1 << 64) - 1
KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


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


def rol64(value: int, shift: int) -> int:
    if shift == 0:
        return value & MASK64
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def keccak_f1600(state: list[int]) -> None:
    for rc in KECCAK_RC:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        delta = [columns[(x - 1) % 5] ^ rol64(columns[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= delta[x]
        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(
                    state[x + 5 * y], KECCAK_ROT[x][y]
                )
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= rc


def keccak256(message: bytes) -> bytes:
    rate = 136
    padded = bytearray(message)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for block_start in range(0, len(padded), rate):
        block = padded[block_start : block_start + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        keccak_f1600(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def point_add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % SECP_P == 0:
        return None
    if a == b:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1 % SECP_P, -1, SECP_P) % SECP_P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % SECP_P, -1, SECP_P) % SECP_P
    x3 = (slope * slope - x1 - x2) % SECP_P
    y3 = (slope * (x1 - x3) - y1) % SECP_P
    return x3, y3


def point_mul(k: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    if point is None or k == 0:
        return None
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def recover_pubkey(digest: bytes, signature: bytes, recovery_id: int) -> tuple[int, int] | None:
    if len(digest) != 32 or len(signature) != 64 or recovery_id not in (0, 1, 2, 3):
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < SECP_N and 1 <= s < SECP_N):
        return None
    x = r + (recovery_id // 2) * SECP_N
    if x >= SECP_P:
        return None
    alpha = (pow(x, 3, SECP_P) + 7) % SECP_P
    beta = pow(alpha, (SECP_P + 1) // 4, SECP_P)
    y = beta if beta % 2 == (recovery_id & 1) else SECP_P - beta
    r_point = (x, y)
    if point_mul(SECP_N, r_point) is not None:
        return None
    z = int.from_bytes(digest, "big")
    r_inv = pow(r, -1, SECP_N)
    return point_mul(
        r_inv,
        point_add(point_mul(s, r_point), point_mul((-z) % SECP_N, SECP_G)),
    )


def compress_pubkey(point: tuple[int, int] | None) -> bytes | None:
    if point is None:
        return None
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}, separators=(",", ":")).encode()
    delay = 0.5
    for attempt in range(7):
        try:
            request = urllib.request.Request(
                RPC, data=body, method="POST",
                headers={"content-type":"application/json","user-agent":"Ghost-Bison-Crypto-Envelope/1"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
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
    groups = meta.get("innerInstructions") if isinstance(meta, Mapping) else None
    out: list[dict[str, Any]] = []
    if not isinstance(groups, list):
        return out
    for group in groups:
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
                out.append({"raw":b58decode(data),"accounts":[str(x) for x in accounts]})
            except Exception:
                continue
    return out


def bison_truth(tx: Mapping[str, Any]) -> list[tuple[int, int]]:
    meta = tx.get("meta")
    logs = meta.get("logMessages") if isinstance(meta, Mapping) else None
    out: list[tuple[int, int]] = []
    if not isinstance(logs, list):
        return out
    for line in logs:
        if not isinstance(line, str):
            continue
        match = EVENT_RE.search(line)
        if match:
            out.append((int(match.group(1)), int(match.group(2))))
    return out


def main() -> int:
    if keccak256(b"").hex() != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise RuntimeError("Keccak self-test failed")
    started = now()
    rows: list[dict[str, Any]] = []
    for signature, label in CASES.items():
        tx = rpc("getTransaction", [signature, {"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
        if not isinstance(tx, Mapping):
            raise RuntimeError(f"transaction unavailable: {signature}")
        truths = bison_truth(tx)
        inners = bison_inners(tx)
        if len(truths) != 1:
            raise RuntimeError(f"Bison truth not unique: {signature}: {truths}")
        amount_in, amount_out = truths[0]
        needle = amount_in.to_bytes(8, "little")
        matching = [row for row in inners if needle in row["raw"]]
        if len(matching) != 1:
            raise RuntimeError(f"Bison input-selected payload not unique: {signature}: {len(matching)}")
        selected = matching[0]
        raw = selected["raw"]
        accounts = selected["accounts"]
        if len(raw) != 153 or raw[0] != 19 or not accounts:
            raise RuntimeError(f"unsupported Bison signed payload shape: {signature}")
        caller_bytes = b58decode(accounts[0])
        if len(caller_bytes) != 32:
            raise RuntimeError(f"caller account did not decode to 32 bytes: {signature}")
        message = raw[9:81]
        digest = keccak256(message)
        compact_signature = raw[81:145]
        recovery_id = raw[145]
        recovered = compress_pubkey(recover_pubkey(digest, compact_signature, recovery_id))
        caller_bound = raw[41:73] == caller_bytes
        signer_exact = recovered == VERIFIER_COMPRESSED_PUBKEY
        padding_zero = raw[146:153] == b"\0" * 7
        rows.append({
            "label":label,
            "signature":signature,
            "slot":int(tx.get("slot", -1)),
            "amount_in":amount_in,
            "amount_out":amount_out,
            "payload_sha256":sha256(raw),
            "message_range":"raw[9:81]",
            "message_len":len(message),
            "message_hex":message.hex(),
            "message_keccak256":digest.hex(),
            "caller_account":accounts[0],
            "caller_binding_range":"raw[41:73]",
            "caller_bound_exact":caller_bound,
            "signature_range":"raw[81:145]",
            "signature_hex":compact_signature.hex(),
            "recovery_id_offset":145,
            "recovery_id":recovery_id,
            "trailing_padding_hex":raw[146:153].hex(),
            "trailing_padding_zero":padding_zero,
            "recovered_compressed_pubkey":recovered.hex() if recovered is not None else None,
            "expected_compressed_pubkey":VERIFIER_COMPRESSED_PUBKEY.hex(),
            "signer_exact":signer_exact,
            "crypto_envelope_exact":caller_bound and signer_exact and padding_zero,
        })

    all_exact = bool(rows) and all(row["crypto_envelope_exact"] for row in rows)
    evidence = {
        "schema":"ghost.bison_signed_quote_crypto_envelope.v1",
        "accepted":True,
        "observation_only":True,
        "execution_authority":False,
        "started_at":started,
        "completed_at":now(),
        "case_count":len(rows),
        "all_crypto_envelopes_exact":all_exact,
        "program_executable_provenance":{
            "program_id":BISON,
            "frozen_elf_sha256":PROGRAM_ELF_SHA256,
            "verifier_compressed_pubkey_file_offset_hex":"0x33610",
            "verifier_compressed_pubkey":VERIFIER_COMPRESSED_PUBKEY.hex(),
            "observed_imports":["sol_keccak256","sol_secp256k1_recover"],
        },
        "verified_layout":{
            "message":"raw[9:81] (72 bytes)",
            "caller_binding":"raw[41:73] == Bison instruction account[0]",
            "compact_secp256k1_signature":"raw[81:145] (64 bytes)",
            "recovery_id":"raw[145]",
            "trailing_padding":"raw[146:153] == seven zero bytes in this corpus",
            "digest":"Keccak-256(message)",
        },
        "cases":rows,
        "interpretation":(
            "This proves the cryptographic envelope and caller binding for the tested settled "
            "BisonFiWithSig family. It does not yet assign semantics to every signed quote field "
            "inside raw[9:41] or prove a deterministic pre-trade amount_out formula."
        ),
        "safety":{
            "wallet":False,"signer":False,"approval":False,"transaction_builder":False,
            "transaction_serialization":False,"transaction_simulation":False,
            "transaction_submission":False,"broadcast":False,"bridge_execution":False,
            "capital_movement":False,
        },
    }
    stamp = started.replace(":","").replace("-","").replace(".","_")
    out = Path("live-evidence") / f"bison-signed-quote-crypto-envelope-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw_evidence = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out/"evidence.json").write_bytes(raw_evidence)
    (out/"evidence.sha256").write_text(f"{sha256(raw_evidence)}  evidence.json\n")
    print(json.dumps({
        "case_count":len(rows),
        "all_crypto_envelopes_exact":all_exact,
        "recovery_ids":[row["recovery_id"] for row in rows],
        "caller_bindings_exact":[row["caller_bound_exact"] for row in rows],
        "signers_exact":[row["signer_exact"] for row in rows],
    }, indent=2, sort_keys=True))
    return 0 if all_exact else 1


if __name__ == "__main__":
    raise SystemExit(main())
