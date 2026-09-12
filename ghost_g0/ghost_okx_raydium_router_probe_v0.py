#!/usr/bin/env python3
"""Fail-closed OKX -> Raydium CPMM direct-root causal-leg probe.

Research-only Ghost G0 adapter. It reads signed OKX SwapTob instruction bytes
plus the already-resolved instruction account list and derives a conditional
Raydium CPMM causal leg without reading inner instructions, logs, balances,
S1, or any other execution result.

V0 intentionally supports only the narrow case proven by Ghost evidence:
- OKX SwapTob
- one direct root edge 0 -> 1 targeting Raydium CPMM
- root weights sum exactly to 10_000
- every root allocation is integral (no rounding/remainder ambiguity)
- exactly one Raydium CPMM adapter block
- locked target pool
- SPL Token / SPL Token

Everything else fails closed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

OKX_ROUTER = "proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u"
RAYDIUM_CPMM = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SWAP_TOB_DISCRIMINATOR = bytes([170, 41, 85, 177, 132, 80, 31, 53])
RAYDIUM_CPMM_DEX_TAG = 14
SHARE_DENOMINATOR = 10_000
SWAP_TOB_FIXED_ACCOUNT_COUNT = 16
RAYDIUM_ADAPTER_BLOCK_LEN = 14

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


class ProbeError(RuntimeError):
    pass


def b58decode(value: str) -> bytes:
    number = 0
    try:
        for char in value:
            number = number * 58 + _B58_INDEX[char]
    except KeyError as exc:
        raise ProbeError(f"invalid base58 character: {exc.args[0]!r}") from exc
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def _take(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    end = offset + size
    if end > len(data):
        raise ProbeError("instruction data truncated")
    return data[offset:end], end


def _u8(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _take(data, offset, 1)
    return raw[0], offset


def _u16(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _take(data, offset, 2)
    return int.from_bytes(raw, "little"), offset


def _u32(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _take(data, offset, 4)
    return int.from_bytes(raw, "little"), offset


def _u64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _take(data, offset, 8)
    return int.from_bytes(raw, "little"), offset


def _skip(data: bytes, offset: int, size: int) -> int:
    _, offset = _take(data, offset, size)
    return offset


def _skip_dex_payload(tag: int, data: bytes, offset: int) -> int:
    """Walk the current OKX Dex enum wire body, failing closed on unknown shapes.

    Body lengths follow OKX's public dex-solana-v3 decoder. V0 does not accept
    SolRfqV2 (tag 117) because it is variable-length and unnecessary for the
    first direct-root Raydium proof.
    """
    fixed: dict[int, int] = {
        23: 1, 24: 1, 34: 1, 35: 1,
        64: 50,
        74: 2, 75: 2,
        81: 8,
        82: 16,
        100: 8,
        103: 16,
        104: 99, 120: 99,
        118: 8,
        121: 1, 125: 1, 138: 1,
        132: 40,
        134: 96,
    }
    if tag in fixed:
        return _skip(data, offset, fixed[tag])

    if tag == 117:
        raise ProbeError("SolRfqV2 route body is unsupported in v0")

    if tag == 119:
        count, offset = _u32(data, offset)
        offset = _skip(data, offset, count * 2)
        return _skip(data, offset, 1)

    if tag == 126:
        count, offset = _u32(data, offset)
        for _ in range(count):
            candidate, offset = _u8(data, offset)
            if candidate in (3, 14):
                offset = _skip(data, offset, 8)
            elif candidate in (5, 16):
                offset = _skip(data, offset, 16)
            elif candidate == 10:
                offset = _skip(data, offset, 99)
            elif candidate == 15:
                offset = _skip(data, offset, 96)
            elif candidate in (0, 1, 2, 4, 6, 7, 8, 9, 11, 12, 13, 17):
                pass
            else:
                raise ProbeError(f"unknown DynamicCandidate tag {candidate}")
        mode, offset = _u8(data, offset)
        if mode in (1, 2):
            return _skip(data, offset, 1)
        if mode == 0:
            return offset
        raise ProbeError(f"invalid SelectionMode tag {mode}")

    if tag == 133:
        size, offset = _u32(data, offset)
        return _skip(data, offset, size)

    no_body = (
        set(range(0, 23))
        | set(range(25, 34))
        | set(range(36, 64))
        | set(range(65, 74))
        | set(range(76, 81))
        | set(range(83, 100))
        | set(range(101, 103))
        | set(range(105, 117))
        | set(range(122, 125))
        | set(range(127, 132))
        | set(range(135, 138))
        | set(range(139, 141))
    )
    if tag in no_body:
        return offset
    raise ProbeError(f"unknown OKX Dex tag {tag}")


def decode_swap_tob(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or data[:8] != SWAP_TOB_DISCRIMINATOR:
        raise ProbeError("instruction is not OKX SwapTob")

    offset = 8
    order_id, offset = _u64(data, offset)
    amount_in, offset = _u64(data, offset)
    expect_amount_out, offset = _u64(data, offset)
    slippage, offset = _u16(data, offset)
    route_count, offset = _u32(data, offset)

    if route_count == 0 or route_count > 64:
        raise ProbeError(f"invalid route count {route_count}")

    routes: list[dict[str, int]] = []
    for _ in range(route_count):
        tag, offset = _u8(data, offset)
        offset = _skip_dex_payload(tag, data, offset)
        weight, offset = _u16(data, offset)
        index, offset = _u8(data, offset)
        routes.append({
            "dex_tag": tag,
            "weight": weight,
            "index": index,
            "source_node": index >> 4,
            "destination_node": index & 0x0F,
        })

    if len(data) - offset != 7:
        raise ProbeError(f"unexpected SwapTob suffix length {len(data) - offset}")

    commission_info, offset = _u32(data, offset)
    platform_fee_rate, offset = _u16(data, offset)
    trim_rate, offset = _u8(data, offset)
    if offset != len(data):
        raise ProbeError("SwapTob decoder did not consume the instruction")

    return {
        "order_id": order_id,
        "amount_in": amount_in,
        "expect_amount_out": expect_amount_out,
        "slippage": slippage,
        "routes": routes,
        "commission_info": commission_info,
        "platform_fee_rate": platform_fee_rate,
        "trim_rate": trim_rate,
    }


def derive_direct_root_raydium_leg(
    instruction_data: bytes,
    instruction_accounts: list[str],
    target_pool_id: str,
) -> dict[str, Any]:
    decoded = decode_swap_tob(instruction_data)
    amount_in = int(decoded["amount_in"])

    root_routes = [r for r in decoded["routes"] if r["source_node"] == 0]
    if not root_routes:
        raise ProbeError("no root routes")
    if any(r["destination_node"] != 1 for r in root_routes):
        raise ProbeError("v0 requires every root route to be edge 0 -> 1")
    if sum(int(r["weight"]) for r in root_routes) != SHARE_DENOMINATOR:
        raise ProbeError("root route weights do not sum to 10_000")

    for route in root_routes:
        if (amount_in * int(route["weight"])) % SHARE_DENOMINATOR != 0:
            raise ProbeError("root route allocation has rounding ambiguity")

    ray_routes = [
        r for r in root_routes if int(r["dex_tag"]) == RAYDIUM_CPMM_DEX_TAG
    ]
    if len(ray_routes) != 1:
        raise ProbeError(
            f"expected exactly one direct-root Raydium CPMM route, got {len(ray_routes)}"
        )
    ray_route = ray_routes[0]

    if len(instruction_accounts) <= SWAP_TOB_FIXED_ACCOUNT_COUNT:
        raise ProbeError("OKX instruction account list has no adapter region")

    ray_positions = [
        index
        for index, pubkey in enumerate(instruction_accounts[SWAP_TOB_FIXED_ACCOUNT_COUNT:],
                                       start=SWAP_TOB_FIXED_ACCOUNT_COUNT)
        if pubkey == RAYDIUM_CPMM
    ]
    if len(ray_positions) != 1:
        raise ProbeError(
            f"expected one Raydium CPMM adapter block, got {len(ray_positions)}"
        )

    start = ray_positions[0]
    end = start + RAYDIUM_ADAPTER_BLOCK_LEN
    if end > len(instruction_accounts):
        raise ProbeError("Raydium CPMM adapter block is truncated")
    block = instruction_accounts[start:end]

    if block[0] != RAYDIUM_CPMM:
        raise ProbeError("Raydium adapter program mismatch")
    if block[6] != target_pool_id:
        raise ProbeError("Raydium adapter block does not target locked pool")
    if block[9] != SPL_TOKEN or block[10] != SPL_TOKEN:
        raise ProbeError("v0 requires SPL Token / SPL Token")

    ray_amount = (amount_in * int(ray_route["weight"])) // SHARE_DENOMINATOR
    if ray_amount <= 0:
        raise ProbeError("derived Raydium amount is zero")

    canonical_inner_accounts = [
        block[1], block[4], block[5], block[6], block[2], block[3],
        block[7], block[8], block[9], block[10], block[11], block[12], block[13],
    ]

    return {
        "schema": "ghost_okx_raydium_direct_root_leg_v0",
        "authority": {
            "read_only": True,
            "signing": False,
            "submission": False,
            "capital_movement": False,
        },
        "outer_program_id": OKX_ROUTER,
        "outer_instruction": "swap_tob",
        "outer_amount_in": amount_in,
        "outer_expect_amount_out": int(decoded["expect_amount_out"]),
        "outer_slippage": int(decoded["slippage"]),
        "route": dict(ray_route),
        "derived_raydium_amount_in": ray_amount,
        "minimum_amount_out": None,
        "state_projection_condition": "outer transaction and Raydium leg execute successfully",
        "adapter_block_offset": start - SWAP_TOB_FIXED_ACCOUNT_COUNT,
        "raydium_accounts": {
            "payer": block[1],
            "authority": block[4],
            "amm_config": block[5],
            "pool_state": block[6],
            "user_input": block[2],
            "user_output": block[3],
            "input_vault": block[7],
            "output_vault": block[8],
            "input_token_program": block[9],
            "output_token_program": block[10],
            "input_mint": block[11],
            "output_mint": block[12],
            "observation_state": block[13],
        },
        "canonical_inner_account_order": canonical_inner_accounts,
        "all_routes": list(decoded["routes"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instruction-data-base58", required=True)
    parser.add_argument("--instruction-accounts-json", required=True)
    parser.add_argument("--target-pool-id", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()

    try:
        accounts = json.loads(Path(args.instruction_accounts_json).read_text())
        if not isinstance(accounts, list) or not all(isinstance(x, str) for x in accounts):
            raise ProbeError("instruction accounts JSON must be a string array")
        result = derive_direct_root_raydium_leg(
            b58decode(args.instruction_data_base58),
            accounts,
            args.target_pool_id,
        )
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        if args.output:
            Path(args.output).write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")
        return 0
    except (ProbeError, OSError, json.JSONDecodeError) as exc:
        print(f"FAIL_CLOSED: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
