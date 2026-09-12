#!/usr/bin/env python3
"""Pure Raydium CPMM state transition used by Ghost router shadow probes.

No network, signing, submission, or execution authority. Inputs are a finalized
six-account S0 RPC bundle plus a causal leg derived independently from signed
transaction data. Output is a projected six-account RPC bundle.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from typing import Any, Mapping

POOL_DISC = bytes([247, 237, 227, 245, 215, 195, 222, 70])
AMM_DISC = bytes([218, 244, 33, 104, 203, 203, 43, 111])
SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
WSOL_MINT = "So11111111111111111111111111111111111111112"
DENOM = 1_000_000
TOKEN_AMOUNT_OFFSET = 64
SLOTS_PER_EPOCH = 432_000


class TransitionError(RuntimeError):
    pass


def _u64(data: bytes | bytearray, offset: int) -> int:
    if offset + 8 > len(data):
        raise TransitionError("u64 field truncated")
    return int.from_bytes(data[offset:offset + 8], "little")


def _set_u64(data: bytearray, offset: int, value: int) -> None:
    if value < 0 or value > 0xFFFF_FFFF_FFFF_FFFF:
        raise TransitionError("u64 field overflow")
    data[offset:offset + 8] = value.to_bytes(8, "little")


def _data(value: Mapping[str, Any]) -> bytes:
    field = value.get("data")
    if not isinstance(field, list) or len(field) != 2 or field[1] != "base64":
        raise TransitionError("account data is not base64 RPC form")
    try:
        return base64.b64decode(field[0], validate=True)
    except Exception as exc:
        raise TransitionError(f"invalid account base64: {exc}") from exc


def _replace_data(value: dict[str, Any], data: bytes) -> None:
    value["data"] = [base64.b64encode(data).decode("ascii"), "base64"]


def _pool(data: bytes) -> dict[str, Any]:
    if len(data) != 637 or data[:8] != POOL_DISC:
        raise TransitionError("unsupported Raydium PoolState")
    return {
        "status": data[329],
        "protocol0": _u64(data, 341),
        "protocol1": _u64(data, 349),
        "fund0": _u64(data, 357),
        "fund1": _u64(data, 365),
        "recent_epoch": _u64(data, 381),
        "creator_fee_on": data[389],
        "enable_creator_fee": data[390] != 0,
        "creator0": _u64(data, 397),
        "creator1": _u64(data, 405),
    }


def _amm(data: bytes) -> dict[str, int]:
    if len(data) != 236 or data[:8] != AMM_DISC:
        raise TransitionError("unsupported Raydium AmmConfig")
    return {
        "trade": _u64(data, 12),
        "protocol": _u64(data, 20),
        "fund": _u64(data, 28),
        "creator": _u64(data, 108),
    }


def _token_amount(data: bytes) -> int:
    if len(data) < 165:
        raise TransitionError("token account too short")
    return _u64(data, TOKEN_AMOUNT_OFFSET)


def _ceil_fee(amount: int, rate: int) -> int:
    if amount == 0 or rate == 0:
        return 0
    return (amount * rate + DENOM - 1) // DENOM


def _floor_fee(amount: int, rate: int, denominator: int = DENOM) -> int:
    if denominator <= 0:
        raise TransitionError("invalid fee denominator")
    return (amount * rate) // denominator


def project_rpc_bundle(
    s0_values: list[Mapping[str, Any]],
    six_account_keys: list[str],
    leg: Mapping[str, Any],
    transaction_slot: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if len(s0_values) != 6 or len(six_account_keys) != 6:
        raise TransitionError("six-account bundle required")

    target_pool, _config, vault0, vault1, mint0, mint1 = six_account_keys
    accounts = leg.get("raydium_accounts")
    if not isinstance(accounts, Mapping):
        raise TransitionError("causal leg missing raydium_accounts")
    if accounts.get("pool_state") != target_pool:
        raise TransitionError("causal leg pool mismatch")
    if accounts.get("input_token_program") != SPL_TOKEN or accounts.get("output_token_program") != SPL_TOKEN:
        raise TransitionError("SPL Token / SPL Token required")

    if accounts.get("input_vault") == vault0 and accounts.get("output_vault") == vault1:
        zero_for_one = True
        if accounts.get("input_mint") != mint0 or accounts.get("output_mint") != mint1:
            raise TransitionError("mint direction mismatch")
    elif accounts.get("input_vault") == vault1 and accounts.get("output_vault") == vault0:
        zero_for_one = False
        if accounts.get("input_mint") != mint1 or accounts.get("output_mint") != mint0:
            raise TransitionError("mint direction mismatch")
    else:
        raise TransitionError("vault direction mismatch")

    amount_in = int(leg.get("derived_raydium_amount_in", 0))
    if amount_in <= 0:
        raise TransitionError("invalid causal input amount")

    out = deepcopy([dict(v) for v in s0_values])
    pool_raw = bytearray(_data(out[0]))
    amm_raw = _data(out[1])
    vault0_raw = bytearray(_data(out[2]))
    vault1_raw = bytearray(_data(out[3]))
    pool = _pool(bytes(pool_raw))
    amm = _amm(amm_raw)

    if pool["status"] & 4:
        raise TransitionError("pool swap disabled")

    amount0 = _token_amount(vault0_raw)
    amount1 = _token_amount(vault1_raw)
    accrued0 = pool["protocol0"] + pool["fund0"] + pool["creator0"]
    accrued1 = pool["protocol1"] + pool["fund1"] + pool["creator1"]
    if amount0 < accrued0 or amount1 < accrued1:
        raise TransitionError("accrued fees exceed vault amount")

    effective0 = amount0 - accrued0
    effective1 = amount1 - accrued1
    input_reserve, output_reserve = (
        (effective0, effective1) if zero_for_one else (effective1, effective0)
    )
    if input_reserve <= 0 or output_reserve <= 0:
        raise TransitionError("empty effective reserve")

    creator_rate = amm["creator"] if pool["enable_creator_fee"] else 0
    mode = pool["creator_fee_on"]
    if mode not in (0, 1, 2):
        raise TransitionError("invalid creator fee mode")
    creator_on_input = (
        mode == 0
        or (mode == 1 and zero_for_one)
        or (mode == 2 and not zero_for_one)
    )

    if creator_on_input:
        combined_rate = amm["trade"] + creator_rate
        if combined_rate >= DENOM:
            raise TransitionError("combined fee rate too large")
        total_fee = _ceil_fee(amount_in, combined_rate)
        creator_fee = 0 if combined_rate == 0 else _floor_fee(total_fee, creator_rate, combined_rate)
        trade_fee = total_fee - creator_fee
        curve_input = amount_in - total_fee
    else:
        trade_fee = _ceil_fee(amount_in, amm["trade"])
        creator_fee = 0
        curve_input = amount_in - trade_fee

    if curve_input <= 0:
        raise TransitionError("input consumed by fees")

    protocol_fee = _floor_fee(trade_fee, amm["protocol"])
    fund_fee = _floor_fee(trade_fee, amm["fund"])
    curve_output = (curve_input * output_reserve) // (input_reserve + curve_input)
    if creator_on_input:
        output_amount = curve_output
    else:
        creator_fee = _ceil_fee(curve_output, creator_rate)
        output_amount = curve_output - creator_fee
    if output_amount <= 0:
        raise TransitionError("projected output is zero")

    if zero_for_one:
        new0 = amount0 + amount_in
        new1 = amount1 - output_amount
        pool["protocol0"] += protocol_fee
        pool["fund0"] += fund_fee
        if creator_on_input:
            pool["creator0"] += creator_fee
        else:
            pool["creator1"] += creator_fee
    else:
        new1 = amount1 + amount_in
        new0 = amount0 - output_amount
        pool["protocol1"] += protocol_fee
        pool["fund1"] += fund_fee
        if creator_on_input:
            pool["creator1"] += creator_fee
        else:
            pool["creator0"] += creator_fee

    if new0 < 0 or new1 < 0:
        raise TransitionError("vault underflow")

    _set_u64(vault0_raw, TOKEN_AMOUNT_OFFSET, new0)
    _set_u64(vault1_raw, TOKEN_AMOUNT_OFFSET, new1)
    _set_u64(pool_raw, 341, pool["protocol0"])
    _set_u64(pool_raw, 349, pool["protocol1"])
    _set_u64(pool_raw, 357, pool["fund0"])
    _set_u64(pool_raw, 365, pool["fund1"])
    _set_u64(pool_raw, 397, pool["creator0"])
    _set_u64(pool_raw, 405, pool["creator1"])
    _set_u64(pool_raw, 381, transaction_slot // SLOTS_PER_EPOCH)

    _replace_data(out[0], bytes(pool_raw))
    _replace_data(out[2], bytes(vault0_raw))
    _replace_data(out[3], bytes(vault1_raw))

    if accounts.get("input_mint") == WSOL_MINT:
        out[2 if zero_for_one else 3]["lamports"] = int(out[2 if zero_for_one else 3]["lamports"]) + amount_in
    if accounts.get("output_mint") == WSOL_MINT:
        idx = 3 if zero_for_one else 2
        lamports = int(out[idx]["lamports"]) - output_amount
        if lamports < 0:
            raise TransitionError("WSOL lamports underflow")
        out[idx]["lamports"] = lamports

    detail = {
        "zero_for_one": zero_for_one,
        "amount_in": amount_in,
        "amount_out": output_amount,
        "trade_fee": trade_fee,
        "protocol_fee": protocol_fee,
        "fund_fee": fund_fee,
        "creator_fee": creator_fee,
        "curve_input": curve_input,
    }
    return out, detail
