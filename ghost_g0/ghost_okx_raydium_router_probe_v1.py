#!/usr/bin/env python3
"""Ghost OKX -> Raydium CPMM direct-root probe v1.

Extends v0 only where real signed-chain evidence justified it:
- multiple Raydium CPMM routes are allowed when route/block order is unambiguous;
- weighted split rounding is deterministic: each edge except the last receives
  floor(stage_amount * weight / 10_000), and the final edge receives the exact
  residual.

V1 remains direct-root only (node 0 -> node 1). Multi-stage propagation is a
separate gate and fails closed.
"""
from __future__ import annotations

from typing import Any

try:
    from .ghost_okx_raydium_router_probe_v0 import (
        OKX_ROUTER,
        ProbeError,
        RAYDIUM_ADAPTER_BLOCK_LEN,
        RAYDIUM_CPMM,
        RAYDIUM_CPMM_DEX_TAG,
        SHARE_DENOMINATOR,
        SPL_TOKEN,
        SWAP_TOB_FIXED_ACCOUNT_COUNT,
        decode_swap_tob,
    )
except ImportError:
    from ghost_okx_raydium_router_probe_v0 import (
        OKX_ROUTER,
        ProbeError,
        RAYDIUM_ADAPTER_BLOCK_LEN,
        RAYDIUM_CPMM,
        RAYDIUM_CPMM_DEX_TAG,
        SHARE_DENOMINATOR,
        SPL_TOKEN,
        SWAP_TOB_FIXED_ACCOUNT_COUNT,
        decode_swap_tob,
    )


def _allocation(stage_amount: int, routes: list[dict[str, int]]) -> list[int]:
    if stage_amount <= 0:
        raise ProbeError("stage amount must be positive")
    if not routes:
        raise ProbeError("stage has no routes")
    if sum(int(route["weight"]) for route in routes) != SHARE_DENOMINATOR:
        raise ProbeError("stage route weights do not sum to 10_000")

    values: list[int] = []
    allocated = 0
    for index, route in enumerate(routes):
        if index + 1 == len(routes):
            value = stage_amount - allocated
        else:
            value = (stage_amount * int(route["weight"])) // SHARE_DENOMINATOR
            allocated += value
        if value <= 0:
            raise ProbeError("stage allocation produced non-positive amount")
        values.append(value)
    if sum(values) != stage_amount:
        raise ProbeError("stage allocation did not conserve input")
    return values


def _ray_blocks(instruction_accounts: list[str]) -> list[tuple[int, list[str]]]:
    found: list[tuple[int, list[str]]] = []
    for start in range(SWAP_TOB_FIXED_ACCOUNT_COUNT, len(instruction_accounts)):
        if instruction_accounts[start] != RAYDIUM_CPMM:
            continue
        end = start + RAYDIUM_ADAPTER_BLOCK_LEN
        if end > len(instruction_accounts):
            raise ProbeError("Raydium CPMM adapter block is truncated")
        block = instruction_accounts[start:end]
        if block[9] != SPL_TOKEN or block[10] != SPL_TOKEN:
            raise ProbeError("v1 requires SPL Token / SPL Token for every Raydium block")
        found.append((start, block))
    return found


def derive_direct_root_raydium_leg_v1(
    instruction_data: bytes,
    instruction_accounts: list[str],
    target_pool_id: str,
) -> dict[str, Any]:
    decoded = decode_swap_tob(instruction_data)
    stage_amount = int(decoded["amount_in"])

    root_routes = [
        route
        for route in decoded["routes"]
        if int(route["source_node"]) == 0
    ]
    if not root_routes:
        raise ProbeError("no root routes")
    if any(int(route["destination_node"]) != 1 for route in root_routes):
        raise ProbeError("v1 requires every root route to be edge 0 -> 1")

    allocations = _allocation(stage_amount, root_routes)

    all_ray_routes = [
        route for route in decoded["routes"]
        if int(route["dex_tag"]) == RAYDIUM_CPMM_DEX_TAG
    ]
    blocks = _ray_blocks(instruction_accounts)
    if len(all_ray_routes) != len(blocks):
        raise ProbeError(
            f"Raydium route/block count mismatch: routes={len(all_ray_routes)} blocks={len(blocks)}"
        )

    ray_route_to_block = list(zip(all_ray_routes, blocks))
    target_matches = [
        (route, start, block)
        for route, (start, block) in ray_route_to_block
        if block[6] == target_pool_id
    ]
    if len(target_matches) != 1:
        raise ProbeError(
            f"expected exactly one Raydium block for locked pool, got {len(target_matches)}"
        )
    target_route, block_start, block = target_matches[0]
    if int(target_route["source_node"]) != 0 or int(target_route["destination_node"]) != 1:
        raise ProbeError("locked-pool Raydium route is not direct-root")

    root_position = None
    for index, route in enumerate(root_routes):
        if route is target_route:
            root_position = index
            break
    if root_position is None:
        raise ProbeError("target route was not found in root stage")
    ray_amount = allocations[root_position]

    canonical_inner_accounts = [
        block[1], block[4], block[5], block[6], block[2], block[3],
        block[7], block[8], block[9], block[10], block[11], block[12], block[13],
    ]

    return {
        "schema": "ghost_okx_raydium_direct_root_leg_v1",
        "authority": {
            "read_only": True,
            "signing": False,
            "submission": False,
            "capital_movement": False,
        },
        "outer_program_id": OKX_ROUTER,
        "outer_instruction": "swap_tob",
        "outer_amount_in": stage_amount,
        "outer_expect_amount_out": int(decoded["expect_amount_out"]),
        "outer_slippage": int(decoded["slippage"]),
        "root_routes": root_routes,
        "root_allocations": allocations,
        "route": dict(target_route),
        "derived_raydium_amount_in": ray_amount,
        "minimum_amount_out": None,
        "state_projection_condition": "outer transaction and locked-pool Raydium leg execute successfully",
        "adapter_block_offset": block_start - SWAP_TOB_FIXED_ACCOUNT_COUNT,
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
        "raydium_route_count": len(all_ray_routes),
    }
