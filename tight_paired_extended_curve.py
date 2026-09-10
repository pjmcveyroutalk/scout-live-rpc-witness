#!/usr/bin/env python3
"""Scout tightly paired cross-domain USDC->USDT size curve.

For each notional, capture Solana/Raydium first and Arbitrum/Velora immediately
afterward before moving to the next size.

READ ONLY:
- HTTPS GET quote requests only
- no wallet
- no signer
- no approvals
- no transaction construction
- no transaction submission
- no capital movement
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

SIZES_USDC = (250, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000)

RAY_HOST = "transaction-v1.raydium.io"
RAY_PATH = "/compute/swap-base-in"
SOL_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOL_USDT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

EVM_HOST = "api.paraswap.io"
EVM_PATH = "/prices"
ARB_CHAIN_ID = 42161
VELORA_VERSION = "6.2"
ARB_USDC = "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
ARB_USDT0 = "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"

PORT = 443
SLIPPAGE_BPS = 50


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def https_get(host: str, target: str, user_agent: str):
    headers = [
        ("Host", host),
        ("User-Agent", user_agent),
        ("Accept", "application/json"),
        ("Accept-Encoding", "identity"),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Connection", "close"),
    ]
    request_bytes = (
        f"GET {target} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in headers)
        + "\r\n"
    ).encode()

    started = now()
    connection = http.client.HTTPSConnection(
        host, PORT, timeout=20, context=ssl.create_default_context()
    )
    try:
        connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        for key, value in headers:
            connection.putheader(key, value)
        connection.endheaders()
        response = connection.getresponse()
        raw = response.read()
        status = response.status
    finally:
        connection.close()
    completed = now()

    return {
        "started_at_utc": started,
        "completed_at_utc": completed,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(raw),
        "http_status": status,
        "raw_response": raw,
    }


def raydium_quote(units: int):
    amount = units * 1_000_000
    query = urlencode(
        [
            ("inputMint", SOL_USDC),
            ("outputMint", SOL_USDT),
            ("amount", str(amount)),
            ("slippageBps", str(SLIPPAGE_BPS)),
            ("txVersion", "V0"),
        ]
    )
    target = f"{RAY_PATH}?{query}"
    transport = https_get(RAY_HOST, target, "Scout-Tight-Paired-Ray/1.0.0")
    obj = json.loads(transport["raw_response"].decode())
    data = obj.get("data") if isinstance(obj, dict) else None

    accepted = (
        transport["http_status"] == 200
        and obj.get("success") is True
        and isinstance(data, dict)
        and data.get("inputMint") == SOL_USDC
        and data.get("outputMint") == SOL_USDT
        and str(data.get("inputAmount")) == str(amount)
        and str(data.get("outputAmount", "")).isdigit()
        and int(data["outputAmount"]) > 0
        and isinstance(data.get("routePlan"), list)
        and len(data["routePlan"]) > 0
    )

    return {
        "accepted": accepted,
        "chain": "solana-mainnet",
        "provider": "raydium",
        "input_units_usdc": units,
        "input_amount_base_units": amount,
        "output_amount_base_units": int(data["outputAmount"]) if accepted else None,
        "output_units_usdt": int(data["outputAmount"]) / 1_000_000 if accepted else None,
        "started_at_utc": transport["started_at_utc"],
        "completed_at_utc": transport["completed_at_utc"],
        "request_url": f"https://{RAY_HOST}{target}",
        "request_sha256": transport["request_sha256"],
        "response_sha256": transport["response_sha256"],
        "http_status": transport["http_status"],
        "route_plan": data.get("routePlan") if isinstance(data, dict) else None,
    }


def arbitrum_quote(units: int):
    amount = units * 1_000_000
    query = urlencode(
        [
            ("srcToken", ARB_USDC),
            ("destToken", ARB_USDT0),
            ("amount", str(amount)),
            ("srcDecimals", "6"),
            ("destDecimals", "6"),
            ("side", "SELL"),
            ("network", str(ARB_CHAIN_ID)),
            ("version", VELORA_VERSION),
        ]
    )
    target = f"{EVM_PATH}?{query}"
    transport = https_get(EVM_HOST, target, "Scout-Tight-Paired-Arb/1.0.0")
    obj = json.loads(transport["raw_response"].decode())
    route = obj.get("priceRoute") if isinstance(obj, dict) else None

    accepted = (
        transport["http_status"] == 200
        and isinstance(route, dict)
        and str(route.get("srcToken", "")).lower() == ARB_USDC.lower()
        and str(route.get("destToken", "")).lower() == ARB_USDT0.lower()
        and str(route.get("srcAmount")) == str(amount)
        and str(route.get("destAmount", "")).isdigit()
        and int(route["destAmount"]) > 0
        and route.get("side") == "SELL"
        and str(route.get("network")) == str(ARB_CHAIN_ID)
        and isinstance(route.get("bestRoute"), list)
        and len(route["bestRoute"]) > 0
    )

    return {
        "accepted": accepted,
        "chain": "arbitrum-one",
        "provider": "velora-paraswap",
        "input_units_usdc": units,
        "input_amount_base_units": amount,
        "gross_output_amount_base_units": int(route["destAmount"]) if accepted else None,
        "gross_output_units_usdt": int(route["destAmount"]) / 1_000_000 if accepted else None,
        "gas_cost": route.get("gasCost") if isinstance(route, dict) else None,
        "gas_cost_usd": route.get("gasCostUSD") if isinstance(route, dict) else None,
        "src_usd": route.get("srcUSD") if isinstance(route, dict) else None,
        "dest_usd": route.get("destUSD") if isinstance(route, dict) else None,
        "started_at_utc": transport["started_at_utc"],
        "completed_at_utc": transport["completed_at_utc"],
        "request_url": f"https://{EVM_HOST}{target}",
        "request_sha256": transport["request_sha256"],
        "response_sha256": transport["response_sha256"],
        "http_status": transport["http_status"],
        "best_route": route.get("bestRoute") if isinstance(route, dict) else None,
    }


def main():
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)

    started = now()
    directory = root / (
        "tight-paired-extended-curve-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    directory.mkdir()

    ray_dns = sorted(
        {x[4][0] for x in socket.getaddrinfo(RAY_HOST, PORT, type=socket.SOCK_STREAM)}
    )
    arb_dns = sorted(
        {x[4][0] for x in socket.getaddrinfo(EVM_HOST, PORT, type=socket.SOCK_STREAM)}
    )

    pairs = []
    for units in SIZES_USDC:
        sol = raydium_quote(units)
        arb = arbitrum_quote(units)
        pairs.append(
            {
                "size_usdc": units,
                "solana": sol,
                "arbitrum": arb,
                "pair_accepted": sol["accepted"] and arb["accepted"],
            }
        )

    accepted = all(pair["pair_accepted"] for pair in pairs)

    evidence = {
        "schema": "scout.tight_paired_extended_size_curve.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": False,
        "pair": "USDC/USDT",
        "arbitrum_output_representation": "USD₮0",
        "sizes_usdc": list(SIZES_USDC),
        "capture_order_per_size": "solana_then_arbitrum",
        "dns": {
            "raydium": {"hostname": RAY_HOST, "addresses": ray_dns},
            "velora": {"hostname": EVM_HOST, "addresses": arb_dns},
        },
        "pairs": pairs,
        "executor": {
            "kind": "github_actions" if os.getenv("GITHUB_RUN_ID") else "local",
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "commit_sha": os.getenv("GITHUB_SHA"),
        },
        "safety": {
            "wallet": False,
            "signer": False,
            "approval": False,
            "transaction_builder": False,
            "transaction_submission": False,
            "bridge_execution": False,
            "capital_movement": False,
        },
    }

    evidence_path = directory / "evidence.json"
    evidence_path.write_bytes(json_bytes(evidence))
    (directory / "manifest.sha256").write_text(
        f"{sha256(evidence_path.read_bytes())}  evidence.json\n"
    )

    summary = []
    for pair in pairs:
        summary.append(
            {
                "size_usdc": pair["size_usdc"],
                "solana_output": pair["solana"]["output_units_usdt"],
                "arbitrum_output": pair["arbitrum"]["gross_output_units_usdt"],
                "arbitrum_gas_usd": pair["arbitrum"]["gas_cost_usd"],
                "pair_accepted": pair["pair_accepted"],
            }
        )
    print(
        json.dumps(
            {
                "accepted": accepted,
                "pairs": summary,
                "execution_authority": False,
            },
            indent=2,
        )
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

