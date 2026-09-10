#!/usr/bin/env python3
"""Scout repeated tightly paired 1500 USDC -> USDT observation witness.

Purpose:
- test whether the previously observed ~11.58 bps 1500-USDC cross-domain edge repeats
- capture multiple tightly paired Solana then Arbitrum observations
- remain strictly read-only

No wallet, signer, approvals, transaction construction, submission, bridge execution,
or capital movement.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

REPETITIONS = 8
INPUT_USDC = 1500
AMOUNT = INPUT_USDC * 1_000_000
INTER_PAIR_SLEEP_SECONDS = 0.35

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
    c = http.client.HTTPSConnection(
        host, PORT, timeout=20, context=ssl.create_default_context()
    )
    try:
        c.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        for k, v in headers:
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        raw = r.read()
        status = r.status
    finally:
        c.close()
    completed = now()

    return {
        "started_at_utc": started,
        "completed_at_utc": completed,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(raw),
        "http_status": status,
        "raw": raw,
    }


def raydium_quote():
    q = urlencode(
        [
            ("inputMint", SOL_USDC),
            ("outputMint", SOL_USDT),
            ("amount", str(AMOUNT)),
            ("slippageBps", str(SLIPPAGE_BPS)),
            ("txVersion", "V0"),
        ]
    )
    target = f"{RAY_PATH}?{q}"
    t = https_get(RAY_HOST, target, "Scout-Repeat1500-Ray/1.0.0")
    obj = json.loads(t["raw"].decode())
    d = obj.get("data") if isinstance(obj, dict) else None
    accepted = (
        t["http_status"] == 200
        and obj.get("success") is True
        and isinstance(d, dict)
        and d.get("inputMint") == SOL_USDC
        and d.get("outputMint") == SOL_USDT
        and str(d.get("inputAmount")) == str(AMOUNT)
        and str(d.get("outputAmount", "")).isdigit()
        and int(d["outputAmount"]) > 0
        and isinstance(d.get("routePlan"), list)
        and len(d["routePlan"]) > 0
    )
    return {
        "accepted": accepted,
        "output_units_usdt": int(d["outputAmount"]) / 1_000_000 if accepted else None,
        "started_at_utc": t["started_at_utc"],
        "completed_at_utc": t["completed_at_utc"],
        "request_sha256": t["request_sha256"],
        "response_sha256": t["response_sha256"],
        "http_status": t["http_status"],
        "route_plan": d.get("routePlan") if isinstance(d, dict) else None,
    }


def arbitrum_quote():
    q = urlencode(
        [
            ("srcToken", ARB_USDC),
            ("destToken", ARB_USDT0),
            ("amount", str(AMOUNT)),
            ("srcDecimals", "6"),
            ("destDecimals", "6"),
            ("side", "SELL"),
            ("network", str(ARB_CHAIN_ID)),
            ("version", VELORA_VERSION),
        ]
    )
    target = f"{EVM_PATH}?{q}"
    t = https_get(EVM_HOST, target, "Scout-Repeat1500-Arb/1.0.0")
    obj = json.loads(t["raw"].decode())
    r = obj.get("priceRoute") if isinstance(obj, dict) else None
    accepted = (
        t["http_status"] == 200
        and isinstance(r, dict)
        and str(r.get("srcToken", "")).lower() == ARB_USDC.lower()
        and str(r.get("destToken", "")).lower() == ARB_USDT0.lower()
        and str(r.get("srcAmount")) == str(AMOUNT)
        and str(r.get("destAmount", "")).isdigit()
        and int(r["destAmount"]) > 0
        and r.get("side") == "SELL"
        and str(r.get("network")) == str(ARB_CHAIN_ID)
        and isinstance(r.get("bestRoute"), list)
        and len(r["bestRoute"]) > 0
    )
    return {
        "accepted": accepted,
        "gross_output_units_usdt": int(r["destAmount"]) / 1_000_000 if accepted else None,
        "gas_cost_usd": r.get("gasCostUSD") if isinstance(r, dict) else None,
        "started_at_utc": t["started_at_utc"],
        "completed_at_utc": t["completed_at_utc"],
        "request_sha256": t["request_sha256"],
        "response_sha256": t["response_sha256"],
        "http_status": t["http_status"],
        "best_route": r.get("bestRoute") if isinstance(r, dict) else None,
    }


def main():
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)
    started = now()
    d = root / (
        "repeat-1500-pair-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    d.mkdir()

    ray_dns = sorted(
        {x[4][0] for x in socket.getaddrinfo(RAY_HOST, PORT, type=socket.SOCK_STREAM)}
    )
    arb_dns = sorted(
        {x[4][0] for x in socket.getaddrinfo(EVM_HOST, PORT, type=socket.SOCK_STREAM)}
    )

    observations = []
    for i in range(1, REPETITIONS + 1):
        sol = raydium_quote()
        arb = arbitrum_quote()

        if sol["accepted"] and arb["accepted"]:
            gross_diff = arb["gross_output_units_usdt"] - sol["output_units_usdt"]
            gross_bps = gross_diff / INPUT_USDC * 10_000
            gas_usd = None
            try:
                gas_usd = float(arb["gas_cost_usd"]) if arb["gas_cost_usd"] is not None else None
            except Exception:
                gas_usd = None
            gas_aware_diff = gross_diff - gas_usd if gas_usd is not None else None
            gas_aware_bps = (
                gas_aware_diff / INPUT_USDC * 10_000
                if gas_aware_diff is not None
                else None
            )
        else:
            gross_diff = None
            gross_bps = None
            gas_aware_diff = None
            gas_aware_bps = None

        observations.append(
            {
                "repetition": i,
                "input_usdc": INPUT_USDC,
                "solana": sol,
                "arbitrum": arb,
                "pair_accepted": sol["accepted"] and arb["accepted"],
                "gross_difference_usdt": gross_diff,
                "gross_difference_bps": gross_bps,
                "gas_aware_difference_usd_approx": gas_aware_diff,
                "gas_aware_bps_approx": gas_aware_bps,
            }
        )

        if i != REPETITIONS:
            time.sleep(INTER_PAIR_SLEEP_SECONDS)

    accepted = all(x["pair_accepted"] for x in observations)

    evidence = {
        "schema": "scout.repeat_1500_pair.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": False,
        "pair": "USDC/USDT",
        "input_usdc": INPUT_USDC,
        "repetitions": REPETITIONS,
        "capture_order": "solana_then_arbitrum_per_repetition",
        "inter_pair_sleep_seconds": INTER_PAIR_SLEEP_SECONDS,
        "dns": {
            "raydium": {"hostname": RAY_HOST, "addresses": ray_dns},
            "velora": {"hostname": EVM_HOST, "addresses": arb_dns},
        },
        "observations": observations,
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

    p = d / "evidence.json"
    p.write_bytes(json_bytes(evidence))
    (d / "manifest.sha256").write_text(
        f"{sha256(p.read_bytes())}  evidence.json\n"
    )

    print(
        json.dumps(
            {
                "accepted": accepted,
                "repetitions": [
                    {
                        "n": x["repetition"],
                        "solana_output": x["solana"]["output_units_usdt"],
                        "arbitrum_output": x["arbitrum"]["gross_output_units_usdt"],
                        "gross_bps": x["gross_difference_bps"],
                        "gas_aware_bps_approx": x["gas_aware_bps_approx"],
                    }
                    for x in observations
                ],
                "execution_authority": False,
            },
            indent=2,
        )
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

