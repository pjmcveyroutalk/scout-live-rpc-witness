#!/usr/bin/env python3
"""Scout T671 cross-domain quote-volatility reserve witness.

Read-only calibration only.

For each fixed USDC notional (100, 500, 1500, 5000, 10000), collect five
tightly paired Raydium then Velora quotes. Preserve exact request and response
bytes for every observation and calculate within-venue quote deterioration.

This does NOT claim realized slippage. It measures short-window quote movement
that may be used later as a conservative pre-execution reserve input.

No wallet, signer, approvals, transaction construction, serialization,
simulation, submission, bridge execution, or capital movement.
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
from typing import Any, Dict, List, Tuple
from urllib.parse import urlencode

WITNESS_VERSION = "1.0.0"
EXECUTION_AUTHORITY = False

SIZES_USDC = (100, 500, 1500, 5000, 10000)
REPETITIONS = 5

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
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def parse_iso_ms(value: str) -> int:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def https_get(host: str, target: str, user_agent: str) -> Dict[str, Any]:
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
    ).encode("utf-8")

    started = now()
    mono_start = time.monotonic_ns()
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
        response_headers = {k: v for k, v in response.getheaders()}
    finally:
        connection.close()
    mono_end = time.monotonic_ns()
    completed = now()

    return {
        "started_at_utc": started,
        "completed_at_utc": completed,
        "duration_ms": round((mono_end - mono_start) / 1_000_000, 3),
        "request_bytes": request_bytes,
        "response_bytes": raw,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(raw),
        "http_status": status,
        "response_headers": response_headers,
    }


def raydium_quote(units: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
    transport = https_get(RAY_HOST, target, f"Scout-T671-Ray/{WITNESS_VERSION}")
    obj = json.loads(transport["response_bytes"].decode("utf-8"))
    data = obj.get("data") if isinstance(obj, dict) else None

    accepted = (
        transport["http_status"] == 200
        and isinstance(obj, dict)
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

    record = {
        "accepted": accepted,
        "chain": "solana-mainnet",
        "provider": "raydium",
        "input_units_usdc": units,
        "input_amount_base_units": amount,
        "output_amount_base_units": int(data["outputAmount"]) if accepted else None,
        "output_units_usdt": int(data["outputAmount"]) / 1_000_000 if accepted else None,
        "started_at_utc": transport["started_at_utc"],
        "completed_at_utc": transport["completed_at_utc"],
        "duration_ms": transport["duration_ms"],
        "request_url": f"https://{RAY_HOST}{target}",
        "request_sha256": transport["request_sha256"],
        "response_sha256": transport["response_sha256"],
        "http_status": transport["http_status"],
        "route_plan": data.get("routePlan") if isinstance(data, dict) else None,
    }
    return record, transport


def arbitrum_quote(units: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
    transport = https_get(EVM_HOST, target, f"Scout-T671-Arb/{WITNESS_VERSION}")
    obj = json.loads(transport["response_bytes"].decode("utf-8"))
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

    record = {
        "accepted": accepted,
        "chain": "arbitrum-one",
        "provider": "velora-paraswap",
        "input_units_usdc": units,
        "input_amount_base_units": amount,
        "output_amount_base_units": int(route["destAmount"]) if accepted else None,
        "output_units_usdt": int(route["destAmount"]) / 1_000_000 if accepted else None,
        "gas_cost": route.get("gasCost") if isinstance(route, dict) else None,
        "gas_cost_usd": route.get("gasCostUSD") if isinstance(route, dict) else None,
        "started_at_utc": transport["started_at_utc"],
        "completed_at_utc": transport["completed_at_utc"],
        "duration_ms": transport["duration_ms"],
        "request_url": f"https://{EVM_HOST}{target}",
        "request_sha256": transport["request_sha256"],
        "response_sha256": transport["response_sha256"],
        "http_status": transport["http_status"],
        "best_route": route.get("bestRoute") if isinstance(route, dict) else None,
    }
    return record, transport


def deterioration_bps(outputs: List[int]) -> float:
    best = max(outputs)
    worst = min(outputs)
    if best <= 0:
        return 0.0
    return (best - worst) * 10_000.0 / best


def main() -> int:
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)

    started = now()
    run_dir = root / (
        "t671-quote-volatility-reserve-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    run_dir.mkdir()

    ray_dns = sorted(
        {x[4][0] for x in socket.getaddrinfo(RAY_HOST, PORT, type=socket.SOCK_STREAM)}
    )
    arb_dns = sorted(
        {x[4][0] for x in socket.getaddrinfo(EVM_HOST, PORT, type=socket.SOCK_STREAM)}
    )

    size_groups = []
    all_pair_skews_ms: List[int] = []

    for units in SIZES_USDC:
        observations = []
        for rep in range(1, REPETITIONS + 1):
            obs_dir = run_dir / f"size-{units}-rep-{rep}"
            obs_dir.mkdir()

            sol, sol_transport = raydium_quote(units)
            arb, arb_transport = arbitrum_quote(units)

            (obs_dir / "solana_request.bin").write_bytes(sol_transport["request_bytes"])
            (obs_dir / "solana_response.bin").write_bytes(sol_transport["response_bytes"])
            (obs_dir / "arbitrum_request.bin").write_bytes(arb_transport["request_bytes"])
            (obs_dir / "arbitrum_response.bin").write_bytes(arb_transport["response_bytes"])
            (obs_dir / "solana_headers.json").write_bytes(
                json_bytes(sol_transport["response_headers"])
            )
            (obs_dir / "arbitrum_headers.json").write_bytes(
                json_bytes(arb_transport["response_headers"])
            )

            pair_skew_ms = max(
                0,
                parse_iso_ms(arb["started_at_utc"])
                - parse_iso_ms(sol["completed_at_utc"]),
            )
            pair_span_ms = max(
                0,
                parse_iso_ms(arb["completed_at_utc"])
                - parse_iso_ms(sol["started_at_utc"]),
            )
            all_pair_skews_ms.append(pair_skew_ms)

            observation = {
                "repetition": rep,
                "solana": sol,
                "arbitrum": arb,
                "pair_gap_ms": pair_skew_ms,
                "pair_span_ms": pair_span_ms,
                "pair_accepted": sol["accepted"] and arb["accepted"],
            }
            (obs_dir / "observation.json").write_bytes(json_bytes(observation))

            manifest = []
            for path in sorted(obs_dir.iterdir()):
                if path.is_file() and path.name != "manifest.sha256":
                    manifest.append(f"{sha256(path.read_bytes())}  {path.name}")
            (obs_dir / "manifest.sha256").write_text(
                "\n".join(manifest) + "\n", encoding="utf-8"
            )
            observations.append(observation)

        sol_outputs = [
            int(o["solana"]["output_amount_base_units"])
            for o in observations
            if o["solana"]["accepted"]
        ]
        arb_outputs = [
            int(o["arbitrum"]["output_amount_base_units"])
            for o in observations
            if o["arbitrum"]["accepted"]
        ]

        group_accepted = (
            len(sol_outputs) == REPETITIONS
            and len(arb_outputs) == REPETITIONS
            and all(o["pair_accepted"] for o in observations)
        )

        size_groups.append(
            {
                "size_usdc": units,
                "accepted": group_accepted,
                "observations": observations,
                "solana": {
                    "best_output_base_units": max(sol_outputs) if sol_outputs else None,
                    "worst_output_base_units": min(sol_outputs) if sol_outputs else None,
                    "quote_deterioration_bps": (
                        deterioration_bps(sol_outputs) if sol_outputs else None
                    ),
                },
                "arbitrum": {
                    "best_output_base_units": max(arb_outputs) if arb_outputs else None,
                    "worst_output_base_units": min(arb_outputs) if arb_outputs else None,
                    "quote_deterioration_bps": (
                        deterioration_bps(arb_outputs) if arb_outputs else None
                    ),
                },
            }
        )

    accepted = all(group["accepted"] for group in size_groups)
    worst_sol_bps = max(
        group["solana"]["quote_deterioration_bps"] for group in size_groups
    )
    worst_arb_bps = max(
        group["arbitrum"]["quote_deterioration_bps"] for group in size_groups
    )
    conservative_observed_reserve_bps = max(worst_sol_bps, worst_arb_bps)

    evidence = {
        "schema": "scout.t671.quote_volatility_reserve.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "claim_boundary": {
            "realized_slippage_proven": False,
            "quote_volatility_observed": True,
            "reserve_is_pre_execution_observation_only": True,
        },
        "pair": "USDC/USDT",
        "arbitrum_output_representation": "USD₮0",
        "sizes_usdc": list(SIZES_USDC),
        "repetitions_per_size": REPETITIONS,
        "capture_order_per_repetition": "solana_then_arbitrum",
        "dns": {
            "raydium": {"hostname": RAY_HOST, "addresses": ray_dns},
            "velora": {"hostname": EVM_HOST, "addresses": arb_dns},
        },
        "size_groups": size_groups,
        "calibration": {
            "metric": "within_venue_best_to_worst_quote_deterioration",
            "worst_solana_quote_deterioration_bps": worst_sol_bps,
            "worst_arbitrum_quote_deterioration_bps": worst_arb_bps,
            "conservative_observed_reserve_bps": conservative_observed_reserve_bps,
            "max_pair_gap_ms": max(all_pair_skews_ms) if all_pair_skews_ms else None,
            "important": (
                "Observed quote-volatility reserve only; not realized slippage "
                "and not execution-cost certification."
            ),
        },
        "executor": {
            "kind": "github_actions" if os.getenv("GITHUB_RUN_ID") else "local",
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "commit_sha": os.getenv("GITHUB_SHA"),
            "workflow": os.getenv("GITHUB_WORKFLOW"),
        },
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

    evidence_path = run_dir / "evidence.json"
    evidence_path.write_bytes(json_bytes(evidence))

    top_manifest = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.sha256":
            rel = path.relative_to(run_dir)
            top_manifest.append(f"{sha256(path.read_bytes())}  {rel}")
    (run_dir / "manifest.sha256").write_text(
        "\n".join(top_manifest) + "\n", encoding="utf-8"
    )

    print(
        json.dumps(
            {
                "accepted": accepted,
                "sizes_usdc": list(SIZES_USDC),
                "repetitions_per_size": REPETITIONS,
                "worst_solana_quote_deterioration_bps": worst_sol_bps,
                "worst_arbitrum_quote_deterioration_bps": worst_arb_bps,
                "conservative_observed_reserve_bps": conservative_observed_reserve_bps,
                "realized_slippage_proven": False,
                "execution_authority": False,
            },
            indent=2,
        )
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

