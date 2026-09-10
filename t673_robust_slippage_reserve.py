#!/usr/bin/env python3
"""Scout T673 robust read-only quote-volatility reserve certification.

Purpose
-------
Collect repeated quote windows across fixed USDC notionals on Raydium (Solana)
and Velora/ParaSwap (Arbitrum) and derive a robust pre-execution quote-volatility
reserve from the observed distribution.

This is NOT realized slippage. It does not execute trades and does not prove
post-trade fills. It only measures short-window quote movement.

Safety
------
- read-only HTTPS quote requests only
- no wallet
- no signer
- no approvals
- no transaction construction/serialization/simulation/submission
- no broadcast
- no bridge execution
- no capital movement
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import socket
import ssl
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple
from urllib.parse import urlencode

WITNESS_VERSION = "1.0.0"
EXECUTION_AUTHORITY = False

SIZES_USDC = (100, 500, 1500, 5000, 10000)
WINDOWS = 4
REPETITIONS_PER_WINDOW = 5

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


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be between 0 and 1")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * q
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(ordered[lo])
    weight = rank - lo
    return float(ordered[lo] * (1.0 - weight) + ordered[hi] * weight)


def iqr_upper_fence(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("IQR requires values")
    q1 = percentile(values, 0.25)
    q3 = percentile(values, 0.75)
    return q3 + 1.5 * (q3 - q1)


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
    conn = http.client.HTTPSConnection(
        host, PORT, timeout=20, context=ssl.create_default_context()
    )
    try:
        conn.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        for key, value in headers:
            conn.putheader(key, value)
        conn.endheaders()
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        response_headers = {k: v for k, v in response.getheaders()}
    finally:
        conn.close()
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
    transport = https_get(RAY_HOST, target, f"Scout-T673-Ray/{WITNESS_VERSION}")
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
    )
    return (
        {
            "accepted": accepted,
            "provider": "raydium",
            "chain": "solana-mainnet",
            "input_usdc": units,
            "output_base_units": int(data["outputAmount"]) if accepted else None,
            "output_units": int(data["outputAmount"]) / 1_000_000 if accepted else None,
            "started_at_utc": transport["started_at_utc"],
            "completed_at_utc": transport["completed_at_utc"],
            "duration_ms": transport["duration_ms"],
            "http_status": transport["http_status"],
            "request_sha256": transport["request_sha256"],
            "response_sha256": transport["response_sha256"],
            "route_plan": data.get("routePlan") if isinstance(data, dict) else None,
        },
        transport,
    )


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
    transport = https_get(EVM_HOST, target, f"Scout-T673-Arb/{WITNESS_VERSION}")
    obj = json.loads(transport["response_bytes"].decode("utf-8"))
    route = obj.get("priceRoute") if isinstance(obj, dict) else None

    accepted = (
        transport["http_status"] == 200
        and isinstance(route, dict)
        and str(route.get("srcToken", "")).lower() == ARB_USDC
        and str(route.get("destToken", "")).lower() == ARB_USDT0
        and str(route.get("srcAmount")) == str(amount)
        and str(route.get("destAmount", "")).isdigit()
        and int(route["destAmount"]) > 0
        and route.get("side") == "SELL"
        and str(route.get("network")) == str(ARB_CHAIN_ID)
    )
    return (
        {
            "accepted": accepted,
            "provider": "velora-paraswap",
            "chain": "arbitrum-one",
            "input_usdc": units,
            "output_base_units": int(route["destAmount"]) if accepted else None,
            "output_units": int(route["destAmount"]) / 1_000_000 if accepted else None,
            "gas_cost": route.get("gasCost") if isinstance(route, dict) else None,
            "gas_cost_usd": route.get("gasCostUSD") if isinstance(route, dict) else None,
            "started_at_utc": transport["started_at_utc"],
            "completed_at_utc": transport["completed_at_utc"],
            "duration_ms": transport["duration_ms"],
            "http_status": transport["http_status"],
            "request_sha256": transport["request_sha256"],
            "response_sha256": transport["response_sha256"],
            "best_route": route.get("bestRoute") if isinstance(route, dict) else None,
        },
        transport,
    )


def deterioration_bps(outputs: Sequence[int]) -> float:
    best = max(outputs)
    worst = min(outputs)
    if best <= 0:
        return 0.0
    return (best - worst) * 10_000.0 / best


def robust_metrics(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        raise ValueError("no values")
    fence = iqr_upper_fence(values)
    non_outliers = [v for v in values if v <= fence]
    outliers = [v for v in values if v > fence]
    p95 = percentile(values, 0.95)
    p99 = percentile(values, 0.99)
    return {
        "count": len(values),
        "median_bps": statistics.median(values),
        "p95_bps": p95,
        "p99_bps": p99,
        "max_bps": max(values),
        "iqr_upper_fence_bps": fence,
        "outlier_count": len(outliers),
        "outliers_bps": outliers,
        "non_outlier_max_bps": max(non_outliers) if non_outliers else None,
    }


def main() -> int:
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)

    started = now()
    run_dir = root / (
        "t673-robust-slippage-reserve-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    run_dir.mkdir()

    observations: List[Dict[str, Any]] = []
    window_metrics: List[Dict[str, Any]] = []
    all_pair_gaps_ms: List[int] = []

    for window in range(1, WINDOWS + 1):
        for units in SIZES_USDC:
            sol_outputs: List[int] = []
            arb_outputs: List[int] = []
            reps: List[Dict[str, Any]] = []

            for rep in range(1, REPETITIONS_PER_WINDOW + 1):
                obs_dir = run_dir / f"window-{window}" / f"size-{units}" / f"rep-{rep}"
                obs_dir.mkdir(parents=True)

                sol, sol_transport = raydium_quote(units)
                arb, arb_transport = arbitrum_quote(units)

                (obs_dir / "solana_request.bin").write_bytes(sol_transport["request_bytes"])
                (obs_dir / "solana_response.bin").write_bytes(sol_transport["response_bytes"])
                (obs_dir / "arbitrum_request.bin").write_bytes(arb_transport["request_bytes"])
                (obs_dir / "arbitrum_response.bin").write_bytes(arb_transport["response_bytes"])

                pair_gap_ms = max(
                    0,
                    parse_iso_ms(arb["started_at_utc"])
                    - parse_iso_ms(sol["completed_at_utc"]),
                )
                pair_span_ms = max(
                    0,
                    parse_iso_ms(arb["completed_at_utc"])
                    - parse_iso_ms(sol["started_at_utc"]),
                )
                all_pair_gaps_ms.append(pair_gap_ms)

                record = {
                    "window": window,
                    "size_usdc": units,
                    "repetition": rep,
                    "solana": sol,
                    "arbitrum": arb,
                    "pair_gap_ms": pair_gap_ms,
                    "pair_span_ms": pair_span_ms,
                    "pair_accepted": sol["accepted"] and arb["accepted"],
                }
                (obs_dir / "observation.json").write_bytes(json_bytes(record))
                reps.append(record)
                observations.append(record)

                if sol["accepted"]:
                    sol_outputs.append(int(sol["output_base_units"]))
                if arb["accepted"]:
                    arb_outputs.append(int(arb["output_base_units"]))

            window_accepted = (
                len(sol_outputs) == REPETITIONS_PER_WINDOW
                and len(arb_outputs) == REPETITIONS_PER_WINDOW
                and all(rep["pair_accepted"] for rep in reps)
            )
            window_metrics.append(
                {
                    "window": window,
                    "size_usdc": units,
                    "accepted": window_accepted,
                    "solana_deterioration_bps": (
                        deterioration_bps(sol_outputs) if sol_outputs else None
                    ),
                    "arbitrum_deterioration_bps": (
                        deterioration_bps(arb_outputs) if arb_outputs else None
                    ),
                }
            )

    accepted_windows = [w for w in window_metrics if w["accepted"]]
    accepted = len(accepted_windows) == WINDOWS * len(SIZES_USDC)

    sol_samples = [
        float(w["solana_deterioration_bps"]) for w in accepted_windows
    ]
    arb_samples = [
        float(w["arbitrum_deterioration_bps"]) for w in accepted_windows
    ]
    combined_samples = sol_samples + arb_samples

    sol_stats = robust_metrics(sol_samples)
    arb_stats = robust_metrics(arb_samples)
    combined_stats = robust_metrics(combined_samples)

    # Conservative reserve policy:
    # use the greater of cross-venue p95 and the largest non-outlier sample.
    # Round upward to one hundredth of a basis point so the reserve never
    # understates the observed robust sample.
    raw_reserve = max(
        combined_stats["p95_bps"],
        combined_stats["non_outlier_max_bps"] or 0.0,
    )
    certified_reserve_bps = math.ceil(raw_reserve * 100.0) / 100.0

    evidence = {
        "schema": "scout.t673.robust_quote_volatility_reserve.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "claim_boundary": {
            "realized_slippage_proven": False,
            "quote_volatility_observed": True,
            "reserve_is_pre_execution_only": True,
            "execution_cost_certified": False,
        },
        "pair": "USDC/USDT",
        "arbitrum_output_representation": "USD₮0",
        "sizes_usdc": list(SIZES_USDC),
        "windows": WINDOWS,
        "repetitions_per_window": REPETITIONS_PER_WINDOW,
        "total_cross_domain_pairs": len(observations),
        "window_metrics": window_metrics,
        "statistics": {
            "solana": sol_stats,
            "arbitrum": arb_stats,
            "combined": combined_stats,
        },
        "reserve_policy": {
            "method": "max(combined_p95, combined_non_outlier_max), rounded_up_0.01bp",
            "raw_reserve_bps": raw_reserve,
            "certified_pre_execution_quote_volatility_reserve_bps": certified_reserve_bps,
            "t671_prior_single_window_max_bps": 1.469710,
            "t672_prior_focused_500_replay_bps": 0.618615,
            "prior_values_are_context_only_not_reused_as_current_samples": True,
        },
        "timing": {
            "max_pair_gap_ms": max(all_pair_gaps_ms) if all_pair_gaps_ms else None,
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

    manifest = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.sha256":
            manifest.append(
                f"{sha256(path.read_bytes())}  {path.relative_to(run_dir)}"
            )
    (run_dir / "manifest.sha256").write_text(
        "\n".join(manifest) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "accepted": accepted,
                "windows": WINDOWS,
                "sizes_usdc": list(SIZES_USDC),
                "samples_per_venue": len(sol_samples),
                "solana_p95_bps": sol_stats["p95_bps"],
                "arbitrum_p95_bps": arb_stats["p95_bps"],
                "combined_p95_bps": combined_stats["p95_bps"],
                "combined_max_bps": combined_stats["max_bps"],
                "combined_outlier_count": combined_stats["outlier_count"],
                "certified_pre_execution_quote_volatility_reserve_bps": certified_reserve_bps,
                "realized_slippage_proven": False,
                "execution_authority": False,
            },
            indent=2,
        )
    )

    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

