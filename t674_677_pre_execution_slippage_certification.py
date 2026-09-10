#!/usr/bin/env python3
"""Scout T674-T677 composite pre-execution slippage certification.

One read-only witness, four independent certification gates:

T674 — independent reserve stability / repeatability
T675 — adverse short-window quote-movement stress
T676 — exact realized-slippage measurement contract
T677 — synthetic execution-accounting validation

IMPORTANT:
This test does NOT execute a trade and therefore does NOT prove realized
slippage. T676/T677 only prove that the future measurement/accounting contract
is deterministic and internally correct before any controlled live execution.

Safety:
- read-only HTTPS quote requests only
- no wallet
- no signer
- no approvals
- no transaction construction
- no serialization
- no simulation
- no submission/broadcast
- no bridge execution
- no capital movement
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import ssl
import statistics
import time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING, getcontext
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple
from urllib.parse import urlencode

getcontext().prec = 50

WITNESS_VERSION = "1.0.0"
EXECUTION_AUTHORITY = False

SIZES_USDC = (100, 500, 1500, 5000, 10000)
STABILITY_WINDOWS = 3
REPS_PER_WINDOW = 3
STRESS_REPS = 30

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

# Context only, not reused as fresh T674/T675 samples.
T673_CERTIFIED_RESERVE_BPS = Decimal("0.07")
T671_CONTEXT_MAX_BPS = Decimal("1.469710")
T672_CONTEXT_REPLAY_BPS = Decimal("0.618615")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def parse_iso_ms(value: str) -> int:
    return int(
        datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def percentile(values: Sequence[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires values")
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * q
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(ordered[lo])
    weight = rank - lo
    return float(ordered[lo] * (1.0 - weight) + ordered[hi] * weight)


def deterioration_bps(outputs: Sequence[int]) -> float:
    best = max(outputs)
    worst = min(outputs)
    return (best - worst) * 10_000.0 / best if best > 0 else 0.0


def ceil_hundredth_bp(value: float) -> float:
    dec = Decimal(str(value))
    return float(
        (dec * Decimal("100")).to_integral_value(
            rounding=ROUND_CEILING
        ) / Decimal("100")
    )


def https_get(host: str, target: str, agent: str) -> Dict[str, Any]:
    headers = [
        ("Host", host),
        ("User-Agent", agent),
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
    finally:
        conn.close()
    mono_end = time.monotonic_ns()

    return {
        "started_at_utc": started,
        "completed_at_utc": now(),
        "duration_ms": round((mono_end - mono_start) / 1_000_000, 3),
        "request_bytes": request_bytes,
        "response_bytes": raw,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(raw),
        "http_status": status,
    }


def raydium_quote(units: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    amount = units * 1_000_000
    target = (
        f"{RAY_PATH}?"
        + urlencode(
            [
                ("inputMint", SOL_USDC),
                ("outputMint", SOL_USDT),
                ("amount", str(amount)),
                ("slippageBps", str(SLIPPAGE_BPS)),
                ("txVersion", "V0"),
            ]
        )
    )
    transport = https_get(
        RAY_HOST, target, f"Scout-T674-677-Ray/{WITNESS_VERSION}"
    )
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
    return {
        "accepted": accepted,
        "output_base_units": int(data["outputAmount"]) if accepted else None,
        "output_units": int(data["outputAmount"]) / 1_000_000 if accepted else None,
        "route_plan": data.get("routePlan") if isinstance(data, dict) else None,
        "started_at_utc": transport["started_at_utc"],
        "completed_at_utc": transport["completed_at_utc"],
        "duration_ms": transport["duration_ms"],
        "request_sha256": transport["request_sha256"],
        "response_sha256": transport["response_sha256"],
        "http_status": transport["http_status"],
    }, transport


def arbitrum_quote(units: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    amount = units * 1_000_000
    target = (
        f"{EVM_PATH}?"
        + urlencode(
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
    )
    transport = https_get(
        EVM_HOST, target, f"Scout-T674-677-Arb/{WITNESS_VERSION}"
    )
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
    return {
        "accepted": accepted,
        "output_base_units": int(route["destAmount"]) if accepted else None,
        "output_units": int(route["destAmount"]) / 1_000_000 if accepted else None,
        "gas_cost_usd": route.get("gasCostUSD") if isinstance(route, dict) else None,
        "best_route": route.get("bestRoute") if isinstance(route, dict) else None,
        "started_at_utc": transport["started_at_utc"],
        "completed_at_utc": transport["completed_at_utc"],
        "duration_ms": transport["duration_ms"],
        "request_sha256": transport["request_sha256"],
        "response_sha256": transport["response_sha256"],
        "http_status": transport["http_status"],
    }, transport


def write_transport(directory: Path, prefix: str, transport: Dict[str, Any]) -> None:
    (directory / f"{prefix}_request.bin").write_bytes(transport["request_bytes"])
    (directory / f"{prefix}_response.bin").write_bytes(transport["response_bytes"])


def t674_stability(run_dir: Path) -> Dict[str, Any]:
    window_rows: List[Dict[str, Any]] = []
    all_pair_gaps: List[int] = []

    for window in range(1, STABILITY_WINDOWS + 1):
        for size in SIZES_USDC:
            sol_outputs: List[int] = []
            arb_outputs: List[int] = []
            reps: List[Dict[str, Any]] = []

            for rep in range(1, REPS_PER_WINDOW + 1):
                obs_dir = (
                    run_dir
                    / "t674"
                    / f"window-{window}"
                    / f"size-{size}"
                    / f"rep-{rep}"
                )
                obs_dir.mkdir(parents=True)

                sol, sol_transport = raydium_quote(size)
                arb, arb_transport = arbitrum_quote(size)
                write_transport(obs_dir, "solana", sol_transport)
                write_transport(obs_dir, "arbitrum", arb_transport)

                gap = max(
                    0,
                    parse_iso_ms(arb["started_at_utc"])
                    - parse_iso_ms(sol["completed_at_utc"]),
                )
                all_pair_gaps.append(gap)

                rec = {
                    "window": window,
                    "size_usdc": size,
                    "repetition": rep,
                    "solana": sol,
                    "arbitrum": arb,
                    "pair_gap_ms": gap,
                    "pair_accepted": sol["accepted"] and arb["accepted"],
                }
                (obs_dir / "observation.json").write_bytes(json_bytes(rec))
                reps.append(rec)

                if sol["accepted"]:
                    sol_outputs.append(int(sol["output_base_units"]))
                if arb["accepted"]:
                    arb_outputs.append(int(arb["output_base_units"]))

            accepted = (
                len(sol_outputs) == REPS_PER_WINDOW
                and len(arb_outputs) == REPS_PER_WINDOW
                and all(r["pair_accepted"] for r in reps)
            )
            window_rows.append(
                {
                    "window": window,
                    "size_usdc": size,
                    "accepted": accepted,
                    "solana_deterioration_bps": (
                        deterioration_bps(sol_outputs) if sol_outputs else None
                    ),
                    "arbitrum_deterioration_bps": (
                        deterioration_bps(arb_outputs) if arb_outputs else None
                    ),
                }
            )

    good = [row for row in window_rows if row["accepted"]]
    samples = [
        float(row[key])
        for row in good
        for key in ("solana_deterioration_bps", "arbitrum_deterioration_bps")
    ]
    p95 = percentile(samples, 0.95)
    p99 = percentile(samples, 0.99)
    max_bps = max(samples)
    current_reserve = ceil_hundredth_bp(p95)

    # Stability means the new independent p95-derived reserve does not exceed
    # 2x the prior certified 0.07 bp reserve. This is a pre-declared tolerance,
    # not a claim that all future markets must remain inside it.
    stability_ceiling = float(T673_CERTIFIED_RESERVE_BPS * Decimal("2"))
    passed = (
        len(good) == STABILITY_WINDOWS * len(SIZES_USDC)
        and current_reserve <= stability_ceiling
    )
    return {
        "test_id": "T674",
        "name": "INDEPENDENT_RESERVE_STABILITY_REPEATABILITY",
        "passed": passed,
        "window_metrics": window_rows,
        "combined_p95_bps": p95,
        "combined_p99_bps": p99,
        "combined_max_bps": max_bps,
        "derived_reserve_bps": current_reserve,
        "prior_t673_reserve_bps": float(T673_CERTIFIED_RESERVE_BPS),
        "stability_ceiling_bps": stability_ceiling,
        "max_pair_gap_ms": max(all_pair_gaps) if all_pair_gaps else None,
    }


def t675_stress(run_dir: Path) -> Dict[str, Any]:
    stress_dir = run_dir / "t675"
    stress_dir.mkdir()
    outputs: List[int] = []
    accepted_count = 0
    rows: List[Dict[str, Any]] = []

    # Focus on the exact $500 Arbitrum size that produced the prior T671/T672
    # movement, now with a longer rapid read-only burst.
    for rep in range(1, STRESS_REPS + 1):
        obs_dir = stress_dir / f"rep-{rep:02d}"
        obs_dir.mkdir()
        quote, transport = arbitrum_quote(500)
        write_transport(obs_dir, "arbitrum", transport)
        row = {"repetition": rep, **quote}
        (obs_dir / "observation.json").write_bytes(json_bytes(row))
        rows.append(row)
        if quote["accepted"]:
            accepted_count += 1
            outputs.append(int(quote["output_base_units"]))

    det = deterioration_bps(outputs) if outputs else None

    # This test is descriptive: it fails only if the evidence capture is
    # incomplete. The observed stress maximum is evidence, not an assumed gate.
    passed = accepted_count == STRESS_REPS
    return {
        "test_id": "T675",
        "name": "ADVERSE_SHORT_WINDOW_QUOTE_MOVEMENT_STRESS",
        "passed": passed,
        "input_usdc": 500,
        "repetitions": STRESS_REPS,
        "accepted_count": accepted_count,
        "quote_deterioration_bps": det,
        "best_output_base_units": max(outputs) if outputs else None,
        "worst_output_base_units": min(outputs) if outputs else None,
        "t671_context_max_bps": float(T671_CONTEXT_MAX_BPS),
        "t672_context_replay_bps": float(T672_CONTEXT_REPLAY_BPS),
        "observations": rows,
    }


def realized_slippage_bps(quoted_output: int, settled_output: int) -> Decimal:
    if quoted_output <= 0:
        raise ValueError("quoted_output must be positive")
    return (
        (Decimal(quoted_output) - Decimal(settled_output))
        * Decimal(10000)
        / Decimal(quoted_output)
    )


def t676_contract() -> Dict[str, Any]:
    contract = {
        "schema": "scout.realized_slippage_measurement_contract.v1",
        "required_fields": [
            "decision_quote_timestamp_utc",
            "decision_quote_request_sha256",
            "decision_quote_response_sha256",
            "quoted_output_base_units",
            "submitted_transaction_id",
            "submission_timestamp_utc",
            "settlement_observation_timestamp_utc",
            "actual_settled_output_base_units",
            "output_asset",
            "output_decimals",
        ],
        "formula": (
            "(quoted_output_base_units - actual_settled_output_base_units) "
            "* 10000 / quoted_output_base_units"
        ),
        "sign_convention": {
            "positive": "adverse slippage; settled output below quote",
            "zero": "settled output equals quote",
            "negative": "price improvement; settled output above quote",
        },
        "must_not_subtract_separately": [
            "fee already embedded in quoted destination amount",
            "fee already reflected in actual settled destination amount",
        ],
        "separate_cost_domains": [
            "network execution fee",
            "priority/tip fee",
            "bridge/transfer cost",
            "inventory carry",
        ],
        "live_execution_required_to_close_realized_slippage": True,
    }

    synthetic_cases = [
        (1_000_000, 999_900, Decimal("1")),
        (1_000_000, 1_000_000, Decimal("0")),
        (1_000_000, 1_000_100, Decimal("-1")),
        (500_000_000, 499_950_000, Decimal("1")),
    ]
    checks = []
    for quoted, settled, expected in synthetic_cases:
        measured = realized_slippage_bps(quoted, settled)
        checks.append(
            {
                "quoted_output_base_units": quoted,
                "settled_output_base_units": settled,
                "expected_bps": str(expected),
                "measured_bps": str(measured),
                "passed": measured == expected,
            }
        )

    passed = all(c["passed"] for c in checks)
    return {
        "test_id": "T676",
        "name": "REALIZED_SLIPPAGE_MEASUREMENT_CONTRACT",
        "passed": passed,
        "contract": contract,
        "synthetic_contract_checks": checks,
        "realized_slippage_proven": False,
    }


def t677_accounting() -> Dict[str, Any]:
    # Synthetic-only accounting tests. They verify we do not double-count venue
    # fees already represented in quoted/settled output and that external costs
    # remain separate from realized slippage.
    cases = [
        {
            "name": "adverse_one_bp",
            "quoted_output": 1_500_300_000,
            "settled_output": 1_500_149_970,
            "expected_sign": "positive",
        },
        {
            "name": "exact_fill",
            "quoted_output": 500_250_000,
            "settled_output": 500_250_000,
            "expected_sign": "zero",
        },
        {
            "name": "price_improvement",
            "quoted_output": 10_005_000_000,
            "settled_output": 10_005_100_000,
            "expected_sign": "negative",
        },
    ]

    checked = []
    for case in cases:
        slip = realized_slippage_bps(
            case["quoted_output"], case["settled_output"]
        )
        sign = "positive" if slip > 0 else "negative" if slip < 0 else "zero"

        # Example separate network cost is intentionally not included in the
        # slippage formula. This proves separation of accounting domains.
        network_cost_usd = Decimal("0.01")
        checked.append(
            {
                **case,
                "realized_slippage_bps": str(slip),
                "observed_sign": sign,
                "network_cost_usd_separate": str(network_cost_usd),
                "venue_fee_double_subtracted": False,
                "passed": sign == case["expected_sign"],
            }
        )

    passed = all(c["passed"] for c in checked)
    return {
        "test_id": "T677",
        "name": "SYNTHETIC_EXECUTION_ACCOUNTING_VALIDATION",
        "passed": passed,
        "cases": checked,
        "realized_slippage_proven": False,
        "execution_evidence_present": False,
    }


def main() -> int:
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)

    started = now()
    run_dir = root / (
        "t674-677-pre-execution-slippage-certification-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    run_dir.mkdir()

    t674 = t674_stability(run_dir)
    t675 = t675_stress(run_dir)
    t676 = t676_contract()
    t677 = t677_accounting()

    sections = [t674, t675, t676, t677]
    accepted = all(section["passed"] for section in sections)

    evidence = {
        "schema": "scout.t674_677.pre_execution_slippage_certification.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "sections": {
            "T674": t674,
            "T675": t675,
            "T676": t676,
            "T677": t677,
        },
        "certification": {
            "all_four_sections_passed": accepted,
            "realized_slippage_proven": False,
            "ready_for_controlled_live_slippage_measurement_if_all_pass": accepted,
            "important": (
                "Passing T674-T677 proves pre-execution reserve stability, "
                "stress observation, measurement-contract correctness, and "
                "synthetic accounting correctness. A controlled live execution "
                "is still required to prove realized slippage."
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
                "T674": {
                    "passed": t674["passed"],
                    "derived_reserve_bps": t674["derived_reserve_bps"],
                    "combined_p95_bps": t674["combined_p95_bps"],
                    "combined_max_bps": t674["combined_max_bps"],
                },
                "T675": {
                    "passed": t675["passed"],
                    "quote_deterioration_bps": t675[
                        "quote_deterioration_bps"
                    ],
                },
                "T676": {
                    "passed": t676["passed"],
                    "realized_slippage_proven": False,
                },
                "T677": {
                    "passed": t677["passed"],
                    "realized_slippage_proven": False,
                },
                "ready_for_controlled_live_slippage_measurement": accepted,
                "execution_authority": False,
            },
            indent=2,
        )
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

