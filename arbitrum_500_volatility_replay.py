#!/usr/bin/env python3
"""Scout T672 focused $500 Arbitrum quote-volatility replay.

Read-only only.

Collect 20 consecutive Velora/ParaSwap USDC->USD₮0 SELL quotes at exactly
500 USDC on Arbitrum One. Preserve exact request/response bytes and route
fingerprints. Measure best-to-worst output deterioration and whether route
identity changes.

This does NOT prove realized slippage and does not authorize execution.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlencode

WITNESS_VERSION = "1.0.0"
EXECUTION_AUTHORITY = False

HOST = "api.paraswap.io"
PATH = "/prices"
PORT = 443
CHAIN_ID = 42161
VERSION = "6.2"
USDC = "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
USDT0 = "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"
INPUT_USDC = 500
INPUT_BASE_UNITS = INPUT_USDC * 1_000_000
REPETITIONS = 20


def now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def target_path() -> str:
    query = urlencode(
        [
            ("srcToken", USDC),
            ("destToken", USDT0),
            ("amount", str(INPUT_BASE_UNITS)),
            ("srcDecimals", "6"),
            ("destDecimals", "6"),
            ("side", "SELL"),
            ("network", str(CHAIN_ID)),
            ("version", VERSION),
        ]
    )
    return f"{PATH}?{query}"


def https_get(target: str) -> Dict[str, Any]:
    headers = [
        ("Host", HOST),
        ("User-Agent", f"Scout-T672-Arb500/{WITNESS_VERSION}"),
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
        HOST, PORT, timeout=20, context=ssl.create_default_context()
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

    return {
        "started_at_utc": started,
        "completed_at_utc": now(),
        "duration_ms": round((mono_end - mono_start) / 1_000_000, 3),
        "request_bytes": request_bytes,
        "response_bytes": raw,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(raw),
        "http_status": status,
        "response_headers": response_headers,
    }


def route_fingerprint(route: Dict[str, Any]) -> Dict[str, Any]:
    exchanges: List[str] = []
    pools: List[str] = []
    fallback_blocks: List[int] = []
    sources: List[str] = []

    for top in route.get("bestRoute", []) or []:
        for swap in top.get("swaps", []) or []:
            for exchange in swap.get("swapExchanges", []) or []:
                name = exchange.get("exchange")
                if isinstance(name, str):
                    exchanges.append(name)
                for pool in exchange.get("poolAddresses", []) or []:
                    if isinstance(pool, str):
                        pools.append(pool.lower())

                data = exchange.get("data")
                if isinstance(data, dict):
                    block = data.get("blockNumber")
                    if isinstance(block, int):
                        fallback_blocks.append(block)
                    source = data.get("source")
                    if isinstance(source, str):
                        sources.append(source)

                fallback = exchange.get("fallback")
                if isinstance(fallback, dict):
                    fdata = fallback.get("data")
                    if isinstance(fdata, dict):
                        block = fdata.get("blockNumber")
                        if isinstance(block, int):
                            fallback_blocks.append(block)
                        source = fdata.get("source")
                        if isinstance(source, str):
                            sources.append(source)

    canonical = {
        "exchanges": exchanges,
        "pools": pools,
    }
    return {
        "exchanges": exchanges,
        "pools": pools,
        "observed_block_numbers": sorted(set(fallback_blocks)),
        "observed_sources": sorted(set(sources)),
        "identity_sha256": sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
    }


def deterioration_bps(outputs: List[int]) -> float:
    best = max(outputs)
    worst = min(outputs)
    return (best - worst) * 10_000.0 / best


def main() -> int:
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)

    started = now()
    run_dir = root / (
        "t672-arbitrum-500-volatility-replay-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    run_dir.mkdir()

    target = target_path()
    observations = []

    for rep in range(1, REPETITIONS + 1):
        obs_dir = run_dir / f"rep-{rep:02d}"
        obs_dir.mkdir()

        transport = https_get(target)
        raw = transport["response_bytes"]
        obj = json.loads(raw.decode("utf-8"))
        route = obj.get("priceRoute") if isinstance(obj, dict) else None

        accepted = (
            transport["http_status"] == 200
            and isinstance(route, dict)
            and str(route.get("srcToken", "")).lower() == USDC
            and str(route.get("destToken", "")).lower() == USDT0
            and str(route.get("srcAmount")) == str(INPUT_BASE_UNITS)
            and str(route.get("destAmount", "")).isdigit()
            and int(route["destAmount"]) > 0
            and route.get("side") == "SELL"
            and str(route.get("network")) == str(CHAIN_ID)
            and isinstance(route.get("bestRoute"), list)
            and len(route["bestRoute"]) > 0
        )

        fingerprint = route_fingerprint(route) if isinstance(route, dict) else None
        record = {
            "repetition": rep,
            "accepted": accepted,
            "input_usdc": INPUT_USDC,
            "output_amount_base_units": int(route["destAmount"]) if accepted else None,
            "output_units_usdt0": int(route["destAmount"]) / 1_000_000 if accepted else None,
            "gas_cost": route.get("gasCost") if isinstance(route, dict) else None,
            "gas_cost_usd": route.get("gasCostUSD") if isinstance(route, dict) else None,
            "route_fingerprint": fingerprint,
            "started_at_utc": transport["started_at_utc"],
            "completed_at_utc": transport["completed_at_utc"],
            "duration_ms": transport["duration_ms"],
            "http_status": transport["http_status"],
            "request_url": f"https://{HOST}{target}",
            "request_sha256": transport["request_sha256"],
            "response_sha256": transport["response_sha256"],
        }

        (obs_dir / "request.bin").write_bytes(transport["request_bytes"])
        (obs_dir / "response.bin").write_bytes(raw)
        (obs_dir / "headers.json").write_bytes(json_bytes(transport["response_headers"]))
        (obs_dir / "observation.json").write_bytes(json_bytes(record))

        manifest = []
        for path in sorted(obs_dir.iterdir()):
            if path.is_file() and path.name != "manifest.sha256":
                manifest.append(f"{sha256(path.read_bytes())}  {path.name}")
        (obs_dir / "manifest.sha256").write_text(
            "\n".join(manifest) + "\n", encoding="utf-8"
        )

        observations.append(record)

    accepted_records = [o for o in observations if o["accepted"]]
    outputs = [int(o["output_amount_base_units"]) for o in accepted_records]
    route_ids = [
        o["route_fingerprint"]["identity_sha256"]
        for o in accepted_records
        if o["route_fingerprint"] is not None
    ]

    accepted = len(accepted_records) == REPETITIONS
    unique_route_ids = sorted(set(route_ids))
    observed_deterioration = deterioration_bps(outputs) if outputs else None

    evidence = {
        "schema": "scout.t672.arbitrum_500_volatility_replay.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "claim_boundary": {
            "realized_slippage_proven": False,
            "quote_volatility_observed": True,
            "route_identity_observed": True,
            "execution_cost_certified": False,
        },
        "chain": "arbitrum-one",
        "provider": "velora-paraswap",
        "pair": "USDC/USD₮0",
        "input_usdc": INPUT_USDC,
        "repetitions": REPETITIONS,
        "observations": observations,
        "summary": {
            "best_output_base_units": max(outputs) if outputs else None,
            "worst_output_base_units": min(outputs) if outputs else None,
            "quote_deterioration_bps": observed_deterioration,
            "unique_route_identity_count": len(unique_route_ids),
            "route_identity_sha256s": unique_route_ids,
            "all_quotes_same_route_identity": len(unique_route_ids) == 1,
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
                "input_usdc": INPUT_USDC,
                "repetitions": REPETITIONS,
                "quote_deterioration_bps": observed_deterioration,
                "unique_route_identity_count": len(unique_route_ids),
                "all_quotes_same_route_identity": len(unique_route_ids) == 1,
                "realized_slippage_proven": False,
                "execution_authority": False,
            },
            indent=2,
        )
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

