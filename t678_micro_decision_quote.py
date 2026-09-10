#!/usr/bin/env python3
"""T678 — micro live decision quote for controlled realized-slippage measurement.

READ-ONLY ONLY.
Captures one fresh Raydium 0.001 SOL -> USDC quote.
No wallet, signer, transaction construction, simulation, submission, broadcast,
or capital movement exists in this witness.
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

HOST = "transaction-v1.raydium.io"
PORT = 443
PATH = "/compute/swap-base-in"
SOL = "So11111111111111111111111111111111111111112"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

AMOUNT_BASE_UNITS = 1_000_000  # 0.001 SOL
SLIPPAGE_BPS = 50
TX_VERSION = "V0"

HEADERS = [
    ("Host", HOST),
    ("User-Agent", "Scout-T678-Micro-Decision-Quote/1.0.0"),
    ("Accept", "application/json"),
    ("Accept-Encoding", "identity"),
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("Connection", "close"),
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def main() -> int:
    query = urlencode(
        [
            ("inputMint", SOL),
            ("outputMint", USDC),
            ("amount", str(AMOUNT_BASE_UNITS)),
            ("slippageBps", str(SLIPPAGE_BPS)),
            ("txVersion", TX_VERSION),
        ]
    )
    target = f"{PATH}?{query}"
    request_bytes = (
        f"GET {target} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in HEADERS)
        + "\r\n"
    ).encode("ascii")

    root = Path("live-evidence")
    root.mkdir(exist_ok=True)
    started = now()
    bundle = root / (
        "t678-micro-decision-quote-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    bundle.mkdir()

    (bundle / "request.http").write_bytes(request_bytes)

    dns_started = now()
    try:
        infos = socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)
        addresses = sorted({entry[4][0] for entry in infos})
        dns_ok = True
        dns_error = None
    except Exception as exc:
        addresses = []
        dns_ok = False
        dns_error = f"{type(exc).__name__}: {exc}"
    dns_completed = now()

    raw = b""
    status = None
    reason = None
    sent_at = None
    completed = now()
    transport_ok = False
    transport_error = None

    if dns_ok:
        conn = None
        try:
            conn = http.client.HTTPSConnection(
                HOST,
                PORT,
                timeout=20,
                context=ssl.create_default_context(),
            )
            sent_at = now()
            conn.putrequest(
                "GET",
                target,
                skip_host=True,
                skip_accept_encoding=True,
            )
            for key, value in HEADERS:
                conn.putheader(key, value)
            conn.endheaders()
            response = conn.getresponse()
            status = response.status
            reason = response.reason
            raw = response.read()
            transport_ok = True
        except Exception as exc:
            transport_error = f"{type(exc).__name__}: {exc}"
        finally:
            completed = now()
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    (bundle / "response.body").write_bytes(raw)

    obj = None
    data = None
    try:
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            data = obj.get("data")
    except Exception:
        pass

    checks = {
        "dns_success": dns_ok,
        "transport_success": transport_ok,
        "http_200": status == 200,
        "json_object": isinstance(obj, dict),
        "success_true": isinstance(obj, dict) and obj.get("success") is True,
        "data_object": isinstance(data, dict),
        "swap_type_base_in": isinstance(data, dict)
        and data.get("swapType") == "BaseIn",
        "input_mint_matches": isinstance(data, dict)
        and data.get("inputMint") == SOL,
        "output_mint_matches": isinstance(data, dict)
        and data.get("outputMint") == USDC,
        "input_amount_matches": isinstance(data, dict)
        and str(data.get("inputAmount")) == str(AMOUNT_BASE_UNITS),
        "output_amount_positive": isinstance(data, dict)
        and str(data.get("outputAmount", "")).isdigit()
        and int(data["outputAmount"]) > 0,
        "route_nonempty": isinstance(data, dict)
        and isinstance(data.get("routePlan"), list)
        and len(data["routePlan"]) > 0,
    }
    accepted = all(checks.values())

    quote = {
        "quote_id": obj.get("id") if isinstance(obj, dict) else None,
        "input_asset": "SOL",
        "input_mint": SOL,
        "input_amount_base_units": AMOUNT_BASE_UNITS,
        "input_units": 0.001,
        "output_asset": "USDC",
        "output_mint": USDC,
        "output_amount_base_units": (
            int(data["outputAmount"])
            if accepted
            else None
        ),
        "output_units": (
            int(data["outputAmount"]) / 1_000_000
            if accepted
            else None
        ),
        "other_amount_threshold_base_units": (
            int(data["otherAmountThreshold"])
            if accepted
            and str(data.get("otherAmountThreshold", "")).isdigit()
            else None
        ),
        "slippage_bps": (
            data.get("slippageBps") if isinstance(data, dict) else None
        ),
        "price_impact_pct": (
            data.get("priceImpactPct") if isinstance(data, dict) else None
        ),
        "route_plan": data.get("routePlan") if isinstance(data, dict) else None,
    }
    (bundle / "quote.normalized.json").write_bytes(json_bytes(quote))

    evidence = {
        "schema": "scout.t678.micro_decision_quote.v1",
        "milestone": "T678",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": False,
        "purpose": (
            "Capture a fresh decision quote immediately before an "
            "operator-controlled micro swap for realized-slippage measurement."
        ),
        "request": {
            "method": "GET",
            "endpoint": f"https://{HOST}{PATH}",
            "target": target,
            "request_sha256": sha256(request_bytes),
            "started_at_utc": started,
            "sent_at_utc": sent_at,
        },
        "response": {
            "http_status": status,
            "http_reason": reason,
            "response_sha256": sha256(raw),
            "completed_at_utc": completed,
        },
        "dns": {
            "success": dns_ok,
            "addresses": addresses,
            "started_at_utc": dns_started,
            "completed_at_utc": dns_completed,
            "error": dns_error,
        },
        "transport": {
            "success": transport_ok,
            "error": transport_error,
        },
        "quote": quote,
        "validation": checks,
        "executor": {
            "kind": "github_actions"
            if os.getenv("GITHUB_RUN_ID")
            else "local",
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "commit_sha": os.getenv("GITHUB_SHA"),
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

    evidence_path = bundle / "evidence.json"
    evidence_path.write_bytes(json_bytes(evidence))

    manifest = []
    for path in sorted(bundle.iterdir()):
        if path.is_file() and path.name != "manifest.sha256":
            manifest.append(f"{sha256(path.read_bytes())}  {path.name}")
    (bundle / "manifest.sha256").write_text(
        "\n".join(manifest) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "accepted": accepted,
                "input_units_sol": 0.001,
                "quoted_output_units_usdc": quote["output_units"],
                "quoted_output_base_units": quote[
                    "output_amount_base_units"
                ],
                "decision_quote_timestamp_utc": sent_at,
                "request_sha256": sha256(request_bytes),
                "response_sha256": sha256(raw),
                "execution_authority": False,
            },
            indent=2,
        )
    )

    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

