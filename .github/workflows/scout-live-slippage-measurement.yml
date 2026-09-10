#!/usr/bin/env python3
"""Scout permanent live realized-slippage settlement verifier.

READ-ONLY VERIFIER. This program NEVER constructs, signs, simulates, submits,
or broadcasts a transaction. It only verifies a transaction that the operator
already executed independently.

Required public evidence:
- finalized Solana transaction signature
- public wallet owner address
- quoted output amount in base units
- decision quote UTC timestamp
- SHA-256 of exact quote request
- SHA-256 of exact quote response

The verifier:
1. calls getSignatureStatuses(searchTransactionHistory=true)
2. requires err=null and confirmationStatus=finalized
3. calls getTransaction(commitment=finalized, encoding=json)
4. derives the owner's output-token increase from pre/postTokenBalances
5. computes realized slippage:
   (quoted_output - actual_settled_output) * 10000 / quoted_output

No private keys or secrets belong in this workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import ssl
import time
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple
from urllib.parse import urlparse

getcontext().prec = 60

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
DEFAULT_OUTPUT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")

EXECUTION_AUTHORITY = False


def now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def validate_public_identifier(value: str, label: str, min_len: int, max_len: int) -> str:
    value = value.strip()
    if not (min_len <= len(value) <= max_len) or not BASE58_RE.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def validate_sha(value: str, label: str) -> str:
    value = value.strip().lower()
    if not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a 64-character SHA-256 hex digest")
    return value


def validate_timestamp(value: str) -> str:
    value = value.strip()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("decision quote timestamp must include UTC/offset")
    return parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def rpc_call(endpoint: str, method: str, params: list, request_id: int) -> Dict[str, Any]:
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("RPC endpoint must be HTTPS")

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    headers = [
        ("Host", parsed.netloc),
        ("User-Agent", "Scout-Live-Slippage-Verifier/1.0.0"),
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
        ("Accept-Encoding", "identity"),
        ("Content-Length", str(len(body))),
        ("Connection", "close"),
    ]

    request_bytes = (
        f"POST {path} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in headers)
        + "\r\n"
    ).encode("utf-8") + body

    started = now()
    mono_start = time.monotonic_ns()
    conn = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=30,
        context=ssl.create_default_context(),
    )
    try:
        conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        for key, value in headers:
            conn.putheader(key, value)
        conn.endheaders(body)
        response = conn.getresponse()
        raw = response.read()
        status = response.status
    finally:
        conn.close()
    mono_end = time.monotonic_ns()

    obj = json.loads(raw.decode("utf-8"))
    return {
        "method": method,
        "endpoint": endpoint,
        "started_at_utc": started,
        "completed_at_utc": now(),
        "duration_ms": round((mono_end - mono_start) / 1_000_000, 3),
        "http_status": status,
        "request_bytes": request_bytes,
        "response_bytes": raw,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(raw),
        "json": obj,
    }


def token_sum(entries: Iterable[Dict[str, Any]], owner: str, mint: str) -> int:
    total = 0
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("owner") != owner or entry.get("mint") != mint:
            continue
        token = entry.get("uiTokenAmount")
        if not isinstance(token, dict):
            continue
        amount = token.get("amount")
        if isinstance(amount, str) and amount.isdigit():
            total += int(amount)
    return total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signature", required=True)
    parser.add_argument("--wallet-owner", required=True)
    parser.add_argument("--quoted-output-base-units", required=True, type=int)
    parser.add_argument("--decision-quote-timestamp-utc", required=True)
    parser.add_argument("--quote-request-sha256", required=True)
    parser.add_argument("--quote-response-sha256", required=True)
    parser.add_argument("--output-mint", default=DEFAULT_OUTPUT_MINT)
    parser.add_argument("--rpc-endpoint", default=DEFAULT_RPC)
    args = parser.parse_args()

    signature = validate_public_identifier(args.signature, "transaction signature", 64, 100)
    wallet_owner = validate_public_identifier(args.wallet_owner, "wallet owner", 32, 50)
    output_mint = validate_public_identifier(args.output_mint, "output mint", 32, 50)
    quote_request_sha = validate_sha(args.quote_request_sha256, "quote request hash")
    quote_response_sha = validate_sha(args.quote_response_sha256, "quote response hash")
    quote_timestamp = validate_timestamp(args.decision_quote_timestamp_utc)

    if args.quoted_output_base_units <= 0:
        raise ValueError("quoted output must be positive")

    root = Path("live-evidence")
    root.mkdir(exist_ok=True)
    stamp = now().replace(":", "").replace("-", "").replace(".", "_")
    run_dir = root / f"live-realized-slippage-{stamp}"
    run_dir.mkdir()

    status_rpc = rpc_call(
        args.rpc_endpoint,
        "getSignatureStatuses",
        [[signature], {"searchTransactionHistory": True}],
        1,
    )
    (run_dir / "status_request.bin").write_bytes(status_rpc["request_bytes"])
    (run_dir / "status_response.bin").write_bytes(status_rpc["response_bytes"])

    status_obj = status_rpc["json"]
    status_value = None
    if isinstance(status_obj, dict):
        result = status_obj.get("result")
        if isinstance(result, dict):
            values = result.get("value")
            if isinstance(values, list) and values:
                status_value = values[0]

    finalized = (
        status_rpc["http_status"] == 200
        and isinstance(status_value, dict)
        and status_value.get("err") is None
        and status_value.get("confirmationStatus") == "finalized"
    )

    tx_rpc = rpc_call(
        args.rpc_endpoint,
        "getTransaction",
        [
            signature,
            {
                "commitment": "finalized",
                "encoding": "json",
                "maxSupportedTransactionVersion": 0,
            },
        ],
        2,
    )
    (run_dir / "transaction_request.bin").write_bytes(tx_rpc["request_bytes"])
    (run_dir / "transaction_response.bin").write_bytes(tx_rpc["response_bytes"])

    tx_obj = tx_rpc["json"]
    tx_result = tx_obj.get("result") if isinstance(tx_obj, dict) else None
    meta = tx_result.get("meta") if isinstance(tx_result, dict) else None
    transaction = tx_result.get("transaction") if isinstance(tx_result, dict) else None

    returned_signatures = []
    if isinstance(transaction, dict):
        sigs = transaction.get("signatures")
        if isinstance(sigs, list):
            returned_signatures = [s for s in sigs if isinstance(s, str)]

    tx_success = (
        tx_rpc["http_status"] == 200
        and isinstance(tx_result, dict)
        and isinstance(meta, dict)
        and meta.get("err") is None
        and signature in returned_signatures
    )

    pre = token_sum(
        meta.get("preTokenBalances", []) if isinstance(meta, dict) else [],
        wallet_owner,
        output_mint,
    )
    post = token_sum(
        meta.get("postTokenBalances", []) if isinstance(meta, dict) else [],
        wallet_owner,
        output_mint,
    )
    settled_output = post - pre

    measurement_valid = finalized and tx_success and settled_output > 0

    quoted = Decimal(args.quoted_output_base_units)
    settled = Decimal(settled_output)
    slippage_bps = (
        (quoted - settled) * Decimal("10000") / quoted
        if measurement_valid
        else None
    )

    evidence = {
        "schema": "scout.live_realized_slippage_measurement.v1",
        "accepted": measurement_valid,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "operator_execution_external_to_witness": True,
        "decision_quote": {
            "timestamp_utc": quote_timestamp,
            "request_sha256": quote_request_sha,
            "response_sha256": quote_response_sha,
            "quoted_output_base_units": args.quoted_output_base_units,
            "output_mint": output_mint,
        },
        "settlement": {
            "transaction_signature": signature,
            "wallet_owner": wallet_owner,
            "finalized": finalized,
            "transaction_success": tx_success,
            "slot": tx_result.get("slot") if isinstance(tx_result, dict) else None,
            "block_time": tx_result.get("blockTime") if isinstance(tx_result, dict) else None,
            "network_fee_lamports": meta.get("fee") if isinstance(meta, dict) else None,
            "pre_output_token_balance_base_units": pre,
            "post_output_token_balance_base_units": post,
            "actual_settled_output_base_units": settled_output,
        },
        "measurement": {
            "formula": (
                "(quoted_output_base_units - actual_settled_output_base_units) "
                "* 10000 / quoted_output_base_units"
            ),
            "realized_slippage_bps": str(slippage_bps) if slippage_bps is not None else None,
            "positive_means_adverse": True,
            "realized_slippage_proven_for_this_observation": measurement_valid,
        },
        "rpc_evidence": {
            "status": {
                "method": status_rpc["method"],
                "endpoint": status_rpc["endpoint"],
                "http_status": status_rpc["http_status"],
                "started_at_utc": status_rpc["started_at_utc"],
                "completed_at_utc": status_rpc["completed_at_utc"],
                "request_sha256": status_rpc["request_sha256"],
                "response_sha256": status_rpc["response_sha256"],
            },
            "transaction": {
                "method": tx_rpc["method"],
                "endpoint": tx_rpc["endpoint"],
                "http_status": tx_rpc["http_status"],
                "started_at_utc": tx_rpc["started_at_utc"],
                "completed_at_utc": tx_rpc["completed_at_utc"],
                "request_sha256": tx_rpc["request_sha256"],
                "response_sha256": tx_rpc["response_sha256"],
            },
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
    for path in sorted(run_dir.iterdir()):
        if path.is_file() and path.name != "manifest.sha256":
            manifest.append(f"{sha256(path.read_bytes())}  {path.name}")
    (run_dir / "manifest.sha256").write_text(
        "\n".join(manifest) + "\n", encoding="utf-8"
    )

    print(
        json.dumps(
            {
                "accepted": measurement_valid,
                "finalized": finalized,
                "transaction_success": tx_success,
                "quoted_output_base_units": args.quoted_output_base_units,
                "actual_settled_output_base_units": settled_output,
                "realized_slippage_bps": (
                    str(slippage_bps) if slippage_bps is not None else None
                ),
                "execution_authority": False,
            },
            indent=2,
        )
    )
    return 0 if measurement_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

