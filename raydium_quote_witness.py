#!/usr/bin/env python3
"""Scout Raydium Live Quote Witness.

Single-purpose, read-only witness for one genuine Raydium SOL->USDC quote.
Standard-library only. It has no wallet, signer, transaction-builder, or send path.

Allowed network request:
  GET https://transaction-v1.raydium.io/compute/swap-base-in

The request parameters are intentionally hard-coded. The CLI cannot supply an
endpoint, method, mint, wallet, or transaction path.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

WITNESS_VERSION = "1.0.0"
HOST = "transaction-v1.raydium.io"
PORT = 443
SCHEME = "https"
PATH = "/compute/swap-base-in"
HTTP_METHOD = "GET"

SOL_MINT = "So11111111111111111111111111111111111111112"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
AMOUNT = 1_000_000_000  # 1 SOL, hypothetical quote amount only; nothing is spent.
SLIPPAGE_BPS = 50
TX_VERSION = "V0"
TIMEOUT_SECONDS = 20

QUERY_ITEMS = [
    ("inputMint", SOL_MINT),
    ("outputMint", USDC_MINT),
    ("amount", str(AMOUNT)),
    ("slippageBps", str(SLIPPAGE_BPS)),
    ("txVersion", TX_VERSION),
]
QUERY = urlencode(QUERY_ITEMS)
REQUEST_TARGET = f"{PATH}?{QUERY}"
ENDPOINT = f"{SCHEME}://{HOST}{PATH}"
FULL_URL = f"{SCHEME}://{HOST}{REQUEST_TARGET}"

REQUEST_HEADERS = [
    ("Host", HOST),
    ("User-Agent", f"Scout-Raydium-Quote-Witness/{WITNESS_VERSION}"),
    ("Accept", "application/json"),
    ("Accept-Encoding", "identity"),
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("Connection", "close"),
]

FORBIDDEN_RESPONSE_KEYS = {
    "transaction",
    "serializedtransaction",
    "signedtransaction",
    "messagebytes",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_dump_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build_request_bytes() -> bytes:
    head = f"{HTTP_METHOD} {REQUEST_TARGET} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in REQUEST_HEADERS)
    head += "\r\n"
    return head.encode("ascii")


def executor_identity() -> dict[str, Any]:
    github = {
        "repository": os.getenv("GITHUB_REPOSITORY"),
        "commit_sha": os.getenv("GITHUB_SHA"),
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "workflow": os.getenv("GITHUB_WORKFLOW"),
        "job": os.getenv("GITHUB_JOB"),
        "ref": os.getenv("GITHUB_REF"),
        "actor": os.getenv("GITHUB_ACTOR"),
        "runner_name": os.getenv("RUNNER_NAME"),
        "runner_os": os.getenv("RUNNER_OS"),
        "runner_arch": os.getenv("RUNNER_ARCH"),
    }
    github = {k: v for k, v in github.items() if v is not None}
    return {
        "kind": "github_actions" if github else "local_python",
        "github": github or None,
        "hostname": socket.gethostname(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "witness_version": WITNESS_VERSION,
    }


def resolve_dns() -> tuple[dict[str, Any], list[tuple]]:
    started = utc_now()
    t0 = time.monotonic_ns()
    try:
        infos = socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)
        addresses = sorted({entry[4][0] for entry in infos})
        return (
            {
                "success": True,
                "started_at_utc": started,
                "completed_at_utc": utc_now(),
                "duration_ms": round((time.monotonic_ns() - t0) / 1_000_000, 3),
                "addresses": addresses,
                "error": None,
            },
            infos,
        )
    except Exception as exc:
        return (
            {
                "success": False,
                "started_at_utc": started,
                "completed_at_utc": utc_now(),
                "duration_ms": round((time.monotonic_ns() - t0) / 1_000_000, 3),
                "addresses": [],
                "error": f"{type(exc).__name__}: {exc}",
            },
            [],
        )


def contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).replace("_", "").lower() in FORBIDDEN_RESPONSE_KEYS:
                return True
            if contains_forbidden_key(child):
                return True
    elif isinstance(value, list):
        return any(contains_forbidden_key(x) for x in value)
    return False


def positive_decimal_string(value: Any) -> bool:
    return isinstance(value, str) and value.isdigit() and int(value) > 0


def validate_quote(raw_body: bytes, http_status: int, response_headers: list[tuple[str, str]], completed_at: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    checks: dict[str, Any] = {
        "http_200": http_status == 200,
        "content_encoding_identity": True,
        "json_valid": False,
        "root_object": False,
        "success_true": False,
        "quote_id_present": False,
        "data_object": False,
        "swap_type_base_in": False,
        "input_mint_matches": False,
        "output_mint_matches": False,
        "input_amount_matches": False,
        "output_amount_positive": False,
        "threshold_positive": False,
        "slippage_matches": False,
        "route_plan_nonempty": False,
        "route_pool_ids_present": False,
        "no_transaction_payload": False,
        "server_date_not_future": None,
        "server_date_reasonably_fresh": None,
    }
    header_map = {k.lower(): v for k, v in response_headers}
    content_encoding = header_map.get("content-encoding", "identity").lower().strip()
    checks["content_encoding_identity"] = content_encoding in ("", "identity")

    parsed: dict[str, Any] | None = None
    if checks["content_encoding_identity"]:
        try:
            obj = json.loads(raw_body.decode("utf-8"))
            checks["json_valid"] = True
            checks["root_object"] = isinstance(obj, dict)
            if isinstance(obj, dict):
                parsed = obj
        except Exception:
            pass

    if parsed is not None:
        checks["success_true"] = parsed.get("success") is True
        checks["quote_id_present"] = isinstance(parsed.get("id"), str) and bool(parsed.get("id"))
        data = parsed.get("data")
        checks["data_object"] = isinstance(data, dict)
        checks["no_transaction_payload"] = not contains_forbidden_key(parsed)
        if isinstance(data, dict):
            checks["swap_type_base_in"] = data.get("swapType") == "BaseIn"
            checks["input_mint_matches"] = data.get("inputMint") == SOL_MINT
            checks["output_mint_matches"] = data.get("outputMint") == USDC_MINT
            checks["input_amount_matches"] = str(data.get("inputAmount")) == str(AMOUNT)
            checks["output_amount_positive"] = positive_decimal_string(str(data.get("outputAmount", "")))
            checks["threshold_positive"] = positive_decimal_string(str(data.get("otherAmountThreshold", "")))
            checks["slippage_matches"] = int(data.get("slippageBps", -1)) == SLIPPAGE_BPS if str(data.get("slippageBps", "")).isdigit() else False
            route = data.get("routePlan")
            checks["route_plan_nonempty"] = isinstance(route, list) and len(route) > 0
            if isinstance(route, list) and route:
                checks["route_pool_ids_present"] = all(isinstance(x, dict) and isinstance(x.get("poolId"), str) and bool(x.get("poolId")) for x in route)

    date_header = header_map.get("date")
    if date_header:
        try:
            server_dt = parsedate_to_datetime(date_header)
            if server_dt.tzinfo is None:
                server_dt = server_dt.replace(tzinfo=timezone.utc)
            complete_dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            delta = (complete_dt - server_dt.astimezone(timezone.utc)).total_seconds()
            checks["server_date_not_future"] = delta >= -120
            checks["server_date_reasonably_fresh"] = -120 <= delta <= 300
        except Exception:
            checks["server_date_not_future"] = False
            checks["server_date_reasonably_fresh"] = False

    required = [
        "http_200",
        "content_encoding_identity",
        "json_valid",
        "root_object",
        "success_true",
        "quote_id_present",
        "data_object",
        "swap_type_base_in",
        "input_mint_matches",
        "output_mint_matches",
        "input_amount_matches",
        "output_amount_positive",
        "threshold_positive",
        "slippage_matches",
        "route_plan_nonempty",
        "route_pool_ids_present",
        "no_transaction_payload",
    ]
    if date_header:
        required.extend(["server_date_not_future", "server_date_reasonably_fresh"])
    checks["accepted"] = all(checks[name] is True for name in required)
    return checks, parsed


def write_manifest(directory: Path) -> None:
    lines = []
    for path in sorted(p for p in directory.iterdir() if p.is_file() and p.name != "manifest.sha256"):
        lines.append(f"{sha256_bytes(path.read_bytes())}  {path.name}")
    (directory / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def capture(output_root: Path) -> int:
    started_at = utc_now()
    stamp = started_at.replace(":", "").replace("-", "").replace(".", "_")
    bundle = output_root / f"raydium-quote-{stamp}"
    bundle.mkdir(parents=True, exist_ok=False)

    request_bytes = build_request_bytes()
    request_body = b""
    (bundle / "request.http").write_bytes(request_bytes)
    (bundle / "request_body.bin").write_bytes(request_body)

    dns, _ = resolve_dns()
    response_body = b""
    response_headers: list[tuple[str, str]] = []
    http_status: int | None = None
    http_reason: str | None = None
    transport_success = False
    transport_error: str | None = None
    tls: dict[str, Any] = {}
    request_sent_at: str | None = None
    completed_at = utc_now()
    t0 = time.monotonic_ns()

    if dns["success"]:
        conn: http.client.HTTPSConnection | None = None
        try:
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(HOST, PORT, timeout=TIMEOUT_SECONDS, context=context)
            request_sent_at = utc_now()
            conn.putrequest(HTTP_METHOD, REQUEST_TARGET, skip_host=True, skip_accept_encoding=True)
            for key, value in REQUEST_HEADERS:
                conn.putheader(key, value)
            conn.endheaders()
            response = conn.getresponse()
            http_status = response.status
            http_reason = response.reason
            response_headers = [(str(k), str(v)) for k, v in response.getheaders()]
            if conn.sock is not None:
                try:
                    cert = conn.sock.getpeercert(binary_form=True)
                    tls = {
                        "version": conn.sock.version(),
                        "cipher": conn.sock.cipher(),
                        "peer_certificate_sha256": sha256_bytes(cert) if cert else None,
                    }
                except Exception as tls_exc:
                    tls = {"error": f"{type(tls_exc).__name__}: {tls_exc}"}
            response_body = response.read()
            transport_success = True
        except Exception as exc:
            transport_error = f"{type(exc).__name__}: {exc}"
        finally:
            completed_at = utc_now()
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    (bundle / "response.body").write_bytes(response_body)
    (bundle / "response_headers.json").write_bytes(json_dump_bytes(response_headers))

    response_hash_before = sha256_bytes(response_body)
    response_hash_after = sha256_bytes((bundle / "response.body").read_bytes())
    request_hash_before = sha256_bytes(request_bytes)
    request_hash_after = sha256_bytes((bundle / "request.http").read_bytes())
    body_hash_before = sha256_bytes(request_body)
    body_hash_after = sha256_bytes((bundle / "request_body.bin").read_bytes())

    validation: dict[str, Any]
    parsed: dict[str, Any] | None
    if transport_success and http_status is not None:
        validation, parsed = validate_quote(response_body, http_status, response_headers, completed_at)
    else:
        validation, parsed = {"accepted": False, "reason": "transport_or_dns_failed"}, None

    digest_checks = {
        "request_http_digest_recheck_matches": request_hash_before == request_hash_after,
        "request_body_digest_recheck_matches": body_hash_before == body_hash_after,
        "response_body_digest_recheck_matches": response_hash_before == response_hash_after,
    }
    accepted = bool(
        dns["success"]
        and transport_success
        and validation.get("accepted") is True
        and all(digest_checks.values())
    )

    normalized = None
    if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
        data = parsed["data"]
        normalized = {
            "quote_id": parsed.get("id"),
            "version": parsed.get("version"),
            "swap_type": data.get("swapType"),
            "input_mint": data.get("inputMint"),
            "input_amount": data.get("inputAmount"),
            "output_mint": data.get("outputMint"),
            "output_amount": data.get("outputAmount"),
            "other_amount_threshold": data.get("otherAmountThreshold"),
            "slippage_bps": data.get("slippageBps"),
            "price_impact_pct": data.get("priceImpactPct"),
            "route_plan": data.get("routePlan"),
        }
        (bundle / "quote.normalized.json").write_bytes(json_dump_bytes(normalized))

    evidence = {
        "schema": "scout.raydium_live_quote_evidence.v1",
        "milestone": "QUOTE-1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": False,
        "safety_contract": {
            "allowed_http_method": HTTP_METHOD,
            "allowed_endpoint": ENDPOINT,
            "allowed_path": PATH,
            "arbitrary_endpoint_input": False,
            "arbitrary_method_input": False,
            "wallet_input": False,
            "signing_capability": False,
            "transaction_build_capability": False,
            "transaction_submission_capability": False,
            "forbidden_endpoint_prefix": "/transaction/",
        },
        "request": {
            "method": HTTP_METHOD,
            "endpoint": ENDPOINT,
            "full_url": FULL_URL,
            "request_target": REQUEST_TARGET,
            "headers": REQUEST_HEADERS,
            "body_length": 0,
            "request_http_sha256": request_hash_before,
            "request_body_sha256": body_hash_before,
            "started_at_utc": started_at,
            "sent_at_utc": request_sent_at,
            "parameters": dict(QUERY_ITEMS),
        },
        "dns": dns,
        "transport": {
            "success": transport_success,
            "error": transport_error,
            "http_status": http_status,
            "http_reason": http_reason,
            "tls": tls,
            "completed_at_utc": completed_at,
            "duration_ms": round((time.monotonic_ns() - t0) / 1_000_000, 3),
        },
        "response": {
            "raw_body_length": len(response_body),
            "raw_body_sha256": response_hash_before,
            "headers_file": "response_headers.json",
            "raw_body_file": "response.body",
        },
        "digest_checks": digest_checks,
        "validation": validation,
        "executor": executor_identity(),
        "authoritative_artifacts": ["request.http", "request_body.bin", "response.body", "response_headers.json", "evidence.json"],
        "derived_artifacts": ["quote.normalized.json"] if normalized is not None else [],
    }
    (bundle / "evidence.json").write_bytes(json_dump_bytes(evidence))
    write_manifest(bundle)

    print(json.dumps({"status": "PASS" if accepted else "FAIL", "bundle": str(bundle), "evidence": str(bundle / "evidence.json")}, indent=2))
    return 0 if accepted else 1


def verify_bundle(bundle: Path) -> int:
    failures: list[str] = []
    evidence_path = bundle / "evidence.json"
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: cannot read evidence.json: {exc}", file=sys.stderr)
        return 2

    required_files = ["request.http", "request_body.bin", "response.body", "response_headers.json"]
    for name in required_files:
        if not (bundle / name).is_file():
            failures.append(f"missing {name}")

    if not failures:
        if sha256_bytes((bundle / "request.http").read_bytes()) != evidence["request"]["request_http_sha256"]:
            failures.append("request.http digest mismatch")
        if sha256_bytes((bundle / "request_body.bin").read_bytes()) != evidence["request"]["request_body_sha256"]:
            failures.append("request_body.bin digest mismatch")
        if sha256_bytes((bundle / "response.body").read_bytes()) != evidence["response"]["raw_body_sha256"]:
            failures.append("response.body digest mismatch")
        if (bundle / "request.http").read_bytes() != build_request_bytes():
            failures.append("request.http does not equal the hard-coded allowlisted request")
        try:
            headers = json.loads((bundle / "response_headers.json").read_text(encoding="utf-8"))
            headers = [(str(k), str(v)) for k, v in headers]
            checks, _ = validate_quote(
                (bundle / "response.body").read_bytes(),
                int(evidence["transport"]["http_status"]),
                headers,
                str(evidence["transport"]["completed_at_utc"]),
            )
            if checks.get("accepted") is not True:
                failures.append("quote validation no longer passes")
        except Exception as exc:
            failures.append(f"offline validation error: {type(exc).__name__}: {exc}")

    if evidence.get("execution_authority") is not False:
        failures.append("execution_authority is not false")
    safety = evidence.get("safety_contract", {})
    if safety.get("allowed_endpoint") != ENDPOINT or safety.get("allowed_http_method") != HTTP_METHOD:
        failures.append("safety contract endpoint/method mismatch")
    if safety.get("transaction_build_capability") is not False or safety.get("transaction_submission_capability") is not False:
        failures.append("transaction capability safety flags invalid")

    if failures:
        print("FAIL")
        for item in failures:
            print(f" - {item}")
        return 1
    print("PASS: raw request/response digests and quote structure reproduce successfully")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Scout read-only Raydium live quote witness")
    sub = parser.add_subparsers(dest="command", required=True)
    cap = sub.add_parser("capture", help="make the one hard-coded read-only quote request")
    cap.add_argument("--output", type=Path, default=Path("live-evidence"), help="output directory only")
    ver = sub.add_parser("verify", help="offline verification of a previously captured bundle")
    ver.add_argument("bundle", type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        return capture(args.output)
    return verify_bundle(args.bundle)


if __name__ == "__main__":
    raise SystemExit(main())

