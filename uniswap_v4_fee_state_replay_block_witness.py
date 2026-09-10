#!/usr/bin/env python3
"""Scout T662 historical Uniswap v4 fee-state witness for Arbitrum One.

Purpose:
Bind the accepted $1,500 Velora/Uniswap-v4 replay to the exact fee state
at its captured Arbitrum block: 503747103.

Read-only only:
- hard-coded Arbitrum public RPC
- hard-coded canonical Uniswap v4 StateView
- hard-coded accepted USDC/USD₮0 pool id
- hard-coded historical replay block
- eth_call only, getSlot0(bytes32)

No wallet, signer, transaction builder, transaction serialization,
simulation, submission, broadcast, bridge, or capital movement.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

WITNESS_VERSION = "1.0.0"
EXECUTION_AUTHORITY = False

RPC_ENDPOINT = "https://arb1.arbitrum.io/rpc"
CHAIN = "arbitrum"
NETWORK = "arbitrum-one"
RPC_METHOD = "eth_call"

STATE_VIEW = "0x76fd297e2d437cd7f76d50f01afe6160f86e9990"
POOL_ID = "0xab05003a63d2f34ac7eec4670bca3319f0e3d2f62af5c2b9cbd69d03fd804fd2"
REPLAY_BLOCK_DECIMAL = 503_747_103
REPLAY_BLOCK_HEX = hex(REPLAY_BLOCK_DECIMAL)

GET_SLOT0_SELECTOR = "c815641c"

USDC = "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
USDT0 = "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"

EXPECTED_LP_FEE_PIPS = 8
PIPS_DENOMINATOR = 1_000_000
MAX_PROTOCOL_FEE_PIPS = 1_000


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError:
        return None


def jd(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode("utf-8")


def calldata() -> str:
    pool_hex = POOL_ID.removeprefix("0x")
    if len(pool_hex) != 64:
        raise RuntimeError("pool id is not bytes32")
    return "0x" + GET_SLOT0_SELECTOR + pool_hex


def request_body() -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": RPC_METHOD,
        "params": [
            {
                "to": STATE_VIEW,
                "data": calldata(),
            },
            REPLAY_BLOCK_HEX,
        ],
    }
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def resolve_dns(endpoint: str) -> Dict[str, Any]:
    parsed = urlparse(endpoint)
    host = parsed.hostname
    port = parsed.port or 443
    started = utc_now_iso()

    if not host:
        return {
            "success": False,
            "host": None,
            "port": port,
            "addresses": [],
            "started_at_utc": started,
            "completed_at_utc": utc_now_iso(),
            "error": "endpoint has no hostname",
        }

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return {
            "success": True,
            "host": host,
            "port": port,
            "addresses": sorted({info[4][0] for info in infos}),
            "started_at_utc": started,
            "completed_at_utc": utc_now_iso(),
            "error": None,
        }
    except OSError as exc:
        return {
            "success": False,
            "host": host,
            "port": port,
            "addresses": [],
            "started_at_utc": started,
            "completed_at_utc": utc_now_iso(),
            "error": f"{type(exc).__name__}: {exc}",
        }


def make_request(body: bytes) -> Tuple[Optional[int], Dict[str, str], bytes, Optional[str]]:
    req = urllib.request.Request(
        RPC_ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"Scout-T662-V4-Historical-Fee-State/{WITNESS_VERSION}",
        },
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=20,
            context=ssl.create_default_context(),
        ) as response:
            return (
                int(response.status),
                {k: v for k, v in response.headers.items()},
                response.read(),
                None,
            )
    except urllib.error.HTTPError as exc:
        return (
            int(exc.code),
            {k: v for k, v in exc.headers.items()} if exc.headers else {},
            exc.read(),
            f"HTTPError: {exc}",
        )
    except Exception as exc:
        return None, {}, b"", f"{type(exc).__name__}: {exc}"


def decode_int24(word: int) -> int:
    value = word & 0xFFFFFF
    if value & 0x800000:
        value -= 1 << 24
    return value


def decode_slot0_result(raw_hex: str) -> Dict[str, int]:
    if not isinstance(raw_hex, str) or not raw_hex.startswith("0x"):
        raise ValueError("eth_call result is not 0x-prefixed hex")

    payload = raw_hex[2:]
    if len(payload) != 64 * 4:
        raise ValueError(
            f"getSlot0 result must be exactly 128 bytes; got {len(payload) // 2}"
        )

    words = [int(payload[i:i + 64], 16) for i in range(0, len(payload), 64)]

    return {
        "sqrtPriceX96": words[0] & ((1 << 160) - 1),
        "tick": decode_int24(words[1]),
        "protocolFee": words[2] & 0xFFFFFF,
        "lpFee": words[3] & 0xFFFFFF,
    }


def directional_protocol_fees(protocol_fee: int) -> Dict[str, int]:
    return {
        "zero_for_one_pips": protocol_fee & 0xFFF,
        "one_for_zero_pips": protocol_fee >> 12,
    }


def effective_swap_fee_pips(protocol_pips: int, lp_pips: int) -> int:
    return protocol_pips + lp_pips - (
        protocol_pips * lp_pips // PIPS_DENOMINATOR
    )


def main() -> int:
    root = Path("live-evidence")
    root.mkdir(exist_ok=True)

    started = utc_now_iso()
    obs_dir = root / (
        "t662-uniswap-v4-historical-fee-state-"
        + started.replace(":", "").replace("-", "").replace(".", "_")
    )
    obs_dir.mkdir()

    req = request_body()
    (obs_dir / "request.bin").write_bytes(req)

    dns = resolve_dns(RPC_ENDPOINT)
    request_sent = utc_now_iso()
    mono_start = time.monotonic_ns()
    status, headers, raw, network_error = make_request(req)
    mono_end = time.monotonic_ns()
    completed = utc_now_iso()

    (obs_dir / "response.bin").write_bytes(raw)
    (obs_dir / "response_headers.json").write_bytes(jd(headers))

    checks: Dict[str, bool] = {
        "historical_block_exact": REPLAY_BLOCK_HEX == hex(503_747_103),
        "dns_success": bool(dns.get("success")),
        "transport_success": status is not None,
        "http_2xx": status is not None and 200 <= status < 300,
        "json_valid": False,
        "jsonrpc_2_0": False,
        "id_matches": False,
        "rpc_error_absent": False,
        "result_present": False,
        "slot0_decodes": False,
        "pool_initialized": False,
        "protocol_fee_valid": False,
        "lp_fee_matches_replay_route": False,
        "usdc_is_currency0": int(USDC, 16) < int(USDT0, 16),
        "no_transaction_material": False,
    }

    obj: Any = None
    decoded: Optional[Dict[str, int]] = None
    directional: Optional[Dict[str, int]] = None
    effective_pips: Optional[int] = None
    parse_error: Optional[str] = None

    try:
        obj = json.loads(raw.decode("utf-8"))
        checks["json_valid"] = isinstance(obj, dict)
    except Exception as exc:
        parse_error = f"{type(exc).__name__}: {exc}"

    if isinstance(obj, dict):
        checks["jsonrpc_2_0"] = obj.get("jsonrpc") == "2.0"
        checks["id_matches"] = obj.get("id") == 1
        checks["rpc_error_absent"] = "error" not in obj
        checks["result_present"] = isinstance(obj.get("result"), str)

        text = json.dumps(obj).lower()
        checks["no_transaction_material"] = all(
            forbidden not in text
            for forbidden in (
                "signedtransaction",
                "serializedtransaction",
                "rawtransaction",
                "calldata_to_submit",
            )
        )

        if checks["result_present"] and checks["rpc_error_absent"]:
            try:
                decoded = decode_slot0_result(obj["result"])
                checks["slot0_decodes"] = True
                checks["pool_initialized"] = decoded["sqrtPriceX96"] > 0

                directional = directional_protocol_fees(decoded["protocolFee"])
                checks["protocol_fee_valid"] = (
                    0 <= directional["zero_for_one_pips"] <= MAX_PROTOCOL_FEE_PIPS
                    and 0 <= directional["one_for_zero_pips"] <= MAX_PROTOCOL_FEE_PIPS
                )
                checks["lp_fee_matches_replay_route"] = (
                    decoded["lpFee"] == EXPECTED_LP_FEE_PIPS
                )

                effective_pips = effective_swap_fee_pips(
                    directional["zero_for_one_pips"],
                    decoded["lpFee"],
                )
            except Exception as exc:
                parse_error = f"{type(exc).__name__}: {exc}"

    accepted = all(checks.values())

    evidence = {
        "schema": "scout.t662.uniswap_v4_historical_protocol_fee_state.v1",
        "accepted": accepted,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "chain": CHAIN,
        "network": NETWORK,
        "endpoint": RPC_ENDPOINT,
        "rpc_method": RPC_METHOD,
        "state_view": STATE_VIEW,
        "pool_id": POOL_ID,
        "historical_block_decimal": REPLAY_BLOCK_DECIMAL,
        "historical_block_hex": REPLAY_BLOCK_HEX,
        "function_signature": "getSlot0(bytes32)",
        "function_selector": "0x" + GET_SLOT0_SELECTOR,
        "pair": "USDC/USD₮0",
        "currency0": USDC,
        "currency1": USDT0,
        "direction": "zeroForOne",
        "request_started_at_utc": request_sent,
        "response_completed_at_utc": completed,
        "duration_ms": round((mono_end - mono_start) / 1_000_000, 3),
        "dns": dns,
        "http": {
            "status": status,
            "headers": headers,
            "network_error": network_error,
        },
        "request": {
            "sha256": sha256_bytes(req),
            "byte_length": len(req),
            "body_utf8": req.decode("utf-8"),
            "artifact": "request.bin",
        },
        "response": {
            "sha256": sha256_bytes(raw),
            "byte_length": len(raw),
            "body_utf8": raw.decode("utf-8", errors="replace"),
            "artifact": "response.bin",
        },
        "decoded_slot0": decoded,
        "directional_protocol_fee": directional,
        "effective_usdc_to_usdt0_fee_pips": effective_pips,
        "effective_usdc_to_usdt0_fee_bps": (
            effective_pips / 100.0 if effective_pips is not None else None
        ),
        "validation": checks,
        "parse_error": parse_error,
        "provenance": {
            "witness_version": WITNESS_VERSION,
            "script_sha256": sha256_file(Path(__file__).resolve()),
            "python_version": platform.python_version(),
            "github_repository": os.getenv("GITHUB_REPOSITORY"),
            "github_sha": os.getenv("GITHUB_SHA"),
            "github_run_id": os.getenv("GITHUB_RUN_ID"),
            "github_workflow": os.getenv("GITHUB_WORKFLOW"),
        },
        "safety": {
            "wallet": False,
            "signer": False,
            "transaction_builder": False,
            "transaction_serialization": False,
            "transaction_simulation": False,
            "transaction_submission": False,
            "broadcast": False,
            "bridge": False,
            "capital_movement": False,
        },
    }

    (obs_dir / "evidence.json").write_bytes(jd(evidence))

    manifest_lines = []
    for path in sorted(obs_dir.iterdir()):
        if path.is_file() and path.name != "manifest.sha256":
            manifest_lines.append(f"{sha256_file(path)}  {path.name}")
    (obs_dir / "manifest.sha256").write_text(
        "\n".join(manifest_lines) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "accepted": accepted,
                "historical_block": REPLAY_BLOCK_DECIMAL,
                "protocol_fee_packed": (
                    decoded["protocolFee"] if decoded else None
                ),
                "protocol_fee_zero_for_one_pips": (
                    directional["zero_for_one_pips"] if directional else None
                ),
                "lp_fee_pips": decoded["lpFee"] if decoded else None,
                "effective_usdc_to_usdt0_fee_pips": effective_pips,
                "execution_authority": False,
            },
            indent=2,
        )
    )

    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

