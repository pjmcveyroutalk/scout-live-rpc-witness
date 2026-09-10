#!/usr/bin/env python3
"""Scout LIVE RPC Witness

Dependency-free, read-only JSON-RPC evidence capture for the first Scout live anchors.

Hard-coded allowed observations only:
  - Solana mainnet getSlot (finalized)
  - Solana mainnet getBlockHeight (finalized, optional)
  - Arbitrum One eth_blockNumber

The program intentionally accepts no arbitrary RPC URL and no arbitrary RPC method.
It cannot sign, build, simulate, or submit transactions.

Authoritative evidence is the exact request body bytes and exact HTTP response body bytes
written to disk together with SHA-256 digests and provenance metadata.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

WITNESS_VERSION = "1.0.0"
EXECUTION_AUTHORITY = False
READ_ONLY_ALLOWLIST = frozenset({"getSlot", "getBlockHeight", "eth_blockNumber"})


@dataclass(frozen=True)
class Target:
    key: str
    chain: str
    network: str
    endpoint: str
    method: str
    params: List[Any]
    result_kind: str


TARGETS: Dict[str, Target] = {
    "solana-slot": Target(
        key="solana-slot",
        chain="solana",
        network="mainnet-beta",
        endpoint="https://api.mainnet.solana.com",
        method="getSlot",
        params=[{"commitment": "finalized"}],
        result_kind="positive_integer",
    ),
    "solana-blockheight": Target(
        key="solana-blockheight",
        chain="solana",
        network="mainnet-beta",
        endpoint="https://api.mainnet.solana.com",
        method="getBlockHeight",
        params=[{"commitment": "finalized"}],
        result_kind="positive_integer",
    ),
    "arbitrum-block": Target(
        key="arbitrum-block",
        chain="arbitrum",
        network="arbitrum-one",
        endpoint="https://arb1.arbitrum.io/rpc",
        method="eth_blockNumber",
        params=[],
        result_kind="positive_hex_quantity",
    ),
}

HEX_QUANTITY_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError:
        return None


def safe_env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value else None


def provenance() -> Dict[str, Any]:
    script_path = Path(__file__).resolve()

    github = {
        "github_actions": safe_env("GITHUB_ACTIONS"),
        "repository": safe_env("GITHUB_REPOSITORY"),
        "commit_sha": safe_env("GITHUB_SHA"),
        "run_id": safe_env("GITHUB_RUN_ID"),
        "run_number": safe_env("GITHUB_RUN_NUMBER"),
        "run_attempt": safe_env("GITHUB_RUN_ATTEMPT"),
        "workflow": safe_env("GITHUB_WORKFLOW"),
        "job": safe_env("GITHUB_JOB"),
        "runner_name": safe_env("RUNNER_NAME"),
        "runner_os": safe_env("RUNNER_OS"),
        "runner_arch": safe_env("RUNNER_ARCH"),
    }

    return {
        "witness_name": "scout_live_rpc_witness",
        "witness_version": WITNESS_VERSION,
        "witness_script_sha256": sha256_file(script_path),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "hostname": platform.node() or None,
        "user": getpass.getuser() or None,
        "pid": os.getpid(),
        "github": github,
    }


def deterministic_request_bytes(target: Target) -> bytes:
    if target.method not in READ_ONLY_ALLOWLIST:
        raise RuntimeError(
            f"method is not in read-only allowlist: {target.method}"
        )

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": target.method,
        "params": target.params,
    }

    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def resolve_dns(endpoint: str) -> Dict[str, Any]:
    parsed = urlparse(endpoint)
    host = parsed.hostname

    if not host:
        return {
            "success": False,
            "error": "endpoint has no hostname",
            "addresses": [],
        }

    port = parsed.port or (
        443 if parsed.scheme == "https" else 80
    )

    started = utc_now_iso()

    try:
        infos = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )

        addresses = sorted({
            info[4][0]
            for info in infos
        })

        return {
            "success": True,
            "host": host,
            "port": port,
            "addresses": addresses,
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


def validate_rpc_response(
    target: Target,
    raw: bytes,
) -> Dict[str, Any]:

    result: Dict[str, Any] = {
        "utf8_valid": False,
        "json_valid": False,
        "top_level_object": False,
        "jsonrpc_2_0": False,
        "id_matches": False,
        "rpc_error_absent": False,
        "result_present": False,
        "result_valid": False,
        "normalized_result": None,
        "validation_error": None,
    }

    try:
        text = raw.decode("utf-8")
        result["utf8_valid"] = True
    except UnicodeDecodeError as exc:
        result["validation_error"] = (
            f"response is not UTF-8: {exc}"
        )
        return result

    try:
        obj = json.loads(text)
        result["json_valid"] = True
    except json.JSONDecodeError as exc:
        result["validation_error"] = (
            f"response is not valid JSON: {exc}"
        )
        return result

    if not isinstance(obj, dict):
        result["validation_error"] = (
            "JSON-RPC response is not an object"
        )
        return result

    result["top_level_object"] = True
    result["jsonrpc_2_0"] = obj.get("jsonrpc") == "2.0"
    result["id_matches"] = obj.get("id") == 1
    result["rpc_error_absent"] = "error" not in obj
    result["result_present"] = "result" in obj

    if not result["rpc_error_absent"]:
        result["validation_error"] = (
            f"JSON-RPC error present: {obj.get('error')!r}"
        )
        return result

    if "result" not in obj:
        result["validation_error"] = (
            "JSON-RPC result is missing"
        )
        return result

    value = obj["result"]

    if target.result_kind == "positive_integer":
        valid = (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value > 0
        )

        if valid:
            result["result_valid"] = True
            result["normalized_result"] = value
        else:
            result["validation_error"] = (
                "result is not a positive integer"
            )

    elif target.result_kind == "positive_hex_quantity":
        valid = (
            isinstance(value, str)
            and HEX_QUANTITY_RE.fullmatch(value) is not None
        )

        if valid:
            normalized = int(value, 16)

            if normalized > 0:
                result["result_valid"] = True
                result["normalized_result"] = normalized
            else:
                result["validation_error"] = (
                    "hex quantity normalizes to zero"
                )
        else:
            result["validation_error"] = (
                "result is not a valid 0x-prefixed hex quantity"
            )

    else:
        result["validation_error"] = (
            f"unknown result kind: {target.result_kind}"
        )

    return result


def make_http_request(
    endpoint: str,
    request_body: bytes,
    timeout: float,
) -> Tuple[
    Optional[int],
    Dict[str, str],
    bytes,
    Optional[str],
]:

    req = urllib.request.Request(
        endpoint,
        data=request_body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": (
                f"ScoutLiveRpcWitness/{WITNESS_VERSION}"
            ),
        },
    )

    tls_context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(
            req,
            timeout=timeout,
            context=tls_context,
        ) as response:

            status = int(response.status)

            headers = {
                k: v
                for k, v in response.headers.items()
            }

            body = response.read()

            return status, headers, body, None

    except urllib.error.HTTPError as exc:
        headers = (
            {k: v for k, v in exc.headers.items()}
            if exc.headers
            else {}
        )

        body = exc.read()

        return (
            int(exc.code),
            headers,
            body,
            f"HTTPError: {exc}",
        )

    except Exception as exc:
        return (
            None,
            {},
            b"",
            f"{type(exc).__name__}: {exc}",
        )


def write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def capture_once(
    target: Target,
    observation_dir: Path,
    run_id: str,
    observation_index: int,
    timeout: float,
) -> Dict[str, Any]:

    observation_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    request_body = deterministic_request_bytes(target)
    request_sha = sha256_bytes(request_body)

    capture_started = utc_now_iso()
    dns = resolve_dns(target.endpoint)

    request_started = utc_now_iso()
    mono_start = time.monotonic_ns()

    (
        http_status,
        response_headers,
        raw_response,
        network_error,
    ) = make_http_request(
        target.endpoint,
        request_body,
        timeout,
    )

    mono_end = time.monotonic_ns()
    response_completed = utc_now_iso()

    request_path = (
        observation_dir / "request.bin"
    )

    response_path = (
        observation_dir / "response.bin"
    )

    write_atomic(
        request_path,
        request_body,
    )

    write_atomic(
        response_path,
        raw_response,
    )

    response_sha = sha256_bytes(raw_response)
    request_disk_sha = sha256_file(request_path)
    response_disk_sha = sha256_file(response_path)

    if raw_response:
        validation = validate_rpc_response(
            target,
            raw_response,
        )
    else:
        validation = {
            "utf8_valid": False,
            "json_valid": False,
            "top_level_object": False,
            "jsonrpc_2_0": False,
            "id_matches": False,
            "rpc_error_absent": False,
            "result_present": False,
            "result_valid": False,
            "normalized_result": None,
            "validation_error": (
                "no response body captured"
            ),
        }

    transport_success = (
        http_status is not None
    )

    http_success = (
        http_status is not None
        and 200 <= http_status < 300
    )

    structure_success = all(
        bool(validation.get(k))
        for k in (
            "utf8_valid",
            "json_valid",
            "top_level_object",
            "jsonrpc_2_0",
            "id_matches",
            "rpc_error_absent",
            "result_present",
            "result_valid",
        )
    )

    digest_integrity = (
        request_disk_sha == request_sha
        and response_disk_sha == response_sha
    )

    evidence: Dict[str, Any] = {
        "schema": (
            "scout.live_rpc_witness.observation.v1"
        ),
        "run_id": run_id,
        "observation_index": observation_index,
        "chain": target.chain,
        "network": target.network,
        "endpoint": target.endpoint,
        "method": target.method,
        "execution_authority": (
            EXECUTION_AUTHORITY
        ),
        "read_only_allowlist": sorted(
            READ_ONLY_ALLOWLIST
        ),
        "capture_started_at_utc": (
            capture_started
        ),
        "request_started_at_utc": (
            request_started
        ),
        "response_completed_at_utc": (
            response_completed
        ),
        "duration_ms": round(
            (mono_end - mono_start)
            / 1_000_000,
            3,
        ),
        "dns": dns,
        "transport": {
            "success": transport_success,
            "https_tls_verification": True,
            "network_error": network_error,
        },
        "http": {
            "status": http_status,
            "success_2xx": http_success,
            "response_headers": (
                response_headers
            ),
        },
        "request": {
            "content_type": (
                "application/json"
            ),
            "byte_length": len(
                request_body
            ),
            "sha256": request_sha,
            "sha256_after_persist": (
                request_disk_sha
            ),
            "digest_recheck_matches": (
                request_disk_sha
                == request_sha
            ),
            "body_utf8": (
                request_body.decode(
                    "utf-8"
                )
            ),
            "artifact": "request.bin",
        },
        "response": {
            "byte_length": len(
                raw_response
            ),
            "sha256": response_sha,
            "sha256_after_persist": (
                response_disk_sha
            ),
            "digest_recheck_matches": (
                response_disk_sha
                == response_sha
            ),
            "body_utf8": (
                raw_response.decode(
                    "utf-8",
                    errors="replace",
                )
            ),
            "artifact": "response.bin",
        },
        "validation": validation,
        "provenance": provenance(),
        "acceptance": {
            "dns_success": bool(
                dns.get("success")
            ),
            "transport_success": (
                transport_success
            ),
            "http_2xx": http_success,
            "rpc_structure_and_result_valid": (
                structure_success
            ),
            "request_and_response_digest_integrity": (
                digest_integrity
            ),
            "single_observation_accepted": (
                bool(dns.get("success"))
                and transport_success
                and http_success
                and structure_success
                and digest_integrity
            ),
        },
    }

    evidence_path = (
        observation_dir / "evidence.json"
    )

    evidence_path.write_text(
        json.dumps(
            evidence,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return evidence


def pair_summary(
    target: Target,
    observations: List[Dict[str, Any]],
    target_dir: Path,
    run_id: str,
) -> Dict[str, Any]:

    valid_obs = [
        obs
        for obs in observations
        if (
            obs.get(
                "acceptance",
                {},
            ).get(
                "single_observation_accepted"
            )
            and isinstance(
                obs.get(
                    "validation",
                    {},
                ).get(
                    "normalized_result"
                ),
                int,
            )
        )
    ]

    first_valid = (
        valid_obs[0]
        if valid_obs
        else None
    )

    advancing = None

    if first_valid is not None:
        first_value = (
            first_valid[
                "validation"
            ][
                "normalized_result"
            ]
        )

        for obs in valid_obs[1:]:
            if (
                obs[
                    "validation"
                ][
                    "normalized_result"
                ]
                > first_value
            ):
                advancing = obs
                break

    freshness_progression = (
        first_valid is not None
        and advancing is not None
    )

    first_response_sha = (
        first_valid[
            "response"
        ][
            "sha256"
        ]
        if first_valid
        else None
    )

    advancing_response_sha = (
        advancing[
            "response"
        ][
            "sha256"
        ]
        if advancing
        else None
    )

    summary = {
        "schema": (
            "scout.live_rpc_witness.pair_validation.v1"
        ),
        "run_id": run_id,
        "chain": target.chain,
        "network": target.network,
        "endpoint": target.endpoint,
        "method": target.method,
        "execution_authority": (
            EXECUTION_AUTHORITY
        ),
        "observations_attempted": (
            len(observations)
        ),
        "single_observations_accepted": (
            len(valid_obs)
        ),
        "baseline_observation_index": (
            first_valid.get(
                "observation_index"
            )
            if first_valid
            else None
        ),
        "baseline_normalized_result": (
            first_valid.get(
                "validation",
                {},
            ).get(
                "normalized_result"
            )
            if first_valid
            else None
        ),
        "advancing_observation_index": (
            advancing.get(
                "observation_index"
            )
            if advancing
            else None
        ),
        "advancing_normalized_result": (
            advancing.get(
                "validation",
                {},
            ).get(
                "normalized_result"
            )
            if advancing
            else None
        ),
        "freshness": {
            "progression_observed": (
                freshness_progression
            ),
            "strictly_increasing_result": (
                freshness_progression
            ),
            "response_digest_changed": bool(
                freshness_progression
                and first_response_sha
                and advancing_response_sha
                and (
                    first_response_sha
                    != advancing_response_sha
                )
            ),
            "note": (
                "Progression across independently captured responses "
                "is practical liveness/freshness evidence. "
                "It is not a cryptographic proof that a malicious "
                "endpoint could never replay a fabricated increasing "
                "sequence."
            ),
        },
        "pair_accepted": bool(
            freshness_progression
            and first_valid[
                "response"
            ][
                "digest_recheck_matches"
            ]
            and advancing[
                "response"
            ][
                "digest_recheck_matches"
            ]
        )
        if freshness_progression
        else False,
    }

    (
        target_dir
        / "pair_validation.json"
    ).write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return summary


def run_target(
    target: Target,
    run_dir: Path,
    attempts: int,
    interval: float,
    timeout: float,
    run_id: str,
) -> Dict[str, Any]:

    target_dir = run_dir / target.key

    target_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    observations: List[
        Dict[str, Any]
    ] = []

    baseline_value: Optional[int] = None

    for index in range(
        1,
        attempts + 1,
    ):

        obs_dir = (
            target_dir
            / f"observation_{index:02d}"
        )

        evidence = capture_once(
            target,
            obs_dir,
            run_id,
            index,
            timeout,
        )

        observations.append(evidence)

        accepted = evidence[
            "acceptance"
        ][
            "single_observation_accepted"
        ]

        value = evidence[
            "validation"
        ].get(
            "normalized_result"
        )

        if accepted and isinstance(
            value,
            int,
        ):
            if baseline_value is None:
                baseline_value = value
            elif value > baseline_value:
                break

        if index < attempts:
            time.sleep(interval)

    return pair_summary(
        target,
        observations,
        target_dir,
        run_id,
    )


def target_list(
    selection: str,
    include_blockheight: bool,
) -> List[Target]:

    if selection == "solana":
        keys = [
            "solana-slot"
        ]

    elif selection == "arbitrum":
        keys = [
            "arbitrum-block"
        ]

    elif selection == "both":
        keys = [
            "solana-slot",
            "arbitrum-block",
        ]

    else:
        raise ValueError(selection)

    if (
        include_blockheight
        and "solana-slot" in keys
    ):
        keys.append(
            "solana-blockheight"
        )

    return [
        TARGETS[key]
        for key in keys
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Capture genuine read-only "
            "Solana/Arbitrum JSON-RPC "
            "evidence for Scout."
        )
    )

    parser.add_argument(
        "target",
        choices=(
            "solana",
            "arbitrum",
            "both",
        ),
        help=(
            "Hard-coded read-only target(s). "
            "'both' runs LIVE-1 and LIVE-2."
        ),
    )

    parser.add_argument(
        "--include-blockheight",
        action="store_true",
        help=(
            "Also capture Solana "
            "getBlockHeight after getSlot."
        ),
    )

    parser.add_argument(
        "--attempts",
        type=int,
        default=4,
        help=(
            "Maximum observations per target "
            "while looking for progression "
            "(default: 4)."
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help=(
            "Seconds between observations "
            "(default: 1.0)."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help=(
            "HTTP timeout seconds per "
            "observation (default: 10.0)."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path.cwd(),
        help=(
            "Parent output directory "
            "(default: current directory)."
        ),
    )

    args = parser.parse_args()

    if (
        args.attempts < 2
        or args.attempts > 10
    ):
        parser.error(
            "--attempts must be between 2 and 10"
        )

    if (
        args.interval < 0.1
        or args.interval > 30
    ):
        parser.error(
            "--interval must be between 0.1 and 30 seconds"
        )

    if (
        args.timeout < 1
        or args.timeout > 60
    ):
        parser.error(
            "--timeout must be between 1 and 60 seconds"
        )

    run_id = (
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        f"-{uuid.uuid4().hex[:10]}"
    )

    run_dir = (
        args.output.resolve()
        / f"scout_live_rpc_evidence_{run_id}"
    )

    run_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    run_manifest: Dict[str, Any] = {
        "schema": (
            "scout.live_rpc_witness.run.v1"
        ),
        "run_id": run_id,
        "created_at_utc": utc_now_iso(),
        "execution_authority": (
            EXECUTION_AUTHORITY
        ),
        "selection": args.target,
        "include_blockheight": (
            args.include_blockheight
        ),
        "attempts_per_target": (
            args.attempts
        ),
        "interval_seconds": (
            args.interval
        ),
        "timeout_seconds": (
            args.timeout
        ),
        "provenance": provenance(),
        "targets": [],
    }

    all_accepted = True

    for target in target_list(
        args.target,
        args.include_blockheight,
    ):

        print(
            (
                "[Scout LIVE RPC Witness] "
                f"{target.chain}/"
                f"{target.method} -> "
                f"{target.endpoint}"
            ),
            flush=True,
        )

        summary = run_target(
            target,
            run_dir,
            args.attempts,
            args.interval,
            args.timeout,
            run_id,
        )

        run_manifest[
            "targets"
        ].append(
            summary
        )

        all_accepted = (
            all_accepted
            and bool(
                summary[
                    "pair_accepted"
                ]
            )
        )

        status = (
            "PASS"
            if summary[
                "pair_accepted"
            ]
            else "FAIL"
        )

        print(
            (
                f"  {status}: "
                f"baseline="
                f"{summary['baseline_normalized_result']} "
                f"advancing="
                f"{summary['advancing_normalized_result']}"
            ),
            flush=True,
        )

    run_manifest[
        "completed_at_utc"
    ] = utc_now_iso()

    run_manifest[
        "all_requested_targets_accepted"
    ] = all_accepted

    manifest_path = (
        run_dir
        / "run_manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            run_manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"Evidence directory: {run_dir}"
    )

    print(
        f"Run manifest: {manifest_path}"
    )

    return (
        0
        if all_accepted
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
