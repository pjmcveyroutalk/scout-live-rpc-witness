#!/usr/bin/env python3
"""
Scout LIVE RPC Quorum Witness

Purpose:
    Obtain genuinely independent read-only RPC observations from two
    providers on Solana and two providers on Arbitrum, then test whether
    those observations form a bounded live quorum.

This script imports the already-verified scout_live_rpc_witness.py and
therefore preserves its:
    - exact request-byte capture
    - exact response-byte capture
    - SHA-256 evidence binding
    - DNS evidence
    - TLS/HTTP evidence
    - JSON-RPC validation
    - provenance metadata
    - execution_authority = false boundary

No arbitrary RPC URLs or methods are accepted.

Allowed observations only:
    Solana:
        Provider A: https://api.mainnet.solana.com
        Provider B: https://solana-rpc.publicnode.com
        Method: getSlot

    Arbitrum:
        Provider A: https://arb1.arbitrum.io/rpc
        Provider B: https://arbitrum-one-rpc.publicnode.com
        Method: eth_blockNumber

This program cannot sign, build, simulate, submit, bridge,
broadcast, or move capital.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from scout_live_rpc_witness import (
    EXECUTION_AUTHORITY,
    Target,
    capture_once,
    provenance,
)

QUORUM_WITNESS_VERSION = "1.0.0"


@dataclass(frozen=True)
class RpcSource:
    source_id: str
    provider_id: str
    target: Target


SOLANA_SOURCE_A = RpcSource(
    source_id="solana-source-a",
    provider_id="solana-foundation-mainnet",
    target=Target(
        key="solana-source-a",
        chain="solana",
        network="mainnet-beta",
        endpoint="https://api.mainnet.solana.com",
        method="getSlot",
        params=[{"commitment": "finalized"}],
        result_kind="positive_integer",
    ),
)

SOLANA_SOURCE_B = RpcSource(
    source_id="solana-source-b",
    provider_id="publicnode-solana-mainnet",
    target=Target(
        key="solana-source-b",
        chain="solana",
        network="mainnet-beta",
        endpoint="https://solana-rpc.publicnode.com",
        method="getSlot",
        params=[{"commitment": "finalized"}],
        result_kind="positive_integer",
    ),
)

ARBITRUM_SOURCE_A = RpcSource(
    source_id="arbitrum-source-a",
    provider_id="arbitrum-official-rpc",
    target=Target(
        key="arbitrum-source-a",
        chain="arbitrum",
        network="arbitrum-one",
        endpoint="https://arb1.arbitrum.io/rpc",
        method="eth_blockNumber",
        params=[],
        result_kind="positive_hex_quantity",
    ),
)

ARBITRUM_SOURCE_B = RpcSource(
    source_id="arbitrum-source-b",
    provider_id="publicnode-arbitrum-one",
    target=Target(
        key="arbitrum-source-b",
        chain="arbitrum",
        network="arbitrum-one",
        endpoint="https://arbitrum-one-rpc.publicnode.com",
        method="eth_blockNumber",
        params=[],
        result_kind="positive_hex_quantity",
    ),
)


CHAIN_SOURCES: Dict[str, Tuple[RpcSource, RpcSource]] = {
    "solana": (
        SOLANA_SOURCE_A,
        SOLANA_SOURCE_B,
    ),
    "arbitrum": (
        ARBITRUM_SOURCE_A,
        ARBITRUM_SOURCE_B,
    ),
}


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def sha256_json(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def endpoint_identity(endpoint: str) -> Dict[str, Optional[str]]:
    parsed = urlparse(endpoint)

    return {
        "scheme": parsed.scheme or None,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
    }


def accepted_value(
    evidence: Dict[str, Any],
) -> Optional[int]:
    acceptance = evidence.get("acceptance", {})

    if not acceptance.get("single_observation_accepted"):
        return None

    value = evidence.get(
        "validation",
        {},
    ).get("normalized_result")

    if isinstance(value, bool):
        return None

    if not isinstance(value, int):
        return None

    if value <= 0:
        return None

    return value


def evidence_fingerprint(
    evidence: Dict[str, Any],
) -> str:
    payload = {
        "chain": evidence.get("chain"),
        "network": evidence.get("network"),
        "endpoint": evidence.get("endpoint"),
        "method": evidence.get("method"),
        "request_sha256": evidence.get(
            "request",
            {},
        ).get("sha256"),
        "response_sha256": evidence.get(
            "response",
            {},
        ).get("sha256"),
        "request_started_at_utc": evidence.get(
            "request_started_at_utc"
        ),
        "response_completed_at_utc": evidence.get(
            "response_completed_at_utc"
        ),
        "normalized_result": evidence.get(
            "validation",
            {},
        ).get("normalized_result"),
        "execution_authority": evidence.get(
            "execution_authority"
        ),
    }

    return sha256_json(payload)


def validate_source_independence(
    left: RpcSource,
    right: RpcSource,
) -> Tuple[bool, List[str]]:
    rejection_codes: List[str] = []

    if left.source_id == right.source_id:
        rejection_codes.append(
            "QUORUM_DUPLICATE_SOURCE_ID"
        )

    if left.provider_id == right.provider_id:
        rejection_codes.append(
            "QUORUM_DUPLICATE_PROVIDER_ID"
        )

    if left.target.endpoint == right.target.endpoint:
        rejection_codes.append(
            "QUORUM_DUPLICATE_ENDPOINT"
        )

    left_host = endpoint_identity(
        left.target.endpoint
    ).get("hostname")

    right_host = endpoint_identity(
        right.target.endpoint
    ).get("hostname")

    if left_host == right_host:
        rejection_codes.append(
            "QUORUM_DUPLICATE_HOSTNAME"
        )

    if left.target.chain != right.target.chain:
        rejection_codes.append(
            "QUORUM_CHAIN_MISMATCH"
        )

    if left.target.network != right.target.network:
        rejection_codes.append(
            "QUORUM_NETWORK_MISMATCH"
        )

    if left.target.method != right.target.method:
        rejection_codes.append(
            "QUORUM_METHOD_MISMATCH"
        )

    return (
        len(rejection_codes) == 0,
        rejection_codes,
    )


def evaluate_round(
    *,
    chain: str,
    source_a: RpcSource,
    source_b: RpcSource,
    evidence_a: Dict[str, Any],
    evidence_b: Dict[str, Any],
    max_divergence: int,
    round_number: int,
) -> Dict[str, Any]:
    rejection_codes: List[str] = []

    independence_ok, independence_rejections = (
        validate_source_independence(
            source_a,
            source_b,
        )
    )

    rejection_codes.extend(
        independence_rejections
    )

    value_a = accepted_value(evidence_a)
    value_b = accepted_value(evidence_b)

    if value_a is None:
        rejection_codes.append(
            "QUORUM_SOURCE_A_OBSERVATION_INVALID"
        )

    if value_b is None:
        rejection_codes.append(
            "QUORUM_SOURCE_B_OBSERVATION_INVALID"
        )

    if evidence_a.get("chain") != chain:
        rejection_codes.append(
            "QUORUM_SOURCE_A_CHAIN_BINDING_INVALID"
        )

    if evidence_b.get("chain") != chain:
        rejection_codes.append(
            "QUORUM_SOURCE_B_CHAIN_BINDING_INVALID"
        )

    if evidence_a.get("execution_authority") is not False:
        rejection_codes.append(
            "QUORUM_SOURCE_A_EXECUTION_AUTHORITY_INVALID"
        )

    if evidence_b.get("execution_authority") is not False:
        rejection_codes.append(
            "QUORUM_SOURCE_B_EXECUTION_AUTHORITY_INVALID"
        )

    divergence: Optional[int] = None

    if value_a is not None and value_b is not None:
        divergence = abs(value_a - value_b)

        if divergence > max_divergence:
            rejection_codes.append(
                "QUORUM_DIVERGENCE_EXCEEDED"
            )

    accepted = (
        independence_ok
        and value_a is not None
        and value_b is not None
        and divergence is not None
        and divergence <= max_divergence
        and not rejection_codes
    )

    fingerprint_payload = {
        "chain": chain,
        "round_number": round_number,
        "source_a_provider": source_a.provider_id,
        "source_b_provider": source_b.provider_id,
        "source_a_endpoint": source_a.target.endpoint,
        "source_b_endpoint": source_b.target.endpoint,
        "source_a_evidence_fingerprint": (
            evidence_fingerprint(evidence_a)
        ),
        "source_b_evidence_fingerprint": (
            evidence_fingerprint(evidence_b)
        ),
        "source_a_value": value_a,
        "source_b_value": value_b,
        "divergence": divergence,
        "max_divergence": max_divergence,
        "execution_authority": False,
    }

    quorum_fingerprint = (
        sha256_json(fingerprint_payload)
        if accepted
        else None
    )

    return {
        "schema": (
            "scout.live_rpc_quorum.round.v1"
        ),
        "quorum_witness_version": (
            QUORUM_WITNESS_VERSION
        ),
        "chain": chain,
        "round_number": round_number,
        "execution_authority": False,
        "source_independence": {
            "accepted": independence_ok,
            "source_a": {
                "source_id": source_a.source_id,
                "provider_id": source_a.provider_id,
                "endpoint": source_a.target.endpoint,
                "endpoint_identity": endpoint_identity(
                    source_a.target.endpoint
                ),
            },
            "source_b": {
                "source_id": source_b.source_id,
                "provider_id": source_b.provider_id,
                "endpoint": source_b.target.endpoint,
                "endpoint_identity": endpoint_identity(
                    source_b.target.endpoint
                ),
            },
        },
        "source_a_normalized_result": value_a,
        "source_b_normalized_result": value_b,
        "absolute_divergence": divergence,
        "maximum_allowed_divergence": max_divergence,
        "quorum_accepted": accepted,
        "quorum_fingerprint": quorum_fingerprint,
        "rejection_codes": rejection_codes,
    }


def capture_source(
    *,
    source: RpcSource,
    round_dir: Path,
    run_id: str,
    round_number: int,
    timeout: float,
) -> Dict[str, Any]:
    source_dir = (
        round_dir
        / source.source_id
    )

    print(
        (
            f"    {source.provider_id}: "
            f"{source.target.endpoint}"
        ),
        flush=True,
    )

    return capture_once(
        source.target,
        source_dir,
        run_id,
        round_number,
        timeout,
    )


def evaluate_progression(
    round_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if len(round_results) < 2:
        return {
            "progression_evaluable": False,
            "source_a_non_regression": False,
            "source_b_non_regression": False,
            "at_least_one_source_advanced": False,
            "accepted": False,
        }

    first = round_results[0]
    last = round_results[-1]

    a1 = first.get(
        "source_a_normalized_result"
    )

    a2 = last.get(
        "source_a_normalized_result"
    )

    b1 = first.get(
        "source_b_normalized_result"
    )

    b2 = last.get(
        "source_b_normalized_result"
    )

    values_valid = all(
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
        for value in (
            a1,
            a2,
            b1,
            b2,
        )
    )

    if not values_valid:
        return {
            "progression_evaluable": False,
            "source_a_non_regression": False,
            "source_b_non_regression": False,
            "at_least_one_source_advanced": False,
            "accepted": False,
        }

    source_a_non_regression = a2 >= a1
    source_b_non_regression = b2 >= b1

    at_least_one_source_advanced = (
        a2 > a1
        or b2 > b1
    )

    accepted = (
        source_a_non_regression
        and source_b_non_regression
        and at_least_one_source_advanced
    )

    return {
        "progression_evaluable": True,
        "source_a_initial": a1,
        "source_a_final": a2,
        "source_b_initial": b1,
        "source_b_final": b2,
        "source_a_non_regression": (
            source_a_non_regression
        ),
        "source_b_non_regression": (
            source_b_non_regression
        ),
        "at_least_one_source_advanced": (
            at_least_one_source_advanced
        ),
        "accepted": accepted,
    }


def run_chain_quorum(
    *,
    chain: str,
    run_dir: Path,
    run_id: str,
    rounds: int,
    round_interval: float,
    source_gap: float,
    timeout: float,
    max_divergence: int,
) -> Dict[str, Any]:
    source_a, source_b = (
        CHAIN_SOURCES[chain]
    )

    chain_dir = run_dir / chain

    chain_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    round_results: List[
        Dict[str, Any]
    ] = []

    for round_number in range(
        1,
        rounds + 1,
    ):
        print(
            (
                f"[Scout RPC Quorum] "
                f"{chain} round "
                f"{round_number}/{rounds}"
            ),
            flush=True,
        )

        round_dir = (
            chain_dir
            / f"round_{round_number:02d}"
        )

        round_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        evidence_a = capture_source(
            source=source_a,
            round_dir=round_dir,
            run_id=run_id,
            round_number=round_number,
            timeout=timeout,
        )

        time.sleep(source_gap)

        evidence_b = capture_source(
            source=source_b,
            round_dir=round_dir,
            run_id=run_id,
            round_number=round_number,
            timeout=timeout,
        )

        result = evaluate_round(
            chain=chain,
            source_a=source_a,
            source_b=source_b,
            evidence_a=evidence_a,
            evidence_b=evidence_b,
            max_divergence=max_divergence,
            round_number=round_number,
        )

        (
            round_dir
            / "quorum_result.json"
        ).write_text(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        round_results.append(result)

        status = (
            "PASS"
            if result["quorum_accepted"]
            else "FAIL"
        )

        print(
            (
                f"    {status}: "
                f"A="
                f"{result['source_a_normalized_result']} "
                f"B="
                f"{result['source_b_normalized_result']} "
                f"delta="
                f"{result['absolute_divergence']}"
            ),
            flush=True,
        )

        if round_number < rounds:
            time.sleep(round_interval)

    progression = evaluate_progression(
        round_results
    )

    accepted_rounds = [
        result
        for result in round_results
        if result["quorum_accepted"]
    ]

    chain_accepted = (
        len(accepted_rounds) >= 1
        and progression["accepted"]
    )

    chain_summary = {
        "schema": (
            "scout.live_rpc_quorum.chain.v1"
        ),
        "run_id": run_id,
        "chain": chain,
        "execution_authority": False,
        "rounds_attempted": rounds,
        "rounds_accepted": len(
            accepted_rounds
        ),
        "max_divergence": max_divergence,
        "progression": progression,
        "chain_quorum_accepted": (
            chain_accepted
        ),
        "round_results": round_results,
    }

    (
        chain_dir
        / "chain_quorum_summary.json"
    ).write_text(
        json.dumps(
            chain_summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return chain_summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Capture independent read-only "
            "Solana and Arbitrum RPC evidence "
            "and evaluate genuine two-source quorum."
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
            "Chain quorum to test."
        ),
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=2,
        help=(
            "Number of independent quorum rounds "
            "(default: 2)."
        ),
    )

    parser.add_argument(
        "--round-interval",
        type=float,
        default=1.5,
        help=(
            "Seconds between quorum rounds "
            "(default: 1.5)."
        ),
    )

    parser.add_argument(
        "--source-gap",
        type=float,
        default=0.05,
        help=(
            "Seconds between provider A and B "
            "within one quorum round "
            "(default: 0.05)."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help=(
            "HTTP timeout per RPC request "
            "(default: 10)."
        ),
    )

    parser.add_argument(
        "--solana-max-divergence",
        type=int,
        default=64,
        help=(
            "Maximum allowed Solana slot "
            "difference between sources "
            "(default: 64)."
        ),
    )

    parser.add_argument(
        "--arbitrum-max-divergence",
        type=int,
        default=32,
        help=(
            "Maximum allowed Arbitrum block "
            "difference between sources "
            "(default: 32)."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path.cwd(),
        help=(
            "Parent output directory."
        ),
    )

    args = parser.parse_args()

    if args.rounds < 2 or args.rounds > 10:
        parser.error(
            "--rounds must be between 2 and 10"
        )

    if (
        args.round_interval < 0.1
        or args.round_interval > 30
    ):
        parser.error(
            "--round-interval must be between "
            "0.1 and 30 seconds"
        )

    if (
        args.source_gap < 0
        or args.source_gap > 5
    ):
        parser.error(
            "--source-gap must be between "
            "0 and 5 seconds"
        )

    if args.timeout < 1 or args.timeout > 60:
        parser.error(
            "--timeout must be between "
            "1 and 60 seconds"
        )

    if args.solana_max_divergence < 0:
        parser.error(
            "--solana-max-divergence "
            "must be non-negative"
        )

    if args.arbitrum_max_divergence < 0:
        parser.error(
            "--arbitrum-max-divergence "
            "must be non-negative"
        )

    run_id = (
        "quorum-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-"
        + uuid.uuid4().hex[:10]
    )

    run_dir = (
        args.output.resolve()
        / f"scout_live_rpc_quorum_{run_id}"
    )

    run_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    chains: List[str]

    if args.target == "both":
        chains = [
            "solana",
            "arbitrum",
        ]
    else:
        chains = [
            args.target
        ]

    manifest: Dict[str, Any] = {
        "schema": (
            "scout.live_rpc_quorum.run.v1"
        ),
        "quorum_witness_version": (
            QUORUM_WITNESS_VERSION
        ),
        "run_id": run_id,
        "created_at_utc": utc_now_iso(),
        "execution_authority": (
            EXECUTION_AUTHORITY
        ),
        "selection": args.target,
        "rounds": args.rounds,
        "round_interval_seconds": (
            args.round_interval
        ),
        "source_gap_seconds": (
            args.source_gap
        ),
        "timeout_seconds": args.timeout,
        "provenance": provenance(),
        "chains": [],
    }

    all_accepted = True

    for chain in chains:
        if chain == "solana":
            max_divergence = (
                args.solana_max_divergence
            )
        else:
            max_divergence = (
                args.arbitrum_max_divergence
            )

        summary = run_chain_quorum(
            chain=chain,
            run_dir=run_dir,
            run_id=run_id,
            rounds=args.rounds,
            round_interval=args.round_interval,
            source_gap=args.source_gap,
            timeout=args.timeout,
            max_divergence=max_divergence,
        )

        manifest["chains"].append(
            summary
        )

        all_accepted = (
            all_accepted
            and bool(
                summary[
                    "chain_quorum_accepted"
                ]
            )
        )

    manifest["completed_at_utc"] = (
        utc_now_iso()
    )

    manifest[
        "all_requested_chain_quorums_accepted"
    ] = all_accepted

    manifest[
        "execution_authority"
    ] = False

    manifest_fingerprint_payload = {
        "run_id": run_id,
        "chains": [
            {
                "chain": item["chain"],
                "accepted": item[
                    "chain_quorum_accepted"
                ],
                "rounds_accepted": item[
                    "rounds_accepted"
                ],
            }
            for item in manifest["chains"]
        ],
        "execution_authority": False,
    }

    manifest[
        "run_fingerprint"
    ] = sha256_json(
        manifest_fingerprint_payload
    )

    manifest_path = (
        run_dir
        / "quorum_run_manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print(
        "======================================="
    )
    print(
        "Scout LIVE RPC Quorum Witness"
    )
    print(
        "======================================="
    )

    for chain_summary in manifest["chains"]:
        status = (
            "PASS"
            if chain_summary[
                "chain_quorum_accepted"
            ]
            else "FAIL"
        )

        print(
            (
                f"{chain_summary['chain']}: "
                f"{status} "
                f"({chain_summary['rounds_accepted']}"
                f"/{chain_summary['rounds_attempted']} "
                f"rounds accepted)"
            )
        )

    print(
        (
            "execution_authority: "
            f"{EXECUTION_AUTHORITY}"
        )
    )

    print(
        f"Evidence directory: {run_dir}"
    )

    print(
        f"Manifest: {manifest_path}"
    )

    return 0 if all_accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
