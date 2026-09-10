#!/usr/bin/env python3
"""Permanent Scout Lab read-only test harness.

Runs one or more explicitly selected Python witness files, captures stdout/stderr,
detects newly created live-evidence, validates the evidence safety boundary,
writes a machine-readable lab summary, and exits nonzero on any failed witness
or unsafe/malformed evidence.

This harness itself has no wallet, signer, transaction builder, submission
authority, secrets, or capital authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

ROOT = Path(__file__).resolve().parent
EVIDENCE_ROOT = ROOT / "live-evidence"
SUMMARY_ROOT = ROOT / "lab-run-summaries"

EXECUTION_AUTHORITY = False
TEST_NAME_RE = re.compile(r"^t[0-9]{3}_[A-Za-z0-9_.-]+\.py$")

FORBIDDEN_TRUE_SAFETY_KEYS = {
    "wallet",
    "signer",
    "approval",
    "transaction_builder",
    "transaction_serialization",
    "transaction_simulation",
    "transaction_submission",
    "broadcast",
    "bridge_execution",
    "capital_movement",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def snapshot_files(root: Path) -> Set[Path]:
    if not root.exists():
        return set()
    return {p.resolve() for p in root.rglob("*") if p.is_file()}


def validate_test_path(raw: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"unsafe test path: {raw}")
    if len(candidate.parts) != 1:
        raise ValueError(
            f"tests must live at repository root: {raw}"
        )
    if not TEST_NAME_RE.fullmatch(candidate.name):
        raise ValueError(
            f"test filename must match tNNN_description.py: {raw}"
        )

    resolved = (ROOT / candidate).resolve()
    if resolved.parent != ROOT:
        raise ValueError(f"test escaped repository root: {raw}")
    if not resolved.is_file():
        raise FileNotFoundError(f"test not found: {raw}")
    return resolved


def evidence_json_files(paths: Iterable[Path]) -> List[Path]:
    return sorted(
        path for path in paths
        if path.name == "evidence.json"
    )


def validate_evidence(path: Path) -> Dict[str, Any]:
    errors: List[str] = []
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "path": str(path.relative_to(ROOT)),
            "valid": False,
            "errors": [f"invalid JSON: {type(exc).__name__}: {exc}"],
        }

    if not isinstance(obj, dict):
        errors.append("evidence root must be a JSON object")
        obj = {}

    if obj.get("accepted") is not True:
        errors.append("accepted must be true")

    if obj.get("execution_authority") is not False:
        errors.append("execution_authority must be false")

    safety = obj.get("safety")
    if not isinstance(safety, dict):
        errors.append("safety object is required")
    else:
        for key in sorted(FORBIDDEN_TRUE_SAFETY_KEYS):
            if key in safety and safety.get(key) is not False:
                errors.append(f"safety.{key} must be false")

    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256_file(path),
        "schema": obj.get("schema"),
        "accepted": obj.get("accepted"),
        "execution_authority": obj.get("execution_authority"),
        "valid": not errors,
        "errors": errors,
    }


def run_one(test_path: Path) -> Dict[str, Any]:
    before = snapshot_files(EVIDENCE_ROOT)
    started = utc_now()
    mono_start = time.monotonic_ns()

    proc = subprocess.run(
        [sys.executable, str(test_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "SCOUT_LAB_READ_ONLY": "1",
            "SCOUT_LAB_EXECUTION_AUTHORITY": "false",
        },
        check=False,
        timeout=15 * 60,
    )

    mono_end = time.monotonic_ns()
    completed = utc_now()
    after = snapshot_files(EVIDENCE_ROOT)
    created = after - before

    new_evidence = evidence_json_files(created)
    evidence_results = [validate_evidence(path) for path in new_evidence]

    errors: List[str] = []
    if proc.returncode != 0:
        errors.append(f"witness exit code {proc.returncode}")
    if not new_evidence:
        errors.append("witness created no new evidence.json")
    if any(not result["valid"] for result in evidence_results):
        errors.append("one or more evidence files failed safety/acceptance validation")

    return {
        "test": test_path.name,
        "test_sha256": sha256_file(test_path),
        "started_at_utc": started,
        "completed_at_utc": completed,
        "duration_ms": round((mono_end - mono_start) / 1_000_000, 3),
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "created_file_count": len(created),
        "new_evidence": evidence_results,
        "passed": not errors,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "tests",
        nargs="+",
        help="One or more repo-root witness files named tNNN_description.py",
    )
    args = parser.parse_args()

    selected: List[Path] = []
    selection_errors: List[str] = []
    for raw in args.tests:
        try:
            selected.append(validate_test_path(raw))
        except Exception as exc:
            selection_errors.append(f"{raw}: {type(exc).__name__}: {exc}")

    SUMMARY_ROOT.mkdir(exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "").replace(".", "_")
    summary_path = SUMMARY_ROOT / f"scout-lab-run-{stamp}.json"

    results: List[Dict[str, Any]] = []
    if not selection_errors:
        for test_path in selected:
            try:
                results.append(run_one(test_path))
            except subprocess.TimeoutExpired:
                results.append(
                    {
                        "test": test_path.name,
                        "passed": False,
                        "errors": ["witness exceeded 15-minute harness timeout"],
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "test": test_path.name,
                        "passed": False,
                        "errors": [f"{type(exc).__name__}: {exc}"],
                    }
                )

    passed = (
        not selection_errors
        and bool(results)
        and all(result.get("passed") is True for result in results)
    )

    summary = {
        "schema": "scout.lab_harness.run.v1",
        "accepted": passed,
        "observation_only": True,
        "execution_authority": EXECUTION_AUTHORITY,
        "selected_tests": [path.name for path in selected],
        "selection_errors": selection_errors,
        "results": results,
        "github": {
            "repository": os.getenv("GITHUB_REPOSITORY"),
            "sha": os.getenv("GITHUB_SHA"),
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "workflow": os.getenv("GITHUB_WORKFLOW"),
            "event_name": os.getenv("GITHUB_EVENT_NAME"),
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
    summary_path.write_bytes(json_bytes(summary))

    print(json.dumps(
        {
            "accepted": passed,
            "tests": [
                {
                    "test": result.get("test"),
                    "passed": result.get("passed"),
                    "evidence_count": len(result.get("new_evidence", [])),
                    "errors": result.get("errors", []),
                }
                for result in results
            ],
            "selection_errors": selection_errors,
            "summary_path": str(summary_path.relative_to(ROOT)),
            "execution_authority": False,
        },
        indent=2,
    ))

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

