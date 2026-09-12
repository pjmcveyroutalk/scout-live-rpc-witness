#!/usr/bin/env python3
"""Measure exact Raydium pool-info reserve convergence after confirmed on-chain changes.

Read-only observation. Compares confirmed raw vault balances for the locked WSOL/USDC
CPMM pool with Raydium public pool-info mintAmountA/B converted back to raw units.
No wallets, signing, transaction construction, simulation, submission, or broadcasting.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping

RPC = "https://api.mainnet-beta.solana.com"
POOL = "fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
WSOL = "So11111111111111111111111111111111111111112"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
WSOL_VAULT = "v3YN4d7JRhKFcwtex7qNtyg2r5hKYW96Cayb6GivSvY"
USDC_VAULT = "HG2WgeYsjqQhnjhwHj7QdTVvjyWpFRk6VREAQ8MURv2u"
API = f"https://api-v3.raydium.io/pools/info/ids?ids={POOL}"
RUNTIME = 240.0
POLL = 1.0
TOKEN_AMOUNT_OFFSET = 64


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def request_json(url: str, data: bytes | None = None, headers: Mapping[str, str] | None = None, timeout: float = 20) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET", headers=dict(headers or {}))
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return int(response.status), response.read()


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
    delay = 0.4
    for attempt in range(7):
        try:
            status, raw = request_json(RPC, body, {"content-type": "application/json", "user-agent": "Ghost-Ray-Reserve-Convergence/1"})
            obj = json.loads(raw)
            if status != 200 or not isinstance(obj, Mapping) or obj.get("error") is not None:
                raise RuntimeError(f"RPC {method}: {obj.get('error') if isinstance(obj, Mapping) else status}")
            return obj.get("result")
        except Exception:
            if attempt == 6:
                raise
            time.sleep(delay)
            delay = min(delay * 2.0, 6.0)
    raise RuntimeError("RPC unreachable")


def token_amount(account: Mapping[str, Any]) -> int:
    data = account.get("data")
    if not isinstance(data, list) or not data or not isinstance(data[0], str):
        raise RuntimeError("token account base64 missing")
    raw = base64.b64decode(data[0], validate=True)
    if len(raw) < TOKEN_AMOUNT_OFFSET + 8:
        raise RuntimeError("token account too short")
    return int.from_bytes(raw[TOKEN_AMOUNT_OFFSET:TOKEN_AMOUNT_OFFSET + 8], "little")


def chain_sample() -> dict[str, Any]:
    result = rpc("getMultipleAccounts", [[WSOL_VAULT, USDC_VAULT], {"encoding": "base64", "commitment": "confirmed"}])
    if not isinstance(result, Mapping) or not isinstance(result.get("context"), Mapping):
        raise RuntimeError("invalid chain sample")
    values = result.get("value")
    if not isinstance(values, list) or len(values) != 2 or any(not isinstance(x, Mapping) for x in values):
        raise RuntimeError("incomplete vault sample")
    return {
        "at": now(),
        "slot": int(result["context"]["slot"]),
        "wsol_raw": token_amount(values[0]),
        "usdc_raw": token_amount(values[1]),
    }


def nested_addr(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key in ("address", "mint", "id"):
            if isinstance(value.get(key), str):
                return str(value[key])
    return value if isinstance(value, str) else None


def to_raw(value: Any, decimals: int) -> int | None:
    if value is None:
        return None
    try:
        d = Decimal(str(value)) * (Decimal(10) ** decimals)
        integral = d.to_integral_value()
        if abs(d - integral) > Decimal("0.000001"):
            return None
        return int(integral)
    except (InvalidOperation, ValueError, TypeError):
        return None


def api_row() -> Mapping[str, Any]:
    status, raw = request_json(API, headers={"accept": "application/json", "cache-control": "no-cache", "pragma": "no-cache", "user-agent": "Ghost-Ray-Reserve-Convergence/1"})
    obj = json.loads(raw)
    if status != 200 or not isinstance(obj, Mapping) or obj.get("success") is not True:
        raise RuntimeError(f"Raydium API status/shape {status}")
    data = obj.get("data")
    row: Any = None
    if isinstance(data, list) and data:
        row = data[0]
    elif isinstance(data, Mapping):
        rows = data.get("data")
        if isinstance(rows, list) and rows:
            row = rows[0]
    if not isinstance(row, Mapping):
        raise RuntimeError("Raydium pool row missing")
    return row


def api_sample() -> dict[str, Any]:
    row = api_row()
    mint_a = nested_addr(row.get("mintA"))
    mint_b = nested_addr(row.get("mintB"))
    amount_a = row.get("mintAmountA")
    amount_b = row.get("mintAmountB")
    mapped: dict[str, int | None] = {"wsol_raw": None, "usdc_raw": None}
    if mint_a == WSOL:
        mapped["wsol_raw"] = to_raw(amount_a, 9)
    elif mint_a == USDC:
        mapped["usdc_raw"] = to_raw(amount_a, 6)
    if mint_b == WSOL:
        mapped["wsol_raw"] = to_raw(amount_b, 9)
    elif mint_b == USDC:
        mapped["usdc_raw"] = to_raw(amount_b, 6)
    return {
        "at": now(),
        "mint_a": mint_a,
        "mint_b": mint_b,
        "mint_amount_a": str(amount_a) if amount_a is not None else None,
        "mint_amount_b": str(amount_b) if amount_b is not None else None,
        "wsol_raw": mapped["wsol_raw"],
        "usdc_raw": mapped["usdc_raw"],
        "price": row.get("price"),
    }


def main() -> int:
    started = now()
    samples: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    convergence: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    prior_pair: tuple[int, int] | None = None
    pending: list[dict[str, Any]] = []
    t0 = time.monotonic()

    while time.monotonic() - t0 < RUNTIME:
        tick = time.monotonic()
        try:
            chain = chain_sample()
            api = api_sample()
            pair = (int(chain["wsol_raw"]), int(chain["usdc_raw"]))
            sample = {"at": now(), "chain": chain, "api": api, "exact_match": api.get("wsol_raw") == pair[0] and api.get("usdc_raw") == pair[1]}
            samples.append(sample)

            if prior_pair is None or pair != prior_pair:
                event = {
                    "change_index": len(changes) + 1,
                    "observed_at": sample["at"],
                    "slot": chain["slot"],
                    "wsol_raw": pair[0],
                    "usdc_raw": pair[1],
                    "api_wsol_raw_at_change": api.get("wsol_raw"),
                    "api_usdc_raw_at_change": api.get("usdc_raw"),
                    "api_already_equal": sample["exact_match"],
                }
                changes.append(event)
                if not sample["exact_match"]:
                    pending.append({**event, "started_monotonic": time.monotonic()})
                else:
                    convergence.append({**event, "converged_at": sample["at"], "lag_seconds": 0.0})
                prior_pair = pair

            still_pending = []
            for event in pending:
                if api.get("wsol_raw") == event["wsol_raw"] and api.get("usdc_raw") == event["usdc_raw"]:
                    convergence.append({
                        **{k: v for k, v in event.items() if k != "started_monotonic"},
                        "converged_at": sample["at"],
                        "lag_seconds": round(time.monotonic() - float(event["started_monotonic"]), 3),
                    })
                else:
                    still_pending.append(event)
            pending = still_pending
        except Exception as exc:
            errors.append({"at": now(), "error": f"{type(exc).__name__}:{exc}"})
        time.sleep(max(0.0, POLL - (time.monotonic() - tick)))

    unresolved = [
        {
            **{k: v for k, v in event.items() if k != "started_monotonic"},
            "minimum_lag_seconds": round(time.monotonic() - float(event["started_monotonic"]), 3),
        }
        for event in pending
    ]
    completed = now()
    ev = {
        "schema": "ghost.raydium_exact_reserve_convergence.v1",
        "accepted": True,
        "observation_only": True,
        "execution_authority": False,
        "started_at": started,
        "completed_at": completed,
        "runtime_seconds": RUNTIME,
        "target_pool": POOL,
        "vaults": {"wsol": WSOL_VAULT, "usdc": USDC_VAULT},
        "raydium_api": API,
        "sample_count": len(samples),
        "reserve_change_events": changes,
        "convergence_events": convergence,
        "unresolved_events": unresolved,
        "counts": {
            "samples": len(samples),
            "reserve_changes_including_initial": len(changes),
            "converged_events": len(convergence),
            "unresolved_events": len(unresolved),
            "errors": len(errors),
        },
        "errors": errors,
        "interpretation_rule": "Lag is measured only when both Raydium API reserve amounts equal the exact confirmed raw WSOL and USDC vault amounts for a newly observed reserve pair. This is public pool-info convergence, not proof of executable quote lag or profitability.",
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
    stamp = started.replace(":", "").replace("-", "").replace(".", "_")
    bundle = Path("live-evidence") / f"raydium-exact-reserve-convergence-{stamp}"
    bundle.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(ev, sort_keys=True, indent=2) + "\n").encode()
    (bundle / "evidence.json").write_bytes(raw)
    (bundle / "evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n", encoding="utf-8")
    print(json.dumps({"counts": ev["counts"], "convergence": convergence, "unresolved": unresolved}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
