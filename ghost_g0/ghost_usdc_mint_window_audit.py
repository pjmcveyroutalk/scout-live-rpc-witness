#!/usr/bin/env python3
"""Read-only audit for independent USDC mint writes inside a Ghost S0/S1 window."""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any, Mapping

RPC_URL = "https://api.mainnet-beta.solana.com"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    req = urllib.request.Request(
        RPC_URL,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "user-agent": "Ghost-USDC-Window-Audit/1"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, Mapping) or payload.get("error") is not None:
        raise RuntimeError(f"RPC failure {method}: {payload.get('error') if isinstance(payload, Mapping) else 'shape'}")
    return payload.get("result")


def history_to_slot(s0_slot: int, max_pages: int) -> tuple[list[Mapping[str, Any]], int | None, int]:
    all_rows: list[Mapping[str, Any]] = []
    before: str | None = None
    min_slot: int | None = None
    pages = 0
    for _ in range(max_pages):
        cfg: dict[str, Any] = {"commitment": "finalized", "limit": 1000}
        if before is not None:
            cfg["before"] = before
        rows = rpc("getSignaturesForAddress", [USDC_MINT, cfg])
        if not isinstance(rows, list):
            raise RuntimeError("invalid signature history")
        pages += 1
        if not rows:
            break
        page_rows = [row for row in rows if isinstance(row, Mapping)]
        all_rows.extend(page_rows)
        slots = [int(row.get("slot", -1)) for row in page_rows]
        if slots:
            page_min = min(slots)
            min_slot = page_min if min_slot is None else min(min_slot, page_min)
            if page_min <= s0_slot:
                break
        last_sig = page_rows[-1].get("signature") if page_rows else None
        if not isinstance(last_sig, str):
            break
        before = last_sig
    return all_rows, min_slot, pages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--s0-slot", type=int, required=True)
    ap.add_argument("--s1-slot", type=int, required=True)
    ap.add_argument("--target-signature", required=True)
    ap.add_argument("--max-pages", type=int, default=30)
    ap.add_argument("--output", default="USDC_MINT_WINDOW_AUDIT.json")
    args = ap.parse_args()

    rows, min_slot, pages = history_to_slot(args.s0_slot, args.max_pages)
    coverage_ok = min_slot is not None and min_slot <= args.s0_slot

    in_window = []
    for row in rows:
        slot = int(row.get("slot", -1))
        signature = row.get("signature")
        if not isinstance(signature, str) or not (args.s0_slot < slot <= args.s1_slot):
            continue
        tx = rpc(
            "getTransaction",
            [
                signature,
                {
                    "commitment": "finalized",
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
        writable = None
        tx_error = None
        if isinstance(tx, Mapping):
            meta = tx.get("meta")
            if isinstance(meta, Mapping):
                tx_error = meta.get("err")
            transaction = tx.get("transaction")
            if isinstance(transaction, Mapping):
                message = transaction.get("message")
                if isinstance(message, Mapping):
                    keys = message.get("accountKeys")
                    if isinstance(keys, list):
                        for key in keys:
                            if isinstance(key, Mapping) and key.get("pubkey") == USDC_MINT:
                                writable = bool(key.get("writable"))
                                break
        in_window.append(
            {
                "signature": signature,
                "slot": slot,
                "successful": row.get("err") is None and tx_error is None,
                "usdc_mint_writable": writable,
                "is_target_signature": signature == args.target_signature,
            }
        )

    conflicts = [
        row
        for row in in_window
        if row["successful"] and row["usdc_mint_writable"] and not row["is_target_signature"]
    ]
    target_rows = [row for row in in_window if row["is_target_signature"]]
    if not coverage_ok:
        status = "INCONCLUSIVE_HISTORY_DID_NOT_REACH_S0"
    elif conflicts:
        status = "CONFLICT_CONFIRMED"
    else:
        status = "NO_WRITABLE_CONFLICT_FOUND"

    result = {
        "schema": "ghost_usdc_mint_window_audit_v1",
        "authority": {
            "read_only": True,
            "signing": False,
            "submission": False,
            "capital_movement": False,
        },
        "usdc_mint": USDC_MINT,
        "window": {"s0_slot": args.s0_slot, "s1_slot": args.s1_slot},
        "target_signature": args.target_signature,
        "history": {
            "pages_fetched": pages,
            "rows_fetched": len(rows),
            "minimum_slot_seen": min_slot,
            "covers_s0": coverage_ok,
        },
        "target_rows": target_rows,
        "in_window": in_window,
        "independent_successful_writable_conflicts": conflicts,
        "status": status,
    }
    Path(args.output).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
