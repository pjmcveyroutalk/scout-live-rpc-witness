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
        headers={"content-type": "application/json", "user-agent": "Ghost-USDC-Window-Audit/0"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, Mapping) or payload.get("error") is not None:
        raise RuntimeError(f"RPC failure {method}: {payload.get('error') if isinstance(payload, Mapping) else 'shape'}")
    return payload.get("result")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--s0-slot", type=int, required=True)
    ap.add_argument("--s1-slot", type=int, required=True)
    ap.add_argument("--target-signature", required=True)
    ap.add_argument("--output", default="USDC_MINT_WINDOW_AUDIT.json")
    args = ap.parse_args()

    rows = rpc(
        "getSignaturesForAddress",
        [USDC_MINT, {"commitment": "finalized", "limit": 1000}],
    )
    if not isinstance(rows, list):
        raise RuntimeError("invalid signature history")

    in_window = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
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
    result = {
        "schema": "ghost_usdc_mint_window_audit_v0",
        "authority": {
            "read_only": True,
            "signing": False,
            "submission": False,
            "capital_movement": False,
        },
        "usdc_mint": USDC_MINT,
        "window": {"s0_slot": args.s0_slot, "s1_slot": args.s1_slot},
        "target_signature": args.target_signature,
        "target_rows": target_rows,
        "in_window": in_window,
        "independent_successful_writable_conflicts": conflicts,
        "status": "CONFLICT_CONFIRMED" if conflicts else "NO_WRITABLE_CONFLICT_FOUND",
    }
    Path(args.output).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
