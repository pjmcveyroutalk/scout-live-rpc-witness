#!/usr/bin/env python3
"""Correlate signed Bison quote fields with finalized Bison vault direction/truth.

For the same four settled BisonFiWithSig cases used by T902/T903, this witness:
- fail-closed selects the Bison payload by finalized SwapEvent amount_in;
- maps Bison instruction accounts to transaction pre/post token balances;
- requires accounts[2] and accounts[3] to be token accounts owned by accounts[1];
- records their mint, decimals, and signed balance delta;
- determines which Bison-owned vault received amount_in and which paid amount_out;
- correlates that direction with raw[35] and records the still-unknown signed fields
  raw[17:25], raw[25:33], and raw[33:35].

No formula is promoted by this census. Finalized retrospective research only; no
pending monitoring, wallet, signer, simulation, transaction construction,
serialization, submission, broadcast, bridge execution, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

RPC = "https://api.mainnet-beta.solana.com"
BISON = "BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi"
CASES = {
    "3DhDBbxDaENVui8f7vjmmzygBMQnnGoNnfpTtqszuHhYLycZK8KYH5bje79hgpuWTyUCuH8HkTzzCRgTat1iyuhJ": "sealed_ghost",
    "26aKhuit1vWNyimWjCcvMY3mzoTk297PCup5pTiamxXDf6G57Lkq878nnPSzRhGRTma66LyFuWPW8AbpxVSHZVqP": "public_a",
    "2roTgE7GxgW7KwPLTkmmMARH9RpoPLa2kLTnH4mnLMWw2yTWUULzheAQPJHyqcyGsYLpZyi7GkuPvbAR8kQGjkDa": "public_b",
    "31rpu29NYFhHpwkXVgVvLWa9sL51JQddtq8YmyGeP3paCbqp9A9AbuWuWxorGiMJ9pkSRtp49rcmmHcokuPBS1nE": "public_c",
}
EVENT_RE = re.compile(r"SwapEvent \{ dex: BisonFiWithSig, amount_in: (\d+), amount_out: (\d+) \}")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58)}


def b58decode(value: str) -> bytes:
    n = 0
    for ch in value:
        n = n * 58 + B58_MAP[ch]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}, separators=(",", ":")).encode()
    delay = 0.5
    for attempt in range(7):
        try:
            req = urllib.request.Request(RPC, data=body, method="POST", headers={"content-type":"application/json","user-agent":"Ghost-Bison-Signed-Field-Census/1"})
            with urllib.request.urlopen(req, timeout=30) as response:
                obj = json.loads(response.read())
            if not isinstance(obj, Mapping) or obj.get("error") is not None:
                raise RuntimeError(str(obj.get("error") if isinstance(obj, Mapping) else obj))
            return obj.get("result")
        except Exception:
            if attempt == 6:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 6)
    raise AssertionError("unreachable")


def bison_inners(tx: Mapping[str, Any]) -> list[dict[str, Any]]:
    meta = tx.get("meta")
    groups = meta.get("innerInstructions") if isinstance(meta, Mapping) else None
    out: list[dict[str, Any]] = []
    if not isinstance(groups, list):
        return out
    for group in groups:
        instructions = group.get("instructions") if isinstance(group, Mapping) else None
        if not isinstance(instructions, list):
            continue
        for ix in instructions:
            if not isinstance(ix, Mapping) or ix.get("programId") != BISON:
                continue
            data, accounts = ix.get("data"), ix.get("accounts")
            if not isinstance(data, str) or not isinstance(accounts, list):
                continue
            try:
                out.append({"raw":b58decode(data),"accounts":[str(x) for x in accounts]})
            except Exception:
                continue
    return out


def truth(tx: Mapping[str, Any]) -> list[tuple[int, int]]:
    meta = tx.get("meta")
    logs = meta.get("logMessages") if isinstance(meta, Mapping) else None
    out: list[tuple[int, int]] = []
    if isinstance(logs, list):
        for line in logs:
            if isinstance(line, str):
                m = EVENT_RE.search(line)
                if m:
                    out.append((int(m.group(1)), int(m.group(2))))
    return out


def account_keys(tx: Mapping[str, Any]) -> list[str]:
    transaction = tx.get("transaction")
    message = transaction.get("message") if isinstance(transaction, Mapping) else None
    keys = message.get("accountKeys") if isinstance(message, Mapping) else None
    if not isinstance(keys, list):
        return []
    return [str(x.get("pubkey")) if isinstance(x, Mapping) else str(x) for x in keys]


def token_balance_map(tx: Mapping[str, Any], which: str) -> dict[str, dict[str, Any]]:
    keys = account_keys(tx)
    meta = tx.get("meta")
    balances = meta.get(which) if isinstance(meta, Mapping) else None
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(balances, list):
        return out
    for row in balances:
        if not isinstance(row, Mapping):
            continue
        idx = row.get("accountIndex")
        ui = row.get("uiTokenAmount")
        if not isinstance(idx, int) or idx < 0 or idx >= len(keys) or not isinstance(ui, Mapping):
            continue
        amount = ui.get("amount")
        decimals = ui.get("decimals")
        if not isinstance(amount, str) or not isinstance(decimals, int):
            continue
        out[keys[idx]] = {
            "mint":row.get("mint"),
            "owner":row.get("owner"),
            "amount":int(amount),
            "decimals":decimals,
        }
    return out


def main() -> int:
    started = now()
    rows: list[dict[str, Any]] = []
    for signature, label in CASES.items():
        tx = rpc("getTransaction", [signature, {"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
        if not isinstance(tx, Mapping):
            raise RuntimeError(f"transaction unavailable: {signature}")
        truths = truth(tx)
        inners = bison_inners(tx)
        if len(truths) != 1:
            raise RuntimeError(f"truth not unique: {signature}")
        amount_in, amount_out = truths[0]
        needle = amount_in.to_bytes(8, "little")
        matching = [row for row in inners if needle in row["raw"]]
        if len(matching) != 1:
            raise RuntimeError(f"input-selected Bison payload not unique: {signature}: {len(matching)}")
        selected = matching[0]
        raw = selected["raw"]
        accounts = selected["accounts"]
        if len(raw) != 153 or len(accounts) < 6:
            raise RuntimeError(f"unsupported payload/account shape: {signature}")
        pre = token_balance_map(tx, "preTokenBalances")
        post = token_balance_map(tx, "postTokenBalances")
        vault_rows = []
        for account_position in (2, 3):
            address = accounts[account_position]
            before = pre.get(address)
            after = post.get(address)
            if before is None or after is None:
                raise RuntimeError(f"missing vault token balance: {signature}: account {account_position}")
            if before["mint"] != after["mint"] or before["owner"] != after["owner"] or before["decimals"] != after["decimals"]:
                raise RuntimeError(f"vault token metadata changed: {signature}: account {account_position}")
            if str(before["owner"]) != accounts[1]:
                raise RuntimeError(f"vault owner does not equal Bison authority account[1]: {signature}: account {account_position}")
            delta = after["amount"] - before["amount"]
            vault_rows.append({
                "account_position":account_position,
                "address":address,
                "mint":before["mint"],
                "owner":before["owner"],
                "decimals":before["decimals"],
                "pre_amount":before["amount"],
                "post_amount":after["amount"],
                "delta":delta,
            })
        input_matches = [v for v in vault_rows if v["delta"] == amount_in]
        output_matches = [v for v in vault_rows if v["delta"] == -amount_out]
        if len(input_matches) != 1 or len(output_matches) != 1 or input_matches[0]["account_position"] == output_matches[0]["account_position"]:
            raise RuntimeError(f"vault deltas do not uniquely realize event truth: {signature}: {vault_rows}")
        input_vault = input_matches[0]
        output_vault = output_matches[0]
        direction_flag = raw[35]
        rows.append({
            "label":label,
            "signature":signature,
            "slot":int(tx.get("slot", -1)),
            "amount_in":amount_in,
            "amount_out":amount_out,
            "payload_sha256":sha256(raw),
            "signed_timestamp_u64_raw_9":int.from_bytes(raw[9:17], "little"),
            "signed_field_a_u64_raw_17":int.from_bytes(raw[17:25], "little"),
            "signed_field_b_u64_raw_25":int.from_bytes(raw[25:33], "little"),
            "signed_u16_raw_33":int.from_bytes(raw[33:35], "little"),
            "signed_direction_flag_raw_35":direction_flag,
            "signed_reserved_raw_36_40_hex":raw[36:41].hex(),
            "signed_caller_raw_41_72_hex":raw[41:73].hex(),
            "signed_slot_u64_raw_73":int.from_bytes(raw[73:81], "little"),
            "bison_authority_account_1":accounts[1],
            "input_vault":input_vault,
            "output_vault":output_vault,
            "input_is_account_2":input_vault["account_position"] == 2,
            "input_is_account_3":input_vault["account_position"] == 3,
            "derived":{
                "field_a_div_amount_in":int.from_bytes(raw[17:25], "little") / amount_in if amount_in else None,
                "field_b_div_amount_out":int.from_bytes(raw[25:33], "little") / amount_out if amount_out else None,
                "field_b_minus_amount_out":int.from_bytes(raw[25:33], "little") - amount_out,
            },
        })

    flag_to_input_positions: dict[str, list[int]] = {}
    for row in rows:
        key = str(row["signed_direction_flag_raw_35"])
        flag_to_input_positions.setdefault(key, []).append(row["input_vault"]["account_position"])
    evidence = {
        "schema":"ghost.bison_signed_field_semantics_census.v1",
        "accepted":True,
        "observation_only":True,
        "execution_authority":False,
        "started_at":started,
        "completed_at":now(),
        "case_count":len(rows),
        "flag_to_input_vault_positions":flag_to_input_positions,
        "cases":rows,
        "interpretation":(
            "Vault deltas establish direction without relying on token labels. This census may "
            "support a direction-bit interpretation when a flag maps consistently to vault side. "
            "No semantics are assigned to signed field_a, field_b, or u16 without further evidence."
        ),
        "safety":{
            "wallet":False,"signer":False,"approval":False,"transaction_builder":False,
            "transaction_serialization":False,"transaction_simulation":False,
            "transaction_submission":False,"broadcast":False,"bridge_execution":False,
            "capital_movement":False,
        },
    }
    stamp = started.replace(":","").replace("-","").replace(".","_")
    out = Path("live-evidence") / f"bison-signed-field-semantics-census-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    raw_evidence = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    (out/"evidence.json").write_bytes(raw_evidence)
    (out/"evidence.sha256").write_text(f"{sha256(raw_evidence)}  evidence.json\n")
    print(json.dumps({
        "case_count":len(rows),
        "flag_to_input_vault_positions":flag_to_input_positions,
        "rows":[{
            "label":r["label"],
            "flag":r["signed_direction_flag_raw_35"],
            "input_vault_position":r["input_vault"]["account_position"],
            "input_decimals":r["input_vault"]["decimals"],
            "output_vault_position":r["output_vault"]["account_position"],
            "output_decimals":r["output_vault"]["decimals"],
            "field_a":r["signed_field_a_u64_raw_17"],
            "field_b":r["signed_field_b_u64_raw_25"],
            "u16":r["signed_u16_raw_33"],
        } for r in rows],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
