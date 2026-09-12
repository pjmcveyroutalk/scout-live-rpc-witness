#!/usr/bin/env python3
"""Deterministic Ghost G0 Raydium CPMM top-level SwapBaseInput projector.

Reads ONLY a V0.8 blind challenge projector_input/ surface. It does not read
sealed_truth, RPC evidence, transaction metadata/logs, or audit results.
Standard-library only; no network and no execution authority.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

RAYDIUM = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
POOL_DISC = bytes([247, 237, 227, 245, 215, 195, 222, 70])
AMM_DISC = bytes([218, 244, 33, 104, 203, 203, 43, 111])
SWAP_BASE_INPUT_DISC = hashlib.sha256(b"global:swap_base_input").digest()[:8]
DENOM = 1_000_000
TOKEN_AMOUNT_OFFSET = 64
WSOL_MINT = "So11111111111111111111111111111111111111112"
MAINNET_SLOTS_PER_EPOCH = 432_000

class ProjectorError(RuntimeError):
    pass

def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def shortvec(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(4):
        if offset >= len(data):
            raise ProjectorError("shortvec truncated")
        b = data[offset]; offset += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            return result, offset
        shift += 7
    raise ProjectorError("shortvec too long")

def parse_top_level_instructions(raw_tx: bytes) -> list[dict[str, Any]]:
    off = 0
    sig_count, off = shortvec(raw_tx, off)
    sig_bytes = sig_count * 64
    if off + sig_bytes > len(raw_tx):
        raise ProjectorError("signature vector truncated")
    off += sig_bytes
    if off >= len(raw_tx):
        raise ProjectorError("message missing")
    version = None
    if raw_tx[off] & 0x80:
        version = raw_tx[off] & 0x7f
        if version != 0:
            raise ProjectorError(f"unsupported transaction version {version}")
        off += 1
    if off + 3 > len(raw_tx):
        raise ProjectorError("message header truncated")
    off += 3
    static_count, off = shortvec(raw_tx, off)
    end = off + static_count * 32
    if end > len(raw_tx):
        raise ProjectorError("static keys truncated")
    off = end
    if off + 32 > len(raw_tx):
        raise ProjectorError("recent blockhash truncated")
    off += 32
    ix_count, off = shortvec(raw_tx, off)
    out = []
    for i in range(ix_count):
        if off >= len(raw_tx):
            raise ProjectorError("instruction program index truncated")
        pidx = raw_tx[off]; off += 1
        nacc, off = shortvec(raw_tx, off)
        if off + nacc > len(raw_tx):
            raise ProjectorError("instruction account list truncated")
        accs = list(raw_tx[off:off+nacc]); off += nacc
        ndata, off = shortvec(raw_tx, off)
        if off + ndata > len(raw_tx):
            raise ProjectorError("instruction data truncated")
        ixdata = raw_tx[off:off+ndata]; off += ndata
        out.append({"index": i, "program_id_index": pidx, "account_indices": accs, "data": ixdata})
    if version == 0:
        lookup_count, off = shortvec(raw_tx, off)
        for _ in range(lookup_count):
            if off + 32 > len(raw_tx):
                raise ProjectorError("ALT lookup key truncated")
            off += 32
            nw, off = shortvec(raw_tx, off)
            if off + nw > len(raw_tx): raise ProjectorError("ALT writable indexes truncated")
            off += nw
            nr, off = shortvec(raw_tx, off)
            if off + nr > len(raw_tx): raise ProjectorError("ALT readonly indexes truncated")
            off += nr
    if off != len(raw_tx):
        raise ProjectorError(f"transaction parser ended at {off}, length {len(raw_tx)}")
    return out

def u64(data: bytes, off: int) -> int:
    if off + 8 > len(data): raise ProjectorError("u64 truncated")
    return int.from_bytes(data[off:off+8], "little")

def set_u64(buf: bytearray, off: int, value: int) -> None:
    if not 0 <= value <= 0xffffffffffffffff: raise ProjectorError("u64 overflow")
    buf[off:off+8] = value.to_bytes(8, "little")

def parse_pool(raw: bytes) -> dict[str, Any]:
    if len(raw) != 637 or raw[:8] != POOL_DISC:
        raise ProjectorError("unsupported Raydium PoolState image")
    return {
        "status": raw[329],
        "lp_supply": u64(raw,333),
        "protocol0": u64(raw,341), "protocol1": u64(raw,349),
        "fund0": u64(raw,357), "fund1": u64(raw,365),
        "open_time": u64(raw,373), "recent_epoch": u64(raw,381),
        "creator_fee_on": raw[389], "enable_creator_fee": raw[390] != 0,
        "creator0": u64(raw,397), "creator1": u64(raw,405),
    }

def parse_amm(raw: bytes) -> dict[str, int]:
    if len(raw) != 236 or raw[:8] != AMM_DISC:
        raise ProjectorError("unsupported Raydium AmmConfig image")
    return {"trade":u64(raw,12), "protocol":u64(raw,20), "fund":u64(raw,28), "creator":u64(raw,108)}

def token_amount(raw: bytes) -> int:
    if len(raw) < 165: raise ProjectorError("token account too short")
    return u64(raw, TOKEN_AMOUNT_OFFSET)

def ceil_fee(amount: int, rate: int, denom: int = DENOM) -> int:
    if denom <= 0: raise ProjectorError("invalid denominator")
    if amount == 0 or rate == 0: return 0
    return (amount * rate + denom - 1) // denom

def floor_fee(amount: int, rate: int, denom: int = DENOM) -> int:
    if denom <= 0: raise ProjectorError("invalid denominator")
    return (amount * rate) // denom

def epoch_for_mainnet_slot(slot: int) -> int:
    # Mainnet-beta epoch schedule has warmup=false, firstNormalSlot=0.
    if slot < 0:
        raise ProjectorError("negative slot")
    return slot // MAINNET_SLOTS_PER_EPOCH

def record_data(record: Mapping[str, Any]) -> bytes:
    try: return base64.b64decode(record["data_base64"], validate=True)
    except Exception as exc: raise ProjectorError(f"invalid snapshot base64: {exc}") from exc

def update_record(pre: Mapping[str, Any], raw: bytes) -> dict[str, Any]:
    out = dict(pre)
    out["data_base64"] = base64.b64encode(raw).decode("ascii")
    out["data_len"] = len(raw)
    out["data_sha256"] = sha256(raw)
    return out

def project(challenge_dir: Path) -> dict[str, Any]:
    inp = challenge_dir / "projector_input"
    manifest = json.loads((inp/"projector_input_manifest.json").read_text())
    observation = json.loads((inp/"observation.json").read_text())
    s0 = json.loads((inp/"s0_snapshot.json").read_text())
    raw_tx = (inp/"raw_transaction.bin").read_bytes()
    if manifest["network"]["genesis_hash"] != MAINNET_GENESIS:
        raise ProjectorError("unsupported genesis hash")
    if sha256(raw_tx) != manifest["raw_transaction_sha256"]:
        raise ProjectorError("raw transaction hash mismatch")
    if manifest["raydium_cpmm_program_id"] != RAYDIUM:
        raise ProjectorError("unexpected Raydium program")
    if len(s0.get("accounts",[])) != 6:
        raise ProjectorError("six-account S0 required")
    resolved = observation.get("resolved_accounts")
    if not isinstance(resolved, list) or not resolved:
        raise ProjectorError("resolved causal account ordering missing")
    resolved = sorted(resolved, key=lambda x: int(x["account_index"]))
    if [int(x["account_index"]) for x in resolved] != list(range(len(resolved))):
        raise ProjectorError("resolved account indexes are not contiguous")
    keys = [x["pubkey"] for x in resolved]
    matches = []
    for ix in parse_top_level_instructions(raw_tx):
        if ix["program_id_index"] >= len(keys): raise ProjectorError("program index out of bounds")
        if keys[ix["program_id_index"]] != RAYDIUM: continue
        if len(ix["account_indices"]) != 13: continue
        ixkeys=[]
        for j in ix["account_indices"]:
            if j >= len(keys): raise ProjectorError("account index out of bounds")
            ixkeys.append(keys[j])
        if ixkeys[3] != manifest["target_pool_id"]: continue
        if len(ix["data"]) != 24 or ix["data"][:8] != SWAP_BASE_INPUT_DISC: continue
        matches.append((ix,ixkeys))
    if len(matches) != 1:
        raise ProjectorError(f"expected exactly one top-level target SwapBaseInput, got {len(matches)}")
    ix, ixkeys = matches[0]
    amount_in = u64(ix["data"],8)
    minimum_out = u64(ix["data"],16)
    if amount_in <= 0: raise ProjectorError("zero input")
    if ixkeys[2] != manifest["pool_identity"]["amm_config"]: raise ProjectorError("AMM config mismatch")
    if ixkeys[8] != SPL_TOKEN or ixkeys[9] != SPL_TOKEN: raise ProjectorError("only SPL/SPL supported")
    pident=manifest["pool_identity"]
    vault0, vault1 = pident["token_0_vault"], pident["token_1_vault"]
    if ixkeys[6] == vault0 and ixkeys[7] == vault1:
        zero_for_one=True
        if ixkeys[10] != pident["token_0_mint"] or ixkeys[11] != pident["token_1_mint"]: raise ProjectorError("mint direction mismatch")
    elif ixkeys[6] == vault1 and ixkeys[7] == vault0:
        zero_for_one=False
        if ixkeys[10] != pident["token_1_mint"] or ixkeys[11] != pident["token_0_mint"]: raise ProjectorError("mint direction mismatch")
    else:
        raise ProjectorError("instruction vault direction does not match pool")
    recs=[dict(x) for x in s0["accounts"]]
    if [x["pubkey"] for x in recs] != [manifest["target_pool_id"],pident["amm_config"],vault0,vault1,pident["token_0_mint"],pident["token_1_mint"]]:
        raise ProjectorError("S0 account order mismatch")
    pool_raw=bytearray(record_data(recs[0])); amm=parse_amm(record_data(recs[1]))
    p=parse_pool(bytes(pool_raw))
    if p["status"] & 4: raise ProjectorError("pool swap disabled")
    raw0=bytearray(record_data(recs[2])); raw1=bytearray(record_data(recs[3]))
    amt0,amt1=token_amount(raw0),token_amount(raw1)
    accrued0=p["protocol0"]+p["fund0"]+p["creator0"]
    accrued1=p["protocol1"]+p["fund1"]+p["creator1"]
    if amt0 < accrued0 or amt1 < accrued1: raise ProjectorError("accrued fees exceed vault")
    eff0,eff1=amt0-accrued0,amt1-accrued1
    in_eff,out_eff=(eff0,eff1) if zero_for_one else (eff1,eff0)
    creator_rate=amm["creator"] if p["enable_creator_fee"] else 0
    mode=p["creator_fee_on"]
    if mode not in (0,1,2): raise ProjectorError("invalid creator fee mode")
    creator_on_input = mode==0 or (mode==1 and zero_for_one) or (mode==2 and not zero_for_one)
    if creator_on_input:
        combined=amm["trade"]+creator_rate
        if combined >= DENOM: raise ProjectorError("combined fee too large")
        total_fee=ceil_fee(amount_in,combined)
        creator_fee=0 if combined==0 else floor_fee(total_fee,creator_rate,combined)
        trade_fee=total_fee-creator_fee
        curve_in=amount_in-total_fee
    else:
        trade_fee=ceil_fee(amount_in,amm["trade"])
        creator_fee=0
        curve_in=amount_in-trade_fee
    if curve_in <= 0 or in_eff <= 0 or out_eff <= 0: raise ProjectorError("invalid curve inputs")
    protocol_fee=floor_fee(trade_fee,amm["protocol"])
    fund_fee=floor_fee(trade_fee,amm["fund"])
    curve_out=(curve_in*out_eff)//(in_eff+curve_in)
    if not creator_on_input:
        creator_fee=ceil_fee(curve_out,creator_rate)
        output=curve_out-creator_fee
    else:
        output=curve_out
    if output <= 0: raise ProjectorError("zero output")
    if output < minimum_out: raise ProjectorError("projected output below minimum_amount_out")
    if zero_for_one:
        new0=amt0+amount_in; new1=amt1-output
        p["protocol0"] += protocol_fee; p["fund0"] += fund_fee
        if creator_on_input: p["creator0"] += creator_fee
        else: p["creator1"] += creator_fee
    else:
        new1=amt1+amount_in; new0=amt0-output
        p["protocol1"] += protocol_fee; p["fund1"] += fund_fee
        if creator_on_input: p["creator1"] += creator_fee
        else: p["creator0"] += creator_fee
    if new0 < 0 or new1 < 0: raise ProjectorError("vault underflow")
    set_u64(raw0,TOKEN_AMOUNT_OFFSET,new0); set_u64(raw1,TOKEN_AMOUNT_OFFSET,new1)
    set_u64(pool_raw,341,p["protocol0"]); set_u64(pool_raw,349,p["protocol1"])
    set_u64(pool_raw,357,p["fund0"]); set_u64(pool_raw,365,p["fund1"])
    set_u64(pool_raw,397,p["creator0"]); set_u64(pool_raw,405,p["creator1"])
    tx_slot=int(manifest["transaction_slot"])
    set_u64(pool_raw,381,epoch_for_mainnet_slot(tx_slot))
    recs[0]=update_record(recs[0],bytes(pool_raw)); recs[2]=update_record(recs[2],bytes(raw0)); recs[3]=update_record(recs[3],bytes(raw1))
    input_mint = ixkeys[10]
    output_mint = ixkeys[11]
    input_rec_index = 2 if ixkeys[6] == vault0 else 3
    output_rec_index = 2 if ixkeys[7] == vault0 else 3
    if input_mint == WSOL_MINT:
        recs[input_rec_index]["lamports"] = int(recs[input_rec_index]["lamports"]) + amount_in
    if output_mint == WSOL_MINT:
        new_lamports = int(recs[output_rec_index]["lamports"]) - output
        if new_lamports < 0:
            raise ProjectorError("wrapped-SOL vault lamports underflow")
        recs[output_rec_index]["lamports"] = new_lamports
    projected={
        "schema_version":"raydium_g0_snapshot_v1",
        "context_slot":tx_slot,
        "continuity_epoch":int(s0.get("continuity_epoch",0)),
        "transport_interruption_count":int(s0.get("transport_interruption_count",0)),
        "captured_at_unix_ns":int(s0.get("captured_at_unix_ns",0)),
        "rpc_evidence_id":"ghost_native_projection_v0",
        "accounts":recs,
    }
    projected["snapshot_sha256"]=sha256(canonical_json_bytes(projected))
    return projected

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("challenge_dir")
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    try:
        out=project(Path(args.challenge_dir))
        Path(args.output).write_bytes(canonical_json_bytes(out))
        print(f"PROJECTED={args.output}")
        print(f"snapshot_sha256={out['snapshot_sha256']}")
        return 0
    except ProjectorError as exc:
        print(f"FAIL_CLOSED: {exc}")
        return 2
if __name__=="__main__": raise SystemExit(main())
