#!/usr/bin/env python3
"""Fingerprint burst-conflict writers using signed transaction.message only.

Read-only historical discovery. Records top-level program IDs, instruction
indices, account counts, and data prefixes. No inner instructions, logs,
balance deltas, signing, submission, broadcast, or capital movement.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

RPC_URL = "https://api.mainnet-beta.solana.com"
SIGNATURES = [
    "5pgvTKLrJNPToAv5DuxPptkFPqt7emvGPugVXLg28zbvEwfxz4971HuKDuBJLDEbRYovybqhJF6JDRW6sAxGdTvi",
    "5wVFPSLYJzo13Zkagmjb92yY4NJ2Ekz6C1jLR84peVZLBiaY8yKVghRLf1nVEu7WwG1a9JsJnXiqoZTPqQQtqnyt",
    "2vZyLd2WWArweYKTPbVWXt45CbJyqktejLgqjn5QvSTuczBqJjTiBv875fwox5Jdw7qMcbPhixD958bALuN5mtYP",
    "3tBMwopBHWKX3kUkiQVmCncu91t8iemdQcqhNSAvbNeomaoMdJ5xczU4v86PaThQkbTKAYfNVUU32XZBktpK6ZJe",
    "4MJ1V3fL5Er69BCBSctyPr886aPEpArycnzSwp64DDQkJSNEnjQncfKueRCxiQFX4y1heHTbKXzk5UBH3PphqkAE",
]
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58I = {c:i for i,c in enumerate(_B58)}


def b58decode(s: str) -> bytes:
    n=0
    for c in s: n=n*58+_B58I[c]
    raw=n.to_bytes((n.bit_length()+7)//8,"big") if n else b""
    return b"\x00"*(len(s)-len(s.lstrip("1")))+raw

def now(): return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b:bytes): return hashlib.sha256(b).hexdigest()

def rpc(method:str, params:list[Any])->Any:
    body=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params},separators=(",",":")).encode()
    delay=.5
    for attempt in range(6):
        try:
            req=urllib.request.Request(RPC_URL,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Writer-Fingerprint/0"})
            with urllib.request.urlopen(req,timeout=30) as r: payload=json.loads(r.read())
            if not isinstance(payload,Mapping) or payload.get("error") is not None: raise RuntimeError(str(payload))
            return payload.get("result")
        except Exception:
            if attempt==5: raise
            time.sleep(delay); delay=min(delay*2,8)

def main()->int:
    rows=[]; programs=Counter(); discriminators=Counter()
    for sig in SIGNATURES:
        tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
        if not isinstance(tx,Mapping):
            rows.append({"signature":sig,"status":"UNAVAILABLE"}); continue
        t=tx.get("transaction"); msg=t.get("message") if isinstance(t,Mapping) else None
        if not isinstance(msg,Mapping):
            rows.append({"signature":sig,"slot":tx.get("slot"),"status":"NO_MESSAGE"}); continue
        ixs=[]
        for i,ix in enumerate(msg.get("instructions",[]) if isinstance(msg.get("instructions"),list) else []):
            if not isinstance(ix,Mapping): continue
            pid=ix.get("programId")
            if not isinstance(pid,str): continue
            programs[pid]+=1
            data=ix.get("data")
            raw=b""
            if isinstance(data,str):
                try: raw=b58decode(data)
                except Exception: raw=b""
            prefix=raw[:8].hex() if raw else None
            if prefix: discriminators[(pid,prefix)]+=1
            accts=ix.get("accounts")
            ixs.append({"index":i,"program_id":pid,"account_count":len(accts) if isinstance(accts,list) else None,"data_len":len(raw),"data_prefix_8_hex":prefix})
        rows.append({"signature":sig,"slot":int(tx.get("slot",-1)),"status":"OK","instructions":ixs})
    evidence={
        "schema":"ghost.writer_program_fingerprint.v0","accepted":True,"observation_only":True,"execution_authority":False,
        "captured_at":now(),"predictive_surface":"finalized signed transaction.message only",
        "writers":rows,
        "program_frequency":dict(programs),
        "program_discriminator_frequency":[{"program_id":k[0],"prefix_8_hex":k[1],"count":v} for k,v in discriminators.most_common()],
        "safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False},
    }
    stamp=now().replace(":","").replace("-","").replace(".","_")
    d=Path("live-evidence")/f"ghost-writer-program-fingerprint-{stamp}"; d.mkdir(parents=True,exist_ok=True)
    raw=(json.dumps(evidence,sort_keys=True,indent=2)+"\n").encode(); (d/"evidence.json").write_bytes(raw); (d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n")
    print(json.dumps({"program_frequency":dict(programs),"discriminators":evidence["program_discriminator_frequency"][:20]},indent=2))
    return 0

if __name__=="__main__": raise SystemExit(main())
