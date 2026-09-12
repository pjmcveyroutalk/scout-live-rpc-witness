#!/usr/bin/env python3
"""Retrospective truth score for two signed Titan -> locked Raydium allocations.

Prediction amounts are hard-coded from the previously sealed signed-message-only
Titan payload analysis. Execution metadata is read only here as an answer key.
No wallet, signing, transaction building, simulation, submission, or broadcast.
"""
from __future__ import annotations
import hashlib,json,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping

RPC="https://api.mainnet-beta.solana.com"
RAY="CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
DISC=bytes.fromhex("8fbe5adac41e33de")
CASES={
"5pgvTKLrJNPToAv5DuxPptkFPqt7emvGPugVXLg28zbvEwfxz4971HuKDuBJLDEbRYovybqhJF6JDRW6sAxGdTvi":77602,
"2vZyLd2WWArweYKTPbVWXt45CbJyqktejLgqjn5QvSTuczBqJjTiBv875fwox5Jdw7qMcbPhixD958bALuN5mtYP":78461,
}
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";M={c:i for i,c in enumerate(A)}
def b58d(s):
 n=0
 for c in s:n=n*58+M[c]
 r=n.to_bytes((n.bit_length()+7)//8,"big") if n else b""
 return b"\0"*(len(s)-len(s.lstrip("1")))+r
def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b):return hashlib.sha256(b).hexdigest()
def rpc(m,p):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p},separators=(",",":")).encode();d=.5
 for i in range(6):
  try:
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Titan-Ray-Score/0"})
   with urllib.request.urlopen(q,timeout=30) as r:o=json.loads(r.read())
   if not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o))
   return o.get("result")
  except Exception:
   if i==5:raise
   time.sleep(d);d=min(d*2,8)
def account_keys(tx):
 msg=tx.get("transaction",{}).get("message",{}); ks=msg.get("accountKeys",[])
 return [x.get("pubkey") if isinstance(x,Mapping) else x for x in ks]
def main():
 rows=[]
 for sig,pred in CASES.items():
  tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  keys=account_keys(tx) if isinstance(tx,Mapping) else []
  meta=tx.get("meta",{}) if isinstance(tx,Mapping) else {}; inner=meta.get("innerInstructions",[]) if isinstance(meta,Mapping) else []
  found=[]
  for group in inner if isinstance(inner,list) else []:
   for ix in group.get("instructions",[]) if isinstance(group,Mapping) else []:
    if not isinstance(ix,Mapping):continue
    pid=ix.get("programId")
    if pid is None and isinstance(ix.get("programIdIndex"),int) and ix["programIdIndex"]<len(keys):pid=keys[ix["programIdIndex"]]
    if pid!=RAY:continue
    ac=ix.get("accounts",[]); resolved=[]
    for a in ac if isinstance(ac,list) else []:
     if isinstance(a,int) and a<len(keys):resolved.append(keys[a])
     elif isinstance(a,str):resolved.append(a)
    data=ix.get("data")
    if not isinstance(data,str) or POOL not in resolved:continue
    raw=b58d(data)
    if len(raw)>=24 and raw[:8]==DISC:
     found.append({"amount_in":int.from_bytes(raw[8:16],"little"),"minimum_out":int.from_bytes(raw[16:24],"little"),"accounts":resolved})
  amounts=[x["amount_in"] for x in found]
  rows.append({"signature":sig,"slot":int(tx.get("slot",-1)) if isinstance(tx,Mapping) else -1,"predicted_amount_in":pred,"truth_amounts":amounts,"exact":amounts==[pred]})
 ev={"schema":"ghost.titan_raydium_truth_score.v0","accepted":True,"observation_only":True,"execution_authority":False,"prediction_source":"previously sealed signed Titan transaction.message payloads","truth_source":"finalized innerInstructions opened only for retrospective scoring","cases":rows,"all_exact":all(r["exact"] for r in rows),"safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"ghost-titan-ray-score-{st}";d.mkdir(parents=True,exist_ok=True);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps(ev,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
