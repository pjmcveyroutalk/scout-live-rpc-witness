#!/usr/bin/env python3
"""Retrospective truth score for finalized target-pool writes from uncatalogued outer programs.

This witness uses only already-finalized transactions selected by the prior signed-surface census.
It tests whether the observed compact 0x03 instruction family stores a candidate input amount in
bytes 1..8 by comparing it to the finalized Raydium CPMM SwapBaseInput CPI answer key.
No live monitoring, wallet, signing, simulation, transaction construction/submission, broadcast,
or capital movement.
"""
from __future__ import annotations
import hashlib,json,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping

RPC="https://api.mainnet-beta.solana.com"
RAY="CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
DISC=hashlib.sha256(b"global:swap_base_input").digest()[:8]
CASES={
"41NJJrdLnQ2paxjxyMmXjiRDCbBypcuBr9zQXCEGjTooWwGGQfEEcimyu7zCAGdH27UL9UU5DqKip8Z6wBC6gUwz":("7obtMdiXQaLCao2mCRzsanxRusUH8QAz8eT5PJyUTHFQ",17),
"3xLoBHhURmoMU934E7bcULc86nYQh1JpmG98eDLvjSS2WSzi7guFxUVypRm3kCSpUVk1pJCxhvUGVLUB1fpPqVi8":("GLCNMEV6Z7P72YtUciTUzMczWPALAkV9F6k5z9jHsfwy",31),
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
 for i in range(7):
  try:
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Settled-Unknown-Score/1"})
   with urllib.request.urlopen(q,timeout=30) as r:o=json.loads(r.read())
   if not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o.get("error") if isinstance(o,Mapping) else o))
   return o.get("result")
  except Exception:
   if i==6:raise
   time.sleep(d);d=min(d*2,6)
def message(tx):
 t=tx.get("transaction");m=t.get("message") if isinstance(t,Mapping) else None
 if not isinstance(m,Mapping):raise RuntimeError("message missing")
 return m
def target_outer(tx,pid,expected_len):
 found=[]
 for ix in message(tx).get("instructions",[]):
  if not isinstance(ix,Mapping) or ix.get("programId")!=pid:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or POOL not in ac or RAY not in ac or not isinstance(d,str):continue
  raw=b58d(d)
  if len(raw)==expected_len:found.append(raw)
 return found
def truth(tx):
 rows=[];m=message(tx);top=m.get("instructions")
 if isinstance(top,list):rows.extend(x for x in top if isinstance(x,Mapping))
 meta=tx.get("meta");inners=meta.get("innerInstructions") if isinstance(meta,Mapping) else None
 if isinstance(inners,list):
  for g in inners:
   ins=g.get("instructions") if isinstance(g,Mapping) else None
   if isinstance(ins,list):rows.extend(x for x in ins if isinstance(x,Mapping))
 vals=[]
 for ix in rows:
  if ix.get("programId")!=RAY:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or len(ac)!=13 or ac[3]!=POOL or not isinstance(d,str):continue
  raw=b58d(d)
  if len(raw)==24 and raw[:8]==DISC:vals.append(int.from_bytes(raw[8:16],"little"))
 return vals
def main():
 out=[]
 for sig,(pid,expected_len) in CASES.items():
  tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  if not isinstance(tx,Mapping):raise RuntimeError("transaction unavailable")
  outers=target_outer(tx,pid,expected_len);truths=truth(tx)
  raw=outers[0] if len(outers)==1 else b""
  candidate=int.from_bytes(raw[1:9],"little") if len(raw)>=9 and raw[0]==3 else None
  actual=truths[0] if len(truths)==1 else None
  out.append({"signature":sig,"slot":int(tx.get("slot",-1)),"outer_program":pid,"outer_len":len(raw) if raw else None,"outer_prefix_hex":raw[:16].hex() if raw else None,"candidate_amount_bytes_1_8":candidate,"truth_amounts":truths,"actual_amount_in":actual,"exact":candidate is not None and candidate==actual})
 ev={"schema":"ghost.settled_unknown_router_truth_score.v1","accepted":True,"observation_only":True,"execution_authority":False,"cases":out,"all_exact":all(x["exact"] for x in out),"interpretation":"A match supports only the observed compact 0x03 family shape. It does not establish a universal ABI for either program.","safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"ghost-settled-unknown-score-{st}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps(ev,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
