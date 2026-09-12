#!/usr/bin/env python3
"""Settled holdout validation for OKX SwapTobEnhanced -> locked Raydium direct-root legs.

Ten signatures were selected from the signed-surface census solely because the outer
instruction family was SwapTobEnhanced. Prediction uses the same proven SwapTob route
body semantics after replacing only the 8-byte entrypoint discriminator. Finalized inner
Raydium SwapBaseInput is used afterward as answer key. No pending monitoring or execution.
"""
from __future__ import annotations
import hashlib,json,sys,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT/"ghost_g0"))
from ghost_okx_raydium_router_probe_v0 import OKX_ROUTER,RAYDIUM_CPMM,SWAP_TOB_DISCRIMINATOR,ProbeError,b58decode
from ghost_okx_raydium_router_probe_v1 import derive_direct_root_raydium_leg_v1
RPC="https://api.mainnet-beta.solana.com";POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2";ENH=bytes([190,156,169,176,149,154,161,108]);DISC=hashlib.sha256(b"global:swap_base_input").digest()[:8]
SIGS=["4QD3bzSwz8p9GAbaUzaQpGUETsLGhcUAEav3gRBxXdyrCBYdqgoUSBHPJF1ctSd5Ud7De6bXJWjGBv1dPssmq4Rj","2tPpeyki4FqhnNACNWMWitK6ScKYJyTdmJZB8LeakGD3LF391t9qD1WBs85CMqYfUEQsZCSz5rB66GpVWmxvq6MZ","5NCj1tR8dducnTTcfnbXMHv6zz92qbgH9oDjKreRbJRLsmuP7HrbQBQBc2K16sWySSAgk6rqiC1pBJskoAKB1rXq","2K8kB4k6uHqWbSGFanJgmBqJJfUpLAtf8m9TxmaSXTJVG6YpjbpscBLzidVZwgga3M49DiE8yV2Vt4MndxRLyPvz","9RpP1RmNUqidiiDAfXVSfdHvhiUayCLyeUjGm9q85GJxM6JnDctCACgpJNxtHGSFjqwRSDerARFeakvukEMiWeC","hRUhFLmGX7zyr2Ya16NzKfn9yCETuZGWRHU9uhmcBGQdDEYCCa1JRCEZExGn3xXbVUEq9uLdhUT4jCb2zDQp9bj","5dpRJorvLFLMrmyk7HNPLRkpzerRQGYatgkKCF7Dv8AjCFGWTabgwLQPG6RETAHyLaxGCotDDLHv9RcQCSahAEc3","2W2yJxDjwBUca14fHVs5Prye4GWqzQpdYsTAvd3hmRJLHjvcrzRdkGrgWN8mnaQ9q9pXzussUWCVMnCnZxrtWeSP","5Zqt37rbpfRbSZwkBHeT2SBzUbBYPuJzYn97fj4ygAnNdcJQabDxKY19cJdPypk9KZQUSBLoANpdWKM48xnHLzMi","2X9kHpBdutCoqLrXaWK1eLbaGdNmTR3Hd743XEY1iTUE9T3hbXUy5NFagTogM8VahCZsWUboGecBXugLWaMxAs9R"]
def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b):return hashlib.sha256(b).hexdigest()
def rpc(m,p):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p},separators=(",",":")).encode();d=.45
 for i in range(7):
  try:
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-OKX-Enhanced-Holdout/1"})
   with urllib.request.urlopen(q,timeout=30) as r:o=json.loads(r.read())
   if not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o.get("error") if isinstance(o,Mapping) else o))
   return o.get("result")
  except Exception:
   if i==6:raise
   time.sleep(d);d=min(d*2,5)
def msg(tx):
 t=tx.get("transaction");m=t.get("message") if isinstance(t,Mapping) else None
 if not isinstance(m,Mapping):raise RuntimeError("message missing")
 return m
def outer(tx):
 f=[]
 for ix in msg(tx).get("instructions",[]):
  if not isinstance(ix,Mapping) or ix.get("programId")!=OKX_ROUTER:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or POOL not in ac or not isinstance(d,str):continue
  r=b58decode(d)
  if r.startswith(ENH):f.append((r,list(ac)))
 return f
def truth(tx):
 rows=[];m=msg(tx);top=m.get("instructions")
 if isinstance(top,list):rows += [x for x in top if isinstance(x,Mapping)]
 meta=tx.get("meta");inn=meta.get("innerInstructions") if isinstance(meta,Mapping) else None
 if isinstance(inn,list):
  for g in inn:
   ins=g.get("instructions") if isinstance(g,Mapping) else None
   if isinstance(ins,list):rows += [x for x in ins if isinstance(x,Mapping)]
 vals=[]
 for ix in rows:
  if ix.get("programId")!=RAYDIUM_CPMM:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or len(ac)!=13 or ac[3]!=POOL or not isinstance(d,str):continue
  r=b58decode(d)
  if len(r)==24 and r[:8]==DISC:vals.append(int.from_bytes(r[8:16],"little"))
 return vals
def main():
 out=[];rejects=[]
 for sig in SIGS:
  tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  if not isinstance(tx,Mapping):rejects.append({"signature":sig,"reason":"tx unavailable"});continue
  os=outer(tx)
  if len(os)!=1:rejects.append({"signature":sig,"reason":f"enhanced outer count {len(os)}"});continue
  raw,ac=os[0]
  try:leg=derive_direct_root_raydium_leg_v1(SWAP_TOB_DISCRIMINATOR+raw[8:],ac,POOL)
  except Exception as e:rejects.append({"signature":sig,"slot":int(tx.get("slot",-1)),"reason":f"{type(e).__name__}:{e}"});continue
  tv=truth(tx);actual=tv[0] if len(tv)==1 else None;pred=int(leg["derived_raydium_amount_in"])
  out.append({"signature":sig,"slot":int(tx.get("slot",-1)),"outer_amount_in":leg["outer_amount_in"],"predicted_amount_in":pred,"truth_amounts":tv,"actual_amount_in":actual,"exact":actual==pred,"root_routes":leg["root_routes"],"root_allocations":leg["root_allocations"]})
 ev={"schema":"ghost.okx_enhanced_settled_holdout.v1","accepted":True,"observation_only":True,"execution_authority":False,"selected_count":len(SIGS),"projectable_count":len(out),"exact_count":sum(1 for x in out if x["exact"]),"all_projectable_exact":bool(out) and all(x["exact"] for x in out),"results":out,"rejections":rejects,"safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"okx-enhanced-holdout-{st}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps({"selected":len(SIGS),"projectable":len(out),"exact":sum(1 for x in out if x["exact"]),"rejects":rejects},indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
