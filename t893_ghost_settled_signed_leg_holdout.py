#!/usr/bin/env python3
"""Post-settlement holdout validation for Ghost signed-router Raydium leg decoders.

Only finalized transactions at least 128 slots behind the finalized tip are eligible.
The predictor reads top-level signed-message fields; the answer key is the already-finalized
Raydium SwapBaseInput instruction. This is retrospective research, not live transaction
monitoring. No wallet, signing, simulation, transaction building/submission, broadcasting,
or capital movement.
"""
from __future__ import annotations
import hashlib,json,sys,time,urllib.request
from pathlib import Path
from typing import Any,Mapping
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/"ghost_g0"))
from ghost_okx_raydium_router_probe_v0 import OKX_ROUTER,RAYDIUM_CPMM,RAYDIUM_CPMM_DEX_TAG,SWAP_TOB_DISCRIMINATOR,ProbeError,b58decode,decode_swap_tob
from ghost_okx_route_census import ray_blocks

RPC="https://api.mainnet-beta.solana.com"; TARGET="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
TITAN="T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT"; DRSW="DRSw8uSW9De7eCKSM9qXm7aD2QKrvcJnA7Hf4Uu3ezYM"
ENH=bytes([190,156,169,176,149,154,161,108]); SWAP_IN=hashlib.sha256(b"global:swap_base_input").digest()[:8]

def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b):return hashlib.sha256(b).hexdigest()
def rpc(method,params):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params},separators=(",",":")).encode();delay=.5
 for i in range(7):
  try:
   req=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Settled-Holdout/1"})
   with urllib.request.urlopen(req,timeout=30) as r:o=json.loads(r.read())
   if not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o.get("error") if isinstance(o,Mapping) else o))
   return o.get("result")
  except Exception:
   if i==6:raise
   time.sleep(delay);delay=min(delay*2,6)
def msg(tx):
 t=tx.get("transaction");m=t.get("message") if isinstance(t,Mapping) else None
 if not isinstance(m,Mapping):raise ProbeError("message missing")
 return m
def raw_outer(message):
 out=[]
 for i,ix in enumerate(message.get("instructions",[]) if isinstance(message.get("instructions"),list) else []):
  if not isinstance(ix,Mapping):continue
  a,d,p=ix.get("accounts"),ix.get("data"),ix.get("programId")
  if isinstance(a,list) and TARGET in a and isinstance(d,str) and isinstance(p,str):
   try:r=b58decode(d)
   except Exception:continue
   out.append((i,p,list(a),r))
 return out
def okx_pred(accounts,raw):
 kind="okx_swap_tob" if raw.startswith(SWAP_TOB_DISCRIMINATOR) else ("okx_enhanced" if raw.startswith(ENH) else None)
 if not kind:return None
 norm=raw if kind=="okx_swap_tob" else SWAP_TOB_DISCRIMINATOR+raw[8:]
 try:d=decode_swap_tob(norm)
 except ProbeError:return None
 routes=list(d["routes"]);rr=[r for r in routes if int(r["dex_tag"])==RAYDIUM_CPMM_DEX_TAG];blocks=ray_blocks(accounts)
 if len(rr)!=len(blocks):return None
 pairs=list(zip(rr,blocks));m=[(r,b) for r,b in pairs if b.get("pool")==TARGET]
 if len(m)!=1:return None
 target=m[0][0]
 if int(target["source_node"])!=0:return None
 roots=[r for r in routes if int(r["source_node"])==0]
 if not roots or sum(int(r["weight"]) for r in roots)!=10000:return None
 amount=int(d["amount_in"]);used=0;value=None
 for j,r in enumerate(roots):
  x=amount-used if j+1==len(roots) else amount*int(r["weight"])//10000
  if j+1<len(roots):used+=x
  if r is target:value=x
 return (kind,value) if isinstance(value,int) and value>0 else None
def titan_pred(accounts,raw):
 if len(raw)!=36 or raw[:1]!=b"\x2a" or int.from_bytes(raw[24:28],"little")!=1 or raw[28]!=10:return None
 if raw[29]!=0 or raw[30]!=1 or RAYDIUM_CPMM not in accounts:return None
 amount=int.from_bytes(raw[2:10],"little");fee=int.from_bytes(raw[21:23],"little");weight=int.from_bytes(raw[31:35],"little")
 if fee not in (0,8100):return None
 prod=amount*fee
 if prod%1_000_000:return None
 effective=amount-prod//1_000_000;value=effective*min(weight,1_000_000_000)//1_000_000_000
 return ("titan_single_cpmm",value) if value>0 else None
def drsw_pred(accounts,raw):
 if len(raw)==33 and raw[:1]==b"\x03" and RAYDIUM_CPMM in accounts:
  v=int.from_bytes(raw[1:9],"little");return ("drsw_03_len33",v) if v>0 else None
 return None
def predict(message):
 found=[]
 for _,p,a,r in raw_outer(message):
  x=okx_pred(a,r) if p==OKX_ROUTER else (titan_pred(a,r) if p==TITAN else (drsw_pred(a,r) if p==DRSW else None))
  if x:found.append(x)
 return found[0] if len(found)==1 else None
def truth(tx):
 rows=[];m=msg(tx);top=m.get("instructions")
 if isinstance(top,list):rows += [x for x in top if isinstance(x,Mapping)]
 meta=tx.get("meta");inners=meta.get("innerInstructions") if isinstance(meta,Mapping) else None
 if isinstance(inners,list):
  for g in inners:
   ins=g.get("instructions") if isinstance(g,Mapping) else None
   if isinstance(ins,list):rows += [x for x in ins if isinstance(x,Mapping)]
 vals=[]
 for ix in rows:
  if ix.get("programId")!=RAYDIUM_CPMM:continue
  a,d=ix.get("accounts"),ix.get("data")
  if not isinstance(a,list) or len(a)!=13 or a[3]!=TARGET or not isinstance(d,str):continue
  try:r=b58decode(d)
  except Exception:continue
  if len(r)==24 and r[:8]==SWAP_IN:vals.append(int.from_bytes(r[8:16],"little"))
 return vals

def main():
 start=now();tip=int(rpc("getSlot",[{"commitment":"finalized"}]));cutoff=tip-128
 hist=rpc("getSignaturesForAddress",[TARGET,{"commitment":"finalized","limit":500}]);results=[];rejects={}
 for row in hist if isinstance(hist,list) else []:
  if len(results)>=25:break
  if not isinstance(row,Mapping) or row.get("err") is not None or int(row.get("slot",10**18))>cutoff:continue
  sig=row.get("signature")
  if not isinstance(sig,str):continue
  try:tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  except Exception:rejects["rpc"]=rejects.get("rpc",0)+1;continue
  if not isinstance(tx,Mapping):continue
  try:p=predict(msg(tx))
  except Exception:p=None
  if p is None:rejects["not_supported"]=rejects.get("not_supported",0)+1;continue
  tv=truth(tx)
  if len(tv)!=1:rejects["truth_not_unique"]=rejects.get("truth_not_unique",0)+1;continue
  fam,pred=p;actual=tv[0];results.append({"signature":sig,"slot":int(tx.get("slot",-1)),"family":fam,"predicted_amount_in":pred,"actual_amount_in":actual,"exact":pred==actual})
 exact=sum(1 for r in results if r["exact"]);families={}
 for r in results:families[r["family"]]=families.get(r["family"],0)+1
 ev={"schema":"ghost.settled_signed_leg_holdout.v1","accepted":True,"observation_only":True,"execution_authority":False,"started_at":start,"completed_at":now(),"finalized_tip_at_start":tip,"eligibility_cutoff_slot":cutoff,"minimum_tip_distance_slots":128,"sample_count":len(results),"exact_count":exact,"all_exact":bool(results) and exact==len(results),"family_counts":families,"results":results,"rejections":rejects,"safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 stamp=start.replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"ghost-settled-leg-holdout-{stamp}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps({"sample_count":len(results),"exact_count":exact,"families":families,"rejections":rejects},indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
