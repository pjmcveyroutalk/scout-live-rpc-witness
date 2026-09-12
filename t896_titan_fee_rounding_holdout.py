#!/usr/bin/env python3
"""Resolve Titan V3 centi-bps fee rounding on two fresh settled census holdouts.

The two signatures were selected from signed-message census data because each is a
single RaydiumCP route with amount 10,114 / 10,096 and fee_centi_bps=8100, producing
non-integral 81-bps fees. Finalized Raydium CPI amount is used only as the answer key.
No pending monitoring, wallet, signing, simulation, construction/submission or broadcast.
"""
from __future__ import annotations
import hashlib,json,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping
RPC="https://api.mainnet-beta.solana.com";RAY="CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2";DISC=hashlib.sha256(b"global:swap_base_input").digest()[:8]
CASES={
"4ntz9zfeDQb4ZfGEjRCQq16LtSP8mF2BCtnARsoVzyK835qczZiFZXCsWLLBLemc51xGA11eSBsmSRYP65p5pzGc":10114,
"2wSUV82ydrEvATJ5kyjfwFAgrUP1HMkwdzcMKeZoNA621uLSzo1FC73ngVk5GnLyteyWgnqzWDJ5EuQLpyRCptnV":10096,
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
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Titan-Fee-Rounding/1"})
   with urllib.request.urlopen(q,timeout=30) as r:o=json.loads(r.read())
   if not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o.get("error") if isinstance(o,Mapping) else o))
   return o.get("result")
  except Exception:
   if i==6:raise
   time.sleep(d);d=min(d*2,6)
def msg(tx):
 t=tx.get("transaction");m=t.get("message") if isinstance(t,Mapping) else None
 if not isinstance(m,Mapping):raise RuntimeError("message missing")
 return m
def titan_header(tx):
 found=[]
 for ix in msg(tx).get("instructions",[]):
  if not isinstance(ix,Mapping) or ix.get("programId")!="T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT":continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or POOL not in ac or not isinstance(d,str):continue
  raw=b58d(d)
  if len(raw)==36 and raw[:1]==b"\x2a":found.append(raw)
 if len(found)!=1:raise RuntimeError(f"expected one Titan len36 instruction, got {len(found)}")
 r=found[0];return {"amount":int.from_bytes(r[2:10],"little"),"fee_centi_bps":int.from_bytes(r[21:23],"little"),"weight_nanos":int.from_bytes(r[31:35],"little"),"venue_tag":r[28],"from":r[29],"to":r[30],"n_accounts":r[35]}
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
  if ix.get("programId")!=RAY:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or len(ac)!=13 or ac[3]!=POOL or not isinstance(d,str):continue
  r=b58d(d)
  if len(r)==24 and r[:8]==DISC:vals.append(int.from_bytes(r[8:16],"little"))
 return vals
def main():
 rows=[]
 for sig,expected_amount in CASES.items():
  tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  if not isinstance(tx,Mapping):raise RuntimeError("tx unavailable")
  h=titan_header(tx);tv=truth(tx);actual=tv[0] if len(tv)==1 else None
  amount=h["amount"];rate=h["fee_centi_bps"]
  floor_fee=amount*rate//1_000_000;ceil_fee=(amount*rate+999_999)//1_000_000
  floor_effective=amount-floor_fee;ceil_effective=amount-ceil_fee
  rows.append({"signature":sig,"slot":int(tx.get("slot",-1)),"header":h,"census_expected_amount":expected_amount,"fee_floor":floor_fee,"fee_ceil":ceil_fee,"effective_if_floor_fee":floor_effective,"effective_if_ceil_fee":ceil_effective,"truth_amounts":tv,"actual_raydium_input":actual,"matches_floor_fee_rule":actual==floor_effective,"matches_ceil_fee_rule":actual==ceil_effective})
 ev={"schema":"ghost.titan_fee_rounding_holdout.v1","accepted":True,"observation_only":True,"execution_authority":False,"cases":rows,"all_match_floor_fee_rule":all(x["matches_floor_fee_rule"] for x in rows),"all_match_ceil_fee_rule":all(x["matches_ceil_fee_rule"] for x in rows),"safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"titan-fee-rounding-holdout-{st}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps(ev,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
