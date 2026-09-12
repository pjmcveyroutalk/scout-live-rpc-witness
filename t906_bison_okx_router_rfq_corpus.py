#!/usr/bin/env python3
"""Build a finalized BisonFiWithSig RFQ corpus from the cryptographically bound OKX caller.

T905 showed getSignaturesForAddress(Bison program) returns no candidates because this
program is invoked as CPI. T903 proved raw[41:73] is exactly the Bison instruction's
caller account, and the settled family uses OKX router ARu4n5... as that caller. This
witness therefore discovers transactions from that caller's finalized address history,
then applies the same strict Bison admission rules as T905.

No formula is promoted. Finalized retrospective research only; no pending monitoring,
wallet, signer, simulation, transaction construction/serialization/submission, broadcast,
bridge execution, or capital movement.
"""
from __future__ import annotations
import hashlib,json,re,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping
RPC="https://api.mainnet-beta.solana.com";BISON="BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi";CALLER="ARu4n5mFdZogZAravu7CcizaojWnS6oqka37gdLT5SZn"
EVENT_RE=re.compile(r"SwapEvent \{ dex: BisonFiWithSig, amount_in: (\d+), amount_out: (\d+) \}")
B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";M={c:i for i,c in enumerate(B58)}
def b58d(s):
 n=0
 for c in s:n=n*58+M[c]
 r=n.to_bytes((n.bit_length()+7)//8,"big") if n else b"";return b"\0"*(len(s)-len(s.lstrip("1")))+r
def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(x):return hashlib.sha256(x).hexdigest()
def post(p):
 body=json.dumps(p,separators=(",",":")).encode();d=.45
 for a in range(8):
  try:
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Bison-OKX-RFQ-Corpus/1"})
   with urllib.request.urlopen(q,timeout=45) as r:return json.loads(r.read())
  except Exception:
   if a==7:raise
   time.sleep(d);d=min(d*1.8,7)
def rpc(m,p):
 x=post({"jsonrpc":"2.0","id":1,"method":m,"params":p})
 if not isinstance(x,Mapping) or x.get("error") is not None:raise RuntimeError(str(x.get("error") if isinstance(x,Mapping) else x))
 return x.get("result")
def batch(sigs):
 req=[{"jsonrpc":"2.0","id":i,"method":"getTransaction","params":[s,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}]} for i,s in enumerate(sigs)];x=post(req)
 if not isinstance(x,list):raise RuntimeError("batch response")
 by={int(z.get("id")):z for z in x if isinstance(z,Mapping) and isinstance(z.get("id"),int)};return [by[i].get("result") if i in by and by[i].get("error") is None else None for i in range(len(sigs))]
def keys(tx):
 tr=tx.get("transaction");msg=tr.get("message") if isinstance(tr,Mapping) else None;ks=msg.get("accountKeys") if isinstance(msg,Mapping) else None
 return [str(x.get("pubkey")) if isinstance(x,Mapping) else str(x) for x in ks] if isinstance(ks,list) else []
def bals(tx,name):
 ks=keys(tx);meta=tx.get("meta");rs=meta.get(name) if isinstance(meta,Mapping) else None;o={}
 if not isinstance(rs,list):return o
 for z in rs:
  if not isinstance(z,Mapping):continue
  i=z.get("accountIndex");u=z.get("uiTokenAmount")
  if isinstance(i,int) and 0<=i<len(ks) and isinstance(u,Mapping) and isinstance(u.get("amount"),str) and isinstance(u.get("decimals"),int):o[ks[i]]={"mint":z.get("mint"),"owner":z.get("owner"),"amount":int(u["amount"]),"decimals":u["decimals"]}
 return o
def truth(tx):
 meta=tx.get("meta");logs=meta.get("logMessages") if isinstance(meta,Mapping) else None;o=[]
 if isinstance(logs,list):
  for line in logs:
   if isinstance(line,str):
    m=EVENT_RE.search(line)
    if m:o.append((int(m.group(1)),int(m.group(2))))
 return o
def inners(tx):
 meta=tx.get("meta");gs=meta.get("innerInstructions") if isinstance(meta,Mapping) else None;o=[]
 if not isinstance(gs,list):return o
 for g in gs:
  ins=g.get("instructions") if isinstance(g,Mapping) else None
  if not isinstance(ins,list):continue
  for ix in ins:
   if isinstance(ix,Mapping) and ix.get("programId")==BISON and isinstance(ix.get("data"),str) and isinstance(ix.get("accounts"),list):
    try:o.append({"raw":b58d(ix["data"]),"accounts":[str(y) for y in ix["accounts"]]})
    except Exception:pass
 return o
def parse(tx,sig):
 ts=truth(tx)
 if len(ts)!=1:return None,"truth"
 ai,ao=ts[0];needle=ai.to_bytes(8,"little");cs=[z for z in inners(tx) if needle in z["raw"]]
 if len(cs)!=1:return None,"selected"
 z=cs[0];r=z["raw"];ac=z["accounts"]
 if len(r)!=153 or r[0]!=19 or r[35] not in (0,1) or len(ac)<6:return None,"shape"
 if ac[0]!=CALLER or r[41:73]!=b58d(CALLER):return None,"caller"
 pre,po=bals(tx,"preTokenBalances"),bals(tx,"postTokenBalances");vs=[]
 for pos in (2,3):
  a=ac[pos];b=pre.get(a);p=po.get(a)
  if b is None or p is None:return None,"balance"
  if b["mint"]!=p["mint"] or b["owner"]!=p["owner"] or b["decimals"]!=p["decimals"] or str(b["owner"])!=ac[1]:return None,"vaultmeta"
  vs.append({"position":pos,"address":a,"mint":b["mint"],"decimals":b["decimals"],"delta":p["amount"]-b["amount"]})
 iv=[v for v in vs if v["delta"]==ai];ov=[v for v in vs if v["delta"]==-ao]
 if len(iv)!=1 or len(ov)!=1 or iv[0]["position"]==ov[0]["position"]:return None,"vaulttruth"
 if (r[35]==0 and iv[0]["position"]!=2) or (r[35]==1 and iv[0]["position"]!=3):return None,"dir"
 return {"signature":sig,"slot":int(tx.get("slot",-1)),"block_time":int(tx.get("blockTime",-1)),"amount_in":ai,"amount_out":ao,"input_vault":iv[0],"output_vault":ov[0],"input_ui":ai/10**iv[0]["decimals"],"output_ui":ao/10**ov[0]["decimals"],"realized_output_per_input_ui":(ao/10**ov[0]["decimals"])/(ai/10**iv[0]["decimals"]),"payload_sha256":sha(r),"timestamp":int.from_bytes(r[9:17],"little"),"field_a":int.from_bytes(r[17:25],"little"),"field_b":int.from_bytes(r[25:33],"little"),"u16":int.from_bytes(r[33:35],"little"),"direction":r[35],"reserved_36_40":r[36:41].hex(),"signed_slot":int.from_bytes(r[73:81],"little")},None
def main():
 st=now();tip=int(rpc("getSlot",[{"commitment":"finalized"}]));cut=tip-128;hist=rpc("getSignaturesForAddress",[CALLER,{"commitment":"finalized","limit":1000}]);c=[]
 if not isinstance(hist,list):raise RuntimeError("history")
 for x in hist:
  if isinstance(x,Mapping) and x.get("err") is None and isinstance(x.get("signature"),str) and isinstance(x.get("slot"),int) and x["slot"]<=cut:c.append(x["signature"])
  if len(c)>=800:break
 rows=[];rej={};miss=bf=0
 for i in range(0,len(c),10):
  if len(rows)>=40:break
  ch=c[i:i+10]
  try:txs=batch(ch)
  except Exception:bf+=1;continue
  for s,tx in zip(ch,txs):
   if len(rows)>=40:break
   if not isinstance(tx,Mapping):miss+=1;continue
   row,why=parse(tx,s)
   if row:rows.append(row)
   else:rej[why]=rej.get(why,0)+1
  time.sleep(.1)
 ds={str(d):sum(1 for r in rows if r["direction"]==d) for d in (0,1)}
 ev={"schema":"ghost.bison_okx_router_rfq_corpus.v1","accepted":True,"observation_only":True,"execution_authority":False,"started_at":st,"completed_at":now(),"finalized_tip_at_start":tip,"cutoff_slot":cut,"history_address":CALLER,"history_limit":1000,"candidate_count":len(c),"accepted_case_count":len(rows),"direction_counts":ds,"cases":rows,"rejections":rej,"transaction_missing":miss,"batch_failures":bf,"interpretation":"Corpus only; field semantics/formula remain unpromoted.","safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 stamp=st.replace(":","").replace("-","").replace(".","_");out=Path("live-evidence")/f"bison-okx-router-rfq-corpus-{stamp}";out.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(out/"evidence.json").write_bytes(raw);(out/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps({"candidate_count":len(c),"accepted_case_count":len(rows),"direction_counts":ds,"rejections":rej,"transaction_missing":miss,"batch_failures":bf},indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
