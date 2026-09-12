#!/usr/bin/env python3
"""Build a wider finalized corpus for the verified BisonFiWithSig 153-byte RFQ family.

Corpus admission is fail-closed:
- finalized successful transaction at least 128 slots behind finalized tip;
- exactly one Bison SwapEvent in logs;
- exactly one inner Bison payload containing that event's amount_in as u64 LE;
- payload len 153, opcode 19, direction byte raw[35] in {0,1};
- raw[41:73] exactly equals selected Bison instruction account[0];
- selected accounts[2]/[3] are token accounts owned by account[1];
- their finalized pre/post deltas uniquely realize +amount_in and -amount_out.

T903 already cryptographically verified the same structural family against the frozen
Bison executable's Keccak+secp256k1 verifier. This witness widens field/vault evidence;
it does not infer or promote a pricing formula. Finalized retrospective research only:
no pending monitoring, wallet, signer, simulation, transaction construction,
serialization, submission, broadcast, bridge execution, or capital movement.
"""
from __future__ import annotations
import hashlib,json,re,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping

RPC="https://api.mainnet-beta.solana.com"
BISON="BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi"
EVENT_RE=re.compile(r"SwapEvent \{ dex: BisonFiWithSig, amount_in: (\d+), amount_out: (\d+) \}")
B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; B58M={c:i for i,c in enumerate(B58)}

def b58d(s:str)->bytes:
 n=0
 for c in s:n=n*58+B58M[c]
 r=n.to_bytes((n.bit_length()+7)//8,"big") if n else b""
 return b"\0"*(len(s)-len(s.lstrip("1")))+r

def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b:bytes):return hashlib.sha256(b).hexdigest()

def post(payload:Any)->Any:
 body=json.dumps(payload,separators=(",",":")).encode();delay=.5
 for attempt in range(8):
  try:
   req=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Bison-RFQ-Corpus/1"})
   with urllib.request.urlopen(req,timeout=45) as resp:return json.loads(resp.read())
  except Exception:
   if attempt==7:raise
   time.sleep(delay);delay=min(delay*1.8,7)
 raise AssertionError("unreachable")

def rpc(method:str,params:list[Any])->Any:
 obj=post({"jsonrpc":"2.0","id":1,"method":method,"params":params})
 if not isinstance(obj,Mapping) or obj.get("error") is not None:raise RuntimeError(str(obj.get("error") if isinstance(obj,Mapping) else obj))
 return obj.get("result")

def tx_batch(sigs:list[str])->list[Any]:
 reqs=[{"jsonrpc":"2.0","id":i,"method":"getTransaction","params":[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}]} for i,sig in enumerate(sigs)]
 obj=post(reqs)
 if not isinstance(obj,list):raise RuntimeError("batch response not list")
 by={int(x.get("id")):x for x in obj if isinstance(x,Mapping) and isinstance(x.get("id"),int)}
 out=[]
 for i in range(len(sigs)):
  row=by.get(i);out.append(row.get("result") if isinstance(row,Mapping) and row.get("error") is None else None)
 return out

def keys(tx:Mapping[str,Any])->list[str]:
 tr=tx.get("transaction");m=tr.get("message") if isinstance(tr,Mapping) else None;ks=m.get("accountKeys") if isinstance(m,Mapping) else None
 return [str(x.get("pubkey")) if isinstance(x,Mapping) else str(x) for x in ks] if isinstance(ks,list) else []

def balances(tx:Mapping[str,Any],name:str)->dict[str,dict[str,Any]]:
 ks=keys(tx);meta=tx.get("meta");rows=meta.get(name) if isinstance(meta,Mapping) else None;out={}
 if not isinstance(rows,list):return out
 for row in rows:
  if not isinstance(row,Mapping):continue
  idx=row.get("accountIndex");ui=row.get("uiTokenAmount")
  if not isinstance(idx,int) or idx<0 or idx>=len(ks) or not isinstance(ui,Mapping):continue
  amount=ui.get("amount");dec=ui.get("decimals")
  if isinstance(amount,str) and isinstance(dec,int):out[ks[idx]]={"mint":row.get("mint"),"owner":row.get("owner"),"amount":int(amount),"decimals":dec}
 return out

def truths(tx:Mapping[str,Any])->list[tuple[int,int]]:
 meta=tx.get("meta");logs=meta.get("logMessages") if isinstance(meta,Mapping) else None;out=[]
 if isinstance(logs,list):
  for line in logs:
   if isinstance(line,str):
    m=EVENT_RE.search(line)
    if m:out.append((int(m.group(1)),int(m.group(2))))
 return out

def inners(tx:Mapping[str,Any])->list[dict[str,Any]]:
 meta=tx.get("meta");groups=meta.get("innerInstructions") if isinstance(meta,Mapping) else None;out=[]
 if not isinstance(groups,list):return out
 for g in groups:
  ins=g.get("instructions") if isinstance(g,Mapping) else None
  if not isinstance(ins,list):continue
  for ix in ins:
   if not isinstance(ix,Mapping) or ix.get("programId")!=BISON:continue
   d,ac=ix.get("data"),ix.get("accounts")
   if not isinstance(d,str) or not isinstance(ac,list):continue
   try:out.append({"raw":b58d(d),"accounts":[str(x) for x in ac]})
   except Exception:pass
 return out

def parse(tx:Mapping[str,Any],sig:str)->tuple[dict[str,Any]|None,str|None]:
 tv=truths(tx)
 if len(tv)!=1:return None,"truth_not_unique"
 amount_in,amount_out=tv[0];needle=amount_in.to_bytes(8,"little");cand=[x for x in inners(tx) if needle in x["raw"]]
 if len(cand)!=1:return None,"input_selected_payload_not_unique"
 r=cand[0]["raw"];ac=cand[0]["accounts"]
 if len(r)!=153 or r[0]!=19 or r[35] not in (0,1) or len(ac)<6:return None,"shape"
 try:caller=b58d(ac[0])
 except Exception:return None,"caller_decode"
 if len(caller)!=32 or r[41:73]!=caller:return None,"caller_binding"
 pre=balances(tx,"preTokenBalances");post=balances(tx,"postTokenBalances");v=[]
 for pos in (2,3):
  a=ac[pos];b=pre.get(a);p=post.get(a)
  if b is None or p is None:return None,"vault_balance_missing"
  if b["mint"]!=p["mint"] or b["owner"]!=p["owner"] or b["decimals"]!=p["decimals"]:return None,"vault_metadata_changed"
  if str(b["owner"])!=ac[1]:return None,"vault_owner"
  v.append({"position":pos,"address":a,"mint":b["mint"],"decimals":b["decimals"],"pre":b["amount"],"post":p["amount"],"delta":p["amount"]-b["amount"]})
 iv=[x for x in v if x["delta"]==amount_in];ov=[x for x in v if x["delta"]==-amount_out]
 if len(iv)!=1 or len(ov)!=1 or iv[0]["position"]==ov[0]["position"]:return None,"vault_truth"
 if (r[35]==0 and iv[0]["position"]!=2) or (r[35]==1 and iv[0]["position"]!=3):return None,"direction_flag_conflict"
 field_a=int.from_bytes(r[17:25],"little");field_b=int.from_bytes(r[25:33],"little");u16=int.from_bytes(r[33:35],"little")
 return {"signature":sig,"slot":int(tx.get("slot",-1)),"block_time":int(tx.get("blockTime",-1)),"amount_in":amount_in,"amount_out":amount_out,"payload_sha256":sha(r),"timestamp":int.from_bytes(r[9:17],"little"),"field_a":field_a,"field_b":field_b,"u16":u16,"direction":r[35],"reserved_36_40":r[36:41].hex(),"caller":ac[0],"signed_slot":int.from_bytes(r[73:81],"little"),"input_vault":iv[0],"output_vault":ov[0],"input_ui":amount_in/(10**iv[0]["decimals"]),"output_ui":amount_out/(10**ov[0]["decimals"]),"realized_output_per_input_ui":(amount_out/(10**ov[0]["decimals"]))/(amount_in/(10**iv[0]["decimals"])) if amount_in else None},None

def main()->int:
 started=now();tip=int(rpc("getSlot",[{"commitment":"finalized"}]));cutoff=tip-128
 hist=rpc("getSignaturesForAddress",[BISON,{"commitment":"finalized","limit":1000}]);
 if not isinstance(hist,list):raise RuntimeError("history missing")
 candidates=[]
 for x in hist:
  if isinstance(x,Mapping) and x.get("err") is None and isinstance(x.get("signature"),str) and isinstance(x.get("slot"),int) and x["slot"]<=cutoff:
   candidates.append(x["signature"])
  if len(candidates)>=600:break
 rows=[];reject={};missing=0;batch_fail=0
 for start in range(0,len(candidates),10):
  if len(rows)>=30:break
  chunk=candidates[start:start+10]
  try:txs=tx_batch(chunk)
  except Exception:batch_fail+=1;continue
  for sig,tx in zip(chunk,txs):
   if len(rows)>=30:break
   if not isinstance(tx,Mapping):missing+=1;continue
   row,reason=parse(tx,sig)
   if row is not None:rows.append(row)
   else:reject[reason or "unknown"]=reject.get(reason or "unknown",0)+1
  time.sleep(.12)
 summary={}
 for d in (0,1):
  subset=[r for r in rows if r["direction"]==d]
  summary[str(d)]={"count":len(subset),"input_vault_positions":sorted({r["input_vault"]["position"] for r in subset}),"input_decimals":sorted({r["input_vault"]["decimals"] for r in subset}),"output_decimals":sorted({r["output_vault"]["decimals"] for r in subset}),"u16_values":[r["u16"] for r in subset]}
 ev={"schema":"ghost.bison_signed_rfq_corpus.v1","accepted":True,"observation_only":True,"execution_authority":False,"started_at":started,"completed_at":now(),"finalized_tip_at_start":tip,"cutoff_slot":cutoff,"minimum_tip_distance_slots":128,"history_limit":1000,"candidate_count":len(candidates),"accepted_case_count":len(rows),"direction_summary":summary,"cases":rows,"rejections":reject,"transaction_missing":missing,"batch_failures":batch_fail,"interpretation":"Wider finalized field corpus only. No price/field formula is promoted by this witness.","safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 stamp=started.replace(":","").replace("-","").replace(".","_");out=Path("live-evidence")/f"bison-signed-rfq-corpus-{stamp}";out.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(out/"evidence.json").write_bytes(raw);(out/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n")
 print(json.dumps({"accepted_case_count":len(rows),"direction_summary":summary,"rejections":reject,"transaction_missing":missing,"batch_failures":batch_fail},indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
