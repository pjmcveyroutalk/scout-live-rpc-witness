#!/usr/bin/env python3
"""Measure Raydium pool-info API freshness against confirmed on-chain writes.

Read-only observation only. This does not predict, sign, simulate, build, submit,
or broadcast transactions. It measures a public information-surface lag after
transactions are already confirmed.
"""
from __future__ import annotations
import hashlib,http.client,json,ssl,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping

RPC="https://api.mainnet-beta.solana.com"
POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2"
MUTABLE=[POOL,"v3YN4d7JRhKFcwtex7qNtyg2r5hKYW96Cayb6GivSvY","HG2WgeYsjqQhnjhwHj7QdTVvjyWpFRk6VREAQ8MURv2u"]
API=f"https://api-v3.raydium.io/pools/info/ids?ids={POOL}"
RUNTIME=180.0; POLL=1.0

def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b):return hashlib.sha256(b).hexdigest()
def req_json(url,data=None,headers=None,timeout=20):
 q=urllib.request.Request(url,data=data,method="POST" if data is not None else "GET",headers=headers or {})
 with urllib.request.urlopen(q,timeout=timeout) as r:return int(r.status),r.read()
def rpc(method,params):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params},separators=(",",":")).encode();delay=.4
 for i in range(6):
  try:
   s,raw=req_json(RPC,body,{"content-type":"application/json","user-agent":"Ghost-Ray-API-Lag/0"});o=json.loads(raw)
   if s!=200 or not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o))
   return o.get("result"),{"status":s,"request_sha256":sha(body),"response_sha256":sha(raw)}
  except Exception:
   if i==5:raise
   time.sleep(delay);delay=min(delay*2,6)
def api_sample():
 s,raw=req_json(API,headers={"accept":"application/json","cache-control":"no-cache","pragma":"no-cache","user-agent":"Ghost-Ray-API-Lag/0"});o=json.loads(raw)
 if s!=200 or not isinstance(o,Mapping) or o.get("success") is not True:raise RuntimeError(f"api shape/status {s}")
 data=o.get("data")
 row=data[0] if isinstance(data,list) and data else (data.get("data",[None])[0] if isinstance(data,Mapping) and isinstance(data.get("data"),list) and data.get("data") else None)
 if not isinstance(row,Mapping):raise RuntimeError("pool row missing")
 view={k:row.get(k) for k in ("id","price","mintAmountA","mintAmountB","tvl","feeRate")}
 return {"at":now(),"view":view,"fingerprint":sha(json.dumps(view,sort_keys=True,separators=(",",":")).encode()),"response_sha256":sha(raw)}
def chain_sample():
 result,e=rpc("getMultipleAccounts",[MUTABLE,{"encoding":"base64","commitment":"confirmed"}])
 if not isinstance(result,Mapping) or not isinstance(result.get("context"),Mapping):raise RuntimeError("chain shape")
 vals=result.get("value")
 if not isinstance(vals,list) or len(vals)!=3:raise RuntimeError("chain incomplete")
 compact=[]
 for v in vals:
  if not isinstance(v,Mapping):raise RuntimeError("account missing")
  compact.append({"lamports":v.get("lamports"),"owner":v.get("owner"),"data":v.get("data")})
 return {"at":now(),"slot":int(result["context"]["slot"]),"fingerprint":sha(json.dumps(compact,sort_keys=True,separators=(",",":")).encode()),"rpc":e}
def sigs():
 rows,e=rpc("getSignaturesForAddress",[POOL,{"commitment":"confirmed","limit":100}])
 return ([r for r in rows if isinstance(r,Mapping)] if isinstance(rows,list) else []),e

def main():
 start=now(); api0=api_sample(); ch0=chain_sample(); rows,_=sigs(); seen={r.get("signature") for r in rows if isinstance(r.get("signature"),str)}
 api_events=[api0]; chain_events=[ch0]; confirmed=[]; errors=[]; last_api=api0["fingerprint"];last_chain=ch0["fingerprint"]
 t0=time.monotonic()
 while time.monotonic()-t0<RUNTIME:
  tick=time.monotonic()
  try:
   a=api_sample()
   if a["fingerprint"]!=last_api: api_events.append(a);last_api=a["fingerprint"]
  except Exception as x:errors.append({"at":now(),"surface":"raydium_api","error":f"{type(x).__name__}:{x}"})
  try:
   c=chain_sample()
   if c["fingerprint"]!=last_chain:chain_events.append(c);last_chain=c["fingerprint"]
  except Exception as x:errors.append({"at":now(),"surface":"chain","error":f"{type(x).__name__}:{x}"})
  try:
   rr,_=sigs()
   fresh=[]
   for r in rr:
    sg=r.get("signature")
    if isinstance(sg,str) and sg not in seen:
     seen.add(sg)
     if r.get("err") is None:fresh.append({"signature":sg,"slot":int(r.get("slot",-1)),"blockTime":r.get("blockTime"),"observed_at":now()})
   confirmed.extend(reversed(fresh))
  except Exception as x:errors.append({"at":now(),"surface":"signatures","error":f"{type(x).__name__}:{x}"})
  time.sleep(max(0.0,POLL-(time.monotonic()-tick)))
 end=now()
 ev={"schema":"ghost.raydium_api_state_lag.v0","accepted":True,"observation_only":True,"execution_authority":False,"started_at":start,"completed_at":end,"runtime_seconds":RUNTIME,"target_pool":POOL,"raydium_api":API,"initial":{"api":api0,"chain":ch0},"api_change_events":api_events,"chain_change_events":chain_events,"new_successful_confirmed_pool_writes":confirmed,"counts":{"api_fingerprint_changes":max(0,len(api_events)-1),"chain_fingerprint_changes":max(0,len(chain_events)-1),"confirmed_successful_writes":len(confirmed),"errors":len(errors)},"errors":errors,"interpretation_rule":"A static API fingerprint while confirmed pool writes and chain fingerprints advance is evidence of public pool-info staleness only; it is not by itself proof of executable quote lag or profit.","safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=start.replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"raydium-api-state-lag-{st}";d.mkdir(parents=True,exist_ok=True);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps(ev["counts"],indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
