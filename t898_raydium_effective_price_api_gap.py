#!/usr/bin/env python3
"""One-shot read-only comparison of locked Raydium CPMM effective on-chain price vs public API.

Uses confirmed pool state + raw vault balances, subtracts accrued protocol/fund/creator fees
exactly as the Ghost CPMM transition model does, and compares the resulting USDC-per-WSOL
reserve ratio with Raydium public pool-info price/reserves. This is descriptive state research,
not a trade signal. No wallet/signing/simulation/transaction construction/submission/broadcast.
"""
from __future__ import annotations
import base64,hashlib,json,time,urllib.request
from datetime import datetime,timezone
from decimal import Decimal
from pathlib import Path
from typing import Any,Mapping
RPC="https://api.mainnet-beta.solana.com";POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2";WSOL_V="v3YN4d7JRhKFcwtex7qNtyg2r5hKYW96Cayb6GivSvY";USDC_V="HG2WgeYsjqQhnjhwHj7QdTVvjyWpFRk6VREAQ8MURv2u";WSOL="So11111111111111111111111111111111111111112";USDC="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";API=f"https://api-v3.raydium.io/pools/info/ids?ids={POOL}";OFF=64
def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b):return hashlib.sha256(b).hexdigest()
def req(url,data=None,headers=None):
 q=urllib.request.Request(url,data=data,method="POST" if data is not None else "GET",headers=headers or {})
 with urllib.request.urlopen(q,timeout=25) as r:return int(r.status),r.read()
def rpc(m,p):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p},separators=(",",":")).encode();d=.5
 for i in range(7):
  try:
   s,r=req(RPC,body,{"content-type":"application/json","user-agent":"Ghost-Ray-Effective-Gap/1"});o=json.loads(r)
   if s!=200 or not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o))
   return o.get("result")
  except Exception:
   if i==6:raise
   time.sleep(d);d=min(d*2,6)
def rawdata(v):
 d=v.get("data") if isinstance(v,Mapping) else None
 if not isinstance(d,list) or not d or not isinstance(d[0],str):raise RuntimeError("base64 missing")
 return base64.b64decode(d[0],validate=True)
def u64(b,o):return int.from_bytes(b[o:o+8],"little")
def token_amt(v):return u64(rawdata(v),OFF)
def apirow():
 s,r=req(API,headers={"accept":"application/json","cache-control":"no-cache","pragma":"no-cache","user-agent":"Ghost-Ray-Effective-Gap/1"});o=json.loads(r)
 if s!=200 or not isinstance(o,Mapping) or o.get("success") is not True:raise RuntimeError("api shape")
 d=o.get("data");row=d[0] if isinstance(d,list) and d else (d.get("data",[None])[0] if isinstance(d,Mapping) and isinstance(d.get("data"),list) and d.get("data") else None)
 if not isinstance(row,Mapping):raise RuntimeError("row missing")
 return row
def addr(x):
 if isinstance(x,Mapping):
  for k in ("address","mint","id"):
   if isinstance(x.get(k),str):return x[k]
 return x if isinstance(x,str) else None
def main():
 started=now();x=rpc("getMultipleAccounts",[[POOL,WSOL_V,USDC_V],{"encoding":"base64","commitment":"confirmed"}])
 if not isinstance(x,Mapping) or not isinstance(x.get("context"),Mapping) or not isinstance(x.get("value"),list) or len(x["value"])!=3:raise RuntimeError("rpc shape")
 pool=rawdata(x["value"][0]);w=token_amt(x["value"][1]);u=token_amt(x["value"][2]);p0=u64(pool,341);p1=u64(pool,349);f0=u64(pool,357);f1=u64(pool,365);c0=u64(pool,397);c1=u64(pool,405)
 # Locked pool identity established by Ghost G0: token0/vault0=WSOL, token1/vault1=USDC.
 ew=w-p0-f0-c0;eu=u-p1-f1-c1
 if ew<=0 or eu<=0:raise RuntimeError("invalid effective reserves")
 effective_price=(Decimal(eu)/Decimal(10**6))/(Decimal(ew)/Decimal(10**9));raw_price=(Decimal(u)/Decimal(10**6))/(Decimal(w)/Decimal(10**9))
 row=apirow();ma,mb=addr(row.get("mintA")),addr(row.get("mintB"));api_price=Decimal(str(row.get("price"))) if row.get("price") is not None else None
 api_reserve_price=None
 try:
  aa=Decimal(str(row.get("mintAmountA")));bb=Decimal(str(row.get("mintAmountB")))
  if ma==WSOL and mb==USDC:api_reserve_price=bb/aa
  elif ma==USDC and mb==WSOL:api_reserve_price=aa/bb
 except Exception:pass
 def bps(a,b):return str((a/b-Decimal(1))*Decimal(10000)) if a is not None and b is not None and b!=0 else None
 ev={"schema":"ghost.raydium_effective_price_api_gap.v1","accepted":True,"observation_only":True,"execution_authority":False,"captured_at":started,"confirmed_slot":int(x["context"]["slot"]),"raw":{"wsol_raw":w,"usdc_raw":u,"price_usdc_per_wsol":str(raw_price)},"accrued":{"protocol0":p0,"protocol1":p1,"fund0":f0,"fund1":f1,"creator0":c0,"creator1":c1},"effective":{"wsol_raw":ew,"usdc_raw":eu,"price_usdc_per_wsol":str(effective_price)},"api":{"mintA":ma,"mintB":mb,"mintAmountA":row.get("mintAmountA"),"mintAmountB":row.get("mintAmountB"),"price":row.get("price"),"reserve_implied_price_usdc_per_wsol":str(api_reserve_price) if api_reserve_price is not None else None},"gaps_bps":{"effective_vs_api_price":bps(effective_price,api_price),"effective_vs_api_reserve_implied":bps(effective_price,api_reserve_price),"raw_vs_api_reserve_implied":bps(raw_price,api_reserve_price)},"interpretation":"This measures descriptive price separation between confirmed effective CPMM state and Raydium public pool-info. It is not proof that transaction routing/quotes are stale, executable, or profitable.","safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=started.replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"ray-effective-api-gap-{st}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps(ev,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
