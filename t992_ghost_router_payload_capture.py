#!/usr/bin/env python3
"""Capture signed router payloads for Ghost burst research.

Read-only historical witness. Stores only transaction.message top-level
instructions/accounts; explicitly excludes meta/inner/log/balance truth.
"""
from __future__ import annotations
import hashlib,json,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping

RPC="https://api.mainnet-beta.solana.com"
SIGS=[
"5pgvTKLrJNPToAv5DuxPptkFPqt7emvGPugVXLg28zbvEwfxz4971HuKDuBJLDEbRYovybqhJF6JDRW6sAxGdTvi",
"5wVFPSLYJzo13Zkagmjb92yY4NJ2Ekz6C1jLR84peVZLBiaY8yKVghRLf1nVEu7WwG1a9JsJnXiqoZTPqQQtqnyt",
"2vZyLd2WWArweYKTPbVWXt45CbJyqktejLgqjn5QvSTuczBqJjTiBv875fwox5Jdw7qMcbPhixD958bALuN5mtYP",
"3tBMwopBHWKX3kUkiQVmCncu91t8iemdQcqhNSAvbNeomaoMdJ5xczU4v86PaThQkbTKAYfNVUU32XZBktpK6ZJe",
"4MJ1V3fL5Er69BCBSctyPr886aPEpArycnzSwp64DDQkJSNEnjQncfKueRCxiQFX4y1heHTbKXzk5UBH3PphqkAE"]
TITAN="T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT"; OKX="proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u"
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; M={c:i for i,c in enumerate(A)}
def b58d(s):
 n=0
 for c in s:n=n*58+M[c]
 r=n.to_bytes((n.bit_length()+7)//8,"big") if n else b""
 return b"\0"*(len(s)-len(s.lstrip("1")))+r
def now():return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(x):return hashlib.sha256(x).hexdigest()
def rpc(m,p):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p},separators=(",",":")).encode(); d=.5
 for i in range(6):
  try:
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Router-Payload/0"})
   with urllib.request.urlopen(q,timeout=30) as r:o=json.loads(r.read())
   if not isinstance(o,Mapping) or o.get("error") is not None:raise RuntimeError(str(o))
   return o.get("result")
  except Exception:
   if i==5:raise
   time.sleep(d);d=min(d*2,8)
def titan_header(raw):
 if len(raw)<24 or raw[0]!=42:return None
 return {"discriminator":raw[0],"config":raw[1],"amount":int.from_bytes(raw[2:10],"little"),"expected_amount_out":int.from_bytes(raw[10:18],"little"),"slippage_threshold_bps":int.from_bytes(raw[18:20],"little"),"mints":raw[20],"fee_centi_bps":int.from_bytes(raw[21:23],"little"),"mesh_size":raw[23],"tail_hex":raw[24:].hex()}
def main():
 out=[]
 for s in SIGS:
  tx=rpc("getTransaction",[s,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  msg=tx.get("transaction",{}).get("message",{}) if isinstance(tx,Mapping) else {}
  rows=[]
  for i,ix in enumerate(msg.get("instructions",[]) if isinstance(msg,Mapping) else []):
   if not isinstance(ix,Mapping) or ix.get("programId") not in (TITAN,OKX):continue
   data=ix.get("data"); ac=ix.get("accounts")
   if not isinstance(data,str):continue
   raw=b58d(data)
   rows.append({"index":i,"program_id":ix.get("programId"),"data_hex":raw.hex(),"data_sha256":sha(raw),"data_len":len(raw),"accounts":list(ac) if isinstance(ac,list) else [],"titan_v3_header":titan_header(raw)})
  out.append({"signature":s,"slot":int(tx.get("slot",-1)) if isinstance(tx,Mapping) else -1,"instructions":rows})
 ev={"schema":"ghost.router_payload_capture.v0","accepted":True,"observation_only":True,"execution_authority":False,"captured_at":now(),"source_surface":"finalized signed transaction.message only","forbidden":["meta","innerInstructions","logMessages","preTokenBalances","postTokenBalances"],"transactions":out,"safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"ghost-router-payload-{st}";d.mkdir(parents=True,exist_ok=True);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps([{"slot":x["slot"],"n":len(x["instructions"]),"headers":[i["titan_v3_header"] for i in x["instructions"] if i["titan_v3_header"]]} for x in out],indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
