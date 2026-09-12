#!/usr/bin/env python3
"""Resolve Titan V3 provider-fee denomination across six settled controls.

For each finalized transaction, reads the signed Titan swap_route_v3 account list and header,
identifies input/output token mints from signed user token accounts, identifies the provider
fee receiver mint from its signed optional-account slot, and compares finalized Raydium input.
No pending monitoring, wallet, signing, simulation, transaction construction/submission,
broadcast, or capital movement.
"""
from __future__ import annotations
import hashlib,json,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping
RPC="https://api.mainnet-beta.solana.com";TITAN="T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT";RAY="CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2";DISC=hashlib.sha256(b"global:swap_base_input").digest()[:8]
CASES=[
("5pgvTKLrJNPToAv5DuxPptkFPqt7emvGPugVXLg28zbvEwfxz4971HuKDuBJLDEbRYovybqhJF6JDRW6sAxGdTvi","historical_fee_reduced"),
("2vZyLd2WWArweYKTPbVWXt45CbJyqktejLgqjn5QvSTuczBqJjTiBv875fwox5Jdw7qMcbPhixD958bALuN5mtYP","historical_fee_reduced"),
("4ntz9zfeDQb4ZfGEjRCQq16LtSP8mF2BCtnARsoVzyK835qczZiFZXCsWLLBLemc51xGA11eSBsmSRYP65p5pzGc","fresh_rounding_fee_reduced"),
("2wSUV82ydrEvATJ5kyjfwFAgrUP1HMkwdzcMKeZoNA621uLSzo1FC73ngVk5GnLyteyWgnqzWDJ5EuQLpyRCptnV","fresh_rounding_fee_reduced"),
("2R9EZsXZrQgjw8gJgQkFaAkLEBih3QG88Rx5JPdqNFXeFutL4ohdSKKashEscmHmcNnczrQkEKJYxRkce53Kx8CN","holdout_full_input"),
("5qLLJHzbv98s9sif33S41UfPHTqJm7Li6ReSymunb2MUiQoo3UVt9Su78sjBfNAhvT5GHzorSUetRo2R2rr2G6RN","holdout_full_input"),
]
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
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Titan-Fee-Denomination/1"})
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
def titan_ix(tx):
 f=[]
 for ix in msg(tx).get("instructions",[]):
  if isinstance(ix,Mapping) and ix.get("programId")==TITAN and isinstance(ix.get("data"),str) and isinstance(ix.get("accounts"),list):
   r=b58d(ix["data"])
   if r[:1]==b"\x2a" and POOL in ix["accounts"]:f.append((r,list(ix["accounts"])))
 if len(f)!=1:raise RuntimeError(f"expected one Titan ix, got {len(f)}")
 return f[0]
def token_mint(pubkey):
 if pubkey==TITAN:return None
 x=rpc("getAccountInfo",[pubkey,{"encoding":"jsonParsed","commitment":"finalized"}])
 if not isinstance(x,Mapping) or not isinstance(x.get("value"),Mapping):return None
 data=x["value"].get("data")
 if not isinstance(data,Mapping):return None
 parsed=data.get("parsed")
 if not isinstance(parsed,Mapping):return None
 info=parsed.get("info")
 return info.get("mint") if isinstance(info,Mapping) and isinstance(info.get("mint"),str) else None
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
 for sig,label in CASES:
  tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  if not isinstance(tx,Mapping):raise RuntimeError("tx unavailable")
  raw,ac=titan_ix(tx);amount=int.from_bytes(raw[2:10],"little");fee=int.from_bytes(raw[21:23],"little");config=raw[1]
  input_mint=token_mint(ac[3]) if len(ac)>3 else None;output_mint=token_mint(ac[4]) if len(ac)>4 else None;fee_receiver=ac[10] if len(ac)>10 else None;fee_mint=token_mint(fee_receiver) if fee_receiver else None
  tv=truth(tx);actual=tv[0] if len(tv)==1 else None;floor_fee=amount*fee//1_000_000
  rows.append({"signature":sig,"label":label,"slot":int(tx.get("slot",-1)),"config":config,"amount":amount,"fee_centi_bps":fee,"floor_fee":floor_fee,"actual_raydium_input":actual,"input_token_account":ac[3] if len(ac)>3 else None,"output_token_account":ac[4] if len(ac)>4 else None,"input_mint":input_mint,"output_mint":output_mint,"provider_fee_receiver":fee_receiver,"provider_fee_receiver_mint":fee_mint,"fee_receiver_is_input_mint":fee_mint is not None and fee_mint==input_mint,"fee_receiver_is_output_mint":fee_mint is not None and fee_mint==output_mint,"matches_full_input":actual==amount,"matches_input_fee_subtracted":actual==amount-floor_fee})
 ev={"schema":"ghost.titan_fee_denomination_truth.v1","accepted":True,"observation_only":True,"execution_authority":False,"cases":rows,"safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"titan-fee-denomination-{st}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps(ev,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
