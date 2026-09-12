#!/usr/bin/env python3
"""Settled wire-correlation probe for uncatalogued target-pool outer programs.

Uses five finalized transactions selected by an earlier signed-message census. For each,
it records the signed outer instruction bytes and the already-finalized target Raydium
SwapBaseInput amount, then reports exact little-endian u64 occurrences of that truth value
inside the signed outer bytes. It does not infer or execute a route, and does not monitor
pending/unfinalized transactions. Read-only; no wallet/signing/simulation/submission.
"""
from __future__ import annotations
import hashlib,json,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Mapping

RPC="https://api.mainnet-beta.solana.com";RAY="CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";POOL="fAjTnZ9QqJkUmrr8cXutkYhpVge2qqtSZNt9qKn7YC2";DISC=hashlib.sha256(b"global:swap_base_input").digest()[:8]
CASES={
"2cWuUGJtbbeQYvRFAdpj6hQhtfnwAarDKp6qkZtStMZtDcCxoEszH1MmgbhcDHCrSPu1BntC4CATaWP6AnryV4sC":"FoaFt2Dtz58RA6DPjbRb9t9z8sLJRChiGFTv21EfaseZ",
"5hydcgnSEi7hUP8uFsoDZiKs45SCaA3usbxCmj1c8Q25vv9XsCJpYAjeRpwddjtwGWjVqs5CevmKMbeZKdYei94Y":"FoaFt2Dtz58RA6DPjbRb9t9z8sLJRChiGFTv21EfaseZ",
"5TfghUdFSokk9Bi3dsAoKymc1PoX1NpH6w3eLxFpvkfc5hUfHCdYYCjTFsBgV6hef5PVDGzrWqtMverxB8xAvFhA":"LiveiNLxbiyvZECvKAnhmuSzR4t9CWNY7Rj7XbThu9j",
"41NJJrdLnQ2paxjxyMmXjiRDCbBypcuBr9zQXCEGjTooWwGGQfEEcimyu7zCAGdH27UL9UU5DqKip8Z6wBC6gUwz":"7obtMdiXQaLCao2mCRzsanxRusUH8QAz8eT5PJyUTHFQ",
"3xLoBHhURmoMU934E7bcULc86nYQh1JpmG98eDLvjSS2WSzi7guFxUVypRm3kCSpUVk1pJCxhvUGVLUB1fpPqVi8":"GLCNMEV6Z7P72YtUciTUzMczWPALAkV9F6k5z9jHsfwy",
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
   q=urllib.request.Request(RPC,data=body,method="POST",headers={"content-type":"application/json","user-agent":"Ghost-Unknown-Wire-Correlation/1"})
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
def outer(tx,pid):
 found=[]
 for ix in message(tx).get("instructions",[]):
  if not isinstance(ix,Mapping) or ix.get("programId")!=pid:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if isinstance(ac,list) and POOL in ac and RAY in ac and isinstance(d,str):found.append((b58d(d),list(ac)))
 return found
def truths(tx):
 rows=[];m=message(tx);top=m.get("instructions")
 if isinstance(top,list):rows += [x for x in top if isinstance(x,Mapping)]
 meta=tx.get("meta");inn=meta.get("innerInstructions") if isinstance(meta,Mapping) else None
 if isinstance(inn,list):
  for g in inn:
   ins=g.get("instructions") if isinstance(g,Mapping) else None
   if isinstance(ins,list):rows += [x for x in ins if isinstance(x,Mapping)]
 out=[]
 for ix in rows:
  if ix.get("programId")!=RAY:continue
  ac,d=ix.get("accounts"),ix.get("data")
  if not isinstance(ac,list) or len(ac)!=13 or ac[3]!=POOL or not isinstance(d,str):continue
  raw=b58d(d)
  if len(raw)==24 and raw[:8]==DISC:out.append(int.from_bytes(raw[8:16],"little"))
 return out
def u64_matches(raw,value):
 needle=int(value).to_bytes(8,"little");return [i for i in range(0,max(0,len(raw)-7)) if raw[i:i+8]==needle]
def u64_windows(raw):
 return [{"offset":i,"value":int.from_bytes(raw[i:i+8],"little")} for i in range(0,max(0,len(raw)-7))]
def main():
 cases=[]
 for sig,pid in CASES.items():
  tx=rpc("getTransaction",[sig,{"commitment":"finalized","encoding":"jsonParsed","maxSupportedTransactionVersion":0}])
  if not isinstance(tx,Mapping):raise RuntimeError("tx unavailable")
  os=outer(tx,pid);ts=truths(tx);raw,accounts=os[0] if len(os)==1 else (b"",[]);truth=ts[0] if len(ts)==1 else None
  cases.append({"signature":sig,"slot":int(tx.get("slot",-1)),"outer_program":pid,"outer_len":len(raw),"outer_data_hex":raw.hex(),"outer_data_sha256":sha(raw),"account_count":len(accounts),"target_account_index":accounts.index(POOL) if POOL in accounts else None,"raydium_program_index":accounts.index(RAY) if RAY in accounts else None,"truth_amount_in":truth,"truth_u64_exact_offsets":u64_matches(raw,truth) if truth is not None else [],"u64_windows":u64_windows(raw)})
 ev={"schema":"ghost.settled_unknown_wire_correlation.v1","accepted":True,"observation_only":True,"execution_authority":False,"cases":cases,"interpretation":"An exact u64 occurrence is only a wire correlation. A decoder requires repeated stable structure plus independent validation; absence of an exact occurrence means the amount is transformed or derived elsewhere.","safety":{"wallet":False,"signer":False,"approval":False,"transaction_builder":False,"transaction_serialization":False,"transaction_simulation":False,"transaction_submission":False,"broadcast":False,"bridge_execution":False,"capital_movement":False}}
 st=now().replace(":","").replace("-","").replace(".","_");d=Path("live-evidence")/f"ghost-unknown-wire-correlation-{st}";d.mkdir(parents=True,exist_ok=False);raw=(json.dumps(ev,sort_keys=True,indent=2)+"\n").encode();(d/"evidence.json").write_bytes(raw);(d/"evidence.sha256").write_text(f"{sha(raw)}  evidence.json\n");print(json.dumps({"cases":[{"slot":x["slot"],"program":x["outer_program"],"truth":x["truth_amount_in"],"exact_offsets":x["truth_u64_exact_offsets"]} for x in cases]},indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
