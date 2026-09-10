#!/usr/bin/env python3
"""Scout Arbitrum USDC->USDt0 dense size-curve witness. Read-only GET quotes only."""
from __future__ import annotations
import hashlib, http.client, json, os, socket, ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

HOST="api.paraswap.io"; PORT=443; PATH="/prices"; CHAIN_ID=42161; VERSION="6.2"
USDC="0xaf88d065e77c8cc2239327c5edb3a432268e5831"
USDT0="0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"
SIZES_USDC=(250,500,750,1000,1500,2000)
HEADERS=[("Host",HOST),("User-Agent","Scout-Arbitrum-Dense-Size-Curve/1.0.0"),
         ("Accept","application/json"),("Accept-Encoding","identity"),
         ("Cache-Control","no-cache"),("Pragma","no-cache"),("Connection","close")]

def now(): return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b): return hashlib.sha256(b).hexdigest()
def jd(x): return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()

def quote(units:int):
    amount=units*1_000_000
    q=urlencode([("srcToken",USDC),("destToken",USDT0),("amount",str(amount)),
                 ("srcDecimals","6"),("destDecimals","6"),("side","SELL"),
                 ("network",str(CHAIN_ID)),("version",VERSION)])
    target=f"{PATH}?{q}"
    request=(f"GET {target} HTTP/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in HEADERS)+"\r\n").encode()
    start=now()
    c=http.client.HTTPSConnection(HOST,PORT,timeout=20,context=ssl.create_default_context())
    try:
        c.putrequest("GET",target,skip_host=True,skip_accept_encoding=True)
        for k,v in HEADERS: c.putheader(k,v)
        c.endheaders(); r=c.getresponse(); raw=r.read(); status=r.status
    finally:
        c.close()
    obj=json.loads(raw.decode()); pr=obj.get("priceRoute") if isinstance(obj,dict) else None
    accepted=(status==200 and isinstance(pr,dict)
              and str(pr.get("srcToken","")).lower()==USDC.lower()
              and str(pr.get("destToken","")).lower()==USDT0.lower()
              and str(pr.get("srcAmount"))==str(amount)
              and str(pr.get("destAmount","")).isdigit() and int(pr["destAmount"])>0
              and pr.get("side")=="SELL" and str(pr.get("network"))==str(CHAIN_ID)
              and isinstance(pr.get("bestRoute"),list) and len(pr["bestRoute"])>0)
    return {"accepted":accepted,"input_units_usdc":units,"input_amount_base_units":amount,
            "gross_output_amount_base_units":int(pr["destAmount"]) if accepted else None,
            "gross_output_units_usdt":int(pr["destAmount"])/1_000_000 if accepted else None,
            "gas_cost":pr.get("gasCost") if isinstance(pr,dict) else None,
            "gas_cost_usd":pr.get("gasCostUSD") if isinstance(pr,dict) else None,
            "src_usd":pr.get("srcUSD") if isinstance(pr,dict) else None,
            "dest_usd":pr.get("destUSD") if isinstance(pr,dict) else None,
            "started_at_utc":start,"completed_at_utc":now(),
            "request_url":f"https://{HOST}{target}","request_sha256":sha(request),
            "response_sha256":sha(raw),"http_status":status,
            "best_route":pr.get("bestRoute") if isinstance(pr,dict) else None}

def main():
    root=Path("live-evidence"); root.mkdir(exist_ok=True)
    started=now(); d=root/("dense-size-curve-arbitrum-"+started.replace(":","").replace("-","").replace(".","_")); d.mkdir()
    addrs=sorted({x[4][0] for x in socket.getaddrinfo(HOST,PORT,type=socket.SOCK_STREAM)})
    obs=[quote(x) for x in SIZES_USDC]; accepted=all(x["accepted"] for x in obs)
    ev={"schema":"scout.dense_size_curve.arbitrum.v1","accepted":accepted,"observation_only":True,
        "execution_authority":False,"chain":"arbitrum-one","provider":"velora-paraswap",
        "pair":"USDC/USDT","output_representation":"USD₮0","sizes_usdc":list(SIZES_USDC),
        "dns":{"hostname":HOST,"addresses":addrs},"observations":obs,
        "executor":{"kind":"github_actions" if os.getenv("GITHUB_RUN_ID") else "local",
                    "run_id":os.getenv("GITHUB_RUN_ID"),"commit_sha":os.getenv("GITHUB_SHA")},
        "safety":{"wallet":False,"signer":False,"transaction_builder":False,
                  "transaction_submission":False,"capital_movement":False}}
    p=d/"evidence.json"; p.write_bytes(jd(ev))
    (d/"manifest.sha256").write_text(f"{sha(p.read_bytes())}  evidence.json\n")
    print(json.dumps({"accepted":accepted,
                      "gross_outputs":[x["gross_output_units_usdt"] for x in obs],
                      "gas_cost_usd":[x["gas_cost_usd"] for x in obs],
                      "execution_authority":False},indent=2))
    return 0 if accepted else 1
if __name__=="__main__": raise SystemExit(main())

