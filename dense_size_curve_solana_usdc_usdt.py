#!/usr/bin/env python3
"""Scout Solana USDC->USDT dense size-curve witness. Read-only GET quotes only."""
from __future__ import annotations
import hashlib, http.client, json, os, socket, ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

HOST="transaction-v1.raydium.io"; PORT=443; PATH="/compute/swap-base-in"
USDC="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT="Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
SIZES_USDC=(250,500,750,1000,1500,2000)
SLIPPAGE_BPS=50
HEADERS=[("Host",HOST),("User-Agent","Scout-Solana-Dense-Size-Curve/1.0.0"),
         ("Accept","application/json"),("Accept-Encoding","identity"),
         ("Cache-Control","no-cache"),("Pragma","no-cache"),("Connection","close")]

def now(): return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b): return hashlib.sha256(b).hexdigest()
def jd(x): return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()

def quote(units:int):
    amount=units*1_000_000
    q=urlencode([("inputMint",USDC),("outputMint",USDT),("amount",str(amount)),
                 ("slippageBps",str(SLIPPAGE_BPS)),("txVersion","V0")])
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
    obj=json.loads(raw.decode()); d=obj.get("data") if isinstance(obj,dict) else None
    accepted=(status==200 and obj.get("success") is True and isinstance(d,dict)
              and d.get("inputMint")==USDC and d.get("outputMint")==USDT
              and str(d.get("inputAmount"))==str(amount)
              and str(d.get("outputAmount","")).isdigit() and int(d["outputAmount"])>0
              and isinstance(d.get("routePlan"),list) and len(d["routePlan"])>0)
    return {"accepted":accepted,"input_units_usdc":units,"input_amount_base_units":amount,
            "output_amount_base_units":int(d["outputAmount"]) if accepted else None,
            "output_units_usdt":int(d["outputAmount"])/1_000_000 if accepted else None,
            "started_at_utc":start,"completed_at_utc":now(),
            "request_url":f"https://{HOST}{target}","request_sha256":sha(request),
            "response_sha256":sha(raw),"http_status":status,
            "route_plan":d.get("routePlan") if isinstance(d,dict) else None}

def main():
    root=Path("live-evidence"); root.mkdir(exist_ok=True)
    started=now(); d=root/("dense-size-curve-solana-"+started.replace(":","").replace("-","").replace(".","_")); d.mkdir()
    addrs=sorted({x[4][0] for x in socket.getaddrinfo(HOST,PORT,type=socket.SOCK_STREAM)})
    obs=[quote(x) for x in SIZES_USDC]; accepted=all(x["accepted"] for x in obs)
    ev={"schema":"scout.dense_size_curve.solana.v1","accepted":accepted,"observation_only":True,
        "execution_authority":False,"chain":"solana-mainnet","provider":"raydium","pair":"USDC/USDT",
        "sizes_usdc":list(SIZES_USDC),"dns":{"hostname":HOST,"addresses":addrs},"observations":obs,
        "executor":{"kind":"github_actions" if os.getenv("GITHUB_RUN_ID") else "local",
                    "run_id":os.getenv("GITHUB_RUN_ID"),"commit_sha":os.getenv("GITHUB_SHA")},
        "safety":{"wallet":False,"signer":False,"transaction_builder":False,
                  "transaction_submission":False,"capital_movement":False}}
    p=d/"evidence.json"; p.write_bytes(jd(ev))
    (d/"manifest.sha256").write_text(f"{sha(p.read_bytes())}  evidence.json\n")
    print(json.dumps({"accepted":accepted,"outputs":[x["output_units_usdt"] for x in obs],
                      "execution_authority":False},indent=2))
    return 0 if accepted else 1
if __name__=="__main__": raise SystemExit(main())

