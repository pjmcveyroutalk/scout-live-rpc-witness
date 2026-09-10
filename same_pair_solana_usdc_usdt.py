#!/usr/bin/env python3
"""Scout same-pair Solana witness: 100 USDC -> USDT on Raydium, read-only."""
from __future__ import annotations
import hashlib, http.client, json, os, socket, ssl, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

HOST="transaction-v1.raydium.io"; PORT=443; PATH="/compute/swap-base-in"; METHOD="GET"
USDC="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT="Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
AMOUNT=100_000_000; SLIPPAGE_BPS=50; TX_VERSION="V0"
QUERY=urlencode([("inputMint",USDC),("outputMint",USDT),("amount",str(AMOUNT)),
                 ("slippageBps",str(SLIPPAGE_BPS)),("txVersion",TX_VERSION)])
TARGET=f"{PATH}?{QUERY}"; FULL_URL=f"https://{HOST}{TARGET}"
HEADERS=[("Host",HOST),("User-Agent","Scout-Same-Pair-Solana/1.0.0"),
         ("Accept","application/json"),("Accept-Encoding","identity"),
         ("Cache-Control","no-cache"),("Pragma","no-cache"),("Connection","close")]

def now(): return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b): return hashlib.sha256(b).hexdigest()
def jd(x): return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
def req_bytes():
    return (f"{METHOD} {TARGET} HTTP/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in HEADERS)+"\r\n").encode()
def main():
    root=Path("live-evidence"); root.mkdir(exist_ok=True)
    started=now(); d=root/("same-pair-solana-"+started.replace(":","").replace("-","").replace(".","_")); d.mkdir()
    req=req_bytes(); (d/"request.http").write_bytes(req)
    ds=now(); t0=time.monotonic_ns()
    try:
        infos=socket.getaddrinfo(HOST,PORT,type=socket.SOCK_STREAM)
        addrs=sorted({x[4][0] for x in infos}); dns_ok=True; dns_err=None
    except Exception as e:
        addrs=[]; dns_ok=False; dns_err=f"{type(e).__name__}: {e}"
    dns_done=now()
    raw=b""; status=None; reason=None; hdr=[]; transport=False; err=None; tls={}; sent=None
    if dns_ok:
        c=None
        try:
            c=http.client.HTTPSConnection(HOST,PORT,timeout=20,context=ssl.create_default_context())
            sent=now(); c.putrequest(METHOD,TARGET,skip_host=True,skip_accept_encoding=True)
            for k,v in HEADERS: c.putheader(k,v)
            c.endheaders(); r=c.getresponse(); status=r.status; reason=r.reason; hdr=[(k,v) for k,v in r.getheaders()]
            if c.sock:
                cert=c.sock.getpeercert(binary_form=True)
                tls={"version":c.sock.version(),"cipher":c.sock.cipher(),"peer_certificate_sha256":sha(cert) if cert else None}
            raw=r.read(); transport=True
        except Exception as e: err=f"{type(e).__name__}: {e}"
        finally:
            completed=now()
            if c:
                try: c.close()
                except: pass
    else: completed=now()
    (d/"response.body").write_bytes(raw); (d/"response_headers.json").write_bytes(jd(hdr))
    checks={"http_200":status==200,"json_valid":False,"success_true":False,"data_object":False,
            "base_in":False,"input_matches":False,"output_matches":False,"amount_matches":False,
            "output_positive":False,"threshold_positive":False,"slippage_matches":False,
            "route_nonempty":False,"no_transaction_material":False}
    obj=None
    try: obj=json.loads(raw.decode()); checks["json_valid"]=isinstance(obj,dict)
    except: pass
    if isinstance(obj,dict):
        checks["success_true"]=obj.get("success") is True
        data=obj.get("data"); checks["data_object"]=isinstance(data,dict)
        txt=json.dumps(obj).lower()
        checks["no_transaction_material"]=all(x not in txt for x in ["serializedtransaction","signedtransaction","messagebytes"])
        if isinstance(data,dict):
            checks["base_in"]=data.get("swapType")=="BaseIn"
            checks["input_matches"]=data.get("inputMint")==USDC
            checks["output_matches"]=data.get("outputMint")==USDT
            checks["amount_matches"]=str(data.get("inputAmount"))==str(AMOUNT)
            checks["output_positive"]=str(data.get("outputAmount","")).isdigit() and int(data["outputAmount"])>0
            checks["threshold_positive"]=str(data.get("otherAmountThreshold","")).isdigit() and int(data["otherAmountThreshold"])>0
            checks["slippage_matches"]=str(data.get("slippageBps"))==str(SLIPPAGE_BPS)
            checks["route_nonempty"]=isinstance(data.get("routePlan"),list) and len(data["routePlan"])>0
    accepted=dns_ok and transport and all(checks.values())
    ev={"schema":"scout.same_pair.solana.v1","accepted":accepted,"observation_only":True,"execution_authority":False,
        "chain":"solana-mainnet","provider":"raydium","pair":"USDC/USDT","input_asset":"USDC","output_asset":"USDT",
        "input_units":100.0,"input_amount_base_units":AMOUNT,"request_url":FULL_URL,"request_sha256":sha(req),
        "response_sha256":sha(raw),"started_at_utc":started,"request_sent_at_utc":sent,"completed_at_utc":completed,
        "dns":{"success":dns_ok,"hostname":HOST,"addresses":addrs,"started_at_utc":ds,"completed_at_utc":dns_done,
               "duration_ms":round((time.monotonic_ns()-t0)/1e6,3),"error":dns_err},
        "transport_success":transport,"transport_error":err,"http_status":status,"http_reason":reason,"tls":tls,
        "validation":checks,"raw_quote":obj,
        "executor":{"kind":"github_actions" if os.getenv("GITHUB_RUN_ID") else "local",
                    "run_id":os.getenv("GITHUB_RUN_ID"),"commit_sha":os.getenv("GITHUB_SHA")},
        "safety":{"wallet":False,"signer":False,"transaction_builder":False,"transaction_submission":False,"capital_movement":False}}
    (d/"evidence.json").write_bytes(jd(ev))
    lines=[f"{sha(p.read_bytes())}  {p.name}" for p in sorted(d.iterdir()) if p.is_file() and p.name!="manifest.sha256"]
    (d/"manifest.sha256").write_text("\n".join(lines)+"\n")
    print(json.dumps({"accepted":accepted,"output_amount":obj.get("data",{}).get("outputAmount") if isinstance(obj,dict) else None,
                      "execution_authority":False},indent=2))
    return 0 if accepted else 1
if __name__=="__main__": raise SystemExit(main())

