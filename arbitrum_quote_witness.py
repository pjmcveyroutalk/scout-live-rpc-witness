#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, http.client, json, os, platform, socket, ssl, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

HOST="api.paraswap.io"; PORT=443; PATH="/prices"; METHOD="GET"; CHAIN_ID=42161; VERSION="6.2"
WETH="0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"
USDC="0xaf88d065e77c8cc2239327c5edb3a432268e5831"
AMOUNT=10**18
QUERY=urlencode([
 ("srcToken",WETH),("destToken",USDC),("amount",str(AMOUNT)),
 ("srcDecimals","18"),("destDecimals","6"),("side","SELL"),
 ("network",str(CHAIN_ID)),("version",VERSION)])
TARGET=f"{PATH}?{QUERY}"; ENDPOINT=f"https://{HOST}{PATH}"; FULL_URL=f"https://{HOST}{TARGET}"
HEADERS=[("Host",HOST),("User-Agent","Scout-Arbitrum-Quote-Witness/1.0.0"),
 ("Accept","application/json"),("Accept-Encoding","identity"),("Cache-Control","no-cache"),
 ("Pragma","no-cache"),("Connection","close")]
FORBIDDEN={"txparams","transaction","calldata","serializedtransaction","signedtransaction"}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
def sha(b): return hashlib.sha256(b).hexdigest()
def jd(x): return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
def request_bytes():
    s=f"{METHOD} {TARGET} HTTP/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in HEADERS)+"\r\n"
    return s.encode("ascii")
def forbidden(x):
    if isinstance(x,dict):
        for k,v in x.items():
            if str(k).replace("_","").lower() in {q.replace("_","") for q in FORBIDDEN}: return True
            if forbidden(v): return True
    if isinstance(x,list): return any(forbidden(v) for v in x)
    return False
def dns():
    s=now(); t=time.monotonic_ns()
    try:
        a=sorted({x[4][0] for x in socket.getaddrinfo(HOST,PORT,type=socket.SOCK_STREAM)})
        return {"success":True,"hostname":HOST,"addresses":a,"started_at_utc":s,
                "completed_at_utc":now(),"duration_ms":round((time.monotonic_ns()-t)/1e6,3),"error":None}
    except Exception as e:
        return {"success":False,"hostname":HOST,"addresses":[],"started_at_utc":s,
                "completed_at_utc":now(),"duration_ms":round((time.monotonic_ns()-t)/1e6,3),
                "error":f"{type(e).__name__}: {e}"}
def validate(raw,status):
    c={"http_200":status==200,"json_valid":False,"price_route_object":False,
       "src_token_matches":False,"dest_token_matches":False,"src_amount_matches":False,
       "dest_amount_positive":False,"side_sell":False,"network_matches":False,
       "version_6_2":False,"best_route_nonempty":False,"gas_cost_present":False,
       "no_executable_transaction_material":False}
    try: obj=json.loads(raw.decode("utf-8")); c["json_valid"]=isinstance(obj,dict)
    except Exception: c["accepted"]=False; return c,None
    r=obj.get("priceRoute") if isinstance(obj,dict) else None
    c["price_route_object"]=isinstance(r,dict)
    if isinstance(r,dict):
        c["src_token_matches"]=str(r.get("srcToken","")).lower()==WETH.lower()
        c["dest_token_matches"]=str(r.get("destToken","")).lower()==USDC.lower()
        c["src_amount_matches"]=str(r.get("srcAmount"))==str(AMOUNT)
        d=str(r.get("destAmount","")); c["dest_amount_positive"]=d.isdigit() and int(d)>0
        c["side_sell"]=r.get("side")=="SELL"
        c["network_matches"]=str(r.get("network"))==str(CHAIN_ID)
        c["version_6_2"]=str(r.get("version"))==VERSION
        c["best_route_nonempty"]=isinstance(r.get("bestRoute"),list) and len(r["bestRoute"])>0
        c["gas_cost_present"]=str(r.get("gasCost","")).isdigit()
    c["no_executable_transaction_material"]=not forbidden(obj)
    c["accepted"]=all(v is True for k,v in c.items() if k!="accepted")
    return c,obj
def capture(root):
    started=now(); bundle=root/("arbitrum-quote-"+started.replace(":","").replace("-","").replace(".","_"))
    bundle.mkdir(parents=True,exist_ok=False)
    req=request_bytes(); (bundle/"request.http").write_bytes(req); (bundle/"request_body.bin").write_bytes(b"")
    d=dns(); raw=b""; hdr=[]; status=None; reason=None; ok=False; err=None; tls={}; sent=None; t=time.monotonic_ns()
    if d["success"]:
        conn=None
        try:
            conn=http.client.HTTPSConnection(HOST,PORT,timeout=20,context=ssl.create_default_context())
            sent=now(); conn.putrequest(METHOD,TARGET,skip_host=True,skip_accept_encoding=True)
            for k,v in HEADERS: conn.putheader(k,v)
            conn.endheaders(); resp=conn.getresponse(); status=resp.status; reason=resp.reason
            hdr=[(str(k),str(v)) for k,v in resp.getheaders()]
            if conn.sock:
                cert=conn.sock.getpeercert(binary_form=True)
                tls={"version":conn.sock.version(),"cipher":conn.sock.cipher(),
                     "peer_certificate_sha256":sha(cert) if cert else None}
            raw=resp.read(); ok=True
        except Exception as e: err=f"{type(e).__name__}: {e}"
        finally:
            completed=now()
            if conn:
                try: conn.close()
                except: pass
    else: completed=now()
    (bundle/"response.body").write_bytes(raw); (bundle/"response_headers.json").write_bytes(jd(hdr))
    checks,obj=validate(raw,status); req_sha=sha(req); resp_sha=sha(raw)
    dig={"request_digest_recheck_matches":sha((bundle/"request.http").read_bytes())==req_sha,
         "response_digest_recheck_matches":sha((bundle/"response.body").read_bytes())==resp_sha}
    accepted=bool(d["success"] and ok and checks.get("accepted") and all(dig.values()))
    norm=None
    if isinstance(obj,dict) and isinstance(obj.get("priceRoute"),dict):
        r=obj["priceRoute"]; norm={k:r.get(k) for k in
            ["srcToken","srcAmount","destToken","destAmount","side","network","version",
             "gasCost","gasCostUSD","srcUSD","destUSD","contractMethod","bestRoute"]}
        (bundle/"quote.normalized.json").write_bytes(jd(norm))
    evidence={"schema":"scout.arbitrum_live_quote_evidence.v1","milestone":"EVM-QUOTE-1",
      "accepted":accepted,"observation_only":True,"execution_authority":False,
      "provider":"velora-paraswap-market-api","chain":"arbitrum-one","chain_id":CHAIN_ID,
      "endpoint":ENDPOINT,"method":METHOD,"request_url":FULL_URL,"request_sha256":req_sha,
      "response_sha256":resp_sha,"request_started_at_utc":started,"request_sent_at_utc":sent,
      "completed_at_utc":completed,"duration_ms":round((time.monotonic_ns()-t)/1e6,3),
      "http_status":status,"http_reason":reason,"dns":d,"transport_success":ok,
      "transport_error":err,"tls":tls,"validation":checks,"digest_checks":dig,
      "executor":{"kind":"github_actions" if os.getenv("GITHUB_RUN_ID") else "local_python",
        "repository":os.getenv("GITHUB_REPOSITORY"),"commit_sha":os.getenv("GITHUB_SHA"),
        "run_id":os.getenv("GITHUB_RUN_ID"),"run_attempt":os.getenv("GITHUB_RUN_ATTEMPT"),
        "workflow":os.getenv("GITHUB_WORKFLOW"),"runner_os":os.getenv("RUNNER_OS"),
        "runner_arch":os.getenv("RUNNER_ARCH"),"hostname":socket.gethostname(),
        "python":sys.version.split()[0],"platform":platform.platform()},
      "normalized_quote":norm,
      "safety":{"wallet":False,"signer":False,"approvals":False,"transaction_builder":False,
        "transaction_submission":False,"broadcast":False,"capital_movement":False,
        "allowed_method":"GET","allowed_path":"/prices"}}
    (bundle/"evidence.json").write_bytes(jd(evidence))
    lines=[]
    for p in sorted(x for x in bundle.iterdir() if x.is_file() and x.name!="manifest.sha256"):
        lines.append(f"{sha(p.read_bytes())}  {p.name}")
    (bundle/"manifest.sha256").write_text("\n".join(lines)+"\n")
    print(json.dumps({"accepted":accepted,"bundle":str(bundle),
      "dest_amount":norm.get("destAmount") if norm else None,
      "response_sha256":resp_sha,"execution_authority":False},indent=2))
    return 0 if accepted else 1
def main():
    ap=argparse.ArgumentParser(); sp=ap.add_subparsers(dest="cmd",required=True)
    c=sp.add_parser("capture"); c.add_argument("--output",default="live-evidence")
    a=ap.parse_args(); return capture(Path(a.output))
if __name__=="__main__": raise SystemExit(main())

