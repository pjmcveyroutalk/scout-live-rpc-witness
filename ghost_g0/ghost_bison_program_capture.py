#!/usr/bin/env python3
"""Read-only capture of the public BisonFi executable from Solana ProgramData."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any, Mapping

BISON = "BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi"
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    n = int.from_bytes(raw, "big")
    chars = []
    while n:
        n, rem = divmod(n, 58)
        chars.append(B58[rem])
    return "1" * zeros + ("".join(reversed(chars)) if chars else "")


def rpc(endpoint: str, method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "user-agent": "Ghost-Bison-Program-Capture/0"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, Mapping) or payload.get("error") is not None:
        raise RuntimeError(
            f"RPC failure: {payload.get('error') if isinstance(payload, Mapping) else 'shape'}"
        )
    return payload.get("result")


def account_bytes(result: Any) -> tuple[Mapping[str, Any], bytes]:
    if not isinstance(result, Mapping) or not isinstance(result.get("value"), Mapping):
        raise RuntimeError("account missing")
    value = result["value"]
    data = value.get("data")
    if not isinstance(data, list) or len(data) != 2 or data[1] != "base64":
        raise RuntimeError("unexpected account encoding")
    return value, base64.b64decode(data[0], validate=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-url", default="https://api.mainnet-beta.solana.com")
    ap.add_argument("--output-dir", default="ghost-bison-program")
    args = ap.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    program_result = rpc(
        args.rpc_url,
        "getAccountInfo",
        [BISON, {"encoding": "base64", "commitment": "finalized"}],
    )
    program_value, program_raw = account_bytes(program_result)
    if program_value.get("owner") != UPGRADEABLE_LOADER:
        raise RuntimeError(f"unexpected Bison program owner {program_value.get('owner')}")
    if len(program_raw) < 36 or int.from_bytes(program_raw[:4], "little") != 2:
        raise RuntimeError("Bison program account is not UpgradeableLoaderState::Program")
    programdata = b58encode(program_raw[4:36])

    pd_result = rpc(
        args.rpc_url,
        "getAccountInfo",
        [programdata, {"encoding": "base64", "commitment": "finalized"}],
    )
    pd_value, pd_raw = account_bytes(pd_result)
    if pd_value.get("owner") != UPGRADEABLE_LOADER:
        raise RuntimeError("ProgramData owner mismatch")
    elf_offset = pd_raw.find(b"\x7fELF")
    if elf_offset < 0:
        raise RuntimeError("ELF magic not found in ProgramData")
    elf = pd_raw[elf_offset:]
    elf_sha = hashlib.sha256(elf).hexdigest()
    (out / "bisonfi.so").write_bytes(elf)
    meta = {
        "schema": "ghost_bison_program_capture_v0",
        "authority": {
            "read_only": True,
            "signing": False,
            "submission": False,
            "capital_movement": False,
        },
        "program_id": BISON,
        "programdata_address": programdata,
        "program_lamports": program_value.get("lamports"),
        "programdata_lamports": pd_value.get("lamports"),
        "programdata_raw_len": len(pd_raw),
        "elf_offset": elf_offset,
        "elf_len": len(elf),
        "elf_sha256": elf_sha,
    }
    (out / "PROGRAM.json").write_text(
        json.dumps(meta, sort_keys=True, separators=(",", ":")) + "\n"
    )
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
