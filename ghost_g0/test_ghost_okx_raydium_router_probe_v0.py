import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "probe", HERE / "ghost_okx_raydium_router_probe_v0.py"
)
probe = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(probe)


def swap_tob(routes, amount=1_000_000, expect=1_000_029, slippage=50):
    body = bytearray(probe.SWAP_TOB_DISCRIMINATOR)
    body += (1).to_bytes(8, "little")
    body += amount.to_bytes(8, "little")
    body += expect.to_bytes(8, "little")
    body += slippage.to_bytes(2, "little")
    body += len(routes).to_bytes(4, "little")
    for tag, weight, index in routes:
        body.append(tag)
        body += weight.to_bytes(2, "little")
        body.append(index)
    body += (0).to_bytes(4, "little")
    body += (0).to_bytes(2, "little")
    body.append(0)
    return bytes(body)


def accounts(target):
    fixed = [f"fixed-{i}" for i in range(16)]
    ray = [
        probe.RAYDIUM_CPMM,
        "payer",
        "user-in",
        "user-out",
        "authority",
        "config",
        target,
        "input-vault",
        "output-vault",
        probe.SPL_TOKEN,
        probe.SPL_TOKEN,
        "input-mint",
        "output-mint",
        "observation",
    ]
    return fixed + ["prior-adapter"] * 5 + ray


class ProbeTests(unittest.TestCase):
    def test_direct_root_exact_share(self):
        data = swap_tob([
            (88, 6700, 0x01),
            (46, 1100, 0x01),
            (88, 2100, 0x01),
            (14, 100, 0x01),
            (88, 10000, 0x12),
        ])
        out = probe.derive_direct_root_raydium_leg(data, accounts("pool"), "pool")
        self.assertEqual(out["derived_raydium_amount_in"], 10_000)
        self.assertEqual(out["route"]["index"], 0x01)
        self.assertEqual(out["raydium_accounts"]["input_vault"], "input-vault")

    def test_multistage_raydium_fails_closed(self):
        data = swap_tob([
            (88, 10000, 0x01),
            (14, 100, 0x12),
            (59, 9900, 0x12),
        ])
        with self.assertRaises(probe.ProbeError):
            probe.derive_direct_root_raydium_leg(data, accounts("pool"), "pool")

    def test_rounding_ambiguity_fails_closed(self):
        data = swap_tob([
            (14, 3333, 0x01),
            (88, 6667, 0x01),
        ], amount=999_999)
        with self.assertRaises(probe.ProbeError):
            probe.derive_direct_root_raydium_leg(data, accounts("pool"), "pool")

    def test_wrong_pool_fails_closed(self):
        data = swap_tob([(14, 10000, 0x01)])
        with self.assertRaises(probe.ProbeError):
            probe.derive_direct_root_raydium_leg(data, accounts("other"), "pool")


if __name__ == "__main__":
    unittest.main()
