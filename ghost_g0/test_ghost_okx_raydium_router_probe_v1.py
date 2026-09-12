import unittest

try:
    from .ghost_okx_raydium_router_probe_v0 import (
        ProbeError,
        RAYDIUM_CPMM,
        SPL_TOKEN,
        SWAP_TOB_DISCRIMINATOR,
    )
    from .ghost_okx_raydium_router_probe_v1 import derive_direct_root_raydium_leg_v1
except ImportError:
    from ghost_okx_raydium_router_probe_v0 import (
        ProbeError,
        RAYDIUM_CPMM,
        SPL_TOKEN,
        SWAP_TOB_DISCRIMINATOR,
    )
    from ghost_okx_raydium_router_probe_v1 import derive_direct_root_raydium_leg_v1


def swap_tob(routes, amount):
    body = bytearray(SWAP_TOB_DISCRIMINATOR)
    body += (1).to_bytes(8, "little")
    body += amount.to_bytes(8, "little")
    body += (1).to_bytes(8, "little")
    body += (50).to_bytes(2, "little")
    body += len(routes).to_bytes(4, "little")
    for tag, weight, index in routes:
        body.append(tag)
        body += weight.to_bytes(2, "little")
        body.append(index)
    body += bytes(7)
    return bytes(body)


def ray_block(pool, suffix):
    return [
        RAYDIUM_CPMM,
        f"payer-{suffix}",
        f"user-in-{suffix}",
        f"user-out-{suffix}",
        f"authority-{suffix}",
        f"config-{suffix}",
        pool,
        f"input-vault-{suffix}",
        f"output-vault-{suffix}",
        SPL_TOKEN,
        SPL_TOKEN,
        f"input-mint-{suffix}",
        f"output-mint-{suffix}",
        f"observation-{suffix}",
    ]


class ProbeV1Tests(unittest.TestCase):
    def test_last_route_receives_exact_residual(self):
        routes = [
            (137, 9800, 0x01),
            (14, 100, 0x01),
            (14, 100, 0x01),
            (16, 10000, 0x12),
        ]
        accounts = (
            [f"fixed-{i}" for i in range(16)]
            + ["prior"] * 23
            + ray_block("other-pool", "a")
            + ray_block("locked-pool", "b")
        )
        out = derive_direct_root_raydium_leg_v1(
            swap_tob(routes, 4_992_451),
            accounts,
            "locked-pool",
        )
        self.assertEqual(out["root_allocations"], [4_892_601, 49_924, 49_926])
        self.assertEqual(out["derived_raydium_amount_in"], 49_926)
        self.assertEqual(out["raydium_accounts"]["pool_state"], "locked-pool")

    def test_multistage_target_stays_fail_closed(self):
        routes = [
            (88, 10000, 0x01),
            (14, 100, 0x12),
            (59, 9900, 0x12),
        ]
        accounts = [f"fixed-{i}" for i in range(16)] + ray_block("locked-pool", "x")
        with self.assertRaises(ProbeError):
            derive_direct_root_raydium_leg_v1(
                swap_tob(routes, 1_088_881),
                accounts,
                "locked-pool",
            )


if __name__ == "__main__":
    unittest.main()
