#!/usr/bin/env python3
"""Strict first-projector acquisition gate.

Reuses the read-only locked-target sensor but rejects Raydium SwapBaseInput
instructions observed only as inner CPI. The first native Ghost projector must
be able to derive the Raydium instruction from the exact signed transaction
without post-execution inner-instruction leakage.
"""

from __future__ import annotations

import ghost_g0_target_evidence as sensor
from ghost_g0_common import G0Error

_base_classifier = sensor.classify_raydium_swap_base_input


def classify_top_level_only(tx_result, target_pool):
    result = _base_classifier(tx_result, target_pool)
    origin = str((result.get("raydium_instruction") or {}).get("origin", ""))
    if not origin.startswith("top:"):
        raise G0Error(
            "projector_input_insufficient_inner_cpi: first native projector "
            "requires top-level Raydium SwapBaseInput in signed transaction"
        )
    return result


sensor.classify_raydium_swap_base_input = classify_top_level_only

if __name__ == "__main__":
    raise SystemExit(sensor.main())
