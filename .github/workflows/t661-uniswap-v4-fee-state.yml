name: T661 Uniswap v4 Protocol Fee State Witness

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  t661-v4-fee-state:
    name: T661 read-only getSlot0 capture
    runs-on: ubuntu-latest
    timeout-minutes: 5

    steps:
      - name: Checkout witness repository
        uses: actions/checkout@v4

      - name: Show Python runtime
        run: python3 --version

      - name: Capture Uniswap v4 protocol and LP fee state
        run: python3 uniswap_v4_fee_state_witness.py

      - name: Package exact evidence bytes
        if: always()
        shell: bash
        run: |
          set -euo pipefail
          tar -czf t661-uniswap-v4-fee-state-evidence.tgz live-evidence
          sha256sum t661-uniswap-v4-fee-state-evidence.tgz \
            > t661-uniswap-v4-fee-state-evidence.tgz.sha256

      - name: Upload T661 evidence artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: t661-uniswap-v4-fee-state-${{ github.run_id }}
          path: |
            live-evidence/
            t661-uniswap-v4-fee-state-evidence.tgz
            t661-uniswap-v4-fee-state-evidence.tgz.sha256
          if-no-files-found: error
          retention-days: 30

