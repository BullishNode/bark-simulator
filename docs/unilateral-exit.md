# Explicit unilateral exits

The native adapter supports a bounded exit lifecycle against the pinned SDK.
Supply 1–16 exact owned, spendable public-key coin IDs, a positive fee rate, an
absolute lifetime fee cap, and one confirmed owned BIP84 fee-funding outpoint.
The destination is the wallet's owned fallback script. Locked, round-held,
nonstandard, foreign, or unconfirmed inputs are refused.

```json
{
  "operation": "exit",
  "action_id": "exit-001",
  "actor_dir": "/wallets/actor-01",
  "expected_server_pubkey": "<pinned public key>",
  "maximum_fee_sat": 2000,
  "args": {
    "input_vtxo_ids": ["<exact transaction ID>:<output index>"],
    "fee_rate_sat_per_vb": 1,
    "fee_funding_outpoint": "<confirmed owned transaction ID>:<output index>",
    "phase": "start"
  }
}
```

`start` persists the original intent before registering the exit. Subsequent
`advance` and `inspect` calls must retain the original action ID, input set, fee
rate, fee source, and cap. `inspect` reports the saved lifecycle without signing
or broadcasting. Explicit `advance` may progress that known lifecycle and
rebroadcast already saved identical signatures. It never repeats `start`,
reconstructs an uncertain signature, increases the cap, or silently replaces a
transaction with a higher fee.

Each CPFP or whole-principal claim freezes its exact unsigned inputs, values,
scripts, output, and fee before signing. Its fee consumes the original cap
durably, including when signing's outcome is unknown. Confirmed CPFP change can
fund the next declared CPFP. Other wallet operations remain held while an exit
intent is unfinished.

The supervisor must preserve one original action and reservation throughout
these phases. Native acknowledgements remain unverified outcomes until all
declared CPFPs and the complete claim have confirmed independent chain proofs,
linked to independently checked signed ownership. Reconciliation runs once and
preserves the original activity time. Missing, partial, pending, failed,
ambiguous, or contradictory evidence cannot authorize a monetary retry.

The adapter currently requires a responding server to positively attest that
each input is spendable at `start`. Offline-server exits and interrupted-round
exits remain unqualified. The board fixture completed one CPFP and one whole-principal claim for
10,000 sats with 393 sats in fees. The Ark-receipt fixture exercised production
continuation and completed three CPFPs and one 5,000-sat claim with 1,029 sats
in fees. Independent audits rebuilt their raw chains with networking disabled,
rechecked signed owner proofs, and matched every fee to its pre-sign proposal.
These outcomes qualify the stated available-server fixtures. Permanently absent
original wallets must stay closed; returning-device tests require separately
authorized fixture wallets.

Run a declared fixture and reconstruct its chain with:

```sh
python3 integration/run-regtest.py ark-exit-check \
  --sdk-source fixture-source \
  --product-bin-dir source/target/debug \
  --test unilateral_exit::simulator_explicit_ark_exit_with_cpfp
python3 integration/verify-unilateral-exit.py runs/integration/ark-exit-check \
  --bitcoind /path/to/bitcoind
```
