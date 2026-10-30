# PPREV prototype

Research implementation of PPREV, a protocol for privacy-preserving verification of real estate
transactions over notarised registry data. A party proves a predicate over a record that an
authoritative registry serves to its own account, without revealing the record: a TLSNotary session
attests where the bytes came from, a Groth16 proof shows that the hidden fields satisfy the phase's
predicate, and a notary signature binds the result to one transaction, phase, and deployment of an
escrow contract.

The repository holds the contracts (Solidity, Foundry), the three predicate circuits (circom,
Groth16), the off-chain prover, notary, and policy verifier (Rust, tlsn v0.1.0-alpha.15), a local
mock registry, and the committed measurement records behind every figure below. Tag `artifact-v3`
is the snapshot whose records the paper cites.

## Running it

Install the pinned toolchain and run the circuit setup as described in
[REPRODUCTION.md](REPRODUCTION.md) sections 2 and 3 (the setup needs a trusted-setup beacon and takes
about an hour once). After that, the quick check runs without network in about 15 minutes:

```
(cd contracts && forge test)        # contract tests
cargo test --release --workspace    # off-chain tests
script/e2e_register.sh              # Register end to end: TLSNotary session, proof, signature, transaction
script/e2e_lifecycle.sh             # Register, Apply, Engage, Settle end to end, with negative cases
```

Expected: `245 tests passed`, `191 passed, 0 failed, 3 ignored`, `checks: 19/19 passed`,
`checks: 25/25 passed` (gate record `measurements/gate/20261022T184708Z/`).

## Cost

Measured on a local node with the Osaka (Fusaka) gas schedule and priced at one snapshot of
26 September 2026: Ethereum at the median effective gas price of that day (0.133984 gwei) and
ETH/USD 2,685.42; Base from a Base Sepolia campaign, priced with Base mainnet parameters at the same
ETH/USD. Records: `measurements/l1/`, `measurements/l2/`, `measurements/summary/`.

| Complete lifecycle (Register, Apply, Engage, Settle) | |
|---|---:|
| Cost on Ethereum, receipt level | $0.225 |
| Cost on Base (L2), receipt level | $0.0103 |
| Execution gas (the operations alone, without intrinsic and calldata gas) | 538,976 |
| Receipt gas on Ethereum (with intrinsic and calldata gas, net of refunds) | 625,732 |
| Deployment of both contracts, Ethereum | $0.834 |

Register is the most expensive operation: 182,779 execution gas, $0.0658 on Ethereum and $0.0034 on
Base. Off-chain, on an Apple M2 laptop against the local mock registry, proving the Register
predicate takes 3,311.8 ms and the MPC-TLS session 345.4 ms (medians over 20 runs); the pipeline
after attestation uses 1.58% of the 300 s freshness window with Base Sepolia inclusion.

Per-operation gas, off-chain timings, the three circuits, the integrated on-chain verification
baseline, and the network-delay experiment are in
[REPRODUCTION.md section 5](REPRODUCTION.md#5-reproducing-the-results), each with the command that
produces it and the committed record it comes from.

## Scope

This is a prototype, not production software: the registry is a local mock, there is one notary,
every Groth16 setup is single-party, and there is no mainnet deployment. The figures above are the
recorded values for the artifact-v3 keys and settings; a new circuit setup changes proofs,
verifier constants, and calldata, so they have to be measured again for it. Known issues are in
[REPRODUCTION.md section 7](REPRODUCTION.md#7-known-issues).

Licence: MIT, except the snarkjs-exported Groth16 verifiers under `circuits/setup/`, which keep
their GPL-3.0 header and are compiled only for the on-chain comparison.
