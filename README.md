# PPREV prototype

Artifact of PPREV, a protocol that verifies real estate transactions over notarised registry data:
an on-chain enforcement layer, an attested-submission pipeline over a TLS registry, and the scripts
and records behind every measured figure.

## 1. Overview

The artifact contains:

- **On-chain enforcement layer** (`contracts/`, Solidity, Foundry): the seven algorithms Register,
  Apply, Engage, Settle, Expire, Reclaim, Cancel and the auxiliary Withdraw, an ECDSA notary
  verifier, and a test suite with a positive and a negative test for every acceptance condition.
- **Mock title registry** (`mock-registry/`): a local HTTPS server (TLS 1.2) with a fixed-layout JSON
  response and fixture records.
- **Attested session** (`offchain/`, Rust): a TLSNotary (tlsn v0.1.0-alpha.15, MPC mode) prover and
  notary. The prover commits to the owner, account, and property fields of the registry response;
  the presentation reveals only the request line and the response structure.
- **Predicate circuit phi_R** (`circuits/`, circom, Groth16): opens the attested commitments and checks
  that the session's account is an owner of the property in `txData`. The phase-1 parameters come
  from a public powers-of-tau ceremony; phase 2 is local.
- **Policy verifier and notary signer** (`offchain/`): checks the presentation and the phi_R proof,
  records the nonce, and signs x_R. A mock notary checks phi_A and phi_S natively for Apply and Settle.
- **End-to-end Register** on a local chain (`script/e2e_register.sh`) and the **measurement scripts**
  with their committed records (`measurements/`).

The artifact does not contain:

- a real land registry: the registry is a local mock, so network latency to a real registry is absent;
- more than one notary: notary and policy verifier are one trusted process with two keys;
- a production trusted-setup ceremony: phase 2 is single-party, so the proving key suits this
  prototype only;
- circuits for phi_A and phi_S: Apply and Settle are signed by the mock notary;
- a mainnet deployment: Layer-2 figures come from Base Sepolia, priced with Base mainnet parameters.

## 2. Requirements

Tested on an Apple M2 with 16 GB of memory, macOS 26.6, on AC power. Versions are pinned where the
repository can pin them:

| Tool | Version | Pinned by |
|---|---|---|
| Rust | 1.98.1 | `rust-toolchain.toml` |
| Foundry (forge, cast, anvil) | 1.8.3 | install with `foundryup --install 1.8.3` |
| solc | 0.8.36, optimizer 200 runs, via-IR off, EVM cancun | `contracts/foundry.toml` (fetched by forge) |
| forge-std | v1.16.2 | git submodule |
| circom | 2.2.3 | install with `cargo install --git https://github.com/iden3/circom --tag v2.2.3 circom` |
| snarkjs, circomlib | 0.7.6, 2.0.5 | `circuits/package-lock.json` |
| Node.js | v26.9.0 | `.nvmrc`; the scripts stop on another version (`PPREV_NODE` names a binary) |
| TLSNotary | v0.1.0-alpha.15 | `Cargo.toml` (git tag), `Cargo.lock` |
| Python 3, jq, lsof, openssl, curl, git | any recent | standard library only for Python |
| libfaketime | optional | only for the ignored clock-shift tests |

Disk: about 10 GB free (Rust build about 7 GB, circuit build 155 MB, powers-of-tau cache 200 MB).

## 3. Setup

```
git clone --recurse-submodules <repository-url> pprev-prototype
cd pprev-prototype
nvm install && nvm use                     # Node.js from .nvmrc (or install v26.9.0 otherwise)
(cd circuits && npm ci)                    # snarkjs, circomlib
cargo build --release                      # prover, notary, mock registry
(cd contracts && forge build)
script/circuits_build.sh                   # compile phi_R
script/circuits_setup.sh                   # Groth16 setup (downloads the 200 MB phase-1 file once)
cp .env.example .env                       # only for the steps that need a network, see below
```

`script/circuits_setup.sh` produces a new proving key (`circuits/build/phi_r.zkey`, 65 MB, not in the
repository) and rewrites `circuits/setup/` (verification key, Solidity verifier, sample proof,
transcript) accordingly. The measurement scripts refuse a dirty working tree, so commit those files
locally before measuring, or run with `PPREV_ALLOW_DIRTY=1 PPREV_MEASUREMENTS_DIR=<dir>`. No gas
figure depends on the key; proving and verification times do not depend on it either.

`.env` (git-ignored; no script prints its values):

| Variable | Used by |
|---|---|
| `ETH_MAINNET_RPC_URL` | `script/l1_price.sh`; optional beacon of `script/circuits_setup.sh` (or set `PPREV_BEACON`) |
| `BASE_MAINNET_RPC_URL` | `script/measure_l2.sh` (price parameters of one block) |
| `BASE_SEPOLIA_RPC_URL` | `script/measure_l2.sh` (the campaign's transactions) |
| `TESTNET_PRIVATE_KEY` | `script/measure_l2.sh`: a Base Sepolia test wallet, never one with real funds |

Steps that need no network after setup: all tests, `script/e2e_register.sh`,
`script/measure_offchain.sh`, `script/measure.sh`, `script/measure_groth16.sh`. The L2 campaign needs
test ETH on Base Sepolia (about 0.001 ETH per run); the official faucets are listed at
<https://docs.base.org/base-chain/tools/network-faucets>.

## 4. Quick check (about 10 minutes after setup)

```
(cd contracts && forge test)
cargo test --release --workspace
script/e2e_register.sh
```

| Command | Expected |
|---|---|
| `forge test` | `206 tests passed, 0 failed, 0 skipped (206 total tests)` |
| `python3 script/table6_coverage.py` | `Tests: 205/205 passed; invariants: 4/4 held.` and `Conditions without a passing positive and negative test: none.` |
| `cargo test --release --workspace` | 114 passed, 0 failed, 3 ignored (the ignored clock-shift tests need libfaketime: `cargo test --release -p pprev-prover --test time -- --include-ignored`) |
| `script/e2e_register.sh` | `checks: 19/19 passed`; a record in `measurements/e2e_register/` |

`script/e2e_register.sh` starts anvil, deploys the contracts, starts the mock registry and the
notary, runs Register for an owner of a fixture property (TLSNotary session, phi_R proof, notary
signature, transaction), checks the event and the contract state, and runs five negative cases: an
account that is not an owner (no witness; a borrowed proof is refused), a nonce the notary has
signed, the payload sent from another account, the payload replayed, and a submission after Delta.
It stops every process it started, also on failure or interrupt, and needs ports 8545, 4443, 7047,
7048 free (override with `ANVIL_PORT`, `REGISTRY_PORT`, `MPC_PORT`, `VERIFIER_PORT`).

## 5. Reproducing the results

Each row names a result, the command that produces it, the committed record it comes from, and the
value in that record. Gas values reproduce exactly; times, prices, and ETH/USD differ from run to run
(Section 6). Every script writes a new record under `measurements/` with the commit, a dirty flag,
tool versions, and the machine.

<!-- results:begin -->
<!-- Generated by script/render_results.py from the newest record of each kind; do not edit. -->

| Result | Command | Record | Recorded value | Time (estimate) | Network |
|---|---|---|---|---|---|
| End-to-end Register: TLSNotary session, phi_R proof, notary signature, transaction; five negative cases | `script/e2e_register.sh` | `measurements/e2e_register/20260926T183439Z.json` | 19/19 checks pass | ~3 min | no |
| Freshness budget of one Register run (t_prove + t_verify + t_sign + t_incl, local chain) | `script/e2e_register.sh` | `measurements/e2e_register/20260926T183439Z.json` | 4,544 ms, 1.51% of Delta = 300 s | ~3 min | no |
| phi_R circuit size | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 119,680 constraints (O2) | ~15 min | no |
| Proving time t_prove (witness generation + snarkjs), n = 20 | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 3,311.8 ms (IQR 3,235.9-3,354.5) | ~15 min | no |
| Policy verifier: t_verify (presentation checks + Groth16) and t_sign | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | t_verify 1.7 ms (IQR 1.6-1.7); Groth16 alone 1.25 ms; t_sign 5.1 ms (IQR 3.7-6.5) | ~15 min | no |
| MPC-TLS session with the notary | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 345.4 ms (IQR 333.0-380.7); 30.2 MB sent, 3.8 MB received | ~15 min | no |
| Peak memory | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | snarkjs 1,638.6 MB, witness generator 96.9 MB, prover 242.3 MB (medians) | ~15 min | no |
| Freshness budget over 20 runs (medians, local t_incl) | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 3,333 ms, 1.11% of Delta | ~15 min | no |
| MPC-TLS preprocessing stalls (tlsn#1173), recovered by retry | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 3/223 sessions (1.35%); 0 runs gave up | ~15 min | no |
| Contract test suite | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | 206 tests passed, 0 failed, 0 skipped (206 total tests) | ~2 min | no |
| On-chain execution gas per operation | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | Register 182,779, Apply 168,680, Engage 96,593, Settle 90,924, Expire 58,787, Reclaim 23,853, Cancel 21,238 | ~2 min | no |
| Lifecycle gas (Register + Apply + Engage + Settle) | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | execution 538,976; receipts 625,732; 1,753 transaction bytes | ~2 min | no |
| Deployment and bytecode size | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | PPREV 2,124,381 gas, runtime 9,126 B (37.1% of EIP-170); verifier 192,589 gas, 634 B | ~2 min | no |
| Cost decomposition of Register and Apply | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | storage 92.4% and 92.0%; slots initialised 7 and 6; ECDSA marginal 3,574 and 3,594 gas | ~2 min | no |
| ECDSA verifier call | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | frame 4,020 gas against 434 for an accept-all verifier | ~2 min | no |
| Receipts against measured gas (signature-dependent difference) | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | Register +32, Apply +0, Engage +0, Settle +12 gas | ~2 min | no |
| L1 gas price snapshot (one day of blocks) | `script/l1_price.sh` | `measurements/l1_price/20260926T194005Z.json` | blocks 26,056,487-26,063,686; base fee 0.075715 gwei, priority fee 0.05 gwei, effective 0.133984 gwei (medians) | ~1 min | yes: ETH_MAINNET_RPC_URL |
| ETH/USD (Chainlink, one reading, used for L1 and L2) | `script/l1_price.sh` | `measurements/l1_price/20260926T194005Z.json` | $2,685.42 at block 26,063,686 | ~1 min | yes: ETH_MAINNET_RPC_URL |
| L1 lifecycle cost | `script/l1_price.sh` | `measurements/l1_price/20260926T194005Z.json` | execution $0.194, receipts $0.225; deployment $0.834 | ~1 min | yes: ETH_MAINNET_RPC_URL |
| On-chain Groth16 verification of phi_R (9 public inputs) | `script/measure_groth16.sh` | `measurements/groth16/20260926T194031Z.json` | 242,098 gas execution; EIP-1108 model 236,350 | ~1 min | no |
| Lifecycle with three predicate verifications on-chain | `script/measure_groth16.sh` | `measurements/groth16/20260926T194031Z.json` | +726,294 gas, x2.3475 (assumes phi_A, phi_S verified like phi_R) | ~1 min | no |
| L2 receipt gas per operation (Base Sepolia) | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | Register 208,227, Apply 193,736, Engage 113,137, Settle 110,636, Expire 79,991, Reclaim 40,257, Cancel 37,642 | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
| L2 cost per operation (Base mainnet prices) | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | Register $0.0034, Apply $0.0032, Engage $0.0019, Settle $0.0018, Expire $0.0013, Reclaim $0.0007, Cancel $0.0006 | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
| L2 lifecycle cost and L1 data share | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | $0.0103, 1,762 bytes; L1 data 0.12% (per operation 0.07-0.22%) | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
| Inclusion time t_incl on Base Sepolia (Register, n = 10) | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | 1,409.2 ms (IQR 1,300.8-2,780.1) | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
| L1 against L2 lifecycle cost | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | L1 21.94x L2 | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
<!-- results:end -->

`script/render_results.py` regenerates this table from the newest records; `--check` tells whether it
is current. Suggested order after setup: `measure_offchain.sh`, `measure.sh`, `l1_price.sh`,
`measure_groth16.sh`, `measure_l2.sh`. `l1_price.sh`, `measure_groth16.sh`, and `measure_l2.sh` read
the newest L1 record; `measure_l2.sh` also takes ETH/USD from the newest price record.

## 6. Measurement notes

- **Machine preparation** for timings: AC power, other applications closed, and sleep disabled for
  the duration (`caffeinate -dims` in a separate terminal). Records note the power source. Run from
  a directory outside iCloud Drive; the scripts stop if an input file is evicted (dataless).
- **Deterministic**: gas per operation, deployment gas, bytecode sizes, calldata sizes, the storage
  decomposition, constraint count, and on-chain Groth16 gas. Receipt gas of the three operations that
  carry a notary signature varies by a few gas with the signature (calldata zero bytes at 4 against
  16 gas, and the verifier's recovery-parameter check, up to 20 gas); the records reconcile it.
  MPC-TLS traffic varies by well under 1 KB per session.
- **Not deterministic**: all times (the off-chain record gives minimum, quartiles, and maximum of
  every timing over 20 runs), the occurrence of preprocessing stalls, the
  inclusion time on Base Sepolia, and every price. Gas prices and ETH/USD are snapshots: a new run
  of `script/l1_price.sh` or `script/measure_l2.sh` reads other blocks and gives other dollar figures.
  Base Sepolia fees reflect testnet demand; the L2 campaign takes only gas and bytes from it and
  prices them with one Base mainnet block.
- **Scope of t_incl**: `script/e2e_register.sh` and `script/measure_offchain.sh` include on a local
  anvil node; the public-chain figure is the Base Sepolia one of `script/measure_l2.sh`, which is
  the time from sending a transaction until the including block can be read (Base serves
  preconfirmed receipts earlier; the record keeps both times).
- **Gas schedule**: gas figures follow the Osaka (Fusaka) schedule (`script/measure.sh` pins anvil
  to it). The Solidity compiler targets cancun.

## 7. Known issues

- **TLSNotary preprocessing stall.** tlsn v0.1.0-alpha.15 intermittently deadlocks in MPC-TLS
  preprocessing (upstream pull request [tlsnotary/tlsn#1173](https://github.com/tlsnotary/tlsn/pull/1173)).
  The prover bounds preprocessing to 30 s and retries with a new session up to three times; the
  notary cuts sessions above its preprocessing (30 s) or session (120 s) bound. Measured rate in the
  committed off-chain record: 3 of 223 sessions (1.35%), all recovered by the first retry. Failed
  attempts are excluded from every timing and reported separately.
- **Dependency on tlsn's serialisation layout.** tlsn v0.1.0-alpha.15 keeps the transcript
  commitments of an attestation body crate-private; `pprev_notary::attested_commitments` reads them
  from the serialised body of a verified attestation. The golden test
  `g3_attestation_body_layout_matches_golden` fails if a tlsn update changes that layout.
- **GPL-licensed verifier.** `circuits/setup/Groth16Verifier.sol` is the verifier as snarkjs exports it
  and keeps snarkjs' GPL-3.0 header; the rest of the repository is MIT. The protocol never deploys
  it; only `script/measure_groth16.sh` compiles it, for the on-chain comparison.
- **The exported Groth16 verifier fails silently on low gas.** When a precompile call runs out of gas,
  snarkjs' verifier returns `false` instead of reverting. A gas estimate therefore settles on a limit
  at which the pairing check fails, and the transaction succeeds while verifying nothing.
  `script/measure_groth16.sh` sends the verification with an explicit gas limit and checks in the
  call trace that it returned true. PPREV's own calls revert on a rejected signature, so estimation
  is sound for them.
- **Proving key not in the repository.** The 65 MB proving key is produced by
  `script/circuits_setup.sh`; a new setup changes the committed verification key and sample proof
  (Section 3).
- **Python CA bundle.** Python builds without a CA bundle of their own (python.org builds on macOS)
  fall back to `/etc/ssl/cert.pem` in `script/lib/l2_send.py`; certificate verification stays on.

## 8. Repository layout

```
contracts/          Foundry project: PPREV, ECDSA notary verifier, tests (test/), deployment and
                    measurement scripts (script/: Deploy, Lifecycle, MeasureGas, L2Campaign, GenVectors)
circuits/           phi_R in circom (src/), Groth16 setup outputs: verification key, exported verifier,
                    sample proof, transcript (setup/); build/ is generated
mock-registry/      local HTTPS title registry with fixture records
offchain/crates/    pprev-types (layout, policy bundle, circuit parameters, EIP-712 statements),
                    pprev-notary (MPC-TLS notary, presentation checks, Groth16 verification, policy
                    verifier, statement signature, nonce record, mock notary; binary pprev-notary),
                    pprev-prover (login, MPC-TLS session, presentation, phi_R witness and proof,
                    Register client; binary pprev-prover with notarize, register, submit)
policies/           policy bundle rental-v1.json and the registry response layout
test-vectors/       EIP-712, C_tx, and notary signature vectors shared by Solidity and Rust
script/             circuit build and setup, end-to-end Register, measurement scripts, Table VI
                    coverage, results table; lib/ holds the shared parts
measurements/       committed records of the measurement scripts, one JSON file per run
```

## 9. Notation

Code follows Solidity naming conventions. The table maps the paper's notation to code names.

| Paper | Code |
|---|---|
| Register, Apply, Engage, Settle, Expire, Reclaim, Cancel, Withdraw | `register`, `applyFor`, `engage`, `settle`, `expire`, `reclaim`, `cancel`, `withdraw` (`apply` is reserved in Solidity) |
| Acceptance conditions R(a)–R(h), A(a)–A(h), S(a)–S(h), E(a)–E(c) | comments `// R(a)` etc. in `PPREV.sol`, test names `test_R_a_...` |
| $C_{\mathsf{tx}}$ | `cTx` |
| $\mathsf{txData}$ | `txData`, struct `TxData {propertyId, amount, settlementShare}` |
| settlement share (basis points) | `TxData.settlementShare` |
| $r$ | `r` |
| $H$ | `keccak256` |
| $\mathsf{policyID}_R$, $\mathsf{policyID}_A$, $\mathsf{policyID}_S$ | `policyIdR`, `policyIdA`, `policyIdS` |
| $\mathsf{PolicyRegistry}$ | `policyRegistry`, struct `Policy` |
| $\mathsf{reqEscrow}$, $\mathsf{minCollateral}$, $\mathsf{maxCollateral}$ | `reqEscrow`, `minCollateral`, `maxCollateral` |
| $\eta_R$, $\eta_A$, $\eta_S$ | `etaR`, `etaA`, `etaS` (field `eta` in the signed statements) |
| $t_{\mathsf{att},R}$, $t_{\mathsf{att},A}$, $t_{\mathsf{att},S}$ | `tAttR`, `tAttA`, `tAttS` (field `tAtt` in the signed statements) |
| $\sigma_R$, $\sigma_A$, $\sigma_S$ | `sigmaR`, `sigmaA`, `sigmaS` |
| $a_\psi$ ($a_P$, $a_B$) | field `submitter` in the signed statements, fixed to `msg.sender` |
| $c_B$ | `cB` |
| $x_R$, $x_A$, $x_S$ | EIP-712 types `Register`, `Apply`, `Settle`; `PPREVEncoding.RegisterStatement` etc. |
| $\mathsf{tag}_\psi$ | EIP-712 primary type of the statement |
| $\mathsf{enc}(\mathsf{tag}_\psi, x_\psi, \mathsf{chainID}, \mathsf{addr}_{\mathsf{SC}})$ | EIP-712 digest, domain `{name: "PPREV", version: "1", chainId, verifyingContract}` |
| $\mathsf{SVer}$ | `INotaryVerifier.verify` |
| $\mathsf{vk}_{\mathsf{notary}}$ | `EcdsaNotaryVerifier.VK_NOTARY` (an address), installed through `notaryVerifier` |
| $\mathsf{txID}$, $\mathsf{appID}$, $\mathsf{engID}$ | `txId`, `appId`, `engId` |
| $\mathsf{TxState}[\mathsf{txID}]$ | `txState[txId]` |
| ACTIVE, LOCKED, SETTLED, EXPIRED, CANCELLED | `TxState.Active`, `.Locked`, `.Settled`, `.Expired`, `.Cancelled` |
| $\mathsf{collateral}$, $\mathsf{deposit}$ | `collateral`, `deposit` |
| $\mathsf{expiresAt}$, $\mathsf{now}$ | `expiresAt`, `block.timestamp` |
| $\Delta$ | `DELTA` (seconds) |
| $\tau_{\mathsf{lock}}$ | `TAU_LOCK` (seconds) |
| $\mathsf{maxExpirations}$ | `MAX_EXPIRATIONS` |
| $\rho$ | `RHO` (basis points) |
| $t_{\mathsf{att},\psi}$ (source) | notary clock, attestation extension `pprev.t_att` |
| $\mathsf{prov}_\psi$ | TLSNotary `Attestation`, shown to the policy verifier as a `Presentation` |
| $\mathsf{record}_R$ fields committed | `account`, `owners`, `propertyId` byte ranges (`pprev_types::ResponseRanges`) |
| $\phi_R$ | template `PhiR` in `circuits/src/phi_r.circom` |
| $\pi_R$ | Groth16 proof (snarkjs `proof.json`), `pprev_notary::Groth16Proof` |
| binding of $\pi_R$ to $x_R$ | public input `bind` = EIP-712 digest of $x_R$ mod $r_{\mathrm{BN254}}$ |
| $H_c$ | circomlib's two-input Poseidon, `pprev_notary::mock::counterparty_commitment` |
| $\mathsf{sk}_{\mathsf{notary}}$ | `pprev_notary::StatementKey` |
| nonces the notary has signed | `pprev_notary::NonceStore` (append-only file) |
| policy verifier | `pprev_notary::PolicyVerifier` (Register) |
| $\phi_A$, $\phi_S$ (mock) | `pprev_notary::mock::MockNotary::sign_apply`, `sign_settle` |

Undeliverable payouts: every payout made by an algorithm forwards `PAYOUT_GAS` (30,000) gas and copies
