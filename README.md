# PPREV prototype

Prototype of PPREV, a protocol that verifies real estate transactions over notarised registry data.
This repository holds the on-chain enforcement layer (`contracts/`), the attested-submission
session over a local registry (`mock-registry/`, `offchain/`), the registration circuit phi_R
(`circuits/`), and the policy verifier and notary signer (`offchain/`), each with its test suite.

## Layout

```
contracts/        Foundry project: PPREV contract, ECDSA notary verifier, tests, vector script
mock-registry/    Local HTTPS title registry with a fixed-layout response
circuits/         phi_R in circom (src/), Groth16 setup outputs (setup/)
offchain/crates/  pprev-types (layout, circuit parameters, field encoding, EIP-712 statements),
                  pprev-notary (MPC-TLS notary, presentation checks, Groth16 verification,
                  policy verifier, statement signature, nonce record, mock notary),
                  pprev-prover (registry login, MPC-TLS session, commitments, presentation,
                  phi_R witness and proof, end-to-end Register client)
policies/         Policy bundle (rental-v1.json) and response layout of the title registry
test-vectors/     EIP-712, C_tx, and notary signature vectors shared by the Solidity and Rust code
script/           Table VI coverage report, circuit build, Groth16 setup, end-to-end Register
measurements/     Records written by the scripts (JSON)
```

## Toolchain

- solc 0.8.36, optimizer enabled with 200 runs, via-IR disabled, EVM target `cancun`,
  `bytecode_hash = "ipfs"` (see `contracts/foundry.toml`)
- Foundry 1.8.3, forge-std v1.16.2 (git submodule)
- Rust 1.98.1 (`rust-toolchain.toml`), TLSNotary `tlsn` v0.1.0-alpha.15 (git tag), MPC mode
- circom 2.2.3, circomlib 2.0.5 and snarkjs 0.7.6 (`circuits/package.json`), Node.js v26.9.0
  (`.nvmrc`)
- arkworks 0.5 (Groth16 verification on BN254), light-poseidon 0.4 (circomlib's Poseidon),
  alloy 1.7 (EIP-712), alloy-signer-local 2.5 (statement signature), alloy 2.5 (JSON-RPC client of
  the end-to-end run)

## Build and test

```
git submodule update --init --recursive
cd contracts
forge build
forge test
```

The suite covers every acceptance condition of the seven on-chain algorithms with positive and negative
tests, the payout rule under recipients that refuse payment, burn gas, return oversized data, or
re-enter, three independent EIP-712 implementations against each other, and an invariant campaign over
random operation sequences (fund conservation, state consistency, no stranded funds).

Test names carry the acceptance-condition label: `test_R_b_...` exercises condition R(b) of Register,
`test_Engage_ii_...` condition (ii) of Engage; `accepts` marks a positive test and `reverts` a negative
one. `test_P1_...` to `test_P5_...` play the five attack classes against the contract.

Table VI coverage, derived from the test names and the results of `forge test`:

```
python3 script/table6_coverage.py
```

Regenerate the test vectors (each value is checked against two independent encoders before it is
written):

```
cd contracts && forge script script/GenVectors.s.sol
```

## Attested session (off-chain)

The prover logs in to the mock registry, runs an MPC-TLS session with the notary for one title
request, and commits with SHA-256 to byte ranges of the fixed-layout response. The presentation opens
the request line, the response status line, the `Content-Type` header, and the JSON keys; the
`account`, `owners`, and `propertyId` values stay committed and hidden. The notary signs its own clock
into the attestation as the `pprev.t_att` extension. TLSNotary's MPC mode supports TLS 1.2 with
`TLS_ECDHE_{ECDSA,RSA}_WITH_AES_128_GCM_SHA256` over secp256r1, so the registry serves exactly that.

```
cargo test --release --workspace
```

`offchain/crates/pprev-prover/tests/gate.rs` checks that the notary's signature binds the direction,
index set, and hash of every commitment, that the committed bytes are the bytes the registry sent, and
that the verifier reads the hidden index sets. `pprev_notary::attested_commitments` reads the commitments
from tlsn's serialised attestation body, because v0.1.0-alpha.15 keeps the accessor crate-private; the
golden test `g3_attestation_body_layout_matches_golden` fails if a tlsn update changes that layout.
TLSNotary v0.1.0-alpha.15 has an intermittent deadlock in MPC preprocessing (upstream pull request
[tlsnotary/tlsn#1173](https://github.com/tlsnotary/tlsn/pull/1173), open). The prover bounds
preprocessing (30 s by default) and retries with a new session up to three times, logging each retry;
the notary cuts a session that exceeds its preprocessing or session bound. The clock-shift tests run the prover under libfaketime
(`brew install libfaketime` on macOS) and are ignored by default:

```
cargo test --release -p pprev-prover --test time -- --include-ignored
```

## Circuit phi_R and policy verifier

phi_R (`circuits/src/phi_r.circom`) opens the three attested SHA-256 commitments (value || 16-byte
blinder, TLSNotary's convention), checks that the account of the session is a non-empty identifier
equal to one of the owner slots, and that the committed property identifier, zero-padded to 32
bytes, is `txData.propertyId`. Its public inputs are the three commitments and
`txData.propertyId` as 128-bit limbs, and `bind`, the EIP-712 digest of x_R modulo the BN254 scalar
field order. The main component is generated from the layout (`circuits/src/main_title_v1.circom`).

```
script/circuits_build.sh   # compile; size in circuits/build/phi_r.info.json
script/circuits_setup.sh   # Groth16 setup, proving key in circuits/build/phi_r.zkey
cargo test --release --workspace
```

The setup takes phase 1 from the PSE perpetual powers of tau (`ppot_0080_17.ptau`, SHA-256 pinned,
checked with `snarkjs powersoftau verify`, cached in `~/.cache/pprev`). Phase 2 is local and
single-party: two contributions and a beacon, the hash of a finalised Ethereum block. Whoever ran it
knows the toxic waste, so the key serves this prototype only. `circuits/setup/` holds the verification
key, the exported Solidity verifier, one sample proof made with the same key, and the transcript
`setup.json`. The proving key is not committed; the tests that prove (`pprev-prover` `proof` and
`policy_verifier`) need a local setup run. `circuits/setup/Groth16Verifier.sol` is the verifier as
snarkjs exports it and keeps snarkjs' GPL-3.0 license header; the rest of the repository is MIT.

The policy verifier (`pprev_notary::PolicyVerifier`) checks the presentation, recomputes the digest
of x_R, verifies the proof under the policy's own verifying key with public inputs taken from the
attestation, records the nonce, and signs x_R with the statement key. The notary holds two keys: the
attestation key signs TLSNotary attestations, the statement key signs x_R, x_A, x_S. Apply and Settle
signatures come from a mock notary that checks phi_A and phi_S without circuits.

## End-to-end Register

`script/e2e_register.sh` runs Register against a local chain. It starts anvil, deploys
`EcdsaNotaryVerifier` and `PPREV` with the fixture parameters (`contracts/script/Deploy.s.sol`) and
registers the bundle of `policies/rental-v1.json`, then starts the mock registry and the notary
(`pprev-notary`: MPC-TLS notary and policy verifier in one process, with fresh keys for the run).
`pprev-prover register` logs in, runs the notarised session, builds the presentation and x_R, proves
phi_R, obtains sigma_R from the policy verifier, and sends the `register` transaction. The script then
checks the `Registered` event, `txState`, the consumed nonce, the commitment index, and the contract
balance, and runs the negative cases:

| Case | Expected |
|---|---|
| account that is not an owner | phi_R has no witness; a proof borrowed from the owner's run is refused by the policy verifier |
| nonce the notary has already signed | refused by the policy verifier |
| the owner's signed payload sent from another account | `InvalidNotarySignature` |
| the same payload sent again by the owner | `NonceConsumed` |
| a signed payload sent after Delta (anvil time moved forward) | `AttestationExpired` |

```
script/circuits_build.sh   # once: compiled circuit
script/circuits_setup.sh   # once: proving key
script/e2e_register.sh
```

The script needs free ports 8545, 4443, 7047, 7048 (override with `ANVIL_PORT`, `REGISTRY_PORT`,
`MPC_PORT`, `VERIFIER_PORT`) and stops every process it started on exit, including on failure or
interrupt. It uses the Node.js version of `.nvmrc` (the one that produced the setup) and stops if that
version is not found; `PPREV_NODE` names a node binary. The record goes to
`measurements/e2e_register/<run>.json`: the time of each step, split into steps before t_att (login,
MPC-TLS session) and steps after it that the freshness window must cover (presentation, t_prove =
witness generation + `snarkjs groth16 prove`, t_verify, t_sign, t_incl), the sum against Delta, the
MPC-TLS attempts of each run, the result of every check, the commit (with a dirty flag), tool
versions, and the machine. Blocks are mined on demand, so t_incl measures a local node, not a public
chain. Keys, proofs, and logs of a run stay in `target/e2e/<run>/`.

## Notation

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
no return data; a payout that fails is credited to its recipient and claimed with `withdraw`.
