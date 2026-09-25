# PPREV prototype

Prototype of PPREV, a protocol that verifies real estate transactions over notarised registry data.
This repository holds the on-chain enforcement layer (`contracts/`) and the attested-submission
session over a local registry (`mock-registry/`, `offchain/`), each with its test suite.

## Layout

```
contracts/        Foundry project: PPREV contract, ECDSA notary verifier, tests, vector script
mock-registry/    Local HTTPS title registry with a fixed-layout response
offchain/crates/  pprev-types (layout), pprev-notary (MPC-TLS notary, presentation checks),
                  pprev-prover (registry login, MPC-TLS session, commitments, presentation)
policies/         Response layout of the title registry
test-vectors/     EIP-712 and C_tx vectors shared with the off-chain components
script/           Helper scripts (Table VI coverage report)
```

## Toolchain

- solc 0.8.36, optimizer enabled with 200 runs, via-IR disabled, EVM target `cancun`,
  `bytecode_hash = "ipfs"` (see `contracts/foundry.toml`)
- Foundry 1.8.3, forge-std v1.16.2 (git submodule)
- Rust 1.98.1 (`rust-toolchain.toml`), TLSNotary `tlsn` v0.1.0-alpha.15 (git tag), MPC mode

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

Undeliverable payouts: every payout made by an algorithm forwards `PAYOUT_GAS` (30,000) gas and copies
no return data; a payout that fails is credited to its recipient and claimed with `withdraw`.
