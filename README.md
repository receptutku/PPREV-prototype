# PPREV prototype

Prototype of PPREV, a protocol that verifies real estate transactions over notarised registry data.
This repository currently holds the on-chain enforcement layer (`contracts/`) and its test suite.

## Layout

```
contracts/      Foundry project: PPREV contract, ECDSA notary verifier, tests, vector script
test-vectors/   EIP-712 and C_tx vectors shared with the off-chain components
script/         Helper scripts (Table VI coverage report)
```

## Toolchain

- solc 0.8.36, optimizer enabled with 200 runs, via-IR disabled, EVM target `cancun`,
  `bytecode_hash = "ipfs"` (see `contracts/foundry.toml`)
- Foundry 1.8.3, forge-std v1.16.2 (git submodule)

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

Undeliverable payouts: every payout made by an algorithm forwards `PAYOUT_GAS` (30,000) gas and copies
no return data; a payout that fails is credited to its recipient and claimed with `withdraw`.
