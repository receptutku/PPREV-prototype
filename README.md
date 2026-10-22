# PPREV prototype

Artifact of PPREV, a protocol that verifies real estate transactions over notarised registry data.
A party proves a predicate over a record that an authoritative registry serves to its own account,
without revealing the record: a TLSNotary session attests where the bytes came from, a Groth16 proof
shows that the hidden fields satisfy the phase's predicate, and a notary signature binds the result to
one transaction, phase, and deployment of an escrow contract.

This repository holds the contracts, the off-chain pipeline for all three attested phases, a local
mock registry, the circuits and their setup records, and the scripts and records behind every
measured figure. Tag `artifact-v2` is the snapshot of the first October 2026 manuscript; the
integrated on-chain verification baseline (Section 5.3), the controlled link experiment (Section
5.4), and the retry fix of Section 7 came after it. Tag `artifact-v1` is the September 2026 snapshot,
before the phi_A and phi_S circuits.

## 1. Overview

What the artifact contains:

- **On-chain enforcement layer** (`contracts/`, Solidity, Foundry): the seven algorithms Register,
  Apply, Engage, Settle, Expire, Reclaim, Cancel and the auxiliary Withdraw, an ECDSA notary
  verifier, and a test suite with a positive and a negative test for every acceptance condition.
- **Predicate circuits** (`circuits/`, circom, Groth16):
  - phi_R (Register): the logged-in account is an owner of the property in `txData`;
  - phi_A (Apply): the logged-in account's monthly income is at least three times the rent, and the
    applicant's identity commitment c_B opens to that account;
  - phi_S (Settle): a tenancy notation is on the property in `txData`, names the identity in c_B,
    and is dated no earlier than the engagement day.

  Each circuit opens the SHA-256 commitments that the TLSNotary attestation holds for the fields it
  reads, and takes the EIP-712 digest of its statement as a public input. Phase 1 uses public
  powers-of-tau parameters; each phase-2 setup is local and single-party.
- **Mock registry** (`mock-registry/`): a local HTTPS server (TLS 1.2, the one cipher suite that
  TLSNotary's MPC mode handles) with login, fixed-layout title, income, and tenancy-notation
  responses, and synthetic fixture records.
- **Attested-submission pipeline** (`offchain/`, Rust):
  - a TLSNotary prover and notary (tlsn v0.1.0-alpha.15, MPC mode). The prover commits to the
    fields a predicate reads; the presentation reveals only the request line and the response
    structure (status line, Content-Type, JSON keys);
  - the policy verifier: checks the presentation against the phase's layout, derives every public
    input from the attestation and the statement, verifies the Groth16 proof under the phase's
    key, records the nonce (one store for all phases), and signs the statement with the notary key;
  - the prover's client for Register, Apply, Engage, and Settle, including the transactions.
- **Public-portal probe** (`offchain/crates/pprev-prover/src/bin/probe-portal.rs`): one notarised
  session against a public page of a production server, a transport experiment (Section 5.1).
- **Integrated on-chain verification baseline** (`contracts/src/baseline/`, measurement only, not
  part of PPREV): contracts that check an attested phase's submission on-chain the way the policy
  verifier checks it off-chain, with the server identity attested off-chain (Section 5.3).
- **Link emulation** (`offchain/crates/pprev-prover/src/netem.rs`): an application-level proxy that
  delays and paces the bytes of one link, for the controlled link experiment (Section 5.4).
- **End-to-end scripts** on a local chain: `script/e2e_register.sh` (Register with five negative
  cases) and `script/e2e_lifecycle.sh` (Register, Apply, Engage, Settle with nine negative
  scenarios), and the **measurement scripts** with their committed records (`measurements/`).

What it does not contain:

- a real land registry: the registry is a local mock, so latency to a real registry over a real
  network and the layout of real portal responses are untested (Section 5.4 emulates delay and
  bandwidth on loopback at the application level, not a wide-area network);
- more than one notary: notary and policy verifier are one trusted process with two keys;
- a production trusted-setup ceremony: every phase 2 is single-party, so the proving keys suit this
  prototype only;
- a mainnet deployment: Layer-2 figures come from Base Sepolia, priced with Base mainnet parameters.

The September measurement campaign (Section 5.2) predates the phi_A and phi_S circuits. Its Apply and
Settle transactions carry signatures from a fixed-key test signer that checks no predicate. Their gas
depends on what the contract checks, the signature, and not on what the notary checked before
signing; the signature bytes themselves move receipt gas by a few gas (Section 6). The lifecycle runs
and predicate measurements of Section 5.1 are separate experiments.

## 2. Requirements

Tested on an Apple M2 with 16 GB of memory, macOS 26.6. Versions are pinned where the repository
can pin them:

| Tool | Version | Pinned by |
|---|---|---|
| Rust | 1.98.1 | `rust-toolchain.toml` |
| Foundry (forge, cast, anvil) | 1.8.3 | install with `foundryup --install 1.8.3` |
| solc | 0.8.36, optimizer 200 runs, via-IR off, EVM cancun | `contracts/foundry.toml` (fetched by forge) |
| forge-std | v1.16.2 | git submodule |
| circom | 2.2.3 | build from source: `git clone --branch v2.2.3 https://github.com/iden3/circom.git`, then `cargo install --path circom` inside it |
| snarkjs, circomlib | 0.7.6, 2.0.5 | `circuits/package-lock.json` |
| Node.js | v26.9.0 | `.nvmrc`; the scripts stop on another version (`PPREV_NODE` names a binary) |
| TLSNotary | v0.1.0-alpha.15 | `Cargo.toml` (git tag), `Cargo.lock` |
| Python 3, jq, lsof, openssl, curl, git | any recent | standard library only for Python |
| libfaketime | optional | only for the ignored clock-shift tests |

Disk: about 10 GB free (Rust build about 7 GB, circuit builds about 210 MB, proving keys about
155 MB, powers-of-tau cache 200 MB).

## 3. Setup

```
git clone --recurse-submodules https://github.com/receptutku/PPREV-prototype.git pprev-prototype
cd pprev-prototype
cp .env.example .env            # then set the beacon for the phi_R setup, see below
nvm install && nvm use          # Node.js from .nvmrc (or install v26.9.0 otherwise)
(cd circuits && npm ci)         # snarkjs, circomlib
cargo build --release           # prover, notary, mock registry
(cd contracts && forge build)
script/circuits_build.sh        # compile phi_R
script/circuits_setup.sh        # phi_R setup (downloads the 200 MB phase-1 file once)
script/circuits_build_as.sh     # compile phi_A and phi_S
script/circuits_setup_as.sh     # phi_A and phi_S setup, sample proofs, exported verifiers
```

Both setup scripts finish phase 2 with a random beacon. `script/circuits_setup.sh` stops unless one
is configured: `ETH_MAINNET_RPC_URL` in `.env` (the hash of the latest finalised mainnet block), or
`PPREV_BEACON` with 64 hex digits and `PPREV_BEACON_SOURCE` describing where they came from, both
in the environment of the script. For a local trial run that needs no public randomness:

```
export PPREV_BEACON="$(openssl rand -hex 32)" PPREV_BEACON_SOURCE="local random bytes, not public"
script/circuits_setup.sh
```

The transcript then records that source, and the key is no more trustworthy than its phase 2.
`script/circuits_setup_as.sh` takes the same settings and, without either, uses 32 random bytes and
records exactly that.

`script/circuits_setup.sh` runs once and takes about 65 minutes on the tested machine: almost all of
it is `snarkjs powersoftau verify` checking the phase-1 file ending at ceremony contribution 0080,
which runs on a single core and prints its result only at the end; phase 2 takes a few minutes. The
[ceremony history](https://github.com/privacy-ethereum/perpetualpowersoftau#note-on-chain-fork)
branches from 0058 to 0078: 0080 is a contribution identifier, not a count of 80 contributions.

`script/circuits_setup_as.sh` takes a few minutes. It reuses the cached phase-1 file after checking
its SHA-256 against the pinned value and against `circuits/setup/setup.json`, and does not repeat
`powersoftau verify`. It checks that each circuit fits the 2^17 constraints of that file, runs a
separate phase 2 per circuit, verifies each key with `snarkjs zkey verify`, and calls
`script/circuits_samples_as.sh`, which proves one sample statement per circuit and exports the
Solidity verifiers. The phi_R key is not touched.

Every setup produces new proving keys (`circuits/build/phi_{r,a,s}.zkey`, not in the repository) and
rewrites the matching files under `circuits/setup/`: verification key, Solidity verifier, sample
proof, and the transcript `setup.json` with the contribution hashes, the beacon and its source, and
the SHA-256 of the R1CS, the phase-1 file, the proving key, the verification key, and the Solidity
verifier. The end-to-end and measurement scripts check the keys against these
transcripts. The measurement scripts refuse a dirty working tree, so commit the new files locally
before measuring, or run with `PPREV_ALLOW_DIRTY=1 PPREV_MEASUREMENTS_DIR=<dir>`. A new key changes
the proofs, the verifier constants, and calldata, so exact gas and timing results must be measured
again for it.

`.env` (git-ignored; no script prints its values):

| Variable | Used by |
|---|---|
| `ETH_MAINNET_RPC_URL` | `script/l1_price.sh`; the beacon of both setup scripts, unless `PPREV_BEACON` is set (see above) |
| `BASE_MAINNET_RPC_URL` | `script/measure_l2.sh` (price parameters of one block) |
| `BASE_SEPOLIA_RPC_URL` | `script/measure_l2.sh` (the campaign's transactions) |
| `TESTNET_PRIVATE_KEY` | `script/measure_l2.sh`: a Base Sepolia test wallet, never one with real funds |

Steps that need no network after setup: all tests, both end-to-end scripts,
`script/measure_offchain.sh`, `script/measure.sh`, `script/measure_groth16.sh`. The L2 campaign needs
test ETH on Base Sepolia (about 0.001 ETH per run); the official faucets are listed at
<https://docs.base.org/base-chain/tools/network-faucets>.

## 4. Quick check (about 15 minutes after setup)

```
(cd contracts && forge test)
python3 script/table6_coverage.py
cargo test --release --workspace
script/e2e_register.sh
script/e2e_lifecycle.sh
```

| Command | Expected |
|---|---|
| `forge test` | `245 tests passed, 0 failed, 0 skipped (245 total tests)`: 244 unit and fuzz tests (39 of them for the baseline of Section 5.3) and the one invariant suite, which checks four invariants |
| `python3 script/table6_coverage.py` | `Tests: 244/244 passed; invariants: 4/4 held.` and `Conditions without a passing positive and negative test: none.` |
| `cargo test --release --workspace` | 191 passed, 0 failed, 3 ignored (the ignored clock-shift tests need libfaketime: `cargo test --release -p pprev-prover --test time -- --include-ignored`) |
| `script/e2e_register.sh` | `checks: 19/19 passed`; a record in `measurements/e2e_register/` |
| `script/e2e_lifecycle.sh` | `checks: 25/25 passed`; a record in `measurements/e2e_lifecycle/` |

`script/gate.sh` runs formatting and lint checks, both test suites, the measurement helpers' tests,
and a shell syntax check, and writes each step's output to `measurements/gate/<run>/` with the
SHA-256 of every tracked file before and after; the run fails on any difference. The current record
is `measurements/gate/20261022T184708Z/` (commit `824cd23`: Rust 191 passed, 3 ignored; forge 245;
helpers 6). The figures of the earlier records (206 forge and 114 Rust tests in September, 164 Rust
tests on October 21) describe the sources of their dates.

Both end-to-end scripts start anvil, deploy the contracts with the D18 parameters and the
`policies/rental-v1.json` bundle, start the mock registry and the notary with keys generated for the
run, and stop every process they started, also on failure or interrupt. They need ports 8545, 4443,
7047, 7048 free (override with `ANVIL_PORT`, `REGISTRY_PORT`, `MPC_PORT`, `VERIFIER_PORT`). The
notary takes tau_lock from the deployed contract's `TAU_LOCK()`, so the engagement day of phi_S
follows the deployment.

`script/e2e_register.sh` runs Register for an owner of a fixture property (TLSNotary session, phi_R
proof, notary signature, transaction), checks the event and the contract state, and runs five
negative cases: an account that is not an owner (no witness; a borrowed proof is refused), a nonce
the notary has signed, the payload sent from another account, the payload replayed, and a
submission after Delta.

`script/e2e_lifecycle.sh` runs Register, then Apply for a tenant with an income of 3.5 times the
rent, Engage, and Settle with a tenancy notation dated on the engagement day, each attested phase
with its own TLSNotary session, proof, and notary signature. It checks the events, the state of the
listing and the application, and that the deposit and the collateral reach their recipients. The
negative cases are:

| Case | Expected |
|---|---|
| applicant with 2.9 times the rent | phi_A has no witness; the tenant's proof, borrowed, is refused |
| c_B naming another account than the session's | phi_A has no witness |
| the tenant's signed application nonce again | refused by the policy verifier |
| the tenant's Apply payload sent again | `NonceConsumed` |
| a notation of the tenant dated before the engagement day | phi_S has no witness; the valid notation's proof, borrowed, is refused |
| a notation of the tenant on another property | phi_S has no witness |
| a notation of another tenant on the property | phi_S has no witness |
| the Settle payload sent from another account | `NotListingOwner` |
| the Settle payload sent again after settlement | `NotLocked` |

The script dates the valid synthetic notations to the current day in the registry's time zone
(`utcOffsetSecs` of the policy) and records that date. Its per-phase times are single observations,
not a distribution.

### Running the parts by hand

The scripts above are the reference; the binaries can also run one step at a time. A sketch, with
the addresses and key files that `start_stack` in `script/lib/common.sh` sets up:

```
target/release/mock-registry --bind 127.0.0.1:4443 --ca-out registry-ca.der \
    --income-layout policies/layouts/income-v1.json --tenancy-layout policies/layouts/tenancy-v1.json
target/release/pprev-notary --registry-ca registry-ca.der --policy policies/rental-v1.json \
    --attestation-key attestation.key --statement-key statement.key \
    --chain-id 31337 --contract <PPREV> --tau-lock <TAU_LOCK()> --nonces nonces.log --log events.jsonl
target/release/pprev-prover register --account ACC-000000000001 ... --out run/register
target/release/pprev-prover apply    --listing run/register/record.json --account ACC-000000000003 ... --out run/apply
target/release/pprev-prover engage   --application run/apply/record.json ... --out run/engage.json
target/release/pprev-prover settle   --listing run/register/record.json --application run/apply/record.json \
    --engagement run/engage.json --notation N-0001 --account ACC-000000000001 ... --out run/settle
```

`pprev-prover <command> --help` lists every option. `--tau-lock` is trusted configuration of the
notary: it must equal the contract's `TAU_LOCK()`, which the scripts read from the chain. The Apply
payload carries the opening of c_B (identifier and salt) that the tenant hands to the landlord for
Settle. `submit`, `submit-apply`, and `submit-settle` send a payload written with `--no-submit`.

## 5. Reproducing the results

### 5.1 Rental predicates and lifecycle (October 2026)

`measurements/addendum-20261021/` holds the records of the phi_A and phi_S work: the lifecycle and
Register end-to-end records, raw predicate-benchmark samples and proofs, independent witness and
proof checks, phase-verifier gas records, the Rust test record, the helper scripts, and a SHA-256
manifest. The final test record of the committed sources is `final-source-tests/` (164 Rust tests
passed, with the SHA-256 of every file changed since the September snapshot); the public-portal probe records are in
`public-portals/`. The predicate benchmark and the first lifecycle runs used a working tree on top
of the September commit `2f9a9cc` with the phi_A and phi_S implementation before it was committed
(it is in `e1de6f6` and later commits); the later test and probe records name their own sources.
Each record keeps the dirty flag and its own source and artifact hashes. Local paths in
the distributed copies are made repository-relative; the manifest keeps the digests of both the
original and the distributed files, and no number, proof, or test result changed.

| Predicate | Constraints | Public inputs | Witness + proving, median ms (IQR), n = 20 | Standalone verifier execution gas |
|---|---:|---:|---:|---:|
| phi_R | 119,680 | 9 | 2,995.2 (2,955.9-3,053.2) | 242,098 |
| phi_A | 59,963 | 7 | 1,778.9 (1,763.1-1,826.5) | 228,804 |
| phi_S | 89,257 | 11 | 2,795.0 (2,773.6-2,854.8) | 255,392 |

The proving benchmark uses one fixed synthetic input per predicate, one excluded warm-up per
predicate, a rotating predicate order, and verifies every proof. It ran on the M2 on battery power
and covers witness generation and snarkjs proving only: no TLS session, policy verifier, signature,
or transaction. It is not a new estimate of the September end-to-end Register distribution. After
circuit setup:

```
python3 measurements/addendum-20261021/benchmark_predicates.py . target/predicate-benchmark 20
python3 measurements/addendum-20261021/check_as_witnesses.py . \
    circuits/setup/phi_a/sample/input.json circuits/setup/phi_s/sample/input.json target/as-witnesses
python3 measurements/addendum-20261021/check_as_proofs.py . circuits/setup/phi_a/verification_key.json \
    circuits/setup/phi_a/sample/public.json circuits/setup/phi_a/sample/proof.json \
    circuits/setup/phi_s/verification_key.json target/as-proofs-a
python3 measurements/addendum-20261021/check_as_proofs.py . circuits/setup/phi_s/verification_key.json \
    circuits/setup/phi_s/sample/public.json circuits/setup/phi_s/sample/proof.json \
    circuits/setup/phi_a/verification_key.json target/as-proofs-s
bash measurements/addendum-20261021/measure_groth16_phase.sh . phi_a
bash measurements/addendum-20261021/measure_groth16_phase.sh . phi_s
```

The independent checks passed 28 witness and R1CS cases and 22 proof-verification cases (9 for
phi_A, 13 for phi_S): valid baselines, every public input changed by one, and the other phase's key. The three standalone
verifiers execute 726,294 gas together. Added to the 538,976-gas lifecycle of Section 5.2, they give
1,265,270 gas, 2.3475 times as much. This is an additive, partial model: it keeps the signature
checks and leaves out attestation verification, the extra calldata and intrinsic gas, and the
verifier deployments. When these records were taken, no design that verifies the TLSNotary
attestation on-chain had been built; Section 5.3 builds and measures one. The same factor in the September summary row below came from an estimate that assumed all
three verifiers cost like phi_R's; the measured verifiers give the same total, because 7 + 11 public
inputs equal 2 x 9 and the verifier cost is linear in their number. That summary record also states
that neither phi_A nor phi_S exists in the prototype: true when it was written, superseded by this
section; committed records are not edited.

**Public-portal probe.** `probe-portal` runs one TLSNotary session in MPC mode against a public HTTPS
page of a production server, with no login, account, credentials, or query parameters. For each URL
it sends two ordinary requests and then one notarised request (User-Agent
`pprev-probe/0.1 (research prototype; one request per run)`), obtains an attestation from a notary
in the same process with a fixed, public key and the Mozilla root store, and verifies a presentation
of it: it checks the server identity and extracts the signed attestation time (no freshness check). It stores no response content, only byte counts,
the positions at which repeated responses differ, the status line, the Content-Type, and timings.
`measurements/addendum-20261021/public-portals/` holds the records of four endpoints on three hosts
(`SUMMARY.md` gives the results and their limits). The probe contacts live servers, so run it
sparingly and only against public pages:

```
target/release/probe-portal --out target/probe.json https://<host>/<public-path>
```

It is a transport experiment: it shows that sessions complete and their presentations verify, and
says nothing about authenticated record views, a fixed record layout, latency to a remote notary,
or an independent notary deployment.

### 5.2 September 2026 campaign

Each row names a result, the command that produces it, the committed record it comes from, and the
value in that record. Gas values reproduce exactly; times, prices, and ETH/USD differ from run to run
(Section 6). Every script writes a new record under `measurements/` with the commit, a dirty flag,
tool versions, and the machine. The summary record (`script/derive_summary.py`) derives the dollar
figures, their L1/L2 ratio, the freshness budget, and the Groth16 factor from the other records
without network access or new measurements; it lists every input with its SHA-256 and commit, and
the same inputs give the same file. This campaign ran on AC power.

<!-- results:begin -->
<!-- Generated by script/render_results.py from the newest record of each kind; do not edit. -->

| Result | Command | Record | Recorded value | Time (estimate) | Network |
|---|---|---|---|---|---|
| End-to-end Register: TLSNotary session, phi_R proof, notary signature, transaction; five negative cases | `script/e2e_register.sh` | `measurements/e2e_register/20260926T201218Z.json` | 19/19 checks pass | ~3 min | no |
| Freshness budget of one Register run (t_prove + t_verify + t_sign + t_incl, local chain) | `script/e2e_register.sh` | `measurements/e2e_register/20260926T201218Z.json` | 3,279 ms, 1.09% of Delta = 300 s | ~3 min | no |
| phi_R circuit size | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 119,680 constraints (O2) | ~15 min | no |
| Proving time t_prove (witness generation + snarkjs), n = 20 | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 3,311.8 ms (IQR 3,235.9-3,354.5) | ~15 min | no |
| Policy verifier: t_verify (presentation checks + Groth16) and t_sign | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | t_verify 1.7 ms (IQR 1.6-1.7); Groth16 alone 1.25 ms; t_sign 5.1 ms (IQR 3.7-6.5) | ~15 min | no |
| MPC-TLS session with the notary | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 345.4 ms (IQR 333.0-380.7); 30.2 MB sent, 3.8 MB received | ~15 min | no |
| Peak memory | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | snarkjs 1,638.6 MB, witness generator 96.9 MB, prover 242.3 MB (medians) | ~15 min | no |
| MPC-TLS preprocessing stalls (tlsn#1173), recovered by retry | `script/measure_offchain.sh` | `measurements/offchain/20260926T190328Z.json` | 3/223 sessions (1.35%); 0 runs gave up | ~15 min | no |
| Contract tests | `script/record_tests.sh` | `measurements/tests/20260926T212837Z.json` | 206 forge tests (Fuzz 5, Invariant 1, Unit 200), 0 failed; invariants 256 runs x depth 128 | ~10 min | no |
| Security-property coverage (contract conditions) | `script/record_tests.sh` | `measurements/tests/20260926T212837Z.json` | 205/205 tests pass, 4/4 invariants hold; every condition has a passing positive and negative test | ~10 min | no |
| Coverage of contracts/src | `script/record_tests.sh` | `measurements/tests/20260926T212837Z.json` | lines 100.0%, statements 100.0%, branches 100.0%, functions 100.0% | ~10 min | no |
| Rust tests | `script/record_tests.sh` | `measurements/tests/20260926T212837Z.json` | 114 passed, 0 failed, 3 ignored; ignored clock-shift tests under libfaketime: 6 passed | ~10 min | no |
| On-chain execution gas per operation | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | Register 182,779, Apply 168,680, Engage 96,593, Settle 90,924, Expire 58,787, Reclaim 23,853, Cancel 21,238 | ~2 min | no |
| Lifecycle gas (Register + Apply + Engage + Settle) | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | execution 538,976; receipts 625,732; 1,753 transaction bytes | ~2 min | no |
| Deployment and bytecode size | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | PPREV 2,124,381 gas, runtime 9,126 B (37.1% of EIP-170); verifier 192,589 gas, 634 B | ~2 min | no |
| Cost decomposition of Register and Apply | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | storage 92.4% and 92.0%; slots initialised 7 and 6; ECDSA marginal 3,574 and 3,594 gas | ~2 min | no |
| ECDSA verifier call | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | frame 4,020 gas against 434 for an accept-all verifier | ~2 min | no |
| Receipts against measured gas (signature-dependent difference) | `script/measure.sh` | `measurements/l1/20260926T194331Z.json` | Register +32, Apply +0, Engage +0, Settle +12 gas | ~2 min | no |
| L1 gas price snapshot (one day of blocks) | `script/l1_price.sh` | `measurements/l1_price/20260926T194005Z.json` | blocks 26,056,487-26,063,686; base fee 0.075715 gwei, priority fee 0.05 gwei, effective 0.133984 gwei (medians) | ~1 min | yes: ETH_MAINNET_RPC_URL |
| ETH/USD (Chainlink, one reading, used for L1 and L2) | `script/l1_price.sh` | `measurements/l1_price/20260926T194005Z.json` | $2,685.42 at block 26,063,686 | ~1 min | yes: ETH_MAINNET_RPC_URL |
| L1 cost per operation (execution gas at the median effective price) | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | Register $0.0658, Apply $0.0607, Engage $0.0348, Settle $0.0327, Expire $0.0212, Reclaim $0.0086, Cancel $0.0076 | ~1 s | no |
| L1 lifecycle and deployment cost | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | execution $0.194; receipts $0.225 (without refunds $0.229); deployment $0.834 | ~1 s | no |
| L1 lifecycle cost at other gas prices | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | 0.1 gwei $0.145, 1 gwei $1.447, 10 gwei $14.474, 30 gwei $43.421 | ~1 s | no |
| Freshness budget, sum of component medians (Section VII-E) | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | local anvil total: 3,333 ms (1.11% of Delta); Base Sepolia total: 4,728 ms (1.58% of Delta) | ~1 s | no |
| On-chain Groth16 verification of phi_R (9 public inputs) | `script/measure_groth16.sh` | `measurements/groth16/20260926T201202Z.json` | 242,098 gas execution; EIP-1108 model 236,350 | ~1 min | no |
| Lifecycle with three predicate verifications on-chain | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | 1,265,270 gas, x2.3475 (assumes phi_A, phi_S verified like phi_R) | ~1 s | no |
| L2 receipt gas per operation (Base Sepolia) | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | Register 208,227, Apply 193,736, Engage 113,137, Settle 110,636, Expire 79,991, Reclaim 40,257, Cancel 37,642 | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
| L2 cost per operation (Base mainnet prices) | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | Register $0.0034, Apply $0.0032, Engage $0.0019, Settle $0.0018, Expire $0.0013, Reclaim $0.0007, Cancel $0.0006 | ~1 s | no |
| L2 lifecycle cost and L1 data share | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | $0.0103, 1,762 bytes; L1 data 0.12% (per operation 0.07-0.22%) | ~1 s | no |
| Inclusion time t_incl on Base Sepolia (Register, n = 10) | `script/measure_l2.sh` | `measurements/l2/20260926T195911Z.json` | 1,409.2 ms (IQR 1,300.8-2,780.1) | ~4 min | yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY |
| L1 against L2 lifecycle cost (receipt gas, same ETH/USD) | `python3 script/derive_summary.py` | `measurements/summary/20260926T201202Z.json` | L1 21.94x L2 | ~1 s | no |
<!-- results:end -->

`script/render_results.py` regenerates this table from the newest records; `--check` tells whether
it is current. Both read the newest record of each kind, so a record written by your own run (for
example by `script/e2e_register.sh` in the quick check) makes `--check` report the table as out of
date. Suggested order after setup: `record_tests.sh`, `measure_offchain.sh`, `measure.sh`,
`l1_price.sh`, `measure_groth16.sh`, `measure_l2.sh`, then `derive_summary.py` (commit each record
before the next script, which refuses a dirty tree). `measure_groth16.sh` and `measure_l2.sh` read
the newest L1 record; `measure_l2.sh` takes ETH/USD from the newest price record.

### 5.3 Integrated on-chain verification baseline (October 2026)

`contracts/src/baseline/` holds a measurement baseline, not part of PPREV: for Register, Apply, and
Settle, a contract that checks the phase's submission on-chain the way PPREV's policy verifier
checks it off-chain. It verifies the notary's signature over the attestation header (Ethereum-style
secp256k1 over Keccak-256, an option of tlsn that the prover requests), recomputes the Merkle root
over every body field, maps each transcript commitment to its role, opens the request line and the
response structure, checks the connection data, t_att, and freshness, derives the predicate's
public inputs, and verifies its Groth16 proof. The server identity (certificate chain and DNS name)
is not checked on-chain: an identity attestor signs it off-chain over the signed header. The notary
stays trusted for the authenticity of the TLS session.

The fixtures (`contracts/test/baseline/fixtures/`) come from real notarised sessions with the mock
registry (`offchain/crates/pprev-prover/tests/e1_attestation.rs`). Their identity signatures are
test-key signatures, issued by the fixture generator after it verified the session's presentation
(certificate chain against the mock registry's CA, DNS name): not an end-to-end identity service.
The 39 forge tests accept each real submission and reject every altered part.

```
script/measure_e1.sh
```

| Phase | Execution gas | Groth16 call | Rest | Calldata |
|---|---:|---:|---:|---:|
| Register | 304,703 | 242,098 | 62,605 | 2,948 B |
| Apply | 280,088 | 228,804 | 51,284 | 2,820 B |
| Settle | 321,696 | 255,392 | 66,304 | 3,268 B |

Record: `measurements/e1/20261021T133032Z.json` (commit `daa24d3`, clean tree; the sources,
fixtures, compiled artifacts, and verifiers are hashed before and after the run, and each
baseline's runtime code before and after its transaction). Each verification is a standalone view
call: it handles no nonce, state, or caller. The record's lifecycle figures are a compositional
estimate, not a measurement: added to the 538,976-gas lifecycle of Section 5.2, the three
verifications give 1,445,463 gas (x2.68); without PPREV's own signature checks (their ECDSA
marginals), 1,434,713 (x2.66). Calldata, storage, and deployment differences are not modelled. The
contract coverage figure of Section 5.2 covers the September `contracts/src`; the baseline contracts
are tested but not part of that figure.

### 5.4 Controlled link experiment (October 2026)

`script/measure_wan.sh` runs MPC-TLS sessions (the Register request of a fixture owner) with an
emulated delay and bandwidth on one link at a time, prover-notary or prover-registry, through the
proxy of `netem.rs`. It delays and paces application bytes; TCP handshakes, acknowledgements,
congestion control, loss, and jitter are not emulated, so it is not a wide-area network emulation.
Each grid point first calibrates the proxy (one-byte round trips, a bulk transfer) and records the
measured round-trip time and goodput next to the target.

Record: `measurements/wan/20261021T131426Z.json`, 14 points x 10 sessions on the M2 on AC power,
with the SHA-256 of 100 source and binary files at start and end (unchanged). All 140 sessions
succeeded in the end; one (registry link, 0 ms) needed a second attempt after a preprocessing stall
of 60 s, so its process time is 60.4 s while its last attempt took 0.36 s. Medians of the process
time:

| Link | Measured RTT | Bandwidth | Process time, median |
|---|---:|---:|---:|
| direct | - | - | 0.31 s |
| notary | 34.2 ms | unlimited | 2.17 s |
| notary | 104.3 ms | unlimited | 5.76 s |
| notary | 204.5 ms | unlimited | 10.80 s |
| notary | 34.1 ms | 20 Mbit/s | 14.24 s |
| registry | 104.2 ms | unlimited | 1.03 s |

The record also gives the last attempt's MPC-TLS time, quartiles, and the other points. Only the
notarisation is timed: no proof, policy verifier, or transaction.

## 6. Measurement notes

- **Machine preparation** for timings: AC power, other applications closed, and sleep disabled for
  the duration (`caffeinate -dims` in a separate terminal). Records note the power source. Run from
  a directory outside iCloud Drive; the scripts stop if an input file is evicted (dataless).
- **Deterministic**: gas per operation, deployment gas, bytecode sizes, calldata sizes, the storage
  decomposition, constraint counts, and on-chain Groth16 gas. Receipt gas of the three operations
  that carry a notary signature varies by a few gas with the signature (calldata zero bytes at 4
  against 16 gas, and the verifier's recovery-parameter check, up to 20 gas); the records reconcile
  it. MPC-TLS traffic varies by well under 1 KB per session.
- **Not deterministic**: all times (the off-chain record gives minimum, quartiles, and maximum of
  every timing over 20 runs), the occurrence of preprocessing stalls, the inclusion time on Base
  Sepolia, and every price. Gas prices and ETH/USD are snapshots: a new run of `script/l1_price.sh`
  or `script/measure_l2.sh` reads other blocks and gives other dollar figures. Base Sepolia fees
  reflect testnet demand; the L2 campaign takes only gas and bytes from it and prices them with one
  Base mainnet block.
- **Scope of t_incl**: `script/e2e_register.sh` and `script/measure_offchain.sh` include on a local
  anvil node; the public-chain figure is the Base Sepolia one of `script/measure_l2.sh`, which is
  the time from sending a transaction until the including block can be read (Base serves
  preconfirmed receipts earlier; the record keeps both times).
- **Gas schedule**: gas figures follow the Osaka (Fusaka) schedule; every script pins anvil to it.
  The Solidity compiler targets cancun. The price record's own dollar fields were computed from an
  earlier L1 record taken on anvil's default fork at the time (Bpo1, identical gas values), which is
  no longer in the repository; the summary record recomputes every dollar figure from the Osaka L1
  record. The price record remains the source of the fee samples and of ETH/USD.
- **Off-chain record and the fork**: `measure_offchain.sh` ran before the pin, on anvil's default
  fork; its times do not depend on the fork, since only the local t_incl involves the chain.

## 7. Known issues

- **Source and calendar assumptions.** The registry is a synthetic fixed-layout source, not an
  adapter validated against an authenticated government portal; whether a real portal serves a
  fixed-layout response, or needs parsing inside the circuit, is untested. The tenancy route is
  available to any logged-in fixture account: phi_S binds the notation's property and tenant, and
  the contract binds the submitting wallet, but nothing proves that the logged-in source account is
  the landlord. The request target reveals the notation identifier to the policy verifier.
  `utcOffsetSecs` is a fixed policy offset; a source that observes daylight saving needs an explicit
  calendar rule. A date-only notation cannot distinguish a notation entered earlier on the
  engagement day from one entered after engagement.
- **Predicate domains.** The income and tenancy sources must name the applicant with the same
  identifier; the fixtures use one `ACC-...` namespace. phi_A compares 20 zero-padded decimal digits
  directly with three times `txData.amount`, in the unit that the policy names (`amountUnit`, wei
  here), with no currency conversion. The policy verifier rejects `txData.amount >= 2^96` and a c_B
  outside the BN254 scalar field. These are prototype domain bounds, not claims about every
  real-world income format or identifier system.
- **Not exercised end to end.** Settle after `expiresAt` (`LockWindowElapsed`) is covered by the
  contract tests only: on a local chain the notary's clock cannot be moved past the lock window, so
  a late submission fails the freshness check first. Expire, Reclaim, and Cancel are covered by the
  contract tests and the September gas campaign.
- **TLSNotary preprocessing stall.** tlsn v0.1.0-alpha.15 intermittently deadlocks in MPC-TLS
  preprocessing (upstream pull request [tlsnotary/tlsn#1173](https://github.com/tlsnotary/tlsn/pull/1173)).
  The prover bounds preprocessing to 30 s and retries with a new session up to three times; the
  notary cuts sessions above its preprocessing (30 s) or session (120 s) bound. Measured rate in the
  committed off-chain record: 3 of 223 sessions (1.35%), all recovered by the first retry. Failed
  attempts are excluded from every timing and reported separately. A notary that closes the session
  before preprocessing completes is retried in the same way, whichever side observes the closure
  first: the driver of the session ending, or preprocessing failing with an end of stream, a write
  to a closed connection, or tlsn's internal error of an OT setup whose peer went away (taken as a
  closure only if the session driver shows one within 2 s). Rejections, configuration errors, a
  failed driver, and anything after preprocessing are final (`measurements/retry-fix-20261021/`
  holds the failing and passing runs). During such deliberate cuts in the tests, worker threads of
  the MPC dependencies print `Task polled after completion` panics; the tests pass, and the
  prototype makes no claim of production fault tolerance.
- **Dependency on tlsn's serialisation layout.** tlsn v0.1.0-alpha.15 keeps the transcript
  commitments of an attestation body crate-private; `pprev_notary::attested_commitments` reads them
  from the serialised body of a verified attestation. The golden test
  `g3_attestation_body_layout_matches_golden` fails if a tlsn update changes that layout.
- **GPL-licensed verifiers.** `circuits/setup/Groth16Verifier.sol` and
  `circuits/setup/phi_{a,s}/Groth16Verifier.sol` are the verifiers as snarkjs exports them and keep
  snarkjs' GPL-3.0 header; the rest of the repository is MIT. The protocol never deploys them; they
  are compiled only for the on-chain comparison.
- **The exported Groth16 verifier fails silently on low gas.** When a precompile call runs out of
  gas, snarkjs' verifier returns `false` instead of reverting. A gas estimate therefore settles on a
  limit at which the pairing check fails, and the transaction succeeds while verifying nothing.
  `script/measure_groth16.sh` sends the verification with an explicit gas limit and checks in the
  call trace that it returned true. PPREV's own calls revert on a rejected signature, so estimation
  is sound for them.
- **Proving keys not in the repository.** The proving keys (65 MB for phi_R, 35 MB and 53 MB for
  phi_A and phi_S) are produced by the setup scripts; a new setup changes the committed verification
  keys and sample proofs (Section 3).
- **Python CA bundle.** Python builds without a CA bundle of their own (python.org builds on macOS)
  fall back to `/etc/ssl/cert.pem` in `script/lib/l2_send.py`; certificate verification stays on.

## 8. Repository layout

```
contracts/          Foundry project: PPREV, ECDSA notary verifier, tests (test/), deployment and
                    measurement scripts (script/: Deploy, Lifecycle, MeasureGas, L2Campaign, GenVectors,
                    E1Measure); src/baseline/ and test/baseline/ hold the measurement baseline of
                    Section 5.3
circuits/           phi_R, phi_A, phi_S in circom (src/; lib/ holds byte, decimal, and calendar
                    templates); setup outputs (setup/, setup/phi_a/, setup/phi_s/): verification keys,
                    exported verifiers, sample proofs, transcripts; build/ is generated
mock-registry/      local HTTPS title, income, and tenancy registry with fixture records
offchain/crates/    pprev-types (response layouts, policy bundle, circuit parameters and public
                    inputs, calendar days, EIP-712 statements),
                    pprev-notary (MPC-TLS notary, presentation checks, Groth16 verification, policy
                    verifier for Register, Apply, and Settle, statement signature, nonce record,
                    mock notary; binary pprev-notary),
                    pprev-prover (login, MPC-TLS session, presentations, witnesses and proofs of the
                    three predicates, Register/Apply/Engage/Settle clients, attestation encoding
                    for the baseline, link emulation; binaries pprev-prover, probe-portal,
                    netem-proxy, netem-calibrate)
policies/           policy bundle rental-v1.json and the response layouts title-v1, income-v1,
                    tenancy-v1
test-vectors/       EIP-712, C_tx, and notary signature vectors shared by Solidity and Rust
script/             circuit build and setup, end-to-end Register and lifecycle, measurement scripts,
                    security-property coverage, results table, repository gate; lib/ holds the
                    shared parts
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
| $\mathsf{PolicyRegistry}$ | `policyRegistry`, struct `Policy`; off-chain, the bundle `policies/rental-v1.json` (`pprev_types::PolicyBundle`) |
| $\mathsf{reqEscrow}$, $\mathsf{minCollateral}$, $\mathsf{maxCollateral}$ | `reqEscrow`, `minCollateral`, `maxCollateral` |
| $\eta_R$, $\eta_A$, $\eta_S$ | `etaR`, `etaA`, `etaS` (field `eta` in the signed statements) |
| $t_{\mathsf{att},R}$, $t_{\mathsf{att},A}$, $t_{\mathsf{att},S}$ | `tAttR`, `tAttA`, `tAttS` (field `tAtt` in the signed statements) |
| $\sigma_R$, $\sigma_A$, $\sigma_S$ | `sigmaR`, `sigmaA`, `sigmaS` |
| $a_\psi$ ($a_P$, $a_B$) | field `submitter` in the signed statements, fixed to `msg.sender` |
| $c_B$ | `cB` |
| $H_c$ | circomlib's two-input Poseidon: `Poseidon(2)` in `phi_a.circom` and `phi_s.circom`, `pprev_notary::mock::counterparty_commitment` in Rust |
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
| $\tau_{\mathsf{lock}}$ | `TAU_LOCK` (seconds); off-chain, the notary's `--tau-lock` |
| engagement day | `pprev_types::calendar::engagement_day`: Y·10000 + M·100 + D of `expiresAt - TAU_LOCK` in the policy's time zone |
| $\mathsf{maxExpirations}$ | `MAX_EXPIRATIONS` |
| $\rho$ | `RHO` (basis points) |
| $t_{\mathsf{att},\psi}$ (source) | notary clock, attestation extension `pprev.t_att` |
| $\mathsf{prov}_\psi$ | TLSNotary `Attestation`, shown to the policy verifier as a `Presentation` |
| $\mathsf{record}_R$ fields committed | `account`, `owners`, `propertyId` byte ranges (`pprev_types::ResponseRanges`) |
| $\mathsf{record}_A$, $\mathsf{record}_S$ fields committed | the account and every record field: `monthlyIncome`; `propertyId`, `tenant`, `recordDate` (`pprev_types::RecordRanges`) |
| $\phi_R$, $\phi_A$, $\phi_S$ | templates `PhiR`, `PhiA`, `PhiS` in `circuits/src/phi_r.circom`, `phi_a.circom`, `phi_s.circom` |
| $\phi_A$, $\phi_S$ checked natively | `pprev_notary::mock::MockNotary::sign_apply`, `sign_settle` (unit tests only) |
| $\pi_\psi$ | Groth16 proof (snarkjs `proof.json`), `pprev_notary::Groth16Proof` |
| binding of $\pi_\psi$ to $x_\psi$ | public input `bind` = EIP-712 digest of $x_\psi$ mod $r_{\mathrm{BN254}}$ |
| $\mathsf{sk}_{\mathsf{notary}}$ | `pprev_notary::StatementKey` |
| nonces the notary has signed | `pprev_notary::NonceStore` (append-only file, shared by all phases) |
| policy verifier | `pprev_notary::PolicyVerifier` (Register in `register.rs`, Apply and Settle in `phases.rs`) |

Undeliverable payouts: every payout made by an algorithm forwards `PAYOUT_GAS` (30,000) gas. If the
recipient's call fails, the contract credits the amount to `credit[recipient]` and emits
`PayoutCredited`; the recipient collects it with `withdraw()`, so a recipient that rejects payments
cannot block the algorithm that pays it.
