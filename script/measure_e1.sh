#!/usr/bin/env bash
# Integrated on-chain verification baseline: the execution gas of checking each attested phase's
# submission (Register, Apply, Settle) on-chain the way PPREV's policy verifier checks it off-chain,
# except for the server identity, which an off-chain attestor signs
# (contracts/src/baseline/Integrated*Verifier.sol). The notary remains trusted for the authenticity
# of the TLS session; PPREV itself is unchanged.
#
# For each phase: the exported Groth16 verifier of its predicate (circuits/setup/.../Groth16Verifier.sol,
# checked against its setup.json) and the phase's baseline are deployed with the configuration of
# the phase's fixture (contracts/test/baseline/fixtures/<phase>.json, a real notarised session, see
# offchain/crates/pprev-prover/tests/e1_attestation.rs) on an anvil whose clock starts at the
# fixture's t_att. The baseline's runtime code is placed at the fixture's contract address, which its
# EIP-712 domain names (immutables are part of the runtime code). Then eth_call verify(submission)
# must return true, it must revert with BadProof with the submitter changed, and the verification is
# sent as a transaction with an explicit gas limit whose call trace must return true. Execution gas
# is receipt gas minus 21,000 and calldata gas (the EIP-7623 floor is checked not to apply); the
# predicate verifier's share is the gas of its call in the trace.
#
# The lifecycle comparison is a compositional estimate, not a measurement: verify() is a view that
# executes no nonce, state, or caller handling, and no integrated lifecycle contract is measured.
#   additive     the newest L1 record's lifecycle plus the three integrated verifications, keeping
#                PPREV's signature checks;
#   replacement  as additive, minus each attested operation's ECDSA marginal from the same record.
# Calldata, storage, and deployment differences are not modelled.
#
# The identity signatures in the fixtures are test-key signatures, issued by the fixture generator
# after it verified the session's presentation against the mock registry's CA and DNS name.
#
# The inputs (sources, fixtures, configuration, compiled artifacts, verifiers) are hashed before and
# after the run, which fails on any difference; each baseline's runtime code is hashed after it is
# placed and again after its transaction.
#
# Output: measurements/e1/<run>.json. Refuses a dirty working tree (PPREV_ALLOW_DIRTY=1 with
# PPREV_MEASUREMENTS_DIR for a trial run).
set -euo pipefail

LOG_TAG=e1
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

OUT_DIR="${MEASUREMENTS_DIR:?}/e1"
PORTS="${ANVIL_PORT:?}"
GAS_LIMIT=3000000
PHASES="register apply settle"
BAD_PROOF=0x7ca55c77 # BadProof()

for tool in anvil forge cast jq lsof python3 git; do
    command -v "${tool}" >/dev/null || die "missing tool: ${tool}"
done
require_clean_tree
check_ports_free
for setup in "${CIRCUITS}/setup" "${CIRCUITS}/setup/phi_a" "${CIRCUITS}/setup/phi_s"; do
    [ "$(shasum -a 256 "${setup}/Groth16Verifier.sol" | cut -d' ' -f1)" = "$(jq -r .solidityVerifierSha256 "${setup}/setup.json")" ] \
        || die "${setup#"${ROOT}/"}/Groth16Verifier.sol does not match its setup.json"
done
L1_RECORD="${PPREV_L1_RECORD:-$(find "${ROOT}/measurements/l1" -name '*.json' 2>/dev/null | sort | tail -n 1)}"
[ -f "${L1_RECORD}" ] || die "no L1 record in measurements/l1"
init_run e1
mkdir -p "${OUT_DIR:?}" "${ROOT}/target/measure"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
(cd "${ROOT}/contracts" && forge build -q) || die "compiling the contracts failed"

input_hashes() {
    (cd "${ROOT}" && shasum -a 256 \
        script/measure_e1.sh script/lib/common.sh contracts/foundry.toml contracts/script/E1Measure.s.sol \
        contracts/src/baseline/*.sol contracts/src/PPREVEncoding.sol contracts/src/PPREVTypes.sol \
        contracts/test/baseline/E1Fixtures.sol contracts/test/baseline/fixtures/*.json \
        circuits/setup/setup.json circuits/setup/phi_a/setup.json circuits/setup/phi_s/setup.json \
        circuits/setup/Groth16Verifier.sol circuits/setup/phi_a/Groth16Verifier.sol \
        circuits/setup/phi_s/Groth16Verifier.sol \
        contracts/out/Integrated*Verifier.sol/Integrated*Verifier.json \
        contracts/out/E1Measure.s.sol/E1Measure.json contracts/out/Groth16Verifier.sol/Groth16Verifier.json \
        contracts/out/phi_a/Groth16Verifier.sol/Groth16Verifier.json \
        contracts/out/phi_s/Groth16Verifier.sol/Groth16Verifier.json "${L1_RECORD#"${ROOT}/"}") \
        || die "hashing the inputs failed"
}
input_hashes >"${WORK}/inputs-before.txt"

for phase in ${PHASES}; do
    fixture="${ROOT}/contracts/test/baseline/fixtures/${phase}.json"
    dir="${WORK}/${phase}"
    mkdir -p "${dir}"
    t_att="$(jq -r .tAtt "${fixture}")"
    baseline="$(jq -r .baseline "${fixture}")"
    start anvil "${dir}/anvil.log" anvil --port "${ANVIL_PORT}" --chain-id "$(jq -r .chainId "${fixture}")" \
        --hardfork "${HARDFORK_PIN}" --timestamp "$((t_att + 5))" --config-out "${dir}/anvil.json"
    wait_port "${ANVIL_PORT}" anvil "${PIDS[${#PIDS[@]} - 1]}"
    key="$(jq -r '.private_keys[0]' "${dir}/anvil.json")"
    cast rpc anvil_nodeInfo --rpc-url "${RPC}" | jq -r .hardFork >"${dir}/hardfork.txt"

    log "${phase}: deploying"
    (cd "${ROOT}/contracts" && DEPLOYER_KEY="${key}" E1_PHASE="${phase}" \
        forge script script/E1Measure.s.sol --rpc-url "${RPC}" --broadcast -q) >"${dir}/deploy.log" 2>&1 \
        || die "${phase}: deployment failed"
    addresses="$(cat "${ROOT}/target/measure/e1-${phase}-addresses.txt")"
    deployed="${addresses%% *}"
    groth16="${addresses##* }"
    echo "${groth16}" >"${dir}/groth16.txt"
    cast rpc anvil_setCode "${baseline}" "$(cast code "${deployed}" --rpc-url "${RPC}")" --rpc-url "${RPC}" >/dev/null
    cast code "${baseline}" --rpc-url "${RPC}" | cast keccak >"${dir}/runtime-before.txt"
    cp "${ROOT}/target/measure/e1-${phase}-verify-calldata.txt" "${dir}/verify-input.txt"
    cp "${ROOT}/target/measure/e1-${phase}-tampered-calldata.txt" "${dir}/tampered-input.txt"

    valid="$(cast call "${baseline}" "$(cat "${dir}/verify-input.txt")" --rpc-url "${RPC}")"
    [ "${valid}" = 0x0000000000000000000000000000000000000000000000000000000000000001 ] \
        || die "${phase}: eth_call verify did not return true: ${valid}"
    if cast call "${baseline}" "$(cat "${dir}/tampered-input.txt")" --rpc-url "${RPC}" >"${dir}/tampered.out" 2>&1; then
        die "${phase}: a changed statement was accepted"
    fi
    # The rejection must be the baseline's BadProof revert, not a transport or other failure.
    grep -q "${BAD_PROOF}" "${dir}/tampered.out" \
        || die "${phase}: the changed statement was not rejected with BadProof: $(cat "${dir}/tampered.out")"
    cast send "${baseline}" "$(cat "${dir}/verify-input.txt")" --gas-limit "${GAS_LIMIT}" --rpc-url "${RPC}" \
        --private-key "${key}" --json >"${dir}/verify-send.json"
    tx="$(jq -r .transactionHash "${dir}/verify-send.json")"
    cast receipt "${tx}" --json --rpc-url "${RPC}" >"${dir}/verify-receipt.json"
    cast rpc debug_traceTransaction "${tx}" '{"tracer":"callTracer"}' --rpc-url "${RPC}" >"${dir}/verify-trace.json"
    [ "$(jq -r .output "${dir}/verify-trace.json")" = 0x0000000000000000000000000000000000000000000000000000000000000001 ] \
        || die "${phase}: the verification transaction did not return true"
    cast code "${baseline}" --rpc-url "${RPC}" | cast keccak >"${dir}/runtime-after.txt"
    cmp -s "${dir}/runtime-before.txt" "${dir}/runtime-after.txt" || die "${phase}: the baseline's code changed"
    stop_all
done
input_hashes >"${WORK}/inputs-after.txt"
cmp -s "${WORK}/inputs-before.txt" "${WORK}/inputs-after.txt" \
    || die "inputs changed during the run: $(diff "${WORK}/inputs-before.txt" "${WORK}/inputs-after.txt" | tr '\n' ' ')"

python3 - "${WORK}" "${OUT}" "${ROOT}" "${L1_RECORD}" "${GAS_LIMIT}" "$(provenance_json)" <<'PY'
import hashlib, json, sys

work, out, root, l1_path, gas_limit, prov = sys.argv[1:7]
prov = json.loads(prov)
artifacts = {
    "register": "IntegratedRegisterVerifier",
    "apply": "IntegratedApplyVerifier",
    "settle": "IntegratedSettleVerifier",
}
ecdsa_ops = {"register": "Register", "apply": "Apply", "settle": "Settle"}
l1 = json.load(open(l1_path))
phases = {}
for phase, contract in artifacts.items():
    d = f"{work}/{phase}"
    data = bytes.fromhex(open(f"{d}/verify-input.txt").read().strip()[2:])
    zeros = sum(1 for b in data if b == 0)
    standard = 4 * zeros + 16 * (len(data) - zeros)
    floor = 21000 + 10 * (zeros + 4 * (len(data) - zeros))
    receipt = json.load(open(f"{d}/verify-receipt.json"))
    assert int(receipt["status"], 16) == 1
    gas_used = int(receipt["gasUsed"], 16)
    assert gas_used > floor, f"{phase}: the EIP-7623 calldata floor applies"
    execution = gas_used - 21000 - standard
    groth16 = open(f"{d}/groth16.txt").read().strip().lower()
    trace = json.load(open(f"{d}/verify-trace.json"))
    calls = [c for c in trace.get("calls", []) if c["to"].lower() == groth16]
    assert len(calls) == 1, f"{phase}: one call to the predicate verifier"
    predicate = int(calls[0]["gasUsed"], 16)
    fixture = f"{root}/contracts/test/baseline/fixtures/{phase}.json"
    art = json.load(open(f"{root}/contracts/out/{contract}.sol/{contract}.json"))
    phases[phase] = {
        "fixture": {"path": fixture[len(root) + 1:],
                    "sha256": hashlib.sha256(open(fixture, "rb").read()).hexdigest()},
        "anvilHardfork": open(f"{d}/hardfork.txt").read().strip(),
        "checks": {"validSubmissionAccepted": True, "changedSubmitterRejectedWithBadProof": True,
                   "transactionReturnedTrue": True, "transactionGasLimit": int(gas_limit)},
        "receiptGas": gas_used, "intrinsicGas": 21000, "calldataBytes": len(data),
        "calldataGas": standard, "eip7623FloorGas": floor, "executionGas": execution,
        "predicateVerifierCallGas": predicate,
        "executionGasExcludingPredicateCall": execution - predicate,
        "baselineRuntimeBytes": len(bytes.fromhex(art["deployedBytecode"]["object"][2:])),
        "placedRuntimeCodeKeccak": open(f"{d}/runtime-before.txt").read().strip(),
        "ecdsaMarginalInL1Record": l1["decomposition"][ecdsa_ops[phase]]["components"]["ecdsaMarginal"],
    }
lifecycle = l1["lifecycle"]["executionGas"]
integrated = sum(p["executionGas"] for p in phases.values())
ecdsa = sum(p["ecdsaMarginalInL1Record"] for p in phases.values())
result = {
    "runId": out.rsplit("/", 1)[1].removesuffix(".json"),
    "commit": prov["commit"], "workingTreeDirty": prov["workingTreeDirty"],
    "machine": prov["machine"], "tools": prov["tools"],
    "scope": ("Each attested phase's submission checked on-chain except the server identity (certificate "
              "chain and DNS name), which an off-chain attestor signs over the signed attestation header; "
              "the notary remains trusted for TLS session authenticity. Measurement baseline, not part of PPREV."),
    "identitySignatures": ("test-key signatures issued by the fixture generator after verifying the "
                           "presentation (certificate chain against the mock registry's CA, DNS name); "
                           "not an end-to-end identity service"),
    "inputs": {line.split()[1]: line.split()[0] for line in open(f"{work}/inputs-before.txt")},
    "inputsUnchangedDuringRun": True,
    "phases": phases,
    "lifecycleCompositionalEstimate": {
        "note": ("estimate, not a measurement: verify() is a view without nonce, state, or caller "
                 "handling; no integrated lifecycle contract was executed"),
        "l1Record": l1_path[len(root) + 1:],
        "pprevExecutionGas": lifecycle,
        "integratedVerificationExecutionGas": integrated,
        "additive": {"executionGas": lifecycle + integrated,
                     "factor": round((lifecycle + integrated) / lifecycle, 6),
                     "model": "PPREV lifecycle plus the three integrated verifications; signature checks kept"},
        "replacement": {"executionGas": lifecycle + integrated - ecdsa,
                        "factor": round((lifecycle + integrated - ecdsa) / lifecycle, 6),
                        "model": "additive minus the ECDSA marginal of each attested operation (L1 record)"},
        "notModelled": "calldata, storage, and deployment differences of an integrated contract",
    },
}
json.dump(result, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(json.dumps({k: {x: v[x] for x in ("executionGas", "predicateVerifierCallGas", "executionGasExcludingPredicateCall", "calldataBytes")} for k, v in phases.items()}, indent=2))
print(json.dumps(result["lifecycleCompositionalEstimate"], indent=2))
PY
log "record: ${OUT#"${ROOT}/"}"
