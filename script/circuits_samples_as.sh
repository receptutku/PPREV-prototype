#!/usr/bin/env bash
# One sample proof per phase predicate from the keys of script/circuits_setup_as.sh, and the Solidity
# verifiers as snarkjs exports them. The samples prove the apply and settle statements of
# test-vectors/eip712.json (c_B replaced by a real commitment) for fixture records; see
# offchain/crates/pprev-prover/src/bin/gen-phase-sample.rs.
#
# Outputs, for p in phi_a, phi_s:
#   circuits/setup/<p>/sample/{input,proof,public}.json
#   circuits/setup/<p>/Groth16Verifier.sol
#   circuits/setup/<p>/setup.json   gains "sample" and "solidityVerifierSha256"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="${ROOT:?}/circuits"
BUILD="${CIRCUITS:?}/build"
SNARKJS="${CIRCUITS:?}/node_modules/.bin/snarkjs"

NODE_VERSION="$(tr -d '[:space:]' <"${ROOT:?}/.nvmrc")"
[ "$(node --version)" = "${NODE_VERSION}" ] || {
    echo "node $(node --version) is not ${NODE_VERSION} (.nvmrc); run 'nvm use' or put that version first on PATH" >&2
    exit 1
}
strip_colors() { sed 's/\x1b\[[0-9;]*m//g'; }

# sample <phase> <predicate> <circuit>
sample() {
    local phase="$1" predicate="$2" circuit="$3"
    local out="${CIRCUITS:?}/setup/${predicate:?}"
    local work="${BUILD:?}/setup-${predicate:?}"
    local zkey="${BUILD:?}/${predicate:?}.zkey"
    mkdir -p "${out:?}/sample" "${work:?}"
    [ "$(shasum -a 256 "${zkey:?}" | cut -d' ' -f1)" = "$(jq -r .zkeySha256 "${out:?}/setup.json")" ] \
        || { echo "${predicate}.zkey does not match its setup.json" >&2; exit 1; }

    cargo run -q -p pprev-prover --bin gen-phase-sample -- "${phase:?}" \
        "${ROOT:?}/policies/rental-v1.json" "${ROOT:?}" "${ROOT:?}/test-vectors/eip712.json" \
        "${out:?}/sample/input.json"
    node "${BUILD:?}/${circuit:?}_js/generate_witness.js" "${BUILD:?}/${circuit:?}_js/${circuit:?}.wasm" \
        "${out:?}/sample/input.json" "${work:?}/sample.wtns"
    "${SNARKJS:?}" groth16 prove "${zkey:?}" "${work:?}/sample.wtns" \
        "${out:?}/sample/proof.json" "${out:?}/sample/public.json"
    "${SNARKJS:?}" groth16 verify "${out:?}/verification_key.json" "${out:?}/sample/public.json" \
        "${out:?}/sample/proof.json" | strip_colors | tee "${work:?}/sample-verify.log"
    grep -q "OK!" "${work:?}/sample-verify.log"
    "${SNARKJS:?}" zkey export solidityverifier "${zkey:?}" "${out:?}/Groth16Verifier.sol"

    local tmp
    tmp="$(mktemp)"
    jq --arg sol "$(shasum -a 256 "${out:?}/Groth16Verifier.sol" | cut -d' ' -f1)" \
        --arg statement "${phase} message of test-vectors/eip712.json, c_B = H_c(ACC-000000000003, fixed salt)" \
        '. + {solidityVerifierSha256: $sol, sample: {statement: $statement, snarkjsVerify: "OK!"}}' \
        "${out:?}/setup.json" >"${tmp:?}"
    mv "${tmp:?}" "${out:?}/setup.json"
}

sample apply phi_a main_income_v1
sample settle phi_s main_tenancy_v1
