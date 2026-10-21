#!/usr/bin/env bash
# Builds the phi_A and phi_S circuits: generates their main components from the policy bundle and
# its layouts, compiles them, and records their sizes in circuits/build/phi_{a,s}.info.json.
# The phi_R circuit (script/circuits_build.sh) is not touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="${ROOT:?}/circuits"
BUILD="${CIRCUITS:?}/build"
POLICY="${ROOT:?}/policies/rental-v1.json"

# The witness generator and snarkjs run under the Node.js version that produced the setup.
NODE_VERSION="$(tr -d '[:space:]' <"${ROOT:?}/.nvmrc")"
[ "$(node --version)" = "${NODE_VERSION}" ] || {
    echo "node $(node --version) is not ${NODE_VERSION} (.nvmrc); run 'nvm use' or put that version first on PATH" >&2
    exit 1
}

cd "${CIRCUITS:?}"
[ -d node_modules ] || npm ci --no-audit --no-fund
mkdir -p "${BUILD:?}"

# build <phase> <predicate> <circuit>
build() {
    local phase="$1" predicate="$2" circuit="$3"
    cargo run -q -p pprev-types --bin gen-phase-circuit-main -- \
        "${phase:?}" "${POLICY:?}" "${ROOT:?}" "src/${circuit:?}.circom"
    circom "src/${circuit:?}.circom" --r1cs --wasm --sym --O2 -l node_modules -o "${BUILD:?}" \
        | sed 's/\x1b\[[0-9;]*m//g' | tee "${BUILD:?}/${predicate:?}.circom.log"
    npx snarkjs r1cs info "${BUILD:?}/${circuit:?}.r1cs" | sed 's/\x1b\[[0-9;]*m//g' \
        | tee "${BUILD:?}/${predicate:?}.r1cs-info.log"
    python3 - "${BUILD:?}" "${predicate:?}" "${circuit:?}" <<'PY'
import json, re, subprocess, sys
build, predicate, circuit = sys.argv[1:]
circom = open(f"{build}/{predicate}.circom.log").read()
info = open(f"{build}/{predicate}.r1cs-info.log").read()

def num(pattern, text):
    m = re.search(pattern, text)
    if not m:
        sys.exit(f"missing {pattern!r} in the build output")
    return int(m.group(1))

def version(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]

out = {
    "circuit": circuit,
    "optimization": "O2",
    "constraints": num(r"# of Constraints:\s*(\d+)", info),
    "nonLinearConstraints": num(r"non-linear constraints:\s*(\d+)", circom),
    "linearConstraints": num(r"(?<!non-)linear constraints:\s*(\d+)", circom),
    "wires": num(r"# of Wires:\s*(\d+)", info),
    "privateInputs": num(r"# of Private Inputs:\s*(\d+)", info),
    "publicInputs": num(r"# of Public Inputs:\s*(\d+)", info),
    "outputs": num(r"# of Outputs:\s*(\d+)", info),
    "tools": {
        "circom": version(["circom", "--version"]),
        "snarkjs": json.load(open("node_modules/snarkjs/package.json"))["version"],
        "circomlib": json.load(open("node_modules/circomlib/package.json"))["version"],
    },
}
json.dump(out, open(f"{build}/{predicate}.info.json", "w"), indent=2)
print(json.dumps(out, indent=2))
PY
}

build apply phi_a main_income_v1
build settle phi_s main_tenancy_v1
