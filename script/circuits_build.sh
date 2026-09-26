#!/usr/bin/env bash
# Builds the phi_R circuit: generates the main component from the layout, compiles it, and records
# its size in circuits/build/phi_r.info.json.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="${ROOT:?}/circuits"
BUILD="${CIRCUITS:?}/build"
LAYOUT="${ROOT:?}/policies/layouts/title-v1.json"

cd "${CIRCUITS:?}"
[ -d node_modules ] || npm ci --no-audit --no-fund

cargo run -q -p pprev-types --bin gen-circuit-main -- "${LAYOUT:?}" src/main_title_v1.circom

mkdir -p "${BUILD:?}"
circom src/main_title_v1.circom --r1cs --wasm --sym --O2 -l node_modules -o "${BUILD:?}" \
    | sed 's/\x1b\[[0-9;]*m//g' | tee "${BUILD:?}/circom.log"
npx snarkjs r1cs info "${BUILD:?}/main_title_v1.r1cs" | sed 's/\x1b\[[0-9;]*m//g' | tee "${BUILD:?}/r1cs-info.log"

python3 - "${BUILD:?}" <<'PY'
import json, re, subprocess, sys
build = sys.argv[1]
circom = open(f"{build}/circom.log").read()
info = open(f"{build}/r1cs-info.log").read()

def num(pattern, text):
    m = re.search(pattern, text)
    if not m:
        sys.exit(f"missing {pattern!r} in the build output")
    return int(m.group(1))

def version(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]

out = {
    "circuit": "main_title_v1",
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
json.dump(out, open(f"{build}/phi_r.info.json", "w"), indent=2)
print(json.dumps(out, indent=2))
PY
