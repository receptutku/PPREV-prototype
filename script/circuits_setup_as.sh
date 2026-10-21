#!/usr/bin/env bash
# Groth16 setup for phi_A and phi_S, local to this prototype.
#
# Phase 1 reuses the PSE perpetual powers of tau file of phi_R (ppot_0080_17.ptau, up to 2^17
# constraints) from the cache that script/circuits_setup.sh filled. The file is checked against its
# pinned SHA-256; `snarkjs powersoftau verify` is not repeated here, its result is the one that
# circuits/setup/setup.json records for the same file. Each circuit must fit 2^17 constraints.
#
# Phase 2 is local and single-party, as for phi_R: `groth16 setup`, two contributions with
# independent entropy from /dev/urandom, and a beacon (PPREV_BEACON with PPREV_BEACON_SOURCE, else
# the latest finalised Ethereum mainnet block when ETH_MAINNET_RPC_URL is set, else 32 bytes from
# /dev/urandom, recorded as such). Whoever runs this script knows the toxic waste, so these keys
# suit this prototype only. The phi_R key and its files are not touched.
#
# Outputs, for p in phi_a, phi_s:
#   circuits/build/<p>.zkey                    proving key (not committed)
#   circuits/setup/<p>/verification_key.json   verification key
#   circuits/setup/<p>/setup.json              transcript: sources, hashes, beacon, tool versions
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="${ROOT:?}/circuits"
BUILD="${CIRCUITS:?}/build"
CACHE="${PPREV_CACHE:-${XDG_CACHE_HOME:-${HOME:?}/.cache}/pprev}"
SNARKJS="${CIRCUITS:?}/node_modules/.bin/snarkjs"

PTAU_NAME="ppot_0080_17.ptau"
PTAU_SHA256="f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c"
PTAU="${CACHE:?}/${PTAU_NAME:?}"
PTAU_POWER=17

NODE_VERSION="$(tr -d '[:space:]' <"${ROOT:?}/.nvmrc")"
[ "$(node --version)" = "${NODE_VERSION}" ] || {
    echo "node $(node --version) is not ${NODE_VERSION} (.nvmrc); run 'nvm use' or put that version first on PATH" >&2
    exit 1
}

strip_colors() { sed 's/\x1b\[[0-9;]*m//g'; }
entropy() { head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

[ -f "${BUILD:?}/main_income_v1.r1cs" ] && [ -f "${BUILD:?}/main_tenancy_v1.r1cs" ] \
    || "${ROOT:?}/script/circuits_build_as.sh"

# Phase 1: the cached file of phi_R's setup, checked by hash.
[ -f "${PTAU:?}" ] || { echo "${PTAU} is missing; run script/circuits_setup.sh first" >&2; exit 1; }
echo "${PTAU_SHA256:?}  ${PTAU:?}" | shasum -a 256 -c -
[ "$(jq -r .phase1.sha256 "${CIRCUITS:?}/setup/setup.json")" = "${PTAU_SHA256:?}" ] \
    || { echo "circuits/setup/setup.json records another phase-1 file" >&2; exit 1; }

# Beacon.
if [ -z "${PPREV_BEACON:-}" ] && [ -z "${ETH_MAINNET_RPC_URL:-}" ] && [ -f "${ROOT:?}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "${ROOT:?}/.env"
    set +a
fi
if [ -n "${PPREV_BEACON:-}" ]; then
    BEACON="${PPREV_BEACON:?}"
    BEACON_SOURCE="${PPREV_BEACON_SOURCE:-PPREV_BEACON}"
elif [ -n "${ETH_MAINNET_RPC_URL:-}" ]; then
    BLOCK="$(cast block finalized --json --rpc-url "${ETH_MAINNET_RPC_URL:?}")"
    FIELDS="$(printf '%s' "${BLOCK:?}" | python3 -c '
import json, sys
b = json.load(sys.stdin)
b = b.get("data", b)
n = b["number"]
print(b["hash"][2:], int(n, 16) if isinstance(n, str) else n)')"
    read -r BEACON BLOCK_NUMBER <<<"${FIELDS:?}"
    BEACON_SOURCE="hash of Ethereum mainnet block ${BLOCK_NUMBER:?} (finalised at setup time)"
else
    BEACON="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    BEACON_SOURCE="32 bytes from /dev/urandom (no public randomness)"
fi
[[ "${BEACON:?}" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "the beacon must be 64 hex digits" >&2; exit 1; }

# setup <predicate> <circuit>
setup() {
    local predicate="$1" circuit="$2"
    local r1cs="${BUILD:?}/${circuit:?}.r1cs"
    local zkey="${BUILD:?}/${predicate:?}.zkey"
    local out="${CIRCUITS:?}/setup/${predicate:?}"
    local work="${BUILD:?}/setup-${predicate:?}"
    mkdir -p "${out:?}" "${work:?}"

    local constraints
    constraints="$(jq -r .constraints "${BUILD:?}/${predicate:?}.info.json")"
    [ "${constraints:?}" -le $((1 << PTAU_POWER)) ] \
        || { echo "${circuit} has ${constraints} constraints, above 2^${PTAU_POWER}" >&2; exit 1; }

    "${SNARKJS:?}" groth16 setup "${r1cs:?}" "${PTAU:?}" "${work:?}/0.zkey" | strip_colors | tee "${work:?}/setup.log"
    "${SNARKJS:?}" zkey contribute "${work:?}/0.zkey" "${work:?}/1.zkey" --name="contribution 1" \
        -e="$(entropy)" | strip_colors | tee "${work:?}/contribute-1.log"
    "${SNARKJS:?}" zkey contribute "${work:?}/1.zkey" "${work:?}/2.zkey" --name="contribution 2" \
        -e="$(entropy)" | strip_colors | tee "${work:?}/contribute-2.log"
    "${SNARKJS:?}" zkey beacon "${work:?}/2.zkey" "${zkey:?}" "${BEACON:?}" 10 --name="beacon" \
        | strip_colors | tee "${work:?}/beacon.log"
    rm -f "${work:?}/0.zkey" "${work:?}/1.zkey" "${work:?}/2.zkey"
    "${SNARKJS:?}" zkey verify "${r1cs:?}" "${PTAU:?}" "${zkey:?}" | strip_colors | tee "${work:?}/zkey-verify.log"
    grep -q "ZKey Ok!" "${work:?}/zkey-verify.log"
    "${SNARKJS:?}" zkey export verificationkey "${zkey:?}" "${out:?}/verification_key.json"

    python3 - "${ROOT:?}" "${work:?}" "${PTAU:?}" "${zkey:?}" "${BEACON:?}" "${BEACON_SOURCE:?}" \
        "${predicate:?}" "${circuit:?}" "${constraints:?}" <<'PY'
import datetime, hashlib, json, re, subprocess, sys
root, work, ptau, zkey, beacon, beacon_source, predicate, circuit, constraints = sys.argv[1:]
circuits = f"{root}/circuits"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def contribution_hash(log):
    text = open(f"{work}/{log}").read()
    m = re.search(r"Contribution Hash:\s*((?:\s*[0-9a-f]{8})+)", text)
    if not m:
        sys.exit(f"no contribution hash in {log}")
    return "".join(m.group(1).split())

transcript = {
    "circuit": circuit,
    "constraints": int(constraints),
    "r1csSha256": sha256(f"{circuits}/build/{circuit}.r1cs"),
    "phase1": {
        "source": "PSE perpetual powers of tau, branch ending at contribution 0080 (the file of circuits/setup/setup.json)",
        "sha256": sha256(ptau),
        "snarkjsVerify": "not repeated; see circuits/setup/setup.json",
    },
    "phase2": {
        "trust": "single party, local to this prototype: whoever ran this script knows the toxic waste",
        "contributions": [
            {"name": "contribution 1", "entropy": "64 bytes from /dev/urandom", "hash": contribution_hash("contribute-1.log")},
            {"name": "contribution 2", "entropy": "64 bytes from /dev/urandom", "hash": contribution_hash("contribute-2.log")},
        ],
        "beacon": {"source": beacon_source, "value": beacon, "iterationsExp": 10, "hash": contribution_hash("beacon.log")},
        "snarkjsVerify": "ZKey Ok!",
    },
    "zkeySha256": sha256(zkey),
    "verificationKeySha256": sha256(f"{circuits}/setup/{predicate}/verification_key.json"),
    "tools": {
        "snarkjs": json.load(open(f"{circuits}/node_modules/snarkjs/package.json"))["version"],
        "circom": subprocess.run(["circom", "--version"], capture_output=True, text=True).stdout.strip(),
        "node": subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip(),
    },
    "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
path = f"{circuits}/setup/{predicate}/setup.json"
json.dump(transcript, open(path, "w"), indent=2)
open(path, "a").write("\n")
print(json.dumps(transcript, indent=2))
PY
}

setup phi_a main_income_v1
setup phi_s main_tenancy_v1

# Sample proofs and Solidity verifiers.
"${ROOT:?}/script/circuits_samples_as.sh"
