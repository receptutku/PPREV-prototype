#!/usr/bin/env bash
# Groth16 setup for phi_R (D31, D32).
#
# Phase 1: the PSE perpetual powers of tau file ppot_0080_17.ptau (80 contributions, up to 2^17
# constraints), fetched once into a cache outside the repository and checked against its pinned
# SHA-256 and with `snarkjs powersoftau verify`.
#
# Phase 2 is local and single-party: `groth16 setup`, two contributions with independent entropy
# from /dev/urandom, and a beacon: PPREV_BEACON (64 hex digits, described by PPREV_BEACON_SOURCE)
# or, when ETH_MAINNET_RPC_URL is set (in the environment or in .env), the hash of the latest
# finalised Ethereum mainnet block. Whoever runs this script knows the toxic waste of its phase 2,
# so the key suits this prototype only.
#
# Outputs:
#   circuits/build/phi_r.zkey                      proving key (not committed)
#   circuits/setup/verification_key.json           verification key
#   circuits/setup/Groth16Verifier.sol             Solidity verifier as exported by snarkjs
#   circuits/setup/sample/{input,proof,public}.json  one proof made with the same key
#   circuits/setup/setup.json                      transcript: sources, hashes, beacon, tool versions
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="${ROOT:?}/circuits"
BUILD="${CIRCUITS:?}/build"
WORK="${BUILD:?}/setup"
SETUP="${CIRCUITS:?}/setup"
CACHE="${PPREV_CACHE:-${XDG_CACHE_HOME:-${HOME:?}/.cache}/pprev}"
SNARKJS="${CIRCUITS:?}/node_modules/.bin/snarkjs"

PTAU_NAME="ppot_0080_17.ptau"
PTAU_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/${PTAU_NAME:?}"
PTAU_SHA256="f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c"
PTAU="${CACHE:?}/${PTAU_NAME:?}"

R1CS="${BUILD:?}/main_title_v1.r1cs"
WASM_DIR="${BUILD:?}/main_title_v1_js"
ZKEY="${BUILD:?}/phi_r.zkey"

strip_colors() { sed 's/\x1b\[[0-9;]*m//g'; }
entropy() { head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

[ -f "${R1CS:?}" ] || "${ROOT:?}/script/circuits_build.sh"
mkdir -p "${CACHE:?}" "${WORK:?}" "${SETUP:?}/sample"

# Phase 1.
if [ ! -f "${PTAU:?}" ]; then
    curl -fL --retry 3 -o "${PTAU:?}.part" "${PTAU_URL:?}"
    mv "${PTAU:?}.part" "${PTAU:?}"
fi
echo "${PTAU_SHA256:?}  ${PTAU:?}" | shasum -a 256 -c -
"${SNARKJS:?}" powersoftau verify "${PTAU:?}" | strip_colors | tee "${WORK:?}/ptau-verify.log"
grep -q "Powers of Tau Ok!" "${WORK:?}/ptau-verify.log"

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
    # Newer cast versions wrap the block in {"data": ...}.
    FIELDS="$(printf '%s' "${BLOCK:?}" | python3 -c '
import json, sys
b = json.load(sys.stdin)
b = b.get("data", b)
n = b["number"]
print(b["hash"][2:], int(n, 16) if isinstance(n, str) else n)')"
    read -r BEACON BLOCK_NUMBER <<<"${FIELDS:?}"
    BEACON_SOURCE="hash of Ethereum mainnet block ${BLOCK_NUMBER:?} (finalised at setup time)"
else
    echo "set ETH_MAINNET_RPC_URL or PPREV_BEACON (64 hex digits) for the beacon" >&2
    exit 1
fi
[[ "${BEACON:?}" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "the beacon must be 64 hex digits" >&2; exit 1; }

# Phase 2.
Z0="${WORK:?}/phi_r_0.zkey"
Z1="${WORK:?}/phi_r_1.zkey"
Z2="${WORK:?}/phi_r_2.zkey"
"${SNARKJS:?}" groth16 setup "${R1CS:?}" "${PTAU:?}" "${Z0:?}" | strip_colors | tee "${WORK:?}/setup.log"
"${SNARKJS:?}" zkey contribute "${Z0:?}" "${Z1:?}" --name="contribution 1" -e="$(entropy)" \
    | strip_colors | tee "${WORK:?}/contribute-1.log"
"${SNARKJS:?}" zkey contribute "${Z1:?}" "${Z2:?}" --name="contribution 2" -e="$(entropy)" \
    | strip_colors | tee "${WORK:?}/contribute-2.log"
"${SNARKJS:?}" zkey beacon "${Z2:?}" "${ZKEY:?}" "${BEACON:?}" 10 --name="beacon" \
    | strip_colors | tee "${WORK:?}/beacon.log"
rm -f "${Z0:?}" "${Z1:?}" "${Z2:?}"
"${SNARKJS:?}" zkey verify "${R1CS:?}" "${PTAU:?}" "${ZKEY:?}" | strip_colors | tee "${WORK:?}/zkey-verify.log"
grep -q "ZKey Ok!" "${WORK:?}/zkey-verify.log"

# Exports.
"${SNARKJS:?}" zkey export verificationkey "${ZKEY:?}" "${SETUP:?}/verification_key.json"
"${SNARKJS:?}" zkey export solidityverifier "${ZKEY:?}" "${SETUP:?}/Groth16Verifier.sol"

# One proof from the same key: the register statement of test-vectors/eip712.json, proven for the
# owner of the sample record.
cargo run -q -p pprev-prover --bin gen-phi-r-sample -- \
    "${ROOT:?}/policies/layouts/title-v1.json" "${ROOT:?}/test-vectors/eip712.json" \
    "${SETUP:?}/sample/input.json"
node "${WASM_DIR:?}/generate_witness.js" "${WASM_DIR:?}/main_title_v1.wasm" \
    "${SETUP:?}/sample/input.json" "${WORK:?}/sample.wtns"
"${SNARKJS:?}" groth16 prove "${ZKEY:?}" "${WORK:?}/sample.wtns" \
    "${SETUP:?}/sample/proof.json" "${SETUP:?}/sample/public.json"
"${SNARKJS:?}" groth16 verify "${SETUP:?}/verification_key.json" "${SETUP:?}/sample/public.json" \
    "${SETUP:?}/sample/proof.json" | strip_colors | tee "${WORK:?}/sample-verify.log"
grep -q "OK!" "${WORK:?}/sample-verify.log"

# Transcript.
python3 - "${ROOT:?}" "${WORK:?}" "${PTAU:?}" "${ZKEY:?}" "${BEACON:?}" "${BEACON_SOURCE:?}" \
    "${PTAU_URL:?}" <<'PY'
import datetime, hashlib, json, re, subprocess, sys
root, work, ptau, zkey, beacon, beacon_source, ptau_url = sys.argv[1:]
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
    "circuit": "main_title_v1",
    "r1csSha256": sha256(f"{circuits}/build/main_title_v1.r1cs"),
    "phase1": {
        "source": "PSE perpetual powers of tau, 80 contributions",
        "url": ptau_url,
        "sha256": sha256(ptau),
        "snarkjsVerify": "Powers of Tau Ok!",
    },
    "phase2": {
        "trust": "single party: whoever ran this script knows the toxic waste",
        "contributions": [
            {"name": "contribution 1", "entropy": "64 bytes from /dev/urandom", "hash": contribution_hash("contribute-1.log")},
            {"name": "contribution 2", "entropy": "64 bytes from /dev/urandom", "hash": contribution_hash("contribute-2.log")},
        ],
        "beacon": {"source": beacon_source, "value": beacon, "iterationsExp": 10, "hash": contribution_hash("beacon.log")},
        "snarkjsVerify": "ZKey Ok!",
    },
    "zkeySha256": sha256(zkey),
    "verificationKeySha256": sha256(f"{circuits}/setup/verification_key.json"),
    "solidityVerifierSha256": sha256(f"{circuits}/setup/Groth16Verifier.sol"),
    "sample": {"statement": "register message of test-vectors/eip712.json", "snarkjsVerify": "OK!"},
    "tools": {
        "snarkjs": json.load(open(f"{circuits}/node_modules/snarkjs/package.json"))["version"],
        "circom": subprocess.run(["circom", "--version"], capture_output=True, text=True).stdout.strip(),
        "node": subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip(),
    },
    "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
json.dump(transcript, open(f"{circuits}/setup/setup.json", "w"), indent=2)
open(f"{circuits}/setup/setup.json", "a").write("\n")
print(json.dumps(transcript, indent=2))
PY
