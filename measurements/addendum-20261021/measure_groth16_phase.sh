#!/usr/bin/env bash
# Local phase-specific Groth16 gas check derived from the artifact measure_groth16.sh.
# Preserves compiler settings, explicit gas limit, and successful return-value checks.
# Does not contact any remote chain or replace historical measurement records.
set -euo pipefail

# Usage: bash measure_groth16_phase.sh REPO phi_a|phi_s
REPO_ARG="${1:?repository path required}"
PHASE="${2:?phase required}"
case "$PHASE" in phi_a|phi_s) ;; *) echo "expected phi_a or phi_s" >&2; exit 1 ;; esac
LOG_TAG="groth16-${PHASE}"
# shellcheck source=lib/common.sh
. "${REPO_ARG:?}/script/lib/common.sh"

OUT_DIR="${MEASUREMENTS_DIR:?}/groth16_${PHASE}"
PORTS="${ANVIL_PORT:?}"
VERIFIER_SRC="${CIRCUITS}/setup/${PHASE}/Groth16Verifier.sol"
SAMPLE="${CIRCUITS}/setup/${PHASE}/sample"
PUBLIC_COUNT="$(jq length "${SAMPLE}/public.json")"
SIG="verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[${PUBLIC_COUNT}])"

for tool in anvil forge cast jq lsof python3 git; do
    command -v "${tool}" >/dev/null || die "missing tool: ${tool}"
done
select_node
require_clean_tree
check_ports_free
[ "${PUBLIC_COUNT}" = "$(jq -r .nPublic "${CIRCUITS}/setup/${PHASE}/verification_key.json")" ] \
    || die "public input count differs from verification key"
init_run "groth16_${PHASE}"
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
PROVENANCE="$(provenance_json)"

# A throwaway Foundry project with the contract compiler settings and the unmodified verifier.
PROJ="${WORK}/project"
mkdir -p "${PROJ}/src"
cp "${VERIFIER_SRC}" "${PROJ}/src/Groth16Verifier.sol"
awk '/^\[profile.default\]/{p=1} p && /^(solc_version|optimizer|optimizer_runs|via_ir|evm_version|bytecode_hash) /' \
    "${ROOT}/contracts/foundry.toml" >"${WORK}/settings.toml"
{ printf '[profile.default]\nsrc = "src"\nout = "out"\n'; cat "${WORK}/settings.toml"; } >"${PROJ}/foundry.toml"
forge build --root "${PROJ}" -q >"${WORK}/build.log" 2>&1 || die "compiling the verifier failed"

# Proof and public inputs as call arguments.
"${CIRCUITS}/node_modules/.bin/snarkjs" zkey export soliditycalldata "${SAMPLE}/public.json" "${SAMPLE}/proof.json" \
    >"${WORK}/calldata.txt"
python3 - "${WORK}/calldata.txt" "${WORK}" <<'PY'
import json, sys
args = json.loads("[" + open(sys.argv[1]).read() + "]")
assert len(args) == 4 and len(args[3]) in (7, 11), "expected phase public inputs"
fmt = lambda v: "[" + ",".join(fmt(x) if isinstance(x, list) else x for x in v) + "]"
for i, a in enumerate(args):
    open(f"{sys.argv[2]}/arg{i}.txt", "w").write(fmt(a))
# One public input changed by one, modulo the BN254 scalar field order.
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
tampered = list(args[3])
tampered[-1] = hex((int(tampered[-1], 16) + 1) % r)
open(f"{sys.argv[2]}/arg3-tampered.txt", "w").write(fmt(tampered))
PY
A="$(cat "${WORK}/arg0.txt")" B="$(cat "${WORK}/arg1.txt")" C="$(cat "${WORK}/arg2.txt")"
PUB="$(cat "${WORK}/arg3.txt")" PUB_TAMPERED="$(cat "${WORK}/arg3-tampered.txt")"

start anvil "${WORK}/anvil.log" anvil --port "${ANVIL_PORT}" --chain-id "${CHAIN_ID}" --hardfork "${HARDFORK_PIN}" \
    --config-out "${WORK}/anvil.json"
wait_port "${ANVIL_PORT}" anvil "${PIDS[0]}"
HARDFORK="$(cast rpc anvil_nodeInfo --rpc-url "${RPC}" | jq -r .hardFork)"
KEY="$(jq -r '.private_keys[0]' "${WORK}/anvil.json")"

forge create --root "${PROJ}" src/Groth16Verifier.sol:Groth16Verifier --rpc-url "${RPC}" --private-key "${KEY}" \
    --broadcast --json >"${WORK}/create.json" 2>"${WORK}/create.log" || die "deploying the verifier failed"
VERIFIER="$(jq -r .deployedTo "${WORK}/create.json")"
cast receipt "$(jq -r .transactionHash "${WORK}/create.json")" --json --rpc-url "${RPC}" >"${WORK}/create-receipt.json"
cast tx "$(jq -r .transactionHash "${WORK}/create.json")" input --rpc-url "${RPC}" >"${WORK}/create-input.txt"

VALID="$(cast call "${VERIFIER}" "${SIG}(bool)" "${A}" "${B}" "${C}" "${PUB}" --rpc-url "${RPC}")"
TAMPERED="$(cast call "${VERIFIER}" "${SIG}(bool)" "${A}" "${B}" "${C}" "${PUB_TAMPERED}" --rpc-url "${RPC}")"
[ "${VALID}" = true ] || die "the sample proof does not verify on-chain"
[ "${TAMPERED}" = false ] || die "a changed public input verifies on-chain"
cast send "${VERIFIER}" "${SIG}" "${A}" "${B}" "${C}" "${PUB}" --gas-limit 1000000 --rpc-url "${RPC}" \
    --private-key "${KEY}" --json >"${WORK}/verify-receipt.json"
VERIFY_TX="$(jq -r .transactionHash "${WORK}/verify-receipt.json")"
cast tx "${VERIFY_TX}" input --rpc-url "${RPC}" >"${WORK}/verify-input.txt"
cast rpc debug_traceTransaction "${VERIFY_TX}" '{"tracer":"callTracer"}' --rpc-url "${RPC}" >"${WORK}/verify-trace.json"
[ "$(jq -r .output "${WORK}/verify-trace.json")" = 0x0000000000000000000000000000000000000000000000000000000000000001 ] \
    || die "the verification transaction did not return true"
stop_all

python3 - "${WORK}" "${PROJ}/out/Groth16Verifier.sol/Groth16Verifier.json" "${PHASE}" "${OUT}.part" \
    "${HARDFORK}" "${ROOT}" <<'PY'
import json, sys

work, artifact, phase, out, hardfork, root = sys.argv[1:7]
from pathlib import Path
import hashlib
sample = Path(root) / "circuits/setup" / phase / "sample"
setup = sample.parent
cd = lambda data: sum(4 if b == 0 else 16 for b in data)
hexbytes = lambda path: bytes.fromhex(open(path).read().strip()[2:])

receipt = json.load(open(f"{work}/verify-receipt.json"))
assert int(receipt["status"], 16) == 1
verify_input = hexbytes(f"{work}/verify-input.txt")
receipt_gas = int(receipt["gasUsed"], 16)
execution = receipt_gas - 21000 - cd(verify_input)

create = json.load(open(f"{work}/create-receipt.json"))
create_input = hexbytes(f"{work}/create-input.txt")
art = json.load(open(artifact))
runtime = len(bytes.fromhex(art["deployedBytecode"]["object"][2:]))

# EIP-1108 prices: ecAdd 150, ecMul 6,000, pairing 45,000 + 34,000 per pair. snarkjs' verifier does
# one ecMul and one ecAdd per public input and one pairing check over four pairs.
n = len(json.loads((sample / "public.json").read_text()))
model = {"pairing": 45000 + 4 * 34000, "publicInputMsm": n * (6000 + 150)}
model["total"] = model["pairing"] + model["publicInputMsm"]

result = {
    "parameters": {"publicInputs": n, "anvilHardfork": hardfork,
                   "phase": phase, "proof": str(sample),
                   "verifier": str(setup / "Groth16Verifier.sol"),
                   "sourceSha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [setup / "Groth16Verifier.sol", setup / "verification_key.json", sample / "public.json", sample / "proof.json"]}},
    "checks": {"validProofAccepted": True, "changedPublicInputRejected": True,
               "transactionReturnedTrue": True, "transactionGasLimit": 1000000},
    "verification": {"receiptGas": receipt_gas, "intrinsicGas": 21000, "calldataBytes": len(verify_input),
                     "calldataGas": cd(verify_input), "executionGas": execution,
                     "transactionHash": receipt["transactionHash"]},
    "eip1108Model": model | {"executionMinusModel": execution - model["total"],
                             "modelShareOfExecution": round(model["total"] / execution, 4)},
    "deployment": {"transactionGas": int(create["gasUsed"], 16), "initcodeBytes": len(bytes.fromhex(art["bytecode"]["object"][2:])),
                   "runtimeBytes": runtime, "calldataGas": cd(create_input)},

}
json.dump(result, open(out, "w"), indent=2)
PY

jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --slurpfile body "${OUT}.part" \
    '{runId: $runId} + $prov + $body[0]' >"${OUT}"
rm -f -- "${OUT:?}.part"
log "record: ${OUT#"${ROOT}/"}"
jq -r '
    "verification: execution \(.verification.executionGas), receipt \(.verification.receiptGas); EIP-1108 model \(.eip1108Model.total)",
    "verifier runtime \(.deployment.runtimeBytes) B, deployment \(.deployment.transactionGas) gas"
' "${OUT}" >&2
