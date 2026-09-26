#!/usr/bin/env bash
# On-chain costs on Layer 1 terms (stage (e), Section VII-A to VII-D).
#
#   1. forge build and the full contract test suite;
#   2. contracts/script/MeasureGas.s.sol: execution gas of the seven algorithms on fresh deployments,
#      storage decomposition from a recorded state diff, ECDSA marginal against an accept-all
#      verifier, verifier call costs;
#   3. on anvil, contracts/script/Lifecycle.s.sol: deployment and a complete lifecycle (Register,
#      Apply, Engage, Settle) as real transactions; receipt gas, calldata, raw transaction size,
#      bytecode sizes; each receipt reconciled with the measured transaction gas net of its refund.
#
# Output: measurements/l1/<run>.json. Refuses a dirty working tree (PPREV_ALLOW_DIRTY=1 with
# PPREV_MEASUREMENTS_DIR for a trial run).
set -euo pipefail

LOG_TAG=l1
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

OUT_DIR="${MEASUREMENTS_DIR:?}/l1"
# Gas figures follow the Osaka (Fusaka) schedule; anvil's default fork can move with its version.
HARDFORK_PIN=osaka
PORTS="${ANVIL_PORT:?}"

for tool in anvil forge cast jq lsof python3 git; do
    command -v "${tool}" >/dev/null || die "missing tool: ${tool}"
done
select_node
require_clean_tree
check_ports_free
init_run l1
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
PROVENANCE="$(provenance_json)"

cd "${ROOT:?}/contracts"
log "forge build and test"
forge build -q
forge test >"${WORK}/forge-test.log" 2>&1 || die "forge test failed; see ${WORK#"${ROOT}/"}/forge-test.log"
TEST_SUMMARY="$(grep -E 'tests passed' "${WORK}/forge-test.log" | tail -n 1)"

log "execution gas and decomposition"
MEASURE_DIR="${ROOT:?}/target/measure/${RUN_ID:?}"
mkdir -p "${MEASURE_DIR:?}"
GAS_OUT="../target/measure/${RUN_ID}/gas.json" forge script script/MeasureGas.s.sol --tc MeasureGas \
    >"${WORK}/measure-gas.log" 2>&1 || die "MeasureGas failed; see ${WORK#"${ROOT}/"}/measure-gas.log"
cp "${MEASURE_DIR}/gas.json" "${WORK}/gas.json"

log "lifecycle on anvil"
start anvil "${WORK}/anvil.log" anvil --port "${ANVIL_PORT}" --chain-id "${CHAIN_ID}" \
    --hardfork "${HARDFORK_PIN}" --config-out "${WORK}/anvil.json"
wait_port "${ANVIL_PORT}" anvil "${PIDS[0]}"
HARDFORK="$(cast rpc anvil_nodeInfo --rpc-url "${RPC}" | jq -r .hardFork)"
export DEPLOYER_KEY OWNER_KEY APPLICANT_KEY LIFECYCLE_STATE
DEPLOYER_KEY="$(jq -r '.private_keys[0]' "${WORK}/anvil.json")"
OWNER_KEY="$(jq -r '.private_keys[1]' "${WORK}/anvil.json")"
APPLICANT_KEY="$(jq -r '.private_keys[2]' "${WORK}/anvil.json")"
LIFECYCLE_STATE="../target/measure/${RUN_ID}/lifecycle-state.json"
for phase in phaseA phaseB; do
    forge script script/Lifecycle.s.sol --tc Lifecycle --sig "${phase}()" --rpc-url "${RPC}" --broadcast -q \
        >"${WORK}/lifecycle-${phase}.log" 2>&1 || die "Lifecycle ${phase} failed"
    cp "broadcast/Lifecycle.s.sol/${CHAIN_ID}/${phase}-latest.json" "${WORK}/lifecycle-${phase}.json"
done
# Raw signed transactions, for their serialised size.
for phase in phaseA phaseB; do
    for hash in $(jq -r '.receipts[].transactionHash' "${WORK}/lifecycle-${phase}.json"); do
        printf '%s %s\n' "${hash}" "$(cast tx "${hash}" --raw --rpc-url "${RPC}")"
    done
done >"${WORK}/raw-transactions.txt"
stop_all

python3 - "${WORK}" "${ROOT}/contracts/out" "${OUT}.part" "${HARDFORK}" "${TEST_SUMMARY}" <<'PY'
import json, sys

work, out_dir, out, hardfork, test_summary = sys.argv[1:6]
gas = json.load(open(f"{work}/gas.json"))
raw = dict(line.split() for line in open(f"{work}/raw-transactions.txt"))

def calldata_gas(data):
    return sum(4 if b == 0 else 16 for b in data)

def bytecode(name):
    art = json.load(open(f"{out_dir}/{name}.sol/{name}.json"))
    return (len(bytes.fromhex(art["bytecode"]["object"][2:])),
            len(bytes.fromhex(art["deployedBytecode"]["object"][2:])))

txs = []
for phase in ("phaseA", "phaseB"):
    d = json.load(open(f"{work}/lifecycle-{phase}.json"))
    for t, r in zip(d["transactions"], d["receipts"]):
        assert int(r["status"], 16) == 1, f"{t['hash']} failed"
        data = bytes.fromhex(t["transaction"]["input"][2:])
        name = t["contractName"] if t["transactionType"] == "CREATE" else t["function"].split("(")[0]
        txs.append({
            "name": name, "type": t["transactionType"], "hash": r["transactionHash"],
            "blockNumber": int(r["blockNumber"], 16), "receiptGas": int(r["gasUsed"], 16),
            "calldataBytes": len(data), "calldataGas": calldata_gas(data),
            "rawTransactionBytes": len(bytes.fromhex(raw[r["transactionHash"]][2:])),
        })
by_name = {t["name"]: t for t in txs}

# Deployment: 21,000 + 32,000 (creation) + calldata + EIP-3860 initcode words, the rest is
# constructor execution and code deposit (200 gas per runtime byte).
deployment = {}
for name in ("EcdsaNotaryVerifier", "PPREV"):
    t = by_name[name]
    init_len, runtime_len = bytecode(name)
    words = 2 * ((t["calldataBytes"] + 31) // 32)
    deployment[name] = {
        "transactionGas": t["receiptGas"], "intrinsicGas": 53000, "calldataGas": t["calldataGas"],
        "initcodeWordGas": words,
        "creationExecutionGas": t["receiptGas"] - 53000 - t["calldataGas"] - words,
        "codeDepositGas": 200 * runtime_len,
        "initcodeBytes": init_len, "runtimeBytes": runtime_len,
        "runtimeBytesOfEip170Limit": round(runtime_len / 24576, 4),
        "constructorArgsBytes": t["calldataBytes"] - init_len,
    }

ops = gas["operations"]
UNIT = {"initialised": 22100, "updated": 5000, "readOnly": 2100, "warmReaccesses": 100}
decomposition = {}
for name, o in ops.items():
    s = o["storage"]
    parts = {
        "storageInitialisation": s["initialised"] * UNIT["initialised"],
        "storageUpdates": s["updated"] * UNIT["updated"],
        "coldStorageReads": s["readOnly"] * UNIT["readOnly"],
        "warmReaccesses": s["warmReaccesses"] * UNIT["warmReaccesses"],
    }
    if "ecdsaMarginal" in o:
        parts["ecdsaMarginal"] = o["ecdsaMarginal"]
    parts["other"] = o["executionGas"] - sum(parts.values())
    decomposition[name] = {
        "executionGas": o["executionGas"],
        "slots": s,
        "components": parts,
        "percent": {k: round(100 * v / o["executionGas"], 2) for k, v in parts.items()},
        "recorderChangedGas": o["recordedTransactionGas"] != o["transactionGas"],
    }

# Receipt = measured transaction gas - refund (capped at a fifth of the gas used, EIP-3529).
reconciliation = {}
for name in ("register", "applyFor", "engage", "settle"):
    op = {"register": "Register", "applyFor": "Apply", "engage": "Engage", "settle": "Settle"}[name]
    o, t = ops[op], by_name[name]
    predicted = o["transactionGas"] - min(o["refund"], o["transactionGas"] // 5)
    reconciliation[op] = {
        "receiptGas": t["receiptGas"], "predictedFromMeasurement": predicted,
        "difference": t["receiptGas"] - predicted,
        "calldataGasMeasured": o["calldataGas"], "calldataGasOnChain": t["calldataGas"],
        # The signatures differ (other deployment address, so other digests): calldata zero bytes
        # and the verifier's recovery-parameter check depend on them.
        "differenceBeyondCalldata": t["receiptGas"] - predicted - (t["calldataGas"] - o["calldataGas"]),
    }

lifecycle_ops = ["Register", "Apply", "Engage", "Settle"]
lifecycle_tx = [by_name[n] for n in ("register", "applyFor", "engage", "settle")]
result = {
    "parameters": {"deployment": "D18 (Delta 300 s, tau_lock 14 days, maxExpirations 3, rho 5000 bp)",
                   "anvilHardfork": hardfork, "evmVersion": "cancun (compiler target)"},
    "tests": test_summary,
    "method": {
        "executionGas": "forge script, fresh deployment per operation, pranked call as its own transaction: transaction gas before refund minus 21,000 and EIP-2028 calldata gas",
        "warmth": "caller and contract warm; verifier and payees other than the caller cold",
        "callers": {"Register": "owner", "Apply": "applicant", "Engage": "owner", "Settle": "owner (applicant is a cold payee)",
                    "Expire": "applicant (the payee)", "Reclaim": "applicant", "Cancel": "owner"},
        "decomposition": "slots from the recorded state diff priced at 22,100 (initialised), 5,000 (updated), 2,100 (read only), 100 per warm re-access; ECDSA marginal against an accept-all verifier; other is the residual",
    },
    "perOperation": {k: {kk: v[kk] for kk in ("executionGas", "transactionGas", "calldataGas", "calldataBytes", "refund")}
                     | ({"ecdsaMarginal": v["ecdsaMarginal"], "acceptAllTransactionGas": v["acceptAllGas"]} if "ecdsaMarginal" in v else {})
                     for k, v in ops.items()},
    "decomposition": decomposition,
    "verifierCalls": gas["verifier"],
    "deployment": deployment,
    "deploymentTotal": {"creationExecutionGas": sum(d["creationExecutionGas"] for d in deployment.values()),
                        "transactionGas": sum(d["transactionGas"] for d in deployment.values())},
    "lifecycle": {
        "operations": lifecycle_ops,
        "executionGas": sum(ops[o]["executionGas"] for o in lifecycle_ops),
        "receiptGas": sum(t["receiptGas"] for t in lifecycle_tx),
        "calldataGas": sum(t["calldataGas"] for t in lifecycle_tx),
        "rawTransactionBytes": sum(t["rawTransactionBytes"] for t in lifecycle_tx),
        "transactions": lifecycle_tx,
    },
    "reconciliation": reconciliation,
    "allTransactions": txs,
}
json.dump(result, open(out, "w"), indent=2)
PY

jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --slurpfile body "${OUT}.part" \
    '{runId: $runId} + $prov + $body[0]' >"${OUT}"
rm -f -- "${OUT:?}.part"
log "record: ${OUT#"${ROOT}/"}"
jq -r '
    "execution gas: " + ([.perOperation | to_entries[] | "\(.key) \(.value.executionGas)"] | join(", ")),
    "lifecycle: execution \(.lifecycle.executionGas), receipts \(.lifecycle.receiptGas), \(.lifecycle.rawTransactionBytes) raw bytes",
    "deployment: PPREV \(.deployment.PPREV.transactionGas) tx gas, runtime \(.deployment.PPREV.runtimeBytes) B",
    "reconciliation differences: " + ([.reconciliation | to_entries[] | "\(.key) \(.value.difference)"] | join(", ")),
    "tests: \(.tests)"
' "${OUT}" >&2
