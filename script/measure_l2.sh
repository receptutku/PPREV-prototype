#!/usr/bin/env bash
# Layer-2 campaign on Base Sepolia, priced with Base mainnet parameters (stage (e), D37).
#
# Deploys the verifier and two PPREV instances and sends the seven algorithms as real transactions
# (contracts/script/L2Campaign.s.sol, script/lib/l2_send.py): Register M times (default 10, for the
# t_incl distribution), Apply, Engage, Settle, Reclaim, and Cancel on deployment A, Expire on
# deployment B. Apply and Settle are signed by the fixed test notary key, as in the contract tests
# (D23). For every transaction: receipt gas, signed transaction size, the L1 fee fields, hash, block,
# and t_incl (sending to first receipt, polled every 50 ms).
#
# Fixture: the D18 amounts divided by 10^4, so that the campaign fits a faucet grant, and on
# deployment B a lock window of TAU_LOCK_B seconds (default 60), so that Expire can run within the
# campaign. Neither changes gas: amounts and windows are values in storage and calldata, not code
# paths; the record reconciles each receipt with the L1 execution gas.
#
# Prices: one Base mainnet block (L2 gas price, L1 base fee, blob base fee, Fjord scalars, operator
# fee parameters); ETH/USD from the newest L1 price record (not read again). The test wallet's balance
# is recorded at the start and the end; the campaign does not start if it is too low.
#
# Reads BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY from .env; none is printed.
# Output: measurements/l2/<run>.json. Refuses a dirty working tree (PPREV_ALLOW_DIRTY=1 with
# PPREV_MEASUREMENTS_DIR for a trial run).
set -euo pipefail

LOG_TAG=l2
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REGISTER_COUNT="${PPREV_REGISTER_COUNT:-10}"
TAU_LOCK_B="${PPREV_TAU_LOCK_B:-60}"
OUT_DIR="${MEASUREMENTS_DIR:?}/l2"
GAS_PRICE_ORACLE=0x420000000000000000000000000000000000000F
L1_BLOCK=0x4200000000000000000000000000000000000015

# D18 amounts divided by 10^4 (wei).
SCALE=10000
REQ_ESCROW=$((50000000000000000 / SCALE))
MIN_COLLATERAL=$((100000000000000000 / SCALE))
MAX_COLLATERAL=$((1000000000000000000 / SCALE))
COLLATERAL=$((500000000000000000 / SCALE))
DEPOSIT=$((50000000000000000 / SCALE))
AMOUNT=$((1000000000000000000 / SCALE))
APPLICANT_FUNDING=50000000000000 # 3 deposits and the applicant's fees
TAU_LOCK_A=$((14 * 24 * 3600))

# Listings 1-3 of deployment A carry the lifecycle, Reclaim, and Cancel.
[ "${REGISTER_COUNT}" -ge 3 ] || die "PPREV_REGISTER_COUNT must be at least 3"
for tool in forge cast jq python3 git openssl; do
    command -v "${tool}" >/dev/null || die "missing tool: ${tool}"
done
require_clean_tree
[ -f "${ROOT}/.env" ] || die ".env not found"
env_var() (
    set -a
    # shellcheck disable=SC1091
    . "${ROOT}/.env"
    eval "printf '%s' \"\${$1:-}\""
)
SEPOLIA_RPC="$(env_var BASE_SEPOLIA_RPC_URL)"
MAINNET_RPC="$(env_var BASE_MAINNET_RPC_URL)"
[ -n "${SEPOLIA_RPC}" ] && [ -n "${MAINNET_RPC}" ] || die "BASE_SEPOLIA_RPC_URL and BASE_MAINNET_RPC_URL must be set in .env"
L1_RECORD="${PPREV_L1_RECORD:-$(find "${ROOT}/measurements/l1" -name '*.json' | sort | tail -n 1)}"
PRICE_RECORD="${PPREV_PRICE_RECORD:-$(find "${ROOT}/measurements/l1_price" -name '*.json' | sort | tail -n 1)}"
[ -f "${L1_RECORD}" ] && [ -f "${PRICE_RECORD}" ] || die "needs an L1 record and an L1 price record"

init_run l2
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
REL="../target/l2/${RUN_ID}"

# srpc / mrpc <cast args...>: Base Sepolia / mainnet; failures are reported without the URL.
srpc() { cast "$@" --rpc-url "${SEPOLIA_RPC}" 2>/dev/null || die "Base Sepolia call failed: cast $1"; }
mrpc() { cast "$@" --rpc-url "${MAINNET_RPC}" 2>/dev/null || die "Base mainnet call failed: cast $1"; }
[ "$(srpc chain-id)" = 84532 ] || die "BASE_SEPOLIA_RPC_URL is not Base Sepolia"
[ "$(mrpc chain-id)" = 8453 ] || die "BASE_MAINNET_RPC_URL is not Base mainnet"

# Keys: the test wallet owns and operates; a fresh applicant account is funded by it.
owner_key="$(env_var TESTNET_PRIVATE_KEY)"
case "${owner_key}" in 0x*) ;; *) owner_key="0x${owner_key}" ;; esac
printf '%s\n' "${owner_key}" >"${WORK}/owner.key"
printf '0x%s\n' "$(openssl rand -hex 32)" >"${WORK}/applicant.key"
unset owner_key
OWNER="$(cast wallet address --private-key "$(cat "${WORK}/owner.key")")"
APPLICANT="$(cast wallet address --private-key "$(cat "${WORK}/applicant.key")")"
log "owner ${OWNER}, applicant ${APPLICANT} (fresh)"

# Balance check: collateral of every listing, the applicant's funding, and a fee budget of three
# times 20M gas at the current gas price plus an L1 fee allowance.
GAS_PRICE="$(srpc gas-price)"
NEEDED=$(((REGISTER_COUNT + 1) * COLLATERAL + APPLICANT_FUNDING + 3 * 20000000 * GAS_PRICE + 50000000000000))
BALANCE_START="$(srpc balance "${OWNER}")"
log "balance $(cast from-wei "${BALANCE_START}") ETH, needed about $(cast from-wei "${NEEDED}") ETH"
python3 -c "import sys; sys.exit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)" "${BALANCE_START}" "${NEEDED}" \
    || die "the test wallet holds too little for the campaign; fund it from a Base Sepolia faucet"

export OWNER APPLICANT REGISTER_COUNT TAU_LOCK_A TAU_LOCK_B REQ_ESCROW MIN_COLLATERAL MAX_COLLATERAL \
    COLLATERAL DEPOSIT AMOUNT APPLICANT_FUNDING
export DELTA=300 MAX_EXPIRATIONS=3 RHO=5000
export STATE="${REL}/state.json"
export L2_RPC_URL="${SEPOLIA_RPC}" OWNER_KEY_FILE="${WORK}/owner.key" APPLICANT_KEY_FILE="${WORK}/applicant.key"

# phase <function>: simulate against the current state, then sign, send, and time.
phase() {
    log "phase $1"
    (cd "${ROOT}/contracts" && STEPS_OUT="${REL}/steps-$1.json" \
        forge script script/L2Campaign.s.sol --tc L2Campaign --sig "$1()" --rpc-url "${SEPOLIA_RPC}" \
        >"${WORK}/forge-$1.txt" 2>&1) || die "simulating phase $1 failed (see ${WORK#"${ROOT}/"}/forge-$1.txt)"
    python3 "${ROOT}/script/lib/l2_send.py" "${WORK}/steps-$1.json" "${WORK}/results-$1.jsonl" \
        || die "sending phase $1 failed"
}
(cd "${ROOT}/contracts" && forge build -q)
mkdir -p "${ROOT}/target/measure"
for p in deploy registers applies engages settles expires; do
    phase "${p}"
done

# Return what the applicant holds, less the fee of the transfer.
APPLICANT_LEFT="$(srpc balance "${APPLICANT}")"
SWEEP=$((APPLICANT_LEFT - 21000 * 2 * GAS_PRICE - 2000000000000))
if [ "${SWEEP}" -gt 0 ]; then
    cast send "${OWNER}" --value "${SWEEP}" --private-key "$(cat "${WORK}/applicant.key")" \
        --rpc-url "${SEPOLIA_RPC}" >/dev/null 2>&1 || log "returning the applicant's balance failed; left at ${APPLICANT}"
fi
BALANCE_END="$(srpc balance "${OWNER}")"
APPLICANT_END="$(srpc balance "${APPLICANT}")"
jq -n --arg o "${OWNER}" --arg a "${APPLICANT}" --arg s "${BALANCE_START}" --arg e "${BALANCE_END}" \
    --arg al "${APPLICANT_END}" --arg sw "${SWEEP}" \
    '{owner: $o, applicant: $a, ownerBalanceStartWei: ($s | tonumber), ownerBalanceEndWei: ($e | tonumber),
      applicantBalanceEndWei: ($al | tonumber), returnedFromApplicantWei: ($sw | tonumber),
      note: "collateral of the listings that stay open remains in deployment A"}' >"${WORK}/balances.json"

# Fee parameters: Base Sepolia now, Base mainnet at one block.
fee_params() { # fee_params <rpc function> <block>
    local b="$2"
    jq -n \
        --argjson block "${b}" \
        --argjson baseFee "$($1 block "${b}" -f baseFeePerGas)" \
        --argjson prio "$($1 rpc eth_feeHistory 0x1 "$(printf '0x%x' "${b}")" '[50]' | jq '.reward[0][0]' | xargs printf '%d')" \
        --argjson l1BaseFee "$($1 call "${GAS_PRICE_ORACLE}" 'l1BaseFee()(uint256)' --block "${b}" | awk '{print $1}')" \
        --argjson blobBaseFee "$($1 call "${GAS_PRICE_ORACLE}" 'blobBaseFee()(uint256)' --block "${b}" | awk '{print $1}')" \
        --argjson baseFeeScalar "$($1 call "${GAS_PRICE_ORACLE}" 'baseFeeScalar()(uint32)' --block "${b}" | awk '{print $1}')" \
        --argjson blobBaseFeeScalar "$($1 call "${GAS_PRICE_ORACLE}" 'blobBaseFeeScalar()(uint32)' --block "${b}" | awk '{print $1}')" \
        --argjson isFjord "$($1 call "${GAS_PRICE_ORACLE}" 'isFjord()(bool)' --block "${b}")" \
        --argjson isJovian "$($1 call "${GAS_PRICE_ORACLE}" 'isJovian()(bool)' --block "${b}")" \
        --argjson opScalar "$($1 call "${L1_BLOCK}" 'operatorFeeScalar()(uint32)' --block "${b}" | awk '{print $1}')" \
        --argjson opConstant "$($1 call "${L1_BLOCK}" 'operatorFeeConstant()(uint64)' --block "${b}" | awk '{print $1}')" \
        --argjson ts "$($1 block "${b}" -f timestamp)" \
        '{block: $block, timestamp: $ts, baseFeePerGas: $baseFee, medianPriorityFeePerGas: $prio,
          l1BaseFee: $l1BaseFee, blobBaseFee: $blobBaseFee, baseFeeScalar: $baseFeeScalar,
          blobBaseFeeScalar: $blobBaseFeeScalar, isFjord: $isFjord, isJovian: $isJovian,
          operatorFeeScalar: $opScalar, operatorFeeConstant: $opConstant}'
}
fee_params mrpc "$(mrpc block-number)" >"${WORK}/mainnet.json"
fee_params srpc "$(srpc block-number)" >"${WORK}/sepolia.json"

jq -n --argjson m "${REGISTER_COUNT}" --argjson tauA "${TAU_LOCK_A}" --argjson tauB "${TAU_LOCK_B}" \
    --arg reqEscrow "${REQ_ESCROW}" --arg minC "${MIN_COLLATERAL}" --arg maxC "${MAX_COLLATERAL}" \
    --arg coll "${COLLATERAL}" --arg dep "${DEPOSIT}" --arg amount "${AMOUNT}" \
    '{registerCount: $m, deltaS: 300, maxExpirations: 3, rhoBps: 5000,
      tauLockS: {deploymentA: $tauA, deploymentB: $tauB},
      amountsWei: {reqEscrow: $reqEscrow, minCollateral: $minC, maxCollateral: $maxC, collateral: $coll,
                   deposit: $dep, txDataAmount: $amount},
      differenceFromD18: "every amount is the D18 value divided by 10^4; deployment B, used only for Expire, has a lock window of \($tauB) s instead of 14 days",
      reason: "the test wallet holds a faucet grant, far below the D18 collateral; Expire needs the lock window to elapse within the campaign. Gas does not depend on either: amounts and the window are storage and calldata values, not code paths, and each receipt is reconciled with the L1 execution gas (calldata gas taken from the Base Sepolia transaction)",
      notary: "fixed test notary key of the contract tests (D23); Apply and Settle signed as by the mock notary"}' \
    >"${WORK}/params.json"

python3 "${ROOT}/script/lib/l2_report.py" "${WORK}" "${L1_RECORD}" "${PRICE_RECORD}" "${OUT}.part"
PROVENANCE="$(jq -n --arg c "$(git -C "${ROOT}" rev-parse HEAD)" --argjson d "$(git_dirty)" \
    --arg forge "$(first_line forge --version)" --arg cast "$(first_line cast --version)" \
    --arg solc "$(awk -F'"' '/^solc_version/ { print $2 }' "${ROOT}/contracts/foundry.toml")" \
    '{commit: $c, workingTreeDirty: $d, tools: {forge: $forge, cast: $cast, solc: $solc}}')"
jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --slurpfile body "${OUT}.part" \
    '{runId: $runId} + $prov + $body[0]' >"${OUT}"
rm -f -- "${OUT:?}.part"
log "record: ${OUT#"${ROOT}/"}"
jq -r '
    "receipt gas: " + ([.perOperation | to_entries[] | "\(.key) \(.value.receiptGas)"] | join(", ")),
    "lifecycle: \(.lifecycle.receiptGas) gas, \(.lifecycle.rawTransactionBytes) B, $\(.lifecycle.usd), L1 data \(.lifecycle.l1DataShare * 100)%",
    "t_incl registers (ms): median \(.tIncl.registers.median), p25 \(.tIncl.registers.p25), p75 \(.tIncl.registers.p75)",
    "L1/L2: \(.comparisonWithL1.l1OverL2)x; reconciliation: " + ([.perOperation | to_entries[] | "\(.key) \(.value.reconciliation.difference)"] | join(", "))
' "${OUT}" >&2
