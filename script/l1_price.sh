#!/usr/bin/env bash
# Ethereum mainnet gas price snapshot and ETH/USD (Req 10, D38), and the dollar cost of the L1 record.
#
# Usage: script/l1_price.sh [newest_block] [block_count]
#   newest_block  default: the latest finalised block
#   block_count   default: 7200 (one day of 12-second slots)
#
# Reads ETH_MAINNET_RPC_URL from .env. For every block of the range, eth_feeHistory gives the base fee
# and the median (gas-weighted 50th percentile) priority fee; the effective price of a block is their
# sum. ETH/USD is one reading of the Chainlink ETH/USD feed on Ethereum mainnet at the newest block of
# the range; measure_l2.sh takes the price from this record instead of reading it again, so L1 and L2
# dollar figures rest on the same price. The dollar costs use the gas of the newest L1 record
# (measurements/l1/, override with PPREV_L1_RECORD).
#
# Output: measurements/l1_price/<run>.json. Refuses a dirty working tree (PPREV_ALLOW_DIRTY=1 with
# PPREV_MEASUREMENTS_DIR for a trial run). The RPC URL is never printed.
set -euo pipefail

LOG_TAG=l1-price
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Chainlink ETH/USD aggregator proxy on Ethereum mainnet.
CHAINLINK_ETH_USD="0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"
FEE_HISTORY_MAX=1024
OUT_DIR="${MEASUREMENTS_DIR:?}/l1_price"

for tool in cast jq python3 git; do
    command -v "${tool}" >/dev/null || die "missing tool: ${tool}"
done
require_clean_tree
[ -f "${ROOT}/.env" ] || die ".env not found"
ETH_MAINNET_RPC_URL="$(
    set -a
    # shellcheck disable=SC1091
    . "${ROOT}/.env"
    printf '%s' "${ETH_MAINNET_RPC_URL:-}"
)"
[ -n "${ETH_MAINNET_RPC_URL}" ] || die "ETH_MAINNET_RPC_URL is empty in .env"

L1_RECORD="${PPREV_L1_RECORD:-$(find "${ROOT}/measurements/l1" -name '*.json' 2>/dev/null | sort | tail -n 1)}"
[ -f "${L1_RECORD}" ] || die "no L1 record in measurements/l1; run script/measure.sh"

init_run l1_price
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"

# rpc <args...>: cast against mainnet; failures are reported without the URL.
rpc() { cast "$@" --rpc-url "${ETH_MAINNET_RPC_URL}" 2>/dev/null || die "RPC call failed: cast $1"; }

[ "$(rpc chain-id)" = 1 ] || die "ETH_MAINNET_RPC_URL is not Ethereum mainnet"
if [ -n "${1:-}" ]; then
    NEWEST="$1"
    NEWEST_SOURCE=given
else
    NEWEST="$(rpc block finalized -f number)"
    NEWEST_SOURCE="latest finalised block at run time"
fi
COUNT="${2:-7200}"
OLDEST=$((NEWEST - COUNT + 1))
log "blocks ${OLDEST}..${NEWEST} (${COUNT})"

# eth_feeHistory returns at most FEE_HISTORY_MAX blocks per call.
: >"${WORK}/fee-history.jsonl"
end="${NEWEST}"
while [ "${end}" -ge "${OLDEST}" ]; do
    n=$((end - OLDEST + 1))
    [ "${n}" -le "${FEE_HISTORY_MAX}" ] || n="${FEE_HISTORY_MAX}"
    rpc rpc eth_feeHistory "$(printf '0x%x' "${n}")" "$(printf '0x%x' "${end}")" '[50]' \
        | jq -c --argjson n "${n}" '{oldest: (.oldestBlock), baseFeePerGas: .baseFeePerGas[0:$n], reward: .reward, gasUsedRatio: .gasUsedRatio}' \
            >>"${WORK}/fee-history.jsonl"
    end=$((end - n))
done

FIRST_TS="$(rpc block "${OLDEST}" -f timestamp)"
LAST_TS="$(rpc block "${NEWEST}" -f timestamp)"
[ "$(rpc call "${CHAINLINK_ETH_USD}" 'description()(string)' --block "${NEWEST}")" = '"ETH / USD"' ] \
    || die "the Chainlink proxy is not the ETH / USD feed"
DECIMALS="$(rpc call "${CHAINLINK_ETH_USD}" 'decimals()(uint8)' --block "${NEWEST}")"
ROUND="$(rpc call "${CHAINLINK_ETH_USD}" 'latestRoundData()(uint80,int256,uint256,uint256,uint80)' --block "${NEWEST}" \
    | awk '{print $1}' | paste -sd ' ' -)"
PROVENANCE="$(jq -n --arg c "$(git -C "${ROOT}" rev-parse HEAD)" --argjson d "$(git_dirty)" \
    --arg cast "$(first_line cast --version)" '{commit: $c, workingTreeDirty: $d, tools: {cast: $cast}}')"

python3 - "${WORK}/fee-history.jsonl" "${L1_RECORD}" "${OUT}.part" "${OLDEST}" "${NEWEST}" \
    "${FIRST_TS}" "${LAST_TS}" "${CHAINLINK_ETH_USD}" "${DECIMALS}" "${ROUND}" "${ROOT}" "${NEWEST_SOURCE}" <<'PY'
import json, statistics, sys

(hist_path, l1_path, out, oldest, newest, first_ts, last_ts, feed, decimals, round_data, root,
 newest_source) = sys.argv[1:13]
oldest, newest, decimals = int(oldest), int(newest), int(decimals)
blocks = {}
for line in open(hist_path):
    h = json.loads(line)
    start = int(h["oldest"], 16)
    for i, (base, reward) in enumerate(zip(h["baseFeePerGas"], h["reward"])):
        blocks[start + i] = (int(base, 16), int(reward[0], 16))
numbers = list(range(oldest, newest + 1))
missing = [b for b in numbers if b not in blocks]
if missing:
    sys.exit(f"fee history is missing {len(missing)} blocks, first {missing[0]}")
base = [blocks[b][0] for b in numbers]
prio = [blocks[b][1] for b in numbers]
eff = [b + p for b, p in zip(base, prio)]

def summary(xs):
    q = statistics.quantiles(xs, n=4, method="inclusive")
    gwei = lambda v: round(v / 1e9, 6)
    return {"meanGwei": gwei(statistics.fmean(xs)), "medianGwei": gwei(statistics.median(xs)),
            "p25Gwei": gwei(q[0]), "p75Gwei": gwei(q[2]), "minGwei": gwei(min(xs)), "maxGwei": gwei(max(xs))}

round_id, answer, started_at, updated_at, answered_in = round_data.split()
eth_usd = int(answer) / 10 ** decimals
price_gwei = statistics.median(eff) / 1e9

l1 = json.load(open(l1_path))
usd = lambda gas, gwei=price_gwei: round(gas * gwei * 1e-9 * eth_usd, 6)
lc = l1["lifecycle"]
lifecycle_ops = lc["operations"]
exec_gas = lc["executionGas"]
no_refund = exec_gas + 21000 * len(lifecycle_ops) + lc["calldataGas"]

result = {
    "blockRange": {"oldest": oldest, "newest": newest, "count": len(numbers),
                   "oldestTimestamp": int(first_ts), "newestTimestamp": int(last_ts),
                   "spanSeconds": int(last_ts) - int(first_ts), "newestBlockSource": newest_source},
    "method": "eth_feeHistory with reward percentile 50 per block; effective price = base fee + median priority fee of the block; dollar figures use the median effective price over the range",
    "baseFee": summary(base),
    "medianPriorityFee": summary(prio),
    "effectivePrice": summary(eff),
    "ethUsd": {"feed": feed, "chain": "Ethereum mainnet", "description": "ETH / USD", "block": newest,
               "roundId": round_id, "answer": answer, "decimals": decimals, "price": eth_usd,
               "updatedAt": int(updated_at)},
    "costBasis": {"l1Record": l1_path.replace(root + "/", ""), "l1RecordCommit": l1.get("commit"),
                  "gasPriceGwei": round(price_gwei, 6), "ethUsd": eth_usd},
    "costsUsd": {
        "perOperationExecution": {k: usd(v["executionGas"]) for k, v in l1["perOperation"].items()},
        "lifecycle": {
            "executionGas": exec_gas, "execution": usd(exec_gas),
            "receiptGasWithoutRefund": no_refund, "receiptWithoutRefund": usd(no_refund),
            "receiptGas": lc["receiptGas"], "receipt": usd(lc["receiptGas"]),
        },
        "deploymentTransaction": {k: usd(v["transactionGas"]) for k, v in l1["deployment"].items()}
                                 | {"total": usd(l1["deploymentTotal"]["transactionGas"])},
        "lifecycleExecutionSensitivity": {f"{g}Gwei": usd(exec_gas, g) for g in (0.1, 1, 10, 30)},
    },
    "samples": {"blocks": numbers[0], "baseFeeWei": base, "medianPriorityFeeWei": prio},
}
json.dump(result, open(out, "w"), indent=2)
PY

jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --slurpfile body "${OUT}.part" \
    '{runId: $runId} + $prov + $body[0]' >"${OUT}"
rm -f -- "${OUT:?}.part"
log "record: ${OUT#"${ROOT}/"}"
jq -r '
    "blocks \(.blockRange.oldest)..\(.blockRange.newest) (\(.blockRange.spanSeconds) s)",
    "base fee median \(.baseFee.medianGwei) gwei, priority median \(.medianPriorityFee.medianGwei) gwei, effective median \(.effectivePrice.medianGwei) (mean \(.effectivePrice.meanGwei)) gwei",
    "ETH/USD \(.ethUsd.price) at block \(.ethUsd.block)",
    "lifecycle: execution $\(.costsUsd.lifecycle.execution), receipts $\(.costsUsd.lifecycle.receipt)"
' "${OUT}" >&2
