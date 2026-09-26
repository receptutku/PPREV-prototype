"""Builds the Layer-2 record of script/measure_l2.sh from the campaign results.

Usage: l2_report.py <work dir> <l1 record> <l1 price record> <out>

Pricing with Base mainnet parameters of one block (mainnet.json):
  L2 execution fee  = receipt gas x (base fee + median priority fee of the block)
  L1 data fee       = the transaction's Fjord L1 fee on Base Sepolia (receipt) x S_mainnet / S_tx, where
                      S = 16 * baseFeeScalar * l1BaseFee + blobBaseFeeScalar * blobBaseFee. The Fjord
                      size term depends on the transaction bytes alone, so the rescaling is exact when
                      both chains run the Fjord cost function (checked).
  operator fee      = gas x operatorFeeScalar x 100 + operatorFeeConstant (Jovian), zero when both are 0
Dollar figures use the ETH/USD reading of the L1 price record.
"""

import glob
import json
import statistics
import sys

work, l1_path, price_path, out = sys.argv[1:5]
params = json.load(open(f"{work}/params.json"))
mainnet = json.load(open(f"{work}/mainnet.json"))
sepolia = json.load(open(f"{work}/sepolia.json"))
balances = json.load(open(f"{work}/balances.json"))
l1 = json.load(open(l1_path))
price = json.load(open(price_path))
eth_usd = price["ethUsd"]["price"]

txs = []
for path in sorted(glob.glob(f"{work}/results-*.jsonl")):
    txs += [json.loads(line) for line in open(path)]
txs.sort(key=lambda t: (t["blockNumber"], t["sentAtUnixMs"]))
by_label = {t["label"]: t for t in txs}

assert mainnet["isFjord"] and sepolia["isFjord"], "both chains must use the Fjord L1 cost function"
l2_price = mainnet["baseFeePerGas"] + mainnet["medianPriorityFeePerGas"]
s_main = 16 * mainnet["baseFeeScalar"] * mainnet["l1BaseFee"] + mainnet["blobBaseFeeScalar"] * mainnet["blobBaseFee"]


def priced(t):
    l1f = t["l1"]
    s_tx = 16 * l1f["l1BaseFeeScalar"] * l1f["l1GasPrice"] + l1f["l1BlobBaseFeeScalar"] * l1f["l1BlobBaseFee"]
    l1_fee = l1f["l1Fee"] * s_main // s_tx
    l2_fee = t["gasUsed"] * l2_price
    op_fee = t["gasUsed"] * mainnet["operatorFeeScalar"] * 100 + mainnet["operatorFeeConstant"]
    total = l2_fee + l1_fee + op_fee
    return {"l2ExecutionFeeWei": l2_fee, "l1DataFeeWei": l1_fee, "operatorFeeWei": op_fee,
            "totalWei": total, "usd": round(total / 1e18 * eth_usd, 8),
            "l1DataShare": round(l1_fee / total, 6)}


OPS = {"Register": "register-A-1", "Apply": "apply-A-1", "Engage": "engage-A-1", "Settle": "settle-A-1",
       "Expire": "expire-B-1", "Reclaim": "reclaim-A-2", "Cancel": "cancel-A-3"}
LIFECYCLE = ["Register", "Apply", "Engage", "Settle"]

per_op = {}
for op, label in OPS.items():
    t = by_label[label]
    exec_l1 = l1["perOperation"][op]["executionGas"]
    refund = l1["perOperation"][op]["refund"]
    predicted = exec_l1 + 21000 + t["calldataGas"]
    predicted -= min(refund, predicted // 5)
    per_op[op] = {
        "label": label, "hash": t["hash"], "blockNumber": t["blockNumber"],
        "receiptGas": t["gasUsed"], "rawTransactionBytes": t["rawTransactionBytes"],
        "calldataBytes": t["calldataBytes"], "tInclMs": t["tInclMs"],
        "l1FeeFields": t["l1"], "daFootprintGasScalar": t["daFootprintGasScalar"], "blobGasUsed": t["blobGasUsed"],
        "mainnet": priced(t),
        "reconciliation": {"predictedFromL1Execution": predicted, "difference": t["gasUsed"] - predicted},
    }


def dist(xs):
    q = statistics.quantiles(xs, n=4, method="inclusive")
    r = lambda v: round(v, 3)
    return {"n": len(xs), "min": r(min(xs)), "p25": r(q[0]), "median": r(statistics.median(xs)),
            "p75": r(q[2]), "max": r(max(xs)), "mean": r(statistics.fmean(xs))}


lc = [per_op[o] for o in LIFECYCLE]
lc_total = sum(o["mainnet"]["totalWei"] for o in lc)
lc_l1 = sum(o["mainnet"]["l1DataFeeWei"] for o in lc)
lc_usd = round(lc_total / 1e18 * eth_usd, 8)

l1_lifecycle_gas = l1["lifecycle"]["receiptGas"]
l1_price_gwei = price["costBasis"]["gasPriceGwei"]
l1_lifecycle_usd = round(l1_lifecycle_gas * l1_price_gwei * 1e-9 * eth_usd, 8)

registers = [t for t in txs if t["label"].startswith("register-A-")]
spent = sum(t["gasUsed"] * t["effectiveGasPrice"] + t["l1"].get("l1Fee", 0) for t in txs)

result = {
    "network": {"campaign": "Base Sepolia (chain 84532)", "pricing": "Base mainnet (chain 8453)"},
    "fixture": params,
    "mainnetSnapshot": mainnet | {"l2GasPriceWei": l2_price, "scaledFeeTerm": s_main},
    "sepoliaAtCampaign": sepolia,
    "ethUsd": {"price": eth_usd, "source": price_path.split("/measurements/")[-1],
               "block": price["ethUsd"]["block"], "chain": price["ethUsd"]["chain"]},
    "perOperation": per_op,
    "lifecycle": {
        "operations": LIFECYCLE,
        "receiptGas": sum(o["receiptGas"] for o in lc),
        "rawTransactionBytes": sum(o["rawTransactionBytes"] for o in lc),
        "totalWei": lc_total, "usd": lc_usd,
        "l1DataShare": round(lc_l1 / lc_total, 6),
    },
    "l1DataShareRange": {"min": min(o["mainnet"]["l1DataShare"] for o in per_op.values()),
                         "max": max(o["mainnet"]["l1DataShare"] for o in per_op.values())},
    "comparisonWithL1": {
        "l1Record": l1_path.split("/measurements/")[-1], "l1LifecycleReceiptGas": l1_lifecycle_gas,
        "l1GasPriceGwei": l1_price_gwei, "l1LifecycleUsd": l1_lifecycle_usd,
        "l1OverL2": round(l1_lifecycle_usd / lc_usd, 2),
    },
    "tIncl": {"definition": "sending to the first read of the including block with the receipt's block hash; tReceipt is sending to the first (possibly preconfirmed) receipt",
              "registers": dist([t["tInclMs"] for t in registers]),
              "allTransactions": dist([t["tInclMs"] for t in txs]),
              "registersReceipt": dist([t["tReceiptMs"] for t in registers]),
              "allTransactionsReceipt": dist([t["tReceiptMs"] for t in txs])},
    "blocks": {"first": txs[0]["blockNumber"], "last": txs[-1]["blockNumber"]},
    "wallet": balances | {"spentOnFeesWei": spent},
    "transactions": txs,
}
json.dump(result, open(out, "w"), indent=2)
