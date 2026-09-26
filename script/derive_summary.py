#!/usr/bin/env python3
"""Derives the summary of the measurements from committed records, without network access and
without measuring anything: dollar figures on Layer 1 and Layer 2, their ratio, the freshness budget,
and the Groth16 factor.

Inputs, the newest record of each kind (L1 and Groth16 records taken on the Osaka schedule):
  measurements/l1/          gas per operation, lifecycle, deployment
  measurements/l1_price/    L1 base and priority fees per block, ETH/USD (Chainlink)
  measurements/l2/          Base Sepolia receipts priced with Base mainnet parameters
  measurements/offchain/    proving, verification, signing, and local inclusion times
  measurements/groth16/     on-chain Groth16 verification gas

The L1 gas price is the median over the price record's blocks of base fee + median priority fee,
recomputed exactly from the per-block samples in that record. The output depends on the inputs only:
the same inputs give the same file, named after the newest input's run identifier.

Usage: python3 script/derive_summary.py [--check]
  --check  exit with status 1 if the summary of the current inputs is missing or differs
"""

import hashlib
import json
import subprocess
import sys
from fractions import Fraction
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent.parent
MEAS = ROOT / "measurements"
LIFECYCLE = ["Register", "Apply", "Engage", "Settle"]
SENSITIVITY_GWEI = ["0.1", "1", "10", "30"]


def newest(kind, where=lambda r: True):
    for path in sorted((MEAS / kind).glob("*.json"), reverse=True):
        record = json.loads(path.read_text())
        if where(record):
            return path, record
    sys.exit(f"no suitable record in measurements/{kind}")


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.strip()


def describe(path, record):
    rel = path.relative_to(ROOT).as_posix()
    committed = git("log", "-1", "--format=%H", "--", rel)
    if not committed or git("status", "--porcelain", "--", rel):
        sys.exit(f"{rel} is not committed")
    return {"file": rel, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "measuredAtCommit": record.get("commit"), "committedIn": committed}


def usd(wei, eth_usd):
    return round(float(Fraction(wei) / 10**18 * eth_usd), 8)


def main():
    l1_path, l1 = newest("l1", lambda r: r["parameters"].get("anvilHardfork") == "Osaka")
    price_path, price = newest("l1_price")
    l2_path, l2 = newest("l2")
    off_path, off = newest("offchain")
    g16_path, g16 = newest("groth16", lambda r: r["parameters"].get("anvilHardfork") == "Osaka")
    inputs = {"l1": (l1_path, l1), "l1Price": (price_path, price), "l2": (l2_path, l2),
              "offchain": (off_path, off), "groth16": (g16_path, g16)}

    # L1 price: median over blocks of (base fee + median priority fee), exact, in wei.
    samples = price["samples"]
    effective = [b + p for b, p in zip(samples["baseFeeWei"], samples["medianPriorityFeeWei"])]
    price_wei = Fraction(median(effective)).limit_denominator(2)
    eth_usd = Fraction(str(price["ethUsd"]["price"]))

    def l1_usd(gas, wei_per_gas=price_wei):
        return usd(gas * wei_per_gas, eth_usd)

    lc = l1["lifecycle"]
    receipt_no_refund = lc["executionGas"] + 21000 * len(LIFECYCLE) + lc["calldataGas"]
    layer1 = {
        "gasPriceWei": str(price_wei), "gasPriceGwei": float(price_wei / 10**9),
        "perOperationExecution": {op: {"gas": v["executionGas"], "usd": l1_usd(v["executionGas"])}
                                  for op, v in l1["perOperation"].items()},
        "lifecycleExecution": {"gas": lc["executionGas"], "usd": l1_usd(lc["executionGas"])},
        "lifecycleReceiptWithRefunds": {"gas": lc["receiptGas"], "usd": l1_usd(lc["receiptGas"])},
        "lifecycleReceiptWithoutRefunds": {"gas": receipt_no_refund, "usd": l1_usd(receipt_no_refund)},
        "deploymentTransactions": {name: {"gas": d["transactionGas"], "usd": l1_usd(d["transactionGas"])}
                                   for name, d in l1["deployment"].items()}
                                  | {"total": {"gas": l1["deploymentTotal"]["transactionGas"],
                                               "usd": l1_usd(l1["deploymentTotal"]["transactionGas"])}},
        "lifecycleExecutionSensitivity": {f"{g} gwei": l1_usd(lc["executionGas"], Fraction(g) * 10**9)
                                          for g in SENSITIVITY_GWEI},
    }

    l2_ops = {op: {"receiptGas": v["receiptGas"], "usd": usd(v["mainnet"]["totalWei"], eth_usd),
                   "l1DataShare": v["mainnet"]["l1DataShare"]} for op, v in l2["perOperation"].items()}
    l2_lifecycle_usd = usd(l2["lifecycle"]["totalWei"], eth_usd)
    layer2 = {
        "perOperation": l2_ops,
        "lifecycle": {"receiptGas": l2["lifecycle"]["receiptGas"], "usd": l2_lifecycle_usd,
                      "rawTransactionBytes": l2["lifecycle"]["rawTransactionBytes"],
                      "l1DataShare": l2["lifecycle"]["l1DataShare"]},
        "mainnetBlock": l2["mainnetSnapshot"]["block"],
    }
    ratio = {"l1LifecycleReceiptUsd": layer1["lifecycleReceiptWithRefunds"]["usd"],
             "l2LifecycleUsd": l2_lifecycle_usd,
             "l1OverL2": round(layer1["lifecycleReceiptWithRefunds"]["usd"] / l2_lifecycle_usd, 2),
             "basis": "receipt gas on both layers (refunds netted), same ETH/USD"}

    s = off["summary"]
    delta_ms = off["parameters"]["deltaS"] * 1000

    def budget(t_incl, source):
        parts = {"tProveMs": s["tProveMs"]["median"], "tVerifyMs": s["tVerifyMs"]["median"],
                 "tSignMs": s["tSignMs"]["median"], "tInclMs": t_incl}
        total = round(sum(parts.values()), 3)
        return {"tInclSource": source, "components": parts, "totalMs": total, "deltaMs": delta_ms,
                "totalOverDelta": round(total / delta_ms, 6)}

    delta_budget = {
        "formula": "Delta >= t_prove + t_verify + t_sign + t_incl (medians; t_prove = witness generation + snarkjs)",
        "localAnvil": budget(s["tInclLocalMs"]["median"], "offchain record, local anvil node, n = 20"),
        "baseSepolia": budget(l2["tIncl"]["registers"]["median"], "L2 record, Register on Base Sepolia, n = 10"),
    }

    verify_gas = g16["verification"]["executionGas"]
    groth16 = {"verificationExecutionGas": verify_gas, "publicInputs": g16["parameters"]["publicInputs"],
               "lifecycleExecutionGas": lc["executionGas"],
               "lifecycleWithThreeVerificationsGas": lc["executionGas"] + 3 * verify_gas,
               "factor": round((lc["executionGas"] + 3 * verify_gas) / lc["executionGas"], 4),
               "assumption": g16["threeVerificationsOnChain"]["assumption"]}

    newest_run = max(r["runId"] for _, r in inputs.values())
    summary = {
        "derivedBy": {"script": "script/derive_summary.py",
                      "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "inputs": {k: describe(p, r) for k, (p, r) in inputs.items()},
        "ethUsd": {"price": float(eth_usd), "block": price["ethUsd"]["block"], "chain": price["ethUsd"]["chain"]},
        "layer1": layer1,
        "layer2": layer2,
        "l1OverL2": ratio,
        "deltaBudget": delta_budget,
        "groth16": groth16,
    }
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    out = MEAS / "summary" / f"{newest_run}.json"
    if "--check" in sys.argv:
        sys.exit(0 if out.exists() and out.read_text() == text else f"{out.relative_to(ROOT)} is missing or out of date")
    out.parent.mkdir(exist_ok=True)
    out.write_text(text)
    print(out.relative_to(ROOT))


if __name__ == "__main__":
    main()
