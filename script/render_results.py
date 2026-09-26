#!/usr/bin/env python3
"""Renders the "Reproducing the results" table of README.md from the committed records.

Every value in the table is read from the newest record of each kind under measurements/; none is
written by hand. The time column is an estimate for the machine of the records, not a measurement.
The table goes between the markers `<!-- results:begin -->` and `<!-- results:end -->`.

Usage: python3 script/render_results.py [--check]
  --check  exit with status 1 if README.md is not up to date, without writing it
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
BEGIN, END = "<!-- results:begin -->", "<!-- results:end -->"


def newest(kind):
    files = sorted((ROOT / "measurements" / kind).glob("*.json"))
    if not files:
        sys.exit(f"no record in measurements/{kind}")
    return files[-1].relative_to(ROOT).as_posix(), json.load(open(files[-1]))


def n(v):
    return f"{v:,}"


def ms(s):
    return f"{s['median']:,.1f} ms (IQR {s['p25']:,.1f}-{s['p75']:,.1f})"


def mb(b):
    return f"{b / 1e6:,.1f} MB"


def usd(v):
    return f"${v:,.4f}" if v < 0.1 else f"${v:,.3f}"


def main():
    e2e_path, e2e = newest("e2e_register")
    off_path, off = newest("offchain")
    l1_path, l1 = newest("l1")
    price_path, price = newest("l1_price")
    g16_path, g16 = newest("groth16")
    l2_path, l2 = newest("l2")

    s = off["summary"]
    ops = ["Register", "Apply", "Engage", "Settle", "Expire", "Reclaim", "Cancel"]
    passed = sum(c["pass"] for c in e2e["checks"])
    pe = e2e["positive"]["paperFormula"]
    dec = l1["decomposition"]
    storage = lambda op: sum(dec[op]["percent"][k] for k in
                             ("storageInitialisation", "storageUpdates", "coldStorageReads", "warmReaccesses"))
    d33 = off["d33"]
    stalled = d33["registerRuns"]["stalled"] + d33["sessionOnlyRuns"]["stalled"]
    started = d33["registerRuns"]["sessionsStarted"] + d33["sessionOnlyRuns"]["sessionsStarted"]
    lc = l1["lifecycle"]
    cost = price["costsUsd"]
    three = g16["threeVerificationsOnChain"]

    E2E = ("script/e2e_register.sh", e2e_path, "~3 min", "no")
    OFF = ("script/measure_offchain.sh", off_path, "~15 min", "no")
    L1 = ("script/measure.sh", l1_path, "~2 min", "no")
    PRICE = ("script/l1_price.sh", price_path, "~1 min", "yes: ETH_MAINNET_RPC_URL")
    G16 = ("script/measure_groth16.sh", g16_path, "~1 min", "no")
    L2 = ("script/measure_l2.sh", l2_path, "~4 min", "yes: BASE_SEPOLIA_RPC_URL, BASE_MAINNET_RPC_URL, TESTNET_PRIVATE_KEY")

    rows = [
        ("End-to-end Register: TLSNotary session, phi_R proof, notary signature, transaction; five negative cases",
         E2E, f"{passed}/{len(e2e['checks'])} checks pass"),
        ("Freshness budget of one Register run (t_prove + t_verify + t_sign + t_incl, local chain)",
         E2E, f"{n(round(pe['sumMs']))} ms, {pe['sumOverDelta'] * 100:.2f}% of Delta = {e2e['deployment']['deltaS']} s"),
        ("phi_R circuit size", OFF, f"{n(off['circuit']['constraints'])} constraints ({off['circuit']['optimization']})"),
        ("Proving time t_prove (witness generation + snarkjs), n = 20", OFF, ms(s["tProveMs"])),
        ("Policy verifier: t_verify (presentation checks + Groth16) and t_sign", OFF,
         f"t_verify {ms(s['tVerifyMs'])}; Groth16 alone {s['verifierGroth16Ms']['median']:.2f} ms; t_sign {ms(s['tSignMs'])}"),
        ("MPC-TLS session with the notary", OFF,
         f"{ms(s['mpcTlsMs'])}; {mb(s['mpcSentBytes']['median'])} sent, {mb(s['mpcReceivedBytes']['median'])} received"),
        ("Peak memory", OFF,
         f"snarkjs {mb(s['snarkjsPeakRssBytes']['median'])}, witness generator {mb(s['witnessPeakRssBytes']['median'])}, prover {mb(s['proverPeakRssBytes']['median'])} (medians)"),
        ("Freshness budget over 20 runs (medians, local t_incl)", OFF,
         f"{n(round(off['deltaBudget']['medianSumMs']))} ms, {off['deltaBudget']['medianSumOverDelta'] * 100:.2f}% of Delta"),
        ("MPC-TLS preprocessing stalls (tlsn#1173), recovered by retry", OFF,
         f"{stalled}/{started} sessions ({stalled / started * 100:.2f}%); {d33['sessionOnlyRunsFailed']} runs gave up"),
        ("Contract test suite", L1, l1["tests"].split(": ", 1)[-1]),
        ("On-chain execution gas per operation", L1,
         ", ".join(f"{op} {n(l1['perOperation'][op]['executionGas'])}" for op in ops)),
        ("Lifecycle gas (Register + Apply + Engage + Settle)", L1,
         f"execution {n(lc['executionGas'])}; receipts {n(lc['receiptGas'])}; {n(lc['rawTransactionBytes'])} transaction bytes"),
        ("Deployment and bytecode size", L1,
         f"PPREV {n(l1['deployment']['PPREV']['transactionGas'])} gas, runtime {n(l1['deployment']['PPREV']['runtimeBytes'])} B "
         f"({l1['deployment']['PPREV']['runtimeBytesOfEip170Limit'] * 100:.1f}% of EIP-170); verifier "
         f"{n(l1['deployment']['EcdsaNotaryVerifier']['transactionGas'])} gas, {n(l1['deployment']['EcdsaNotaryVerifier']['runtimeBytes'])} B"),
        ("Cost decomposition of Register and Apply", L1,
         f"storage {storage('Register'):.1f}% and {storage('Apply'):.1f}%; slots initialised {dec['Register']['slots']['initialised']} and "
         f"{dec['Apply']['slots']['initialised']}; ECDSA marginal {n(dec['Register']['components']['ecdsaMarginal'])} and "
         f"{n(dec['Apply']['components']['ecdsaMarginal'])} gas"),
        ("ECDSA verifier call", L1,
         f"frame {n(l1['verifierCalls']['ecdsaFrame'])} gas against {n(l1['verifierCalls']['acceptAllFrame'])} for an accept-all verifier"),
        ("Receipts against measured gas (signature-dependent difference)", L1,
         ", ".join(f"{op} {v['difference']:+d}" for op, v in l1["reconciliation"].items()) + " gas"),
        ("L1 gas price snapshot (one day of blocks)", PRICE,
         f"blocks {n(price['blockRange']['oldest'])}-{n(price['blockRange']['newest'])}; base fee {price['baseFee']['medianGwei']} gwei, "
         f"priority fee {price['medianPriorityFee']['medianGwei']} gwei, effective {price['effectivePrice']['medianGwei']} gwei (medians)"),
        ("ETH/USD (Chainlink, one reading, used for L1 and L2)", PRICE,
         f"${price['ethUsd']['price']:,.2f} at block {n(price['ethUsd']['block'])}"),
        ("L1 lifecycle cost", PRICE,
         f"execution {usd(cost['lifecycle']['execution'])}, receipts {usd(cost['lifecycle']['receipt'])}; deployment {usd(cost['deploymentTransaction']['total'])}"),
        ("On-chain Groth16 verification of phi_R (9 public inputs)", G16,
         f"{n(g16['verification']['executionGas'])} gas execution; EIP-1108 model {n(g16['eip1108Model']['total'])}"),
        ("Lifecycle with three predicate verifications on-chain", G16,
         f"+{n(three['addedExecutionGas'])} gas, x{three['factor']} (assumes phi_A, phi_S verified like phi_R)"),
        ("L2 receipt gas per operation (Base Sepolia)", L2,
         ", ".join(f"{op} {n(l2['perOperation'][op]['receiptGas'])}" for op in ops)),
        ("L2 cost per operation (Base mainnet prices)", L2,
         ", ".join(f"{op} {usd(l2['perOperation'][op]['mainnet']['usd'])}" for op in ops)),
        ("L2 lifecycle cost and L1 data share", L2,
         f"{usd(l2['lifecycle']['usd'])}, {n(l2['lifecycle']['rawTransactionBytes'])} bytes; L1 data {l2['lifecycle']['l1DataShare'] * 100:.2f}% "
         f"(per operation {l2['l1DataShareRange']['min'] * 100:.2f}-{l2['l1DataShareRange']['max'] * 100:.2f}%)"),
        ("Inclusion time t_incl on Base Sepolia (Register, n = 10)", L2, ms(l2["tIncl"]["registers"])),
        ("L1 against L2 lifecycle cost", L2, f"L1 {l2['comparisonWithL1']['l1OverL2']}x L2"),
    ]

    lines = [
        BEGIN,
        "<!-- Generated by script/render_results.py from the newest record of each kind; do not edit. -->",
        "",
        "| Result | Command | Record | Recorded value | Time (estimate) | Network |",
        "|---|---|---|---|---|---|",
    ]
    for name, (cmd, path, time, net), value in rows:
        lines.append(f"| {name} | `{cmd}` | `{path}` | {value} | {time} | {net} |")
    lines.append(END)
    table = "\n".join(lines)

    text = README.read_text()
    start, end = text.index(BEGIN), text.index(END) + len(END)
    updated = text[:start] + table + text[end:]
    if "--check" in sys.argv:
        sys.exit(0 if updated == text else "README.md results table is out of date; run script/render_results.py")
    README.write_text(updated)


if __name__ == "__main__":
    main()
