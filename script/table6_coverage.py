#!/usr/bin/env python3
"""Map the contract-side conditions of Table VI, and the conditions outside it, to the Foundry
tests that exercise them, using the condition label in each test name, and report the outcome.

Test names carry the label: test_R_b_... is condition R(b), test_Engage_ii_... is Engage (ii);
"accepts" marks a positive test and "reverts" a negative one. Scenario tests for the five attack
classes are named test_P1_... to test_P5_.

Usage:
    python3 script/table6_coverage.py              # runs `forge test --json` in contracts/
    python3 script/table6_coverage.py results.json # reads saved `forge test --json` output

Exits with status 1 if any condition lacks a passing positive or negative test, or any test fails.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Contract column of Table VI.
TABLE_VI = {
    "P1 Freshness": ["R(e)", "A(f)", "S(g)"],
    "P2 Transaction binding": ["R(b)", "R(c)", "R(f)", "A(c)", "A(d)", "S(d)", "S(e)", "R(d)", "A(e)", "S(f)"],
    "P3 Phase binding": ["R(c)", "A(d)", "S(e)"],
    "P4 Settlement integrity": ["R(h)", "S(b)", "S(c)", "S(d)", "S(h)", "E(a)", "E(b)", "E(c)"],
    "P5 Sender binding": ["R(c)", "A(d)", "S(e)", "S(b)"],
}

# Negative tests of a shared signature condition that target one property.
ASPECTS = {
    "P1 Freshness": r"AfterWindow|FutureAttestation",
    "P2 Transaction binding": r"OtherChain|OtherDeployment|OtherListing|OtherEngagement|Signed(Nonce|Timestamp|Cb|Expiry)Differs",
    "P3 Phase binding": r"OtherPhaseTag|RegistrationPolicy",
    "P4 Settlement integrity": r"ShareRaised|PreviousRound|DoubleSettlement|Counterparty",
    "P5 Sender binding": r"OtherSubmitter|BeforeSignatureCheck",
}

OUTSIDE = ["R(a)", "R(g)", "A(a)", "A(b)", "A(g)", "A(h)", "Engage (i)", "Engage (ii)", "Engage (iii)"]

LABEL = re.compile(r"^test_(?:(R|A|S|E)_([a-h])|Engage_(i{1,3}))_(accepts|reverts)")


def load(argv):
    if len(argv) > 1:
        return json.loads(Path(argv[1]).read_text())
    out = subprocess.run(
        ["forge", "test", "--json"], cwd=ROOT / "contracts", capture_output=True, text=True, check=False
    )
    return json.loads(out.stdout)


def collect(results):
    tests, invariants = [], []
    for suite_key, suite in results.items():
        suite_name = suite_key.split(":")[-1]
        for name, res in suite["test_results"].items():
            ok = res["status"] == "Success"
            if res.get("invariant_predicate_results"):
                for pred in res["invariant_predicate_results"]:
                    invariants.append((pred["name"], pred["status"] == "Success"))
                continue
            tests.append((suite_name, name.split("(")[0], ok))
    return tests, invariants


def condition_of(test_name):
    m = LABEL.match(test_name)
    if not m:
        return None, None
    phase, letter, engage, kind = m.groups()
    cond = f"Engage ({engage})" if engage else f"{phase}({letter})"
    return cond, "positive" if kind == "accepts" else "negative"


def main(argv):
    tests, invariants = collect(load(argv))
    by_cond = {}
    for suite, name, ok in tests:
        cond, kind = condition_of(name)
        if cond:
            by_cond.setdefault(cond, {"positive": [], "negative": []})[kind].append((suite, name, ok))

    in_table = sorted({c for conds in TABLE_VI.values() for c in conds}, key=lambda c: ("RASE".index(c[0]), c))
    gaps, failures = [], [f"{s}.{n}" for s, n, ok in tests if not ok]

    def row(cond, table_flag):
        entry = by_cond.get(cond, {"positive": [], "negative": []})
        pos, neg = entry["positive"], entry["negative"]
        pos_ok, neg_ok = sum(ok for *_, ok in pos), sum(ok for *_, ok in neg)
        white_box = any(s == "WhiteBoxTest" for s, _, _ in neg)
        status = "covered" if pos_ok and neg_ok else "GAP"
        if status == "GAP":
            gaps.append(cond)
        note = " (negative via white-box)" if white_box and not any(s != "WhiteBoxTest" for s, _, _ in neg) else ""
        return f"| {cond} | {table_flag} | {pos_ok}/{len(pos)} | {neg_ok}/{len(neg)} | {status}{note} |"

    print("## Contract conditions\n")
    print("| Condition | In Table VI | Positive passed/total | Negative passed/total | Status |")
    print("|---|---|---|---|---|")
    for cond in in_table:
        print(row(cond, "yes"))
    for cond in OUTSIDE:
        print(row(cond, "no"))

    print("\n## Table VI properties\n")
    print("| Property | Conditions | Property-specific negative tests | Attack-scenario tests |")
    print("|---|---|---|---|")
    for prop, conds in TABLE_VI.items():
        aspect = re.compile(ASPECTS[prop])
        aspect_tests = [(n, ok) for s, n, ok in tests if LABEL.match(n) and "reverts" in n and aspect.search(n)]
        tag = prop.split()[0]
        scenario = [(n, ok) for s, n, ok in tests if n.startswith(f"test_{tag}_")]
        a_ok, s_ok = sum(ok for _, ok in aspect_tests), sum(ok for _, ok in scenario)
        print(f"| {prop} | {', '.join(conds)} | {a_ok}/{len(aspect_tests)} | {s_ok}/{len(scenario)} |")

    print("\n## Invariants\n")
    print("| Invariant | Status |")
    print("|---|---|")
    for name, ok in invariants:
        print(f"| {name} | {'pass' if ok else 'FAIL'} |")

    passed = sum(ok for *_, ok in tests)
    print(
        f"\nTests: {passed}/{len(tests)} passed; invariants: {sum(ok for _, ok in invariants)}/{len(invariants)} held."
    )
    print(f"Conditions without a passing positive and negative test: {', '.join(gaps) if gaps else 'none'}.")
    if failures:
        print("Failed tests: " + ", ".join(failures))
    return 1 if gaps or failures or not all(ok for _, ok in invariants) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
