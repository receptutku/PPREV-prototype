#!/usr/bin/env bash
# Records the state of the test suites (stage (e)): forge tests by kind, the invariant campaign's runs
# and depth, the Table VI coverage report of the same forge run, cargo tests (the ignored clock-shift
# tests are run separately under libfaketime when it is installed), and line, statement, branch, and
# function coverage of contracts/src.
#
# Output: measurements/tests/<run>.json. Refuses a dirty working tree (PPREV_ALLOW_DIRTY=1 with
# PPREV_MEASUREMENTS_DIR for a trial run).
set -euo pipefail

LOG_TAG=tests
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

OUT_DIR="${MEASUREMENTS_DIR:?}/tests"
preflight
require_clean_tree
init_run tests
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
PROVENANCE="$(provenance_json)"

log "forge test"
(cd "${ROOT}/contracts" && forge build -q && forge test --json >"${WORK}/forge.json" 2>"${WORK}/forge-stderr.txt") \
    || die "forge test failed"
log "Table VI coverage (same forge run)"
python3 "${ROOT}/script/table6_coverage.py" "${WORK}/forge.json" >"${WORK}/table6.txt" 2>&1 \
    && TABLE6_EXIT=0 || TABLE6_EXIT=$?
log "forge coverage of contracts/src"
(cd "${ROOT}/contracts" && forge coverage --report summary --no-match-coverage '(test|script)/' \
    >"${WORK}/coverage.txt" 2>&1) || die "forge coverage failed"
log "cargo test"
(cd "${ROOT}" && cargo test --release --workspace >"${WORK}/cargo.txt" 2>&1) || die "cargo test failed"
(cd "${ROOT}" && cargo test --release --workspace -- --list --ignored 2>/dev/null | grep ': test$' >"${WORK}/cargo-ignored.txt") || true
FAKETIME="not run: libfaketime not found"
if [ -f /opt/homebrew/lib/faketime/libfaketime.1.dylib ] || [ -f /usr/local/lib/faketime/libfaketime.1.dylib ]; then
    log "ignored clock-shift tests under libfaketime"
    (cd "${ROOT}" && cargo test --release -p pprev-prover --test time -- --include-ignored >"${WORK}/cargo-time.txt" 2>&1) \
        && FAKETIME=ran || FAKETIME=failed
fi

python3 - "${WORK}" "${ROOT}" "${OUT}.part" "${TABLE6_EXIT}" "${FAKETIME}" <<'PY'
import json, re, sys, tomllib

work, root, out, table6_exit, faketime = sys.argv[1:6]
forge = json.load(open(f"{work}/forge.json"))
cfg = tomllib.load(open(f"{root}/contracts/foundry.toml", "rb"))

by_kind, failed, entries_with_predicates, predicates, invariant_runs = {}, [], 0, 0, []
for suite_key, suite in forge.items():
    for name, res in suite["test_results"].items():
        kind = next(iter(res["kind"]))
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if res["status"] != "Success":
            failed.append(f"{suite_key}::{name}")
        if kind == "Invariant":
            invariant_runs.append({"test": name.split("(")[0], "runs": res["kind"]["Invariant"]["runs"],
                                   "calls": res["kind"]["Invariant"]["calls"], "reverts": res["kind"]["Invariant"]["reverts"]})
        if res.get("invariant_predicate_results"):
            entries_with_predicates += 1
            predicates += len(res["invariant_predicate_results"])
total = sum(by_kind.values())

table6 = open(f"{work}/table6.txt").read()
m = re.search(r"Tests: (\d+)/(\d+) passed; invariants: (\d+)/(\d+) held", table6)
t6 = {"testsPassed": int(m[1]), "tests": int(m[2]), "invariantsHeld": int(m[3]), "invariants": int(m[4])} if m else None

def cargo_totals(path):
    p = f = i = 0
    for line in open(path):
        r = re.match(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", line)
        if r:
            p, f, i = p + int(r[1]), f + int(r[2]), i + int(r[3])
    return {"passed": p, "failed": f, "ignored": i}

coverage = {}
for line in open(f"{work}/coverage.txt"):
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) == 5 and (cells[0].startswith("src/") or cells[0] == "Total"):
        pct = lambda c: {"percent": float(c.split("%")[0]), "covered": c.split("(")[1].rstrip(")")}
        coverage[cells[0]] = {"lines": pct(cells[1]), "statements": pct(cells[2]),
                              "branches": pct(cells[3]), "functions": pct(cells[4])}

result = {
    "forge": {
        "total": total, "byKind": by_kind, "failed": failed,
        "fuzzConfig": {"runs": cfg["fuzz"]["runs"], "seed": cfg["fuzz"]["seed"]},
        "invariantConfig": {"runs": cfg["invariant"]["runs"], "depth": cfg["invariant"]["depth"],
                            "failOnRevert": cfg["invariant"]["fail_on_revert"]},
        "invariantRuns": invariant_runs,
    },
    "table6Coverage": {
        "exitStatus": int(table6_exit), "summary": t6, "report": table6.splitlines(),
        "howItCounts": "forge reports every test function, invariant functions included. table6_coverage.py counts a result as invariants when it carries invariant predicate results (one per predicate) and as a test otherwise.",
        "reconciliation": {"forgeTotal": total, "forgeInvariantFunctions": by_kind.get("Invariant", 0),
                           "resultsWithPredicates": entries_with_predicates, "predicates": predicates,
                           "table6Tests": t6 and t6["tests"], "table6Invariants": t6 and t6["invariants"]},
    },
    "cargo": {"workspace": cargo_totals(f"{work}/cargo.txt"),
              "ignoredTests": [l.split(": test")[0] for l in open(f"{work}/cargo-ignored.txt")],
              "ignoredUnderLibfaketime": (cargo_totals(f"{work}/cargo-time.txt") | {"status": faketime})
                                         if faketime in ("ran", "failed") else {"status": faketime}},
    "coverageContractsSrc": coverage,
}
json.dump(result, open(out, "w"), indent=2)
PY

jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --slurpfile body "${OUT}.part" \
    '{runId: $runId} + $prov + $body[0]' >"${OUT}"
rm -f -- "${OUT:?}.part"
log "record: ${OUT#"${ROOT}/"}"
jq -r '
    "forge: \(.forge.total) (\(.forge.byKind | to_entries | map("\(.key) \(.value)") | join(", "))), failed \(.forge.failed | length)",
    "table6: \(.table6Coverage.summary.testsPassed)/\(.table6Coverage.summary.tests) tests, \(.table6Coverage.summary.invariantsHeld)/\(.table6Coverage.summary.invariants) invariants, exit \(.table6Coverage.exitStatus)",
    "cargo: \(.cargo.workspace.passed) passed, \(.cargo.workspace.failed) failed, \(.cargo.workspace.ignored) ignored; libfaketime: \(.cargo.ignoredUnderLibfaketime)",
    "coverage src total: lines \(.coverageContractsSrc.Total.lines.percent)%, branches \(.coverageContractsSrc.Total.branches.percent)%"
' "${OUT}" >&2
