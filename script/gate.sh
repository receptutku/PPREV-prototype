#!/usr/bin/env bash
# Repository gate with saved outputs: formatting, lints, the Rust workspace tests, the Solidity tests,
# the measurement helpers' tests, and shell syntax. Every tracked file is hashed before and after; the
# run fails on any difference. Output: measurements/gate/<run>/ (one log per step, results.json).
# Expects the ignored build inputs (circuits/build, circuits/node_modules, contracts/lib/forge-std).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${ROOT}/measurements/gate/${RUN_ID}"
mkdir -p "${OUT:?}"
cd "${ROOT}" || exit 1

hashes() { git ls-files -z | xargs -0 shasum -a 256; }
hashes >"${OUT}/source-before.sha256"
DIRTY="$(git status --porcelain --untracked-files=no | wc -l | tr -d ' ')"

STEPS=()
step() {
    local name="$1"
    shift
    local started ended code
    started="$(date +%s)"
    "$@" >"${OUT}/${name}.log" 2>&1
    code=$?
    ended="$(date +%s)"
    STEPS+=("${name}	${code}	$((ended - started))	$*")
    printf '[gate] %s exit %s (%ss)\n' "${name}" "${code}" "$((ended - started))" >&2
}

step cargo-fmt bash -c 'cd offchain && cargo fmt --all --check'
step cargo-clippy bash -c 'cd offchain && cargo clippy --workspace --all-targets --release -- -D warnings'
step cargo-test bash -c 'cd offchain && cargo test --workspace --release'
step forge-fmt bash -c 'cd contracts && forge fmt --check'
step forge-test bash -c 'cd contracts && forge test'
step python-helpers bash -c 'cd script/lib && python3 -I -m unittest -v test_wan_support'
step shell-syntax bash -c 'for f in script/*.sh script/lib/*.sh; do bash -n "$f" || exit 1; done'

hashes >"${OUT}/source-after.sha256"
printf '%s\n' "${STEPS[@]}" >"${OUT}/steps.tsv"

python3 -I - "${OUT}" "$(git rev-parse HEAD)" "${DIRTY}" <<'PY'
import json, re, sys
out, commit, dirty = sys.argv[1], sys.argv[2], int(sys.argv[3])
steps = []
for line in open(f"{out}/steps.tsv"):
    name, code, secs, cmd = line.rstrip("\n").split("\t", 3)
    steps.append({"step": name, "exitCode": int(code), "seconds": int(secs), "command": cmd, "log": f"{name}.log"})
cargo = open(f"{out}/cargo-test.log").read()
counts = [tuple(map(int, m)) for m in re.findall(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", cargo)]
forge = open(f"{out}/forge-test.log").read()
fm = re.findall(r"(\d+) tests passed, (\d+) failed, (\d+) skipped", forge)
py = open(f"{out}/python-helpers.log").read()
pm = re.findall(r"Ran (\d+) tests?", py)
unchanged = open(f"{out}/source-before.sha256").read() == open(f"{out}/source-after.sha256").read()
result = {
    "runId": out.rsplit("/", 1)[1], "commit": commit, "trackedFilesModified": dirty,
    "sourceUnchanged": unchanged, "steps": steps,
    "rust": {"suites": len(counts), "passed": sum(c[0] for c in counts),
             "failed": sum(c[1] for c in counts), "ignored": sum(c[2] for c in counts)},
    "forge": {"passed": int(fm[-1][0]), "failed": int(fm[-1][1]), "skipped": int(fm[-1][2])} if fm else None,
    "pythonHelpers": {"ran": int(pm[-1])} if pm else None,
    "pass": unchanged and all(s["exitCode"] == 0 for s in steps),
}
json.dump(result, open(f"{out}/results.json", "w"), indent=2)
open(f"{out}/results.json", "a").write("\n")
print(json.dumps({k: result[k] for k in ("commit", "sourceUnchanged", "rust", "forge", "pythonHelpers", "pass")}, indent=2))
sys.exit(0 if result["pass"] else 1)
PY
