"""Independent predicate checks with freshly recomputed commitment hashes.

Usage: python3 check_as_witnesses.py REPO A_INPUT S_INPUT OUTPUT_DIR
Requires compiled A/S WASM and R1CS artifacts; no trusted setup or network.
Each expected acceptance is checked against the R1CS as well as the generator.
Rejected witnesses are not evidence of policy-verifier or chain-level rejection.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rehash(witness, field, hash_field=None):
    value = bytes(map(int, witness[field]))
    blind = bytes(map(int, witness[field + "Blinder"]))
    digest = hashlib.sha256(value + blind).digest()
    witness[hash_field or field + "Hash"] = [
        str(int.from_bytes(digest[:16], "big")),
        str(int.from_bytes(digest[16:], "big")),
    ]


def income(witness, value):
    witness["income"] = list(str(value).zfill(20).encode("ascii"))
    rehash(witness, "income")


def date(witness, value, engagement):
    witness["date"] = list(value.encode("ascii"))
    witness["engagementDay"] = str(engagement)
    rehash(witness, "date")


def changed(field, value):
    def mutate(witness):
        witness[field] = value
    return mutate


def increment(field):
    def mutate(witness):
        witness[field] = str(int(witness[field]) + 1)
    return mutate


def corrupt_text(field):
    def mutate(witness):
        witness[field][0] = ord("X") if int(witness[field][0]) != ord("X") else ord("Y")
        rehash(witness, field)
    return mutate


def main():
    root, a_path, s_path, out = map(Path, sys.argv[1:])
    root, out = root.resolve(), out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    version = (root / ".nvmrc").read_text().strip()
    candidates = [os.environ.get("PPREV_NODE"), shutil.which("node"),
                  "/opt/homebrew/bin/node", str(Path.home() / ".nvm/versions/node" / version / "bin/node")]
    node = next((p for p in candidates if p and Path(p).is_file()
                 and subprocess.check_output([p, "--version"], text=True).strip() == version), None)
    if not node:
        raise SystemExit(f"Pinned Node {version} not found")
    env = dict(os.environ, PATH=str(Path(node).parent) + os.pathsep + os.environ["PATH"])
    snarkjs = root / "circuits/node_modules/.bin/snarkjs"
    baseline = {"a": json.loads(a_path.read_text()), "s": json.loads(s_path.read_text())}
    cases = []

    def add(phase, name, accepts, mutate=lambda _: None):
        witness = copy.deepcopy(baseline[phase])
        mutate(witness)
        cases.append((phase, name, accepts, witness))

    add("a", "baseline", True)
    add("a", "income_exact_threshold", True, lambda w: income(w, 3 * int(w["amount"])))
    add("a", "income_below_threshold", False, lambda w: income(w, 3 * int(w["amount"]) - 1))
    add("a", "income_max_twenty_digits", True, lambda w: income(w, 10**20 - 1))
    add("a", "income_nondigit", False, corrupt_text("income"))
    add("a", "amount_exceeds_96_bits", False, changed("amount", str(2**96)))
    add("a", "changed_commitment", False, increment("cB"))
    add("a", "changed_salt", False, increment("salt"))
    add("a", "different_authenticated_account", False, corrupt_text("account"))

    add("s", "baseline", True)
    for name, text, day, accepted in [
        ("same_day", "2026-10-21", 20261021, True),
        ("later_day", "2026-10-22", 20261021, True),
        ("earlier_day", "2026-10-20", 20261021, False),
        ("valid_century_leap_day", "2000-02-29", 20000101, True),
        ("invalid_century_leap_day", "1900-02-29", 19000101, False),
        ("valid_leap_day", "2004-02-29", 20040101, True),
        ("invalid_nonleap_day", "2001-02-29", 20010101, False),
        ("invalid_april_day", "2026-04-31", 20260101, False),
        ("zero_month", "2026-00-01", 20250101, False),
        ("month_thirteen", "2026-13-01", 20260101, False),
        ("zero_day", "2026-10-00", 20260101, False),
        ("signed_month", "2026-+1-01", 20260101, False),
        ("wrong_separator", "2026/10/21", 20261021, False),
    ]:
        add("s", name, accepted, lambda w, text=text, day=day: date(w, text, day))
    add("s", "different_authenticated_property", False, corrupt_text("property"))
    add("s", "different_authenticated_tenant", False, corrupt_text("tenant"))
    add("s", "changed_commitment", False, increment("cB"))
    add("s", "changed_salt", False, increment("salt"))
    add("s", "engagement_day_exceeds_27_bits", False, changed("engagementDay", str(2**27)))

    artifacts = {}
    results = []
    for phase, name, expected, witness in cases:
        circuit = "main_income_v1" if phase == "a" else "main_tenancy_v1"
        build = root / "circuits/build"
        wasm = build / (circuit + "_js") / (circuit + ".wasm")
        generator = wasm.parent / "generate_witness.js"
        r1cs = build / (circuit + ".r1cs")
        for path in (wasm, generator, r1cs):
            if not path.exists():
                raise SystemExit(f"Missing compiled artifact: {path}")
            if str(path) not in artifacts:
                artifacts[str(path)] = sha(path)
        case = out / (phase + "_" + name)
        case.mkdir(exist_ok=False)
        input_path, wtns = case / "input.json", case / "witness.wtns"
        input_path.write_text(json.dumps(witness) + "\n")
        run = subprocess.run([node, str(generator), str(wasm), str(input_path), str(wtns)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        (case / "generator.log").write_text(run.stdout)
        accepted = False
        check_exit = None
        if run.returncode == 0:
            check = subprocess.run([str(snarkjs), "wtns", "check", str(r1cs), str(wtns)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
            (case / "constraints.log").write_text(check.stdout)
            check_exit = check.returncode
            accepted = check.returncode == 0
        result = {"phase": phase, "case": name, "expectedAccepted": expected,
                  "observedAccepted": accepted, "pass": accepted == expected,
                  "generatorExit": run.returncode, "r1csCheckExit": check_exit}
        results.append(result)
        print(json.dumps(result), flush=True)
    unchanged = all(sha(Path(path)) == digest for path, digest in artifacts.items())
    report = {"scope": "Independent witness generation and R1CS checks only; not TLS or verifier integration.",
              "scriptSha256": sha(Path(__file__)), "sourceUnchanged": unchanged,
              "baselineSha256": {str(a_path): sha(a_path), str(s_path): sha(s_path)},
              "artifactSha256": artifacts, "cases": results,
              "passed": sum(r["pass"] for r in results), "total": len(results)}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if not unchanged or not all(r["pass"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
