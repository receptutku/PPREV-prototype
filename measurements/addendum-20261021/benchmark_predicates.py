"""Matched local witness/proving microbenchmark for the three phase circuits.

Usage: python3 benchmark_predicates.py REPO OUTPUT_DIR [N=20]
Excludes TLS, policy-verifier service, signing, and chain submission. One warmup
per phase is recorded separately. Measured rounds rotate phase order. Every
proof is verified; failures abort and remain visible in partial-results.json.
"""

import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def quantile(values, q):
    ordered = sorted(values)
    at = (len(ordered) - 1) * q
    lo = int(at)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (at - lo)


def main():
    root, out = (Path(p).resolve() for p in sys.argv[1:3])
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    assert n > 0
    out.mkdir(parents=True, exist_ok=False)
    work = root / "target/predicate-benchmark" / out.name
    work.mkdir(parents=True, exist_ok=False)
    version = (root / ".nvmrc").read_text().strip()
    candidates = [os.environ.get("PPREV_NODE"), shutil.which("node"), "/opt/homebrew/bin/node",
                  str(Path.home() / ".nvm/versions/node" / version / "bin/node")]
    node = next((p for p in candidates if p and Path(p).is_file()
                 and subprocess.check_output([p, "--version"], text=True).strip() == version), None)
    if not node:
        raise SystemExit(f"Pinned Node {version} not found")
    env = dict(os.environ, PATH=str(Path(node).parent) + os.pathsep + os.environ["PATH"])
    snarkjs = root / "circuits/node_modules/.bin/snarkjs"
    phases = {}
    for phase, circuit in [("r", "main_title_v1"), ("a", "main_income_v1"), ("s", "main_tenancy_v1")]:
        setup = root / "circuits/setup"
        if phase != "r":
            setup = setup / ("phi_" + phase)
        wasm = root / "circuits/build" / (circuit + "_js") / (circuit + ".wasm")
        phases[phase] = {"circuit": circuit, "wasm": wasm, "generator": wasm.parent / "generate_witness.js",
                         "zkey": root / "circuits/build" / ("phi_" + phase + ".zkey"),
                         "vk": setup / "verification_key.json", "input": setup / "sample/input.json",
                         "public": setup / "sample/public.json"}
    source_files = {str(path): sha(path) for files in phases.values()
                    for path in files.values() if isinstance(path, Path)}
    report = {
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "scriptSha256": sha(Path(__file__)),
        "scope": "Local witness generation and Groth16 proving on fixed synthetic fixtures; excludes TLS, service verification, signing, and chain inclusion.",
        "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        "workingTreeStatus": subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True),
        "machine": {"platform": platform.platform(), "architecture": platform.machine()},
        "node": version, "nPerPhase": n, "warmupsPerPhase": 1,
        "quantileMethod": "linear interpolation at (n-1)*q", "sourceSha256": source_files,
        "warmups": [], "samples": [], "status": "running",
    }
    if platform.system() == "Darwin":
        report["machine"]["powerStart"] = subprocess.check_output(["pmset", "-g", "batt"], text=True)
        report["machine"]["cpu"] = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        report["machine"]["memoryBytes"] = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))

    def save():
        (out / "partial-results.json").write_text(json.dumps(report, indent=2) + "\n")

    def timed(command, logfile):
        start = time.perf_counter_ns()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env, timeout=180)
        elapsed = (time.perf_counter_ns() - start) / 1e6
        logfile.write_text(result.stdout)
        if result.returncode:
            raise RuntimeError(f"command failed ({result.returncode}); see {logfile}")
        return elapsed

    def run(phase, index, warmup):
        files = phases[phase]
        prefix = f"{'warmup' if warmup else index}_{phase}"
        wtns = work / (phase + ".wtns")
        proof, public = out / (prefix + "_proof.json"), out / (prefix + "_public.json")
        witness_ms = timed([node, str(files["generator"]), str(files["wasm"]), str(files["input"]), str(wtns)], out / (prefix + "_witness.log"))
        prove_ms = timed([str(snarkjs), "groth16", "prove", str(files["zkey"]), str(wtns), str(proof), str(public)], out / (prefix + "_prove.log"))
        assert json.loads(public.read_text()) == json.loads(files["public"].read_text()), "unexpected public inputs"
        timed([str(snarkjs), "groth16", "verify", str(files["vk"]), str(public), str(proof)], out / (prefix + "_verify.log"))
        entry = {"phase": phase, "round": index, "witnessMs": witness_ms, "proveMs": prove_ms,
                 "totalProvingMs": witness_ms + prove_ms, "proofVerified": True}
        report["warmups" if warmup else "samples"].append(entry)
        save()
        print(json.dumps(entry), flush=True)

    save()
    try:
        for phase in phases:
            run(phase, -1, True)
        order = list(phases)
        for index in range(n):
            for phase in order[index % 3:] + order[:index % 3]:
                run(phase, index, False)
        after = {path: sha(Path(path)) for path in source_files}
        if after != source_files:
            raise RuntimeError("Circuit/key/input artifacts changed during benchmark")
        report["summary"] = {}
        for phase in phases:
            report["summary"][phase] = {}
            for metric in ("witnessMs", "proveMs", "totalProvingMs"):
                values = [row[metric] for row in report["samples"] if row["phase"] == phase]
                report["summary"][phase][metric] = {"n": len(values), "median": statistics.median(values),
                    "p25": quantile(values, .25), "p75": quantile(values, .75), "min": min(values), "max": max(values)}
        report["status"] = "passed"
        report["sourceUnchanged"] = True
        report["finishedAt"] = datetime.now(timezone.utc).isoformat()
        if platform.system() == "Darwin":
            report["machine"]["powerEnd"] = subprocess.check_output(["pmset", "-g", "batt"], text=True)
        save()
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
