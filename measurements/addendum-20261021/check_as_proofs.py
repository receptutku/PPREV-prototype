"""Verify a baseline Groth16 proof and reject each changed public input.

Usage: python3 check_as_proofs.py REPO VK PUBLIC PROOF WRONG_PHASE_VK OUTPUT_DIR
This checks proof binding separately from witness generation. It does not re-prove
after modifying a public input, and it does not claim TLS provenance validation.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def main():
    root, vk, public, proof, other_vk, out = map(lambda p: Path(p).resolve(), sys.argv[1:])
    out.mkdir(parents=True, exist_ok=False)
    version = (root / ".nvmrc").read_text().strip()
    candidates = [os.environ.get("PPREV_NODE"), shutil.which("node"), "/opt/homebrew/bin/node",
                  str(Path.home() / ".nvm/versions/node" / version / "bin/node")]
    node = next((p for p in candidates if p and Path(p).is_file()
                 and subprocess.check_output([p, "--version"], text=True).strip() == version), None)
    if not node:
        raise SystemExit(f"Pinned Node {version} not found")
    env = dict(os.environ, PATH=str(Path(node).parent) + os.pathsep + os.environ["PATH"])
    tool = root / "circuits/node_modules/.bin/snarkjs"
    values = json.loads(public.read_text())
    assert all(0 <= int(value) < R for value in values)
    cases = [("baseline", vk, public, True), ("wrong_phase_key", other_vk, public, False)]
    for i, value in enumerate(values):
        changed = list(values)
        changed[i] = str((int(value) + 1) % R)
        path = out / f"public_changed_{i}.json"
        path.write_text(json.dumps(changed) + "\n")
        cases.append((f"public_changed_{i}", vk, path, False))
    results = []
    for name, key, inputs, expected in cases:
        run = subprocess.run([str(tool), "groth16", "verify", str(key), str(inputs), str(proof)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        (out / (name + ".log")).write_text(run.stdout)
        accepted = run.returncode == 0
        result = {"case": name, "expectedAccepted": expected, "observedAccepted": accepted,
                  "exitCode": run.returncode, "pass": accepted == expected}
        results.append(result)
        print(json.dumps(result), flush=True)
    report = {"scope": "Groth16 public-input binding and phase-key separation only.",
              "sourceSha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (vk, public, proof, other_vk)},
              "cases": results, "passed": sum(r["pass"] for r in results), "total": len(results)}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if not all(r["pass"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
