"""Bounded process execution and auditable accounting for link experiments."""
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path


def hash_files(root, names):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in sorted(set(names))}


def snapshot(root):
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    ).decode().split("\0")
    prefixes = ("offchain/", "mock-registry/", "policies/", "script/", "contracts/src/")
    selected = [n for n in names if n and (root / n).is_file()
                and "__pycache__" not in n
                and (n.startswith(prefixes) or n in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"))]
    selected += [f"target/release/{n}" for n in
                 ("pprev-prover", "pprev-notary", "mock-registry", "netem-proxy", "netem-calibrate")]
    power = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True)
    return {"files": hash_files(root, selected), "power": power.stdout.strip(),
            "unixTime": time.time()}


def run_process(cmd, directory, timeout_s, deadline):
    directory.mkdir(parents=True, exist_ok=True)
    result = {"exitCode": None, "timedOut": False, "processElapsedMs": None,
              "report": None, "outcome": "not-run", "startUnixMs": time.time() * 1000}
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        result["reason"] = os.environ.get("WAN_STOP_REASON", "campaign-budget")
    else:
        start = time.monotonic()
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=min(timeout_s, remaining))
            result.update(exitCode=p.returncode, outcome="success" if p.returncode == 0 else "error")
            stdout, stderr = p.stdout, p.stderr
        except subprocess.TimeoutExpired as exc:
            result.update(timedOut=True, outcome="timeout",
                          reason="campaign-budget" if remaining < timeout_s else "run-timeout")
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
        result["processElapsedMs"] = (time.monotonic() - start) * 1000
        (directory / "stdout.log").write_bytes(stdout)
        (directory / "stderr.log").write_bytes(stderr)
        try:
            result["report"] = json.loads((directory / "report.json").read_text())
        except (OSError, ValueError):
            pass
    result["endUnixMs"] = time.time() * 1000
    (directory / "run.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def stats(values):
    values = sorted(values)
    if not values:
        return None
    def quantile(q):
        index = (len(values) - 1) * q
        low = int(index)
        return values[low] + (values[min(low + 1, len(values) - 1)] - values[low]) * (index - low)
    return {"n": len(values), "min": values[0], "p25": quantile(.25),
            "median": statistics.median(values), "p75": quantile(.75), "max": values[-1]}


def calibrate(cmd, directory, deadline):
    result = run_process(cmd, directory, 60, deadline)
    result["calibration"] = None
    if result["outcome"] == "success":
        try:
            value = json.loads((directory / "stdout.log").read_text())
            if not isinstance(value, dict) or "rttMs" not in value:
                raise ValueError("missing calibration fields")
            result["calibration"] = value
        except (ValueError, OSError):
            result.update(outcome="error", reason="invalid-calibration-output")
    (directory / "run.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def summarize_runs(runs):
    attempted = [r for r in runs if r["outcome"] != "not-run"]
    successful = [r for r in attempted if r["outcome"] == "success"]
    known = [(r.get("report") or {}).get("attempts") for r in attempted]
    unknown = sum(a is None for a in known)
    return {"sessionsPlanned": len(runs), "attempted": len(attempted), "succeeded": len(successful),
            "timedOut": sum(r["outcome"] == "timeout" for r in runs),
            "errors": sum(r["outcome"] == "error" for r in runs),
            "notRun": len(runs) - len(attempted),
            "successProcessElapsedMs": stats([r["processElapsedMs"] for r in successful]),
            "processElapsedAllObservedMs": stats([r["processElapsedMs"] for r in attempted]),
            "lastAttemptMpcTlsMs": stats([r["report"]["mpcTlsMs"] for r in successful
                                          if r.get("report") and "mpcTlsMs" in r["report"]]),
            "attemptsTotal": None if unknown else sum(known),
            "attemptsKnownSubtotal": sum(a for a in known if a is not None),
            "runsWithUnknownAttempts": unknown}


def finalize(path):
    data = json.loads(path.read_text())
    data["sourceUnchanged"] = data["sourceStart"]["files"] == data["sourceEnd"]["files"]
    data["validForAnalysis"] = data["sourceUnchanged"]
    data["summary"] = []
    for point in data["points"]:
        summary = summarize_runs(point["runs"])
        summary.update({k: point[k] for k in ("link", "targetRttMs", "targetMbps")})
        calibration = point.get("calibration") or {}
        summary["measuredRttMedianMs"] = calibration.get("rttMs", {}).get("median")
        summary["measuredGoodputMbps"] = calibration.get("goodputMbps")
        # A closed proxy connection can still omit a partial failed write. Aborted connections
        # do not emit a final record, so counters are never asserted to be wire-level totals.
        point["trafficMeasurement"] = {
            "kind": "proxy-delivered application bytes from ended connections",
            "complete": False,
            "limitations": "excludes TCP overhead, partial failed writes, and aborted connection records",
        }
        attempted = [r for r in point["runs"] if r["outcome"] != "not-run"]
        first = min((r["startUnixMs"] for r in attempted), default=float("inf"))
        connections = point.get("proxyConnections", [])
        point["readinessConnections"] = [c for c in connections if c["startUnixMs"] < first]
        point["proxyConnections"] = [c for c in connections if c["startUnixMs"] >= first]
        data["summary"].append(summary)
    data["timingInterpretation"] = "timeouts are right-censored; successful latency is reported separately"
    path.write_text(json.dumps(data, indent=2) + "\n")
    if not data["sourceUnchanged"]:
        raise SystemExit("source or binaries changed during experiment: record marked invalid")


if __name__ == "__main__":
    if sys.argv[1] == "snapshot":
        Path(sys.argv[3]).write_text(json.dumps(snapshot(Path(sys.argv[2])), indent=2) + "\n")
    elif sys.argv[1] == "finalize":
        finalize(Path(sys.argv[2]))
