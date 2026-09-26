#!/usr/bin/env bash
# Off-chain costs of Register on this machine (stage (e)).
#
# On the local stack of script/e2e_register.sh (anvil, mock registry, notary):
#   1. one warm-up Register run, excluded from the statistics;
#   2. N Register runs (default 20): login, MPC-TLS session and its traffic, presentation, witness,
#      snarkjs, t_verify, t_sign, t_incl (local anvil); peak RSS of the witness generator and snarkjs
#      (each under /usr/bin/time -l) and of the prover process itself (getrusage);
#   3. N standalone Groth16 verifications of one proof (phi-r-verify);
#   4. S sessions that only run MPC-TLS (default 200), for the preprocessing stall rate (D33).
# Failed attempts are excluded from every timing and counted separately.
#
# Output: measurements/offchain/<run>.json with raw samples and, per metric, n, min, quartiles,
# median, max, and mean. Refuses a dirty working tree (PPREV_ALLOW_DIRTY=1 with
# PPREV_MEASUREMENTS_DIR for a trial run). PPREV_OFFCHAIN_N and PPREV_STALL_SESSIONS override the
# counts.
set -euo pipefail

LOG_TAG=offchain
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

N="${PPREV_OFFCHAIN_N:-20}"
STALL_SESSIONS="${PPREV_STALL_SESSIONS:-200}"
PROPERTY="TR-06-CANKAYA-000123"
OWNER_ACCOUNT="ACC-000000000001"
OWNER_PASSWORD="owner-one"
AMOUNT_WEI="1000000000000000000"
COLLATERAL_WEI="500000000000000000"
OUT_DIR="${MEASUREMENTS_DIR:?}/offchain"

preflight
require_clean_tree
check_ports_free
init_run offchain
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
build_all
check_not_dataless "${CIRCUITS}/build/phi_r.zkey" "${CIRCUITS}/build/main_title_v1_js/main_title_v1.wasm" \
    "${CIRCUITS}/setup/verification_key.json" "${CIRCUITS}/node_modules/snarkjs/build/cli.cjs" \
    "${BIN}/pprev-prover" "${BIN}/pprev-notary" "${BIN}/mock-registry" "${NODE_BIN}"
PROVENANCE="$(provenance_json)"
start_stack

# register <name>: one Register run; never fails the script.
register() {
    local name="$1"
    "${BIN}/pprev-prover" register \
        --notary "127.0.0.1:${MPC_PORT}" --verifier "127.0.0.1:${VERIFIER_PORT}" \
        --registry "127.0.0.1:${REGISTRY_PORT}" --ca "${WORK}/registry-ca.der" \
        --account "${OWNER_ACCOUNT}" --password "${OWNER_PASSWORD}" --property "${PROPERTY}" \
        --policy "${POLICY}" --root "${ROOT}" --rpc-url "${RPC}" --contract "${PPREV_ADDRESS}" \
        --key-file "${WORK}/account1.key" --amount-wei "${AMOUNT_WEI}" \
        --collateral-wei "${COLLATERAL_WEI}" --measure-rss \
        --out "${WORK}/register/${name}" >"${WORK}/register/${name}.log" 2>&1 || true
}

mkdir -p "${WORK}/register" "${WORK}/verify" "${WORK}/stall"
log "warm-up run"
register warmup
for i in $(seq 1 "${N}"); do
    log "register ${i}/${N}"
    register "$(printf 'run%03d' "${i}")"
done

PROOF_DIR="${WORK}/register/run001"
[ -f "${PROOF_DIR}/proof.json" ] || die "the first measured run left no proof"
log "standalone verification x${N}"
for i in $(seq 1 "${N}"); do
    "${BIN}/phi-r-verify" "${CIRCUITS}/setup/verification_key.json" "${PROOF_DIR}/proof.json" \
        "${PROOF_DIR}/public.json" >"${WORK}/verify/$(printf 'run%03d' "${i}").json"
done

log "MPC-TLS sessions x${STALL_SESSIONS} (stall rate)"
for i in $(seq 1 "${STALL_SESSIONS}"); do
    name="$(printf 'session%03d' "${i}")"
    "${BIN}/pprev-prover" notarize \
        --notary "127.0.0.1:${MPC_PORT}" --registry "127.0.0.1:${REGISTRY_PORT}" \
        --ca "${WORK}/registry-ca.der" --account "${OWNER_ACCOUNT}" --password "${OWNER_PASSWORD}" \
        --property "${PROPERTY}" --out "${WORK}/stall/${name}" --report "${WORK}/stall/${name}.json" \
        >"${WORK}/stall/${name}.log" 2>&1 || true
    [ -f "${WORK}/stall/${name}.json" ] || die "${name}: no report written"
    if [ $((i % 25)) -eq 0 ]; then log "  ${i}/${STALL_SESSIONS}"; fi
done

stop_all

python3 - "${WORK}" "${OUT}" "${N}" "${STALL_SESSIONS}" "${DELTA}" <<'PY'
import glob, json, os, statistics, sys

work, out, n, stall_sessions, delta = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

def quantile(xs, q):
    xs = sorted(xs)
    pos = (len(xs) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)

def stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    r = lambda v: int(v) if float(v).is_integer() else round(v, 3)
    return {"n": len(xs), "min": r(min(xs)), "p25": r(quantile(xs, 0.25)), "median": r(quantile(xs, 0.5)),
            "p75": r(quantile(xs, 0.75)), "max": r(max(xs)), "mean": r(statistics.fmean(xs))}

runs, failed = [], []
for path in sorted(glob.glob(f"{work}/register/run*/record.json")):
    name = os.path.basename(os.path.dirname(path))
    rec = json.load(open(path))
    (runs if rec.get("outcome") == "registered" else failed).append({"run": name, **rec})
if len(runs) + len(failed) != n:
    sys.exit(f"expected {n} register records, found {len(runs) + len(failed)}")

def col(f):
    return [f(r) for r in runs]

t = lambda r: r["timings"]
metrics = {
    "loginMs": col(lambda r: t(r)["outsideDelta"]["loginMs"]),
    "mpcTlsMs": col(lambda r: t(r)["outsideDelta"]["mpcTlsMs"]),
    "presentationMs": col(lambda r: t(r)["insideDelta"]["presentationMs"]),
    "readTAttMs": col(lambda r: t(r)["insideDelta"]["readTAttMs"]),
    "witnessMs": col(lambda r: t(r)["insideDelta"]["witnessMs"]),
    "snarkjsProveMs": col(lambda r: t(r)["insideDelta"]["snarkjsProveMs"]),
    "tProveMs": col(lambda r: t(r)["insideDelta"]["tProveMs"]),
    "tVerifyMs": col(lambda r: t(r)["insideDelta"]["tVerifyMs"]),
    "tSignMs": col(lambda r: t(r)["insideDelta"]["tSignMs"]),
    "tInclLocalMs": col(lambda r: t(r)["insideDelta"]["tInclMs"]),
    "verifierDecodeMs": col(lambda r: t(r)["verifier"]["decodeMs"]),
    "verifierPresentationMs": col(lambda r: t(r)["verifier"]["presentationMs"]),
    "verifierGroth16Ms": col(lambda r: t(r)["verifier"]["groth16Ms"]),
    "verifierRoundTripMs": col(lambda r: t(r)["verifierRoundTripMs"]),
    "afterAttestationMs": col(lambda r: t(r)["afterAttestationMs"]),
    "mpcSentBytes": col(lambda r: r["resources"]["mpcTraffic"]["sentBytes"]),
    "mpcReceivedBytes": col(lambda r: r["resources"]["mpcTraffic"]["receivedBytes"]),
    "witnessPeakRssBytes": col(lambda r: r["resources"]["witnessPeakRssBytes"]),
    "snarkjsPeakRssBytes": col(lambda r: r["resources"]["snarkjsPeakRssBytes"]),
    "proverPeakRssBytes": col(lambda r: r["resources"]["proverPeakRssBytes"]),
    "blockTimestampMinusTAttS": col(lambda r: r["submission"]["blockTimestamp"] - r["tAtt"]),
}

verify = [json.load(open(p)) for p in sorted(glob.glob(f"{work}/verify/run*.json"))]
metrics["standaloneVerifyKeyMs"] = [v["keyMs"] for v in verify]
metrics["standaloneVerifyMs"] = [v["verifyMs"] for v in verify]

reports = [json.load(open(p)) for p in sorted(glob.glob(f"{work}/stall/session*.json"))]
attested = [r for r in reports if r["outcome"] == "attested"]
metrics["sessionOnlyMpcTlsMs"] = [r["mpcTlsMs"] for r in attested]
metrics["sessionOnlySentBytes"] = [r["mpcTraffic"]["sentBytes"] for r in attested]
metrics["sessionOnlyReceivedBytes"] = [r["mpcTraffic"]["receivedBytes"] for r in attested]

def d33(attempt_list, stall_lists, gave_up):
    attempts = sum(attempt_list)
    stalls = sum(len(s) for s in stall_lists) + gave_up
    return {"sessionsStarted": attempts, "stalled": stalls,
            "stallRate": round(stalls / attempts, 6) if attempts else None,
            "runsNeedingRetry": sum(1 for a in attempt_list if a > 1)}

events = [json.loads(l) for l in open(f"{work}/notary-events.jsonl")]
session_events = [e for e in events if e["event"] == "session"]
notary_outcomes = {}
for e in session_events:
    notary_outcomes[e["outcome"]] = notary_outcomes.get(e["outcome"], 0) + 1

gave_up = [r for r in reports if r["outcome"] != "attested"]
summary = {k: stats(v) for k, v in metrics.items()}
med = lambda k: summary[k]["median"]
formula_median = med("tProveMs") + med("tVerifyMs") + med("tSignMs") + med("tInclLocalMs")
formula_max = summary["tProveMs"]["max"] + summary["tVerifyMs"]["max"] + summary["tSignMs"]["max"] + summary["tInclLocalMs"]["max"]

result = {
    "parameters": {"registerRuns": n, "warmupRuns": 1, "standaloneVerifications": n,
                   "sessionOnlyRuns": stall_sessions, "preprocessTimeoutS": 30, "maxRetries": 3,
                   "deltaS": delta, "blockProduction": "anvil automine (tInclLocalMs is a local node)"},
    "circuit": json.load(open(os.path.join(os.path.dirname(work), "..", "..", "circuits", "build", "phi_r.info.json"))),
    "summary": summary,
    "deltaBudget": {
        "description": "Delta >= t_prove + t_verify + t_sign + t_incl (Section VII-F); t_incl here is a local anvil node, to be replaced by the Base Sepolia measurement",
        "medianSumMs": round(formula_median, 3),
        "medianSumOverDelta": round(formula_median / (delta * 1000), 6),
        "maxSumMs": round(formula_max, 3),
        "maxSumOverDelta": round(formula_max / (delta * 1000), 6),
    },
    "d33": {
        "registerRuns": d33([r["notarization"]["attempts"] for r in runs + failed if "notarization" in r],
                            [r["notarization"]["stalls"] for r in runs + failed if "notarization" in r], 0),
        "sessionOnlyRuns": d33([r["attempts"] for r in reports], [r.get("stalls", []) for r in attested],
                               sum(r["attempts"] for r in gave_up)),
        "sessionOnlyRunsFailed": len(gave_up),
        "notarySessionOutcomes": notary_outcomes,
    },
    "failedRegisterRuns": [{"run": r["run"], "outcome": r.get("outcome"), "reason": r.get("reason")} for r in failed],
    "samples": {k: v for k, v in metrics.items()},
    "stallReasons": [s for r in reports for s in r.get("stalls", [])] + [r.get("reason") for r in gave_up],
}
json.dump(result, open(out + ".part", "w"), indent=2)
PY

jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --slurpfile body "${OUT}.part" \
    --arg zkey "${ZKEY_SHA256}" --arg vk "${VK_SHA256}" \
    '{runId: $runId} + $prov + {artifacts: {zkeySha256: $zkey, verificationKeySha256: $vk}} + $body[0]' >"${OUT}"
rm -f -- "${OUT:?}.part"
log "record: ${OUT#"${ROOT}/"}"
jq -r '
    .summary as $s |
    "median (ms): mpc-tls \($s.mpcTlsMs.median), witness \($s.witnessMs.median), snarkjs \($s.snarkjsProveMs.median), t_verify \($s.tVerifyMs.median), t_sign \($s.tSignMs.median), t_incl(local) \($s.tInclLocalMs.median)",
    "Delta budget: median sum \(.deltaBudget.medianSumMs) ms = \(.deltaBudget.medianSumOverDelta) of Delta; max sum \(.deltaBudget.maxSumMs) ms",
    "D33: register \(.d33.registerRuns.stalled)/\(.d33.registerRuns.sessionsStarted) stalled; session-only \(.d33.sessionOnlyRuns.stalled)/\(.d33.sessionOnlyRuns.sessionsStarted) stalled, \(.d33.sessionOnlyRunsFailed) gave up",
    "failed register runs: \(.failedRegisterRuns | length)"
' "${OUT}" >&2
