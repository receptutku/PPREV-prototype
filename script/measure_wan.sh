#!/usr/bin/env bash
# Controlled application-level link experiment: MPC-TLS sessions (the Register request of a fixture
# owner) with an emulated delay and bandwidth on one link at a time, the prover-notary link or the
# prover-registry link (offchain/crates/pprev-prover/src/netem.rs). It is not a WAN emulation: the
# proxy delays and paces application bytes; TCP handshakes, acknowledgements, congestion control,
# loss, and jitter are not emulated.
#
# For each grid point: a calibration of the proxy configuration (netem-calibrate: one-byte round
# trips and a one-way bulk transfer), then n notarisations through the proxy, each timed by this
# script as a process (monotonic clock), with its exit code, the prover's report (attempts, stalls,
# login and last-attempt MPC-TLS time and traffic), and the proxy's per-connection log (duration and
# bytes each way of every connection, failed attempts included).
#
# Grid (fixed in advance; GRID overrides it for a pilot run):
#   direct            no proxy
#   notary RTT        {0, 10, 30, 60, 100, 200} ms, unlimited bandwidth
#   notary bandwidth  {1000, 100, 50, 20} Mbit/s per direction at 30 ms RTT
#   registry RTT      {0, 30, 100} ms, unlimited bandwidth
# N (default 10) sessions per point. The proxy queue holds 64 MiB per direction, above the
# bandwidth-delay product of every point.
#
# Output: measurements/wan/<run>.json. Intermediate files go to target/wan/<run>/.
set -euo pipefail

LOG_TAG=wan
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

PROPERTY="TR-06-CANKAYA-000123"
OWNER_ACCOUNT="ACC-000000000001"
OWNER_PASSWORD="owner-one"
N="${N:-10}"
PROXY_PORT="${PROXY_PORT:-7147}"
PORTS="${PORTS} ${PROXY_PORT}"
QUEUE_BYTES=$((64 << 20))
# Generous bounds, so that a slow session under a long delay is measured, not cut; a session that
# still exceeds them is recorded as a timeout, separately from a preprocessing stall.
PREPROCESS_TIMEOUT_SECS=60
SESSION_TIMEOUT_SECS=120
RUN_TIMEOUT_SECS=180
CAMPAIGN_SECONDS="${CAMPAIGN_SECONDS:-3600}"
export WAN_DEADLINE="$(python3 -c 'import sys,time; print(time.monotonic()+float(sys.argv[1]))' "${CAMPAIGN_SECONDS}")"
SUPPORT="${ROOT}/script/lib/wan_support.py"
DEFAULT_GRID="direct:0:-
notary:0:- notary:10:- notary:30:- notary:60:- notary:100:- notary:200:-
notary:30:1000 notary:30:100 notary:30:50 notary:30:20
registry:0:- registry:30:- registry:100:-"
GRID="${GRID:-${DEFAULT_GRID}}"

OUT_DIR="${MEASUREMENTS_DIR:?}/wan"

preflight
check_ports_free
init_run wan
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
build_all
python3 "${SUPPORT}" snapshot "${ROOT}" "${WORK}/source-start.json"
PROVENANCE="$(provenance_json)"

# Registry and notary, without a chain: a notarisation needs neither the contract nor sigma.
openssl rand -hex 32 >"${WORK}/attestation.key"
openssl rand -hex 32 >"${WORK}/statement.key"
cd "${ROOT:?}"
start mock-registry "${WORK}/registry.log" "${BIN}/mock-registry" \
    --bind "127.0.0.1:${REGISTRY_PORT}" --ca-out "${WORK}/registry-ca.der"
wait_port "${REGISTRY_PORT}" mock-registry "${PIDS[${#PIDS[@]} - 1]}"
start pprev-notary "${WORK}/notary.log" "${BIN}/pprev-notary" \
    --mpc-bind "127.0.0.1:${MPC_PORT}" --verifier-bind "127.0.0.1:${VERIFIER_PORT}" \
    --registry-ca "${WORK}/registry-ca.der" --policy "${POLICY}" --root "${ROOT}" \
    --attestation-key "${WORK}/attestation.key" --statement-key "${WORK}/statement.key" \
    --chain-id "${CHAIN_ID}" --contract 0x0000000000000000000000000000000000000001 \
    --tau-lock 1209600 --nonces "${WORK}/nonces.log" --log "${WORK}/notary-events.jsonl" \
    --preprocess-timeout-secs "${PREPROCESS_TIMEOUT_SECS}" --session-timeout-secs "${SESSION_TIMEOUT_SECS}"
wait_port "${MPC_PORT}" pprev-notary "${PIDS[${#PIDS[@]} - 1]}"

# run_session <dir> <notary addr> <registry addr>: one notarisation, timed as a process.
run_session() {
    python3 - "$@" "${BIN}/pprev-prover" "${WORK}/registry-ca.der" "${OWNER_ACCOUNT}" \
        "${OWNER_PASSWORD}" "${PROPERTY}" "${PREPROCESS_TIMEOUT_SECS}" "${RUN_TIMEOUT_SECS}" <<'PY'
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "script/lib"))
from wan_support import run_process
d, notary, registry, prover, ca, account, password, prop, pre, limit = sys.argv[1:]
cmd = [prover, "notarize", "--notary", notary, "--registry", registry, "--ca", ca,
       "--account", account, "--password", password, "--property", prop,
       "--max-sent", "1024", "--max-recv", "1024", "--max-retries", "3",
       "--preprocess-timeout-secs", pre, "--layout", "policies/layouts/title-v1.json",
       "--out", f"{d}/out", "--report", f"{d}/report.json"]
run_process(cmd, Path(d), float(limit), float(os.environ["WAN_DEADLINE"]))
PY
}

POINTS="[]"
CAMPAIGN_ERROR=0
for point in ${GRID}; do
    IFS=: read -r link rtt mbps <<<"${point}"
    name="${link}-rtt${rtt}-bw${mbps}"
    dir="${WORK}/${name}"
    mkdir -p "${dir}"
    mbps_args=()
    [ "${mbps}" = "-" ] || mbps_args=(--mbps "${mbps}")
    notary_addr="127.0.0.1:${MPC_PORT}"
    registry_addr="127.0.0.1:${REGISTRY_PORT}"
    calibration=null
    calibration_run=null
    proxy_started=false
    active=true
    python3 -c 'import os,time,sys; sys.exit(time.monotonic() >= float(os.environ["WAN_DEADLINE"]))' || active=false
    if [ "${link}" != direct ] && [ "${active}" = true ]; then
        log "calibrating ${name}"
        calibration_run="$(python3 - "${dir}/calibration" "${BIN}/netem-calibrate" --rtt-ms "${rtt}" "${mbps_args[@]+"${mbps_args[@]}"}" \
            --queue-bytes "${QUEUE_BYTES}" --pings 50 --bulk-mib 32 <<'PY'
import os, sys, json
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "script/lib"))
from wan_support import calibrate
print(json.dumps(calibrate(sys.argv[2:], Path(sys.argv[1]), float(os.environ["WAN_DEADLINE"]))))
PY
)"
        calibration="$(jq -c '.calibration' <<<"${calibration_run}")"
        if [ "${calibration}" = null ]; then
            reason="$(jq -r '.reason // "calibration-error"' <<<"${calibration_run}")"
            export WAN_DEADLINE=0 WAN_STOP_REASON="${reason}"
            [ "${reason}" = campaign-budget ] || CAMPAIGN_ERROR=1
            active=false
            log "calibration stopped (${reason}); retaining results and marking remaining sessions not-run"
        fi
    fi
    if [ "${link}" != direct ] && [ "${active}" = true ]; then
        if [ "${link}" = notary ]; then upstream="${notary_addr}"; else upstream="${registry_addr}"; fi
        start netem-proxy "${dir}/proxy.log" "${BIN}/netem-proxy" --listen "127.0.0.1:${PROXY_PORT}" \
            --upstream "${upstream}" --rtt-ms "${rtt}" "${mbps_args[@]+"${mbps_args[@]}"}" \
            --queue-bytes "${QUEUE_BYTES}" --log "${dir}/connections.jsonl"
        proxy_started=true
        wait_port "${PROXY_PORT}" netem-proxy "${PIDS[${#PIDS[@]} - 1]}"
        if [ "${link}" = notary ]; then notary_addr="127.0.0.1:${PROXY_PORT}"; else registry_addr="127.0.0.1:${PROXY_PORT}"; fi
    fi
    log "${name}: ${N} sessions"
    RUNS="[]"
    failures=0
    for i in $(seq 1 "${N}"); do
        mkdir -p "${dir}/${i}"
        run_session "${dir}/${i}" "${notary_addr}" "${registry_addr}"
        RUNS="$(jq -c --slurpfile r "${dir}/${i}/run.json" '. + $r' <<<"${RUNS}")"
        if jq -e '.outcome == "error" or .outcome == "timeout"' "${dir}/${i}/run.json" >/dev/null; then
            failures=$((failures + 1))
        else
            failures=0
        fi
        if [ "${failures}" -ge 2 ]; then
            export WAN_DEADLINE=0 WAN_STOP_REASON=consecutive-failures
            log "two consecutive failures: remaining planned sessions will be recorded as not-run"
        fi
    done
    if [ "${proxy_started}" = true ]; then
        # Stop this point's proxy (the last process started) before the next point.
        kill -TERM "${PIDS[${#PIDS[@]} - 1]}" 2>/dev/null || true
        wait "${PIDS[${#PIDS[@]} - 1]}" 2>/dev/null || true
        unset 'PIDS[${#PIDS[@]}-1]' 'NAMES[${#NAMES[@]}-1]'
        PIDS=("${PIDS[@]}")
        NAMES=("${NAMES[@]}")
        until [ -z "$(listener_pids "${PROXY_PORT}")" ]; do sleep 0.1; done
    fi
    CONNECTIONS="[]"
    [ -f "${dir}/connections.jsonl" ] && CONNECTIONS="$(jq -s -c . "${dir}/connections.jsonl")"
    POINTS="$(jq -c --arg link "${link}" --argjson rtt "${rtt}" --arg mbps "${mbps}" \
        --argjson cal "${calibration}" --argjson calrun "${calibration_run}" --argjson runs "${RUNS}" --argjson conns "${CONNECTIONS}" \
        '. + [{link: $link, targetRttMs: $rtt, targetMbps: (if $mbps == "-" then null else ($mbps | tonumber) end),
               calibration: $cal, calibrationRun: $calrun, runs: $runs, proxyConnections: $conns}]' <<<"${POINTS}")"
done

stop_all
python3 "${SUPPORT}" snapshot "${ROOT}" "${WORK}/source-end.json"

jq -n --arg runId "${RUN_ID}" --argjson prov "${PROVENANCE}" --argjson points "${POINTS}" \
    --argjson n "${N}" --argjson queue "${QUEUE_BYTES}" \
    --argjson pre "${PREPROCESS_TIMEOUT_SECS}" --argjson sess "${SESSION_TIMEOUT_SECS}" \
    --argjson limit "${RUN_TIMEOUT_SECS}" --arg grid "${GRID}" \
    --slurpfile start "${WORK}/source-start.json" --slurpfile end "${WORK}/source-end.json" \
    --argjson budget "${CAMPAIGN_SECONDS}" '
    {
        sourceStart: $start[0], sourceEnd: $end[0], campaignBudgetS: $budget,
        runId: $runId, commit: $prov.commit, workingTreeDirty: $prov.workingTreeDirty,
        machine: $prov.machine, tools: $prov.tools,
        experiment: "controlled application-level link delay and bandwidth; not a WAN emulation (no TCP-level, loss, jitter, or congestion modelling)",
        sessionsPerPoint: $n, proxyQueueBytesPerDirection: $queue,
        bounds: {proverPreprocessTimeoutS: $pre, notaryPreprocessTimeoutS: $pre, notarySessionTimeoutS: $sess, runTimeoutS: $limit},
        grid: $grid,
        points: $points
    }' >"${OUT}"

python3 "${SUPPORT}" finalize "${OUT}"
log "record: ${OUT#"${ROOT}/"}"
jq -r '.summary[] | "\(.link) rtt \(.targetRttMs) bw \(.targetMbps // "inf"): \(.succeeded)/\(.sessionsPlanned) ok, timeout \(.timedOut), not-run \(.notRun)"' "${OUT}" >&2

exit "${CAMPAIGN_ERROR}"
