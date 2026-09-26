#!/usr/bin/env bash
# End-to-end Register on a local anvil chain (stage (d)).
#
# Starts anvil, deploys EcdsaNotaryVerifier and PPREV with the D18 parameters and the rental-v1
# bundle, starts the mock registry and the notary / policy verifier, and runs `pprev-prover register`
# for the owner of a fixture property. Then the negative runs:
#   non-owner      an account that is not an owner: phi_R has no witness; a proof borrowed from the
#                  owner's run is refused by the policy verifier
#   nonce-reuse    a nonce the notary has already signed: refused
#   other-address  the owner's signed payload sent from another account: InvalidNotarySignature
#   replay         the owner's payload sent again from the owner: NonceConsumed
#   expired        a fresh signed payload sent after Delta (anvil time moved forward):
#                  AttestationExpired; runs last because it moves the chain clock
#
# Output: measurements/e2e_register/<run>.json (timings, D33 attempts, checks, tool versions,
# commit). Intermediate files (keys, proofs, logs) go to target/e2e/<run>/.
#
# Every process started here is stopped on exit, on success, failure, or interrupt, and the ports
# are checked free before starting and after stopping.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="${ROOT:?}/target/e2e/${RUN_ID:?}"
OUT_DIR="${ROOT:?}/measurements/e2e_register"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"

ANVIL_PORT="${ANVIL_PORT:-8545}"
REGISTRY_PORT="${REGISTRY_PORT:-4443}"
MPC_PORT="${MPC_PORT:-7047}"
VERIFIER_PORT="${VERIFIER_PORT:-7048}"
PORTS="${ANVIL_PORT:?} ${REGISTRY_PORT:?} ${MPC_PORT:?} ${VERIFIER_PORT:?}"
CHAIN_ID=31337
RPC="http://127.0.0.1:${ANVIL_PORT:?}"

POLICY="policies/rental-v1.json"
PROPERTY="TR-06-CANKAYA-000123"
OWNER_ACCOUNT="ACC-000000000001"
OWNER_PASSWORD="owner-one"
TENANT_ACCOUNT="ACC-000000000003"
TENANT_PASSWORD="tenant"
AMOUNT_WEI="1000000000000000000"    # txData.amount: 1 ETH monthly rent
SETTLEMENT_SHARE_BPS=0              # rental (D18)
COLLATERAL_WEI="500000000000000000" # 0.5 ETH, within [minCollateral, maxCollateral]

BIN="${ROOT:?}/target/release"
if ! command -v forge >/dev/null && [ -x "${HOME:?}/.foundry/bin/forge" ]; then
    PATH="${HOME:?}/.foundry/bin:${PATH}"
fi
for tool in anvil forge cast jq lsof openssl circom cargo git; do
    command -v "${tool}" >/dev/null || { echo "missing tool: ${tool}" >&2; exit 1; }
done

log() { printf '[e2e] %s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

# Node.js runs the witness generator and snarkjs. The version is pinned in .nvmrc and must equal the
# one that produced the setup (circuits/setup/setup.json). PPREV_NODE names a node binary; without
# it, the node on PATH, Homebrew's, and nvm's are tried in that order.
NODE_VERSION="$(tr -d '[:space:]' <"${ROOT:?}/.nvmrc")"
[ "${NODE_VERSION}" = "$(jq -r .tools.node "${ROOT:?}/circuits/setup/setup.json")" ] \
    || die ".nvmrc (${NODE_VERSION}) differs from the node version in circuits/setup/setup.json"
if [ -n "${PPREV_NODE:-}" ]; then
    NODE_CANDIDATES="${PPREV_NODE}"
else
    NODE_CANDIDATES="$(command -v node || true) /opt/homebrew/bin/node ${HOME:?}/.nvm/versions/node/${NODE_VERSION}/bin/node"
fi
NODE_BIN=""
for candidate in ${NODE_CANDIDATES}; do
    [ -x "${candidate}" ] || continue
    if [ "$("${candidate}" --version)" = "${NODE_VERSION}" ]; then
        NODE_BIN="${candidate}"
        break
    fi
done
[ -n "${NODE_BIN}" ] || die "node ${NODE_VERSION} not found (tried: ${NODE_CANDIDATES}); set PPREV_NODE"
PATH="$(dirname "${NODE_BIN}"):${PATH}"
[ "$(node --version)" = "${NODE_VERSION}" ] || die "node on PATH is not ${NODE_VERSION}"

# ------------------------------------------------------------------ processes and ports

PIDS=()
NAMES=()
STARTED=false

listener_pids() { lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true; }

check_ports_free() {
    local busy=""
    for port in ${PORTS}; do
        local pids
        pids="$(listener_pids "${port}")"
        [ -z "${pids}" ] || busy="${busy} ${port}(pid ${pids//$'\n'/,})"
    done
    [ -z "${busy}" ] || die "ports in use:${busy}"
}

stop_all() {
    local i
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        kill -TERM "${PIDS[i]}" 2>/dev/null || true
    done
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        local waited=0
        while kill -0 "${PIDS[i]}" 2>/dev/null && [ "${waited}" -lt 50 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        if kill -0 "${PIDS[i]}" 2>/dev/null; then
            log "${NAMES[i]} (pid ${PIDS[i]}) did not stop on TERM; killing"
            kill -KILL "${PIDS[i]}" 2>/dev/null || true
        fi
        wait "${PIDS[i]}" 2>/dev/null || true
    done
    PIDS=()
    NAMES=()
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [ "${status}" -ne 0 ] && [ -d "${WORK}" ]; then
        for f in "${WORK}"/*.log; do
            [ -f "${f}" ] || continue
            log "last lines of ${f#"${ROOT}/"}:"
            tail -n 5 "${f}" >&2 || true
        done
    fi
    stop_all
    # Ports busy before anything started belong to other processes; check_ports_free reported them.
    [ "${STARTED}" = true ] || exit "${status}"
    local left=""
    for port in ${PORTS}; do
        [ -z "$(listener_pids "${port}")" ] || left="${left} ${port}"
    done
    if [ -n "${left}" ]; then
        log "ports still in use after stopping:${left}"
        [ "${status}" -ne 0 ] || status=1
    fi
    exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# start <name> <log> <cmd...>: runs cmd in the background and records its pid.
start() {
    local name="$1" logfile="$2"
    shift 2
    STARTED=true
    "$@" >"${logfile}" 2>&1 &
    PIDS+=("$!")
    NAMES+=("${name}")
    log "started ${name} (pid $!)"
}

# wait_port <port> <name> <pid>
wait_port() {
    local port="$1" name="$2" pid="$3" waited=0
    until [ -n "$(listener_pids "${port}")" ]; do
        kill -0 "${pid}" 2>/dev/null || die "${name} exited before listening on ${port}"
        [ "${waited}" -lt 300 ] || die "${name} did not listen on ${port} within 30 s"
        sleep 0.1
        waited=$((waited + 1))
    done
}

# ------------------------------------------------------------------ preparation

check_ports_free
umask 077
mkdir -p "${WORK:?}" "${OUT_DIR:?}"
log "run ${RUN_ID}, work directory ${WORK#"${ROOT}/"}"

CIRCUITS="${ROOT:?}/circuits"
[ -f "${CIRCUITS}/build/main_title_v1_js/main_title_v1.wasm" ] \
    || die "circuit not built; run script/circuits_build.sh"
[ -f "${CIRCUITS}/build/phi_r.zkey" ] || die "proving key missing; run script/circuits_setup.sh"
ZKEY_SHA256="$(shasum -a 256 "${CIRCUITS}/build/phi_r.zkey" | cut -d' ' -f1)"
[ "${ZKEY_SHA256}" = "$(jq -r .zkeySha256 "${CIRCUITS}/setup/setup.json")" ] \
    || die "phi_r.zkey does not match circuits/setup/setup.json"
VK_SHA256="$(shasum -a 256 "${CIRCUITS}/setup/verification_key.json" | cut -d' ' -f1)"
[ "${VK_SHA256}" = "$(jq -r .verificationKeySha256 "${CIRCUITS}/setup/setup.json")" ] \
    || die "verification_key.json does not match circuits/setup/setup.json"

log "building"
(cd "${ROOT:?}" && cargo build -q --release -p pprev-prover -p pprev-notary -p mock-registry --bins)
(cd "${ROOT:?}/contracts" && forge build -q)

# Notary keys (D19), fresh for each run.
openssl rand -hex 32 >"${WORK}/attestation.key"
openssl rand -hex 32 >"${WORK}/statement.key"
VK_NOTARY="$(cast wallet address --private-key "0x$(cat "${WORK}/statement.key")")"

# ------------------------------------------------------------------ chain and deployment

start anvil "${WORK}/anvil.log" anvil --port "${ANVIL_PORT}" --chain-id "${CHAIN_ID}" \
    --config-out "${WORK}/anvil.json"
wait_port "${ANVIL_PORT}" anvil "${PIDS[0]}"
for i in 0 1 2; do
    jq -r ".private_keys[${i}]" "${WORK}/anvil.json" >"${WORK}/account${i}.key"
done
DEPLOYER_KEY="$(cat "${WORK}/account0.key")"
OWNER_ADDRESS="$(cast wallet address --private-key "$(cat "${WORK}/account1.key")")"
ATTACKER_ADDRESS="$(cast wallet address --private-key "$(cat "${WORK}/account2.key")")"

log "deploying"
(cd "${ROOT:?}/contracts" && DEPLOYER_KEY="${DEPLOYER_KEY}" VK_NOTARY="${VK_NOTARY}" \
    PPREV_POLICY="../${POLICY}" \
    forge script script/Deploy.s.sol --rpc-url "${RPC}" --broadcast -q) >"${WORK}/deploy.log" 2>&1
BROADCAST="${ROOT:?}/contracts/broadcast/Deploy.s.sol/${CHAIN_ID}/run-latest.json"
cp "${BROADCAST}" "${WORK}/deploy-broadcast.json"
contract_address() {
    jq -r --arg n "$1" \
        '[.transactions[] | select(.transactionType == "CREATE" and .contractName == $n)][0].contractAddress' \
        "${WORK}/deploy-broadcast.json"
}
PPREV_ADDRESS="$(contract_address PPREV)"
VERIFIER_ADDRESS="$(contract_address EcdsaNotaryVerifier)"
[ "${PPREV_ADDRESS}" != null ] && [ "${VERIFIER_ADDRESS}" != null ] || die "deployment addresses not found"
DELTA="$(cast call "${PPREV_ADDRESS}" "DELTA()(uint256)" --rpc-url "${RPC}")"
[ "$(cast call "${VERIFIER_ADDRESS}" "VK_NOTARY()(address)" --rpc-url "${RPC}")" = "${VK_NOTARY}" ] \
    || die "the verifier does not hold vk_notary"
log "PPREV ${PPREV_ADDRESS}, EcdsaNotaryVerifier ${VERIFIER_ADDRESS}, Delta ${DELTA} s"

# ------------------------------------------------------------------ registry and notary

cd "${ROOT:?}"
start mock-registry "${WORK}/registry.log" "${BIN}/mock-registry" \
    --bind "127.0.0.1:${REGISTRY_PORT}" --ca-out "${WORK}/registry-ca.der"
wait_port "${REGISTRY_PORT}" mock-registry "${PIDS[1]}"

start pprev-notary "${WORK}/notary.log" "${BIN}/pprev-notary" \
    --mpc-bind "127.0.0.1:${MPC_PORT}" --verifier-bind "127.0.0.1:${VERIFIER_PORT}" \
    --registry-ca "${WORK}/registry-ca.der" --policy "${POLICY}" --root "${ROOT}" \
    --attestation-key "${WORK}/attestation.key" --statement-key "${WORK}/statement.key" \
    --chain-id "${CHAIN_ID}" --contract "${PPREV_ADDRESS}" \
    --nonces "${WORK}/nonces.log" --log "${WORK}/notary-events.jsonl"
wait_port "${MPC_PORT}" pprev-notary "${PIDS[2]}"
wait_port "${VERIFIER_PORT}" pprev-notary "${PIDS[2]}"

# register <name> <account> <password> [extra args...]: runs the prover; never fails the script.
register() {
    local name="$1" account="$2" password="$3"
    shift 3
    log "register: ${name}"
    "${BIN}/pprev-prover" register \
        --notary "127.0.0.1:${MPC_PORT}" --verifier "127.0.0.1:${VERIFIER_PORT}" \
        --registry "127.0.0.1:${REGISTRY_PORT}" --ca "${WORK}/registry-ca.der" \
        --account "${account}" --password "${password}" --property "${PROPERTY}" \
        --policy "${POLICY}" --root "${ROOT}" --rpc-url "${RPC}" --contract "${PPREV_ADDRESS}" \
        --key-file "${WORK}/account1.key" --amount-wei "${AMOUNT_WEI}" \
        --settlement-share-bps "${SETTLEMENT_SHARE_BPS}" --collateral-wei "${COLLATERAL_WEI}" \
        --out "${WORK}/${name}" "$@" >"${WORK}/${name}.log" 2>&1 || true
    [ -f "${WORK}/${name}/record.json" ] || die "${name}: no record written"
}

# submit <name> <payload> <key file>: sends a payload; never fails the script.
submit() {
    log "submit: $1"
    "${BIN}/pprev-prover" submit --payload "$2" --rpc-url "${RPC}" --key-file "$3" \
        --out "${WORK}/$1.json" >"${WORK}/$1.log" 2>&1 || true
    [ -f "${WORK}/$1.json" ] || die "$1: no result written"
}

CHECKS="[]"
# check <name> <expected> <observed> <pass: true|false>
check() {
    CHECKS="$(jq -c --arg n "$1" --arg e "$2" --arg o "$3" --argjson p "$4" \
        '. + [{name: $n, expected: $e, observed: $o, pass: $p}]' <<<"${CHECKS}")"
    if [ "$4" = true ]; then log "PASS $1"; else log "FAIL $1: expected ${2}, observed ${3}"; fi
}
eq() { if [ "$1" = "$2" ]; then echo true; else echo false; fi; }
starts() { case "$1" in "$2"*) echo true ;; *) echo false ;; esac; }
has() { case "$1" in *"$2"*) echo true ;; *) echo false ;; esac; }

# ------------------------------------------------------------------ positive run

register positive "${OWNER_ACCOUNT}" "${OWNER_PASSWORD}"
P="${WORK}/positive/record.json"
[ "$(jq -r .outcome "${P}")" = registered ] \
    || die "positive run: $(jq -r '.outcome + " " + (.reason // "")' "${P}")"

TX_ID="$(jq -r .submission.event.txId "${P}")"
TX_ID_DEC="$(cast to-dec "${TX_ID}")"
ETA="$(jq -r .eta "${P}")"
C_TX="$(jq -r .cTx "${P}")"

for field in cTx policyIdR propertyId amount settlementShare r; do
    ev="$(jq -r ".submission.event.${field}" "${P}")"
    pl="$(jq -r ".payload.${field}" "${P}")"
    check "positive: Registered.${field} equals the submitted value" "${pl}" "${ev}" "$(eq "${ev}" "${pl}")"
done
lower() { tr '[:upper:]' '[:lower:]' <<<"$1"; }
ev_owner="$(jq -r .submission.event.owner "${P}")"
check "positive: Registered.owner is the caller" "${OWNER_ADDRESS}" "${ev_owner}" \
    "$(eq "$(lower "${ev_owner}")" "$(lower "${OWNER_ADDRESS}")")"
ev_coll="$(cast to-dec "$(jq -r .submission.event.collateral "${P}")")"
check "positive: Registered.collateral is msg.value" "${COLLATERAL_WEI}" "${ev_coll}" "$(eq "${ev_coll}" "${COLLATERAL_WEI}")"
state="$(cast call "${PPREV_ADDRESS}" "txState(uint256)(uint8)" "${TX_ID_DEC}" --rpc-url "${RPC}")"
check "positive: txState(txId) == Active (1)" 1 "${state}" "$(eq "${state}" 1)"
consumed="$(cast call "${PPREV_ADDRESS}" "consumed(bytes32)(bool)" "${ETA}" --rpc-url "${RPC}")"
check "positive: consumed(eta_R)" true "${consumed}" "$(eq "${consumed}" true)"
registered="$(cast call "${PPREV_ADDRESS}" "registered(bytes32)(bool)" "${C_TX}" --rpc-url "${RPC}")"
check "positive: registered(C_tx)" true "${registered}" "$(eq "${registered}" true)"
balance="$(cast balance "${PPREV_ADDRESS}" --rpc-url "${RPC}")"
check "positive: contract balance is the collateral" "${COLLATERAL_WEI}" "${balance}" "$(eq "${balance}" "${COLLATERAL_WEI}")"

# ------------------------------------------------------------------ negative runs

register non-owner "${TENANT_ACCOUNT}" "${TENANT_PASSWORD}" \
    --proof-from "${WORK}/positive/proof.json"
N="${WORK}/non-owner/record.json"
w="$(jq -r .witness.satisfied "${N}")"
check "non-owner: phi_R has no witness" false "${w} ($(jq -r '.witness.failedAssertion // ""' "${N}"))" "$(eq "${w}" false)"
o="$(jq -r '.outcome + ": " + (.reason // "")' "${N}")"
check "non-owner: borrowed proof refused by the policy verifier" "refused: ...does not verify..." "${o}" \
    "$(if [ "$(starts "${o}" refused)" = true ] && [ "$(has "${o}" "does not verify")" = true ]; then echo true; else echo false; fi)"

register nonce-reuse "${OWNER_ACCOUNT}" "${OWNER_PASSWORD}" --eta "${ETA}"
o="$(jq -r '.outcome + ": " + (.reason // "")' "${WORK}/nonce-reuse/record.json")"
check "nonce-reuse: policy verifier refuses a signed nonce" "refused: ...already been signed..." "${o}" \
    "$(if [ "$(starts "${o}" refused)" = true ] && [ "$(has "${o}" "already been signed")" = true ]; then echo true; else echo false; fi)"

jq .payload "${P}" >"${WORK}/positive-payload.json"
submit other-address "${WORK}/positive-payload.json" "${WORK}/account2.key"
o="$(jq -r '.outcome + ": " + (.error // "")' "${WORK}/other-address.json")"
check "other-address: payload from ${ATTACKER_ADDRESS} reverts" "reverted: InvalidNotarySignature" "${o}" \
    "$(starts "${o}" "reverted: InvalidNotarySignature")"

submit replay "${WORK}/positive-payload.json" "${WORK}/account1.key"
o="$(jq -r '.outcome + ": " + (.error // "")' "${WORK}/replay.json")"
check "replay: same payload from the owner reverts" "reverted: NonceConsumed" "${o}" "$(starts "${o}" "reverted: NonceConsumed")"

register expired "${OWNER_ACCOUNT}" "${OWNER_PASSWORD}" --no-submit
o="$(jq -r .outcome "${WORK}/expired/record.json")"
check "expired: sigma_R obtained before the warp" signed "${o}" "$(eq "${o}" signed)"
if [ "${o}" = signed ]; then
    cast rpc evm_increaseTime "$((DELTA + 1))" --rpc-url "${RPC}" >/dev/null
    submit expired-submit "${WORK}/expired/payload.json" "${WORK}/account1.key"
    o="$(jq -r '.outcome + ": " + (.error // "")' "${WORK}/expired-submit.json")"
    check "expired: submission after Delta + 1 s reverts" "reverted: AttestationExpired" "${o}" \
        "$(starts "${o}" "reverted: AttestationExpired")"
fi

stop_all

# ------------------------------------------------------------------ record

first_line() { "$@" 2>&1 | head -n 1; }
lock_version() { awk -v n="$1" '$0 == "name = \"" n "\"" { getline; gsub(/version = |"/, ""); print; exit }' "${ROOT}/Cargo.lock"; }
DIRTY=false
[ -z "$(git -C "${ROOT}" status --porcelain)" ] || DIRTY=true

RUNS="{}"
for name in positive non-owner nonce-reuse expired; do
    RUNS="$(jq -c --arg n "${name}" --slurpfile r "${WORK}/${name}/record.json" '. + {($n): $r[0]}' <<<"${RUNS}")"
done
SUBMITS="{}"
for name in other-address replay expired-submit; do
    [ -f "${WORK}/${name}.json" ] || continue
    SUBMITS="$(jq -c --arg n "${name}" --slurpfile r "${WORK}/${name}.json" '. + {($n): $r[0]}' <<<"${SUBMITS}")"
done

jq -n \
    --arg runId "${RUN_ID}" \
    --arg commit "$(git -C "${ROOT}" rev-parse HEAD)" \
    --argjson dirty "${DIRTY}" \
    --argjson delta "${DELTA}" \
    --argjson checks "${CHECKS}" \
    --argjson runs "${RUNS}" \
    --argjson submits "${SUBMITS}" \
    --slurpfile events "${WORK}/notary-events.jsonl" \
    --arg pprev "${PPREV_ADDRESS}" --arg verifier "${VERIFIER_ADDRESS}" --arg vkNotary "${VK_NOTARY}" \
    --arg policy "${POLICY}" --arg property "${PROPERTY}" \
    --arg amount "${AMOUNT_WEI}" --arg collateral "${COLLATERAL_WEI}" --arg share "${SETTLEMENT_SHARE_BPS}" \
    --arg zkey "${ZKEY_SHA256}" --arg vk "${VK_SHA256}" \
    --arg anvil "$(first_line anvil --version)" \
    --arg forge "$(first_line forge --version)" \
    --arg cast "$(first_line cast --version)" \
    --arg solc "$(awk -F'"' '/^solc_version/ { print $2 }' "${ROOT}/contracts/foundry.toml")" \
    --arg circom "$(first_line circom --version)" \
    --arg snarkjs "$(jq -r .version "${CIRCUITS}/node_modules/snarkjs/package.json")" \
    --arg circomlib "$(jq -r .version "${CIRCUITS}/node_modules/circomlib/package.json")" \
    --arg node "$(node --version)" \
    --arg rustc "$(first_line rustc --version)" \
    --arg tlsn "$(grep -m 1 -o 'git+https://github.com/tlsnotary/tlsn?tag=[^"]*' "${ROOT}/Cargo.lock" | sed 's/.*tag=//')" \
    --arg alloy "$(lock_version alloy)" \
    --arg cpu "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)" \
    --arg memBytes "$(sysctl -n hw.memsize 2>/dev/null || echo unknown)" \
    --arg os "$(sw_vers -productVersion 2>/dev/null || uname -sr)" \
    '
    def ms(x): if x == null then null else (x * 1000 | round) / 1000 end;
    ($runs.positive) as $p
    | ($p.timings.insideDelta) as $in
    | ([$in.presentationMs, $in.readTAttMs, $in.tProveMs, $in.tVerifyMs, $in.tSignMs, $in.tInclMs] | add) as $sum
    | ([$in.tProveMs, $in.tVerifyMs, $in.tSignMs, $in.tInclMs] | add) as $formula
    | {
        runId: $runId,
        commit: $commit,
        workingTreeDirty: $dirty,
        passed: ($checks | all(.pass)),
        machine: {cpu: $cpu, memoryBytes: ($memBytes | tonumber? // $memBytes), os: $os},
        tools: {
            anvil: $anvil, forge: $forge, cast: $cast, solc: $solc, circom: $circom,
            snarkjs: $snarkjs, circomlib: $circomlib, node: $node, rustc: $rustc,
            tlsn: $tlsn, alloy: $alloy
        },
        artifacts: {zkeySha256: $zkey, verificationKeySha256: $vk},
        deployment: {
            chainId: 31337, pprev: $pprev, ecdsaNotaryVerifier: $verifier, vkNotary: $vkNotary,
            deltaS: $delta, policy: $policy, blockProduction: "anvil automine (one block per transaction)"
        },
        statement: {property: $property, amountWei: $amount, settlementShareBps: ($share | tonumber), collateralWei: $collateral},
        positive: {
            outsideDelta: ($p.timings.outsideDelta | map_values(ms(.))),
            insideDelta: {
                presentationMs: ms($in.presentationMs),
                readTAttMs: ms($in.readTAttMs),
                witnessMs: ms($in.witnessMs),
                snarkjsProveMs: ms($in.snarkjsProveMs),
                tProveMs: ms($in.tProveMs),
                tVerifyMs: ms($in.tVerifyMs),
                tSignMs: ms($in.tSignMs),
                tInclMs: ms($in.tInclMs),
                sumMs: ms($sum),
                deltaMs: ($delta * 1000),
                sumOverDelta: (($sum / ($delta * 1000)) * 1e6 | round / 1e6)
            },
            paperFormula: {
                description: "Delta >= t_prove + t_verify + t_sign + t_incl (Section VII-F); t_prove includes witness generation",
                tProveMs: ms($in.tProveMs),
                tVerifyMs: ms($in.tVerifyMs),
                tSignMs: ms($in.tSignMs),
                tInclMs: ms($in.tInclMs),
                sumMs: ms($formula),
                deltaMs: ($delta * 1000),
                sumOverDelta: (($formula / ($delta * 1000)) * 1e6 | round / 1e6)
            },
            verifierDetail: ($p.timings.verifier | map_values(ms(.))),
            otherAfterAttestation: {
                verifierRoundTripMs: ms($p.timings.verifierRoundTripMs),
                afterAttestationMs: ms($p.timings.afterAttestationMs),
                notInInsideDeltaMs: ms($p.timings.afterAttestationMs - $sum),
                attestationArrivalMinusTAttMs: $p.timings.attestationArrivalMinusTAttMs
            },
            onChain: {
                tAtt: $p.tAtt,
                blockTimestamp: $p.submission.blockTimestamp,
                blockTimestampMinusTAttS: ($p.submission.blockTimestamp - $p.tAtt),
                blockNumber: $p.submission.blockNumber,
                gasUsed: $p.submission.gasUsed,
                txHash: $p.submission.txHash
            }
        },
        d33: {
            sessions: [$runs | to_entries[] | {run: .key, attempts: .value.notarization.attempts, stalls: .value.notarization.stalls}],
            notarySessions: ($events | map(select(.event == "session")) | group_by(.outcome) | map({(.[0].outcome): length}) | add)
        },
        checks: $checks,
        runs: $runs,
        submissions: $submits,
        notaryEvents: $events
    }' >"${OUT}"

log "record: ${OUT#"${ROOT}/"}"
jq -r '
    "Delta-inside (ms): presentation \(.positive.insideDelta.presentationMs), t_prove \(.positive.insideDelta.tProveMs) (witness \(.positive.insideDelta.witnessMs) + snarkjs \(.positive.insideDelta.snarkjsProveMs)), t_verify \(.positive.insideDelta.tVerifyMs), t_sign \(.positive.insideDelta.tSignMs), t_incl \(.positive.insideDelta.tInclMs); sum \(.positive.insideDelta.sumMs) = \(.positive.insideDelta.sumOverDelta) of Delta",
    "checks: \([.checks[] | select(.pass)] | length)/\(.checks | length) passed"
' "${OUT}" >&2
[ "$(jq -r .passed "${OUT}")" = true ] || die "some checks failed"
