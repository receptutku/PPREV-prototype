# Shared parts of the end-to-end and measurement scripts. Source it after `set -euo pipefail` and after
# setting LOG_TAG; it defines ROOT and the helpers below and installs the exit trap.
#
#   init_run <kind>      RUN_ID, WORK=target/<kind>/<run>
#   preflight            tools, pinned Node.js, circuit artifacts checked against setup.json
#   build_all            release binaries and contracts
#   start_stack          anvil, deployment, mock registry, notary (sets RPC, PPREV_ADDRESS, ...)
#   require_clean_tree   refuses a dirty working tree unless PPREV_ALLOW_DIRTY=1
#   provenance_json      commit, dirty flag, tool versions, machine, as one JSON object
#
# Every process started with `start` is stopped on exit, on success, failure, or interrupt, and the
# ports are checked free before starting and after stopping.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ROOT:?}/target/release"
CIRCUITS="${ROOT:?}/circuits"
MEASUREMENTS_DIR="${PPREV_MEASUREMENTS_DIR:-${ROOT:?}/measurements}"

ANVIL_PORT="${ANVIL_PORT:-8545}"
REGISTRY_PORT="${REGISTRY_PORT:-4443}"
MPC_PORT="${MPC_PORT:-7047}"
VERIFIER_PORT="${VERIFIER_PORT:-7048}"
PORTS="${ANVIL_PORT:?} ${REGISTRY_PORT:?} ${MPC_PORT:?} ${VERIFIER_PORT:?}"
CHAIN_ID=31337
RPC="http://127.0.0.1:${ANVIL_PORT:?}"
POLICY="policies/rental-v1.json"
WORK=""

log() { printf '[%s] %s\n' "${LOG_TAG:-pprev}" "$*" >&2; }
die() { log "error: $*"; exit 1; }

if ! command -v forge >/dev/null && [ -x "${HOME:?}/.foundry/bin/forge" ]; then
    PATH="${HOME:?}/.foundry/bin:${PATH}"
fi

init_run() {
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
    WORK="${ROOT:?}/target/$1/${RUN_ID:?}"
    umask 077
    mkdir -p "${WORK:?}"
    log "run ${RUN_ID}, work directory ${WORK#"${ROOT}/"}"
}

# ------------------------------------------------------------------ preflight

# Node.js runs the witness generator and snarkjs. The version is pinned in .nvmrc and must equal the
# one that produced the setup (circuits/setup/setup.json). PPREV_NODE names a node binary; without
# it, the node on PATH, Homebrew's, and nvm's are tried in that order.
select_node() {
    NODE_VERSION="$(tr -d '[:space:]' <"${ROOT:?}/.nvmrc")"
    [ "${NODE_VERSION}" = "$(jq -r .tools.node "${CIRCUITS:?}/setup/setup.json")" ] \
        || die ".nvmrc (${NODE_VERSION}) differs from the node version in circuits/setup/setup.json"
    local candidates candidate
    if [ -n "${PPREV_NODE:-}" ]; then
        candidates="${PPREV_NODE}"
    else
        candidates="$(command -v node || true) /opt/homebrew/bin/node ${HOME:?}/.nvm/versions/node/${NODE_VERSION}/bin/node"
    fi
    NODE_BIN=""
    for candidate in ${candidates}; do
        [ -x "${candidate}" ] || continue
        if [ "$("${candidate}" --version)" = "${NODE_VERSION}" ]; then
            NODE_BIN="${candidate}"
            break
        fi
    done
    [ -n "${NODE_BIN}" ] || die "node ${NODE_VERSION} not found (tried: ${candidates}); set PPREV_NODE"
    PATH="$(dirname "${NODE_BIN}"):${PATH}"
    [ "$(node --version)" = "${NODE_VERSION}" ] || die "node on PATH is not ${NODE_VERSION}"
}

# check_not_dataless <file...>: macOS "Optimize Mac Storage" evicts files; reading one then waits for
# a download, which would enter the timings.
check_not_dataless() {
    local f
    for f in "$@"; do
        [ -e "${f}" ] || die "missing: ${f#"${ROOT}/"}"
        case "$(stat -f %Sf "${f}")" in
            *dataless*) die "${f#"${ROOT}/"} is evicted to iCloud (dataless); download it first" ;;
        esac
    done
}

preflight() {
    local tool
    for tool in anvil forge cast jq lsof openssl circom cargo git python3; do
        command -v "${tool}" >/dev/null || die "missing tool: ${tool}"
    done
    select_node
    [ -f "${CIRCUITS}/build/main_title_v1_js/main_title_v1.wasm" ] \
        || die "circuit not built; run script/circuits_build.sh"
    [ -f "${CIRCUITS}/build/phi_r.zkey" ] || die "proving key missing; run script/circuits_setup.sh"
    ZKEY_SHA256="$(shasum -a 256 "${CIRCUITS}/build/phi_r.zkey" | cut -d' ' -f1)"
    [ "${ZKEY_SHA256}" = "$(jq -r .zkeySha256 "${CIRCUITS}/setup/setup.json")" ] \
        || die "phi_r.zkey does not match circuits/setup/setup.json"
    VK_SHA256="$(shasum -a 256 "${CIRCUITS}/setup/verification_key.json" | cut -d' ' -f1)"
    [ "${VK_SHA256}" = "$(jq -r .verificationKeySha256 "${CIRCUITS}/setup/setup.json")" ] \
        || die "verification_key.json does not match circuits/setup/setup.json"
}

build_all() {
    log "building"
    (cd "${ROOT:?}" && cargo build -q --release -p pprev-prover -p pprev-notary -p mock-registry --bins)
    (cd "${ROOT:?}/contracts" && forge build -q)
}

git_dirty() { if [ -z "$(git -C "${ROOT}" status --porcelain)" ]; then echo false; else echo true; fi; }

require_clean_tree() {
    if [ "$(git_dirty)" = true ]; then
        [ "${PPREV_ALLOW_DIRTY:-0}" = 1 ] || die "working tree is dirty; commit first (PPREV_ALLOW_DIRTY=1 for a trial run)"
        log "working tree is dirty (PPREV_ALLOW_DIRTY=1): the record is marked dirty"
    fi
}

# ------------------------------------------------------------------ processes and ports

PIDS=()
NAMES=()
STARTED=false

listener_pids() { lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true; }

check_ports_free() {
    local busy="" port pids
    for port in ${PORTS}; do
        pids="$(listener_pids "${port}")"
        [ -z "${pids}" ] || busy="${busy} ${port}(pid ${pids//$'\n'/,})"
    done
    [ -z "${busy}" ] || die "ports in use:${busy}"
}

stop_all() {
    local i waited
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        kill -TERM "${PIDS[i]}" 2>/dev/null || true
    done
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        waited=0
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
    local status=$? f port left=""
    trap - EXIT INT TERM
    if [ "${status}" -ne 0 ] && [ -n "${WORK}" ] && [ -d "${WORK}" ]; then
        for f in "${WORK}"/*.log; do
            [ -f "${f}" ] || continue
            log "last lines of ${f#"${ROOT}/"}:"
            tail -n 5 "${f}" >&2 || true
        done
    fi
    stop_all
    # Ports busy before anything started belong to other processes; check_ports_free reported them.
    [ "${STARTED}" = true ] || exit "${status}"
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

# ------------------------------------------------------------------ local stack

# Starts anvil, deploys EcdsaNotaryVerifier and PPREV with the D18 parameters and the rental-v1
# bundle, and starts the mock registry and the notary with keys generated for this run. Sets RPC,
# PPREV_ADDRESS, VERIFIER_ADDRESS, VK_NOTARY, DELTA, and account<i>.key files (anvil accounts 0-2).
start_stack() {
    local i
    openssl rand -hex 32 >"${WORK}/attestation.key"
    openssl rand -hex 32 >"${WORK}/statement.key"
    VK_NOTARY="$(cast wallet address --private-key "0x$(cat "${WORK}/statement.key")")"

    start anvil "${WORK}/anvil.log" anvil --port "${ANVIL_PORT}" --chain-id "${CHAIN_ID}" \
        --config-out "${WORK}/anvil.json"
    wait_port "${ANVIL_PORT}" anvil "${PIDS[${#PIDS[@]} - 1]}"
    for i in 0 1 2; do
        jq -r ".private_keys[${i}]" "${WORK}/anvil.json" >"${WORK}/account${i}.key"
    done

    log "deploying"
    (cd "${ROOT:?}/contracts" && DEPLOYER_KEY="$(cat "${WORK}/account0.key")" VK_NOTARY="${VK_NOTARY}" \
        PPREV_POLICY="../${POLICY}" \
        forge script script/Deploy.s.sol --rpc-url "${RPC}" --broadcast -q) >"${WORK}/deploy.log" 2>&1
    cp "${ROOT:?}/contracts/broadcast/Deploy.s.sol/${CHAIN_ID}/run-latest.json" "${WORK}/deploy-broadcast.json"
    PPREV_ADDRESS="$(deployed_address PPREV)"
    VERIFIER_ADDRESS="$(deployed_address EcdsaNotaryVerifier)"
    [ "${PPREV_ADDRESS}" != null ] && [ "${VERIFIER_ADDRESS}" != null ] || die "deployment addresses not found"
    DELTA="$(cast call "${PPREV_ADDRESS}" "DELTA()(uint256)" --rpc-url "${RPC}")"
    [ "$(cast call "${VERIFIER_ADDRESS}" "VK_NOTARY()(address)" --rpc-url "${RPC}")" = "${VK_NOTARY}" ] \
        || die "the verifier does not hold vk_notary"
    log "PPREV ${PPREV_ADDRESS}, EcdsaNotaryVerifier ${VERIFIER_ADDRESS}, Delta ${DELTA} s"

    cd "${ROOT:?}"
    start mock-registry "${WORK}/registry.log" "${BIN}/mock-registry" \
        --bind "127.0.0.1:${REGISTRY_PORT}" --ca-out "${WORK}/registry-ca.der"
    wait_port "${REGISTRY_PORT}" mock-registry "${PIDS[${#PIDS[@]} - 1]}"

    start pprev-notary "${WORK}/notary.log" "${BIN}/pprev-notary" \
        --mpc-bind "127.0.0.1:${MPC_PORT}" --verifier-bind "127.0.0.1:${VERIFIER_PORT}" \
        --registry-ca "${WORK}/registry-ca.der" --policy "${POLICY}" --root "${ROOT}" \
        --attestation-key "${WORK}/attestation.key" --statement-key "${WORK}/statement.key" \
        --chain-id "${CHAIN_ID}" --contract "${PPREV_ADDRESS}" \
        --nonces "${WORK}/nonces.log" --log "${WORK}/notary-events.jsonl"
    wait_port "${MPC_PORT}" pprev-notary "${PIDS[${#PIDS[@]} - 1]}"
    wait_port "${VERIFIER_PORT}" pprev-notary "${PIDS[${#PIDS[@]} - 1]}"
}

deployed_address() {
    jq -r --arg n "$1" \
        '[.transactions[] | select(.transactionType == "CREATE" and .contractName == $n)][0].contractAddress' \
        "${WORK}/deploy-broadcast.json"
}

# ------------------------------------------------------------------ provenance

first_line() { "$@" 2>&1 | head -n 1; }
lock_version() { awk -v n="$1" '$0 == "name = \"" n "\"" { getline; gsub(/version = |"/, ""); print; exit }' "${ROOT}/Cargo.lock"; }

provenance_json() {
    jq -n \
        --arg commit "$(git -C "${ROOT}" rev-parse HEAD)" \
        --argjson dirty "$(git_dirty)" \
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
        --arg power "$(pmset -g batt 2>/dev/null | head -n 1 | sed "s/.*'\(.*\)'.*/\1/")" \
        '{
            commit: $commit,
            workingTreeDirty: $dirty,
            machine: {cpu: $cpu, memoryBytes: ($memBytes | tonumber? // $memBytes), os: $os, powerSource: $power},
            tools: {
                anvil: $anvil, forge: $forge, cast: $cast, solc: $solc, circom: $circom,
                snarkjs: $snarkjs, circomlib: $circomlib, node: $node, rustc: $rustc,
                tlsn: $tlsn, alloy: $alloy
            }
        }'
}
