#!/usr/bin/env bash
# End-to-end rental lifecycle on a local anvil chain: Register, Apply, Engage, Settle, with a
# TLSNotary session and a Groth16 proof of phi_R, phi_A, and phi_S against the local mock registry.
#
# Starts the stack of lib/common.sh with the registry's tenancy notations dated today in the
# registry's time zone (the engagement happens today on anvil), then runs:
#   register         the owner of a fixture property lists it (phi_R)
#   apply            the tenant applies with an income of 3.5 times the rent (phi_A, multiple 3)
#   apply-poor       an account with 2.9 times the rent: phi_A has no witness; the tenant's proof,
#                    borrowed, is refused by the policy verifier
#   apply-identity   the tenant's session with c_B naming another account: phi_A has no witness
#   apply-nonce      the tenant again with the nonce of its signed application: refused
#   apply-replay     the tenant's Apply payload sent again: NonceConsumed
#   engage           the owner engages the tenant's application
#   settle-stale     a notation of the tenant on the property, dated before the engagement day:
#                    phi_S has no witness; the valid notation's proof, borrowed, is refused
#   settle-property  a notation of the tenant on another property: phi_S has no witness
#   settle-tenant    a notation of another tenant on the property: phi_S has no witness
#   settle           the owner settles with the valid notation (signed, not yet sent)
#   settle-other     that payload sent from another account: NotListingOwner
#   settle-submit    that payload sent from the owner: Settled, with the payouts of a rental
#   settle-replay    the same payload again: NotLocked
#
# Output: measurements/e2e_lifecycle/<run>.json (checks, per-phase timings and gas, tool versions,
# circuit hashes, commit). Intermediate files go to target/e2e_lifecycle/<run>/.
set -euo pipefail

LOG_TAG=lifecycle
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

PROPERTY="TR-06-CANKAYA-000123"
OWNER_ACCOUNT="ACC-000000000001"
OWNER_PASSWORD="owner-one"
POOR_ACCOUNT="ACC-000000000002"
POOR_PASSWORD="owner-two"
TENANT_ACCOUNT="ACC-000000000003"
TENANT_PASSWORD="tenant"
AMOUNT_WEI="1000000000000000000"    # txData.amount: 1 ETH monthly rent
SETTLEMENT_SHARE_BPS=0              # rental (D18)
COLLATERAL_WEI="500000000000000000" # 0.5 ETH, within [minCollateral, maxCollateral]
DEPOSIT_WEI="50000000000000000"     # 0.05 ETH, reqEscrow of rental-v1

OUT_DIR="${MEASUREMENTS_DIR:?}/e2e_lifecycle"

preflight
preflight_phases
check_ports_free
init_run e2e_lifecycle
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"

# Tenancy notations dated today in the registry's time zone, except the stale one.
UTC_OFFSET_SECS="$(jq -r .settle.utcOffsetSecs "${ROOT}/${POLICY}")"
TODAY="$(python3 -c 'import datetime, sys
tz = datetime.timezone(datetime.timedelta(seconds=int(sys.argv[1])))
print(datetime.datetime.now(tz).date().isoformat())' "${UTC_OFFSET_SECS}")"
jq --arg today "${TODAY}" \
    '.tenancies |= map(if .id == "N-0002" then . else .recordDate = $today end)' \
    "${ROOT}/mock-registry/fixtures/records.json" >"${WORK}/fixtures.json"
REGISTRY_FIXTURES="${WORK}/fixtures.json"
log "tenancy notations dated ${TODAY} (UTC offset ${UTC_OFFSET_SECS} s); N-0002 keeps its date"

build_all
start_stack
OWNER_ADDRESS="$(cast wallet address --private-key "$(cat "${WORK}/account1.key")")"
TENANT_ADDRESS="$(cast wallet address --private-key "$(cat "${WORK}/account2.key")")"
[ "${TAU_LOCK}" = "$(cast call "${PPREV_ADDRESS}" "TAU_LOCK()(uint256)" --rpc-url "${RPC}" | cut -d' ' -f1)" ] \
    || die "the notary's tau_lock differs from the contract's"

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
both() { if [ "$1" = true ] && [ "$2" = true ]; then echo true; else echo false; fi; }
outcome() { jq -r '.outcome + ": " + (.reason // "")' "$1"; }

SESSION=(--notary "127.0.0.1:${MPC_PORT}" --verifier "127.0.0.1:${VERIFIER_PORT}"
    --registry "127.0.0.1:${REGISTRY_PORT}" --ca "${WORK}/registry-ca.der"
    --policy "${POLICY}" --root "${ROOT}" --rpc-url "${RPC}" --contract "${PPREV_ADDRESS}")

# run <name> <subcommand> [args...]: runs the prover; never fails the script.
run() {
    local name="$1" sub="$2"
    shift 2
    log "${sub}: ${name}"
    "${BIN}/pprev-prover" "${sub}" "$@" --out "${WORK}/${name}" >"${WORK}/${name}.log" 2>&1 || true
    [ -f "${WORK}/${name}/record.json" ] || die "${name}: no record written"
}

# send <name> <subcommand> <payload> <key file>: sends a payload; never fails the script.
send() {
    log "$2: $1"
    "${BIN}/pprev-prover" "$2" --payload "$3" --rpc-url "${RPC}" --key-file "$4" \
        --out "${WORK}/$1.json" >"${WORK}/$1.log" 2>&1 || true
    [ -f "${WORK}/$1.json" ] || die "$1: no result written"
}

# ------------------------------------------------------------------ Register

log "register: register"
"${BIN}/pprev-prover" register "${SESSION[@]:0:8}" \
    --account "${OWNER_ACCOUNT}" --password "${OWNER_PASSWORD}" --property "${PROPERTY}" \
    --policy "${POLICY}" --root "${ROOT}" --rpc-url "${RPC}" --contract "${PPREV_ADDRESS}" \
    --key-file "${WORK}/account1.key" --amount-wei "${AMOUNT_WEI}" \
    --settlement-share-bps "${SETTLEMENT_SHARE_BPS}" --collateral-wei "${COLLATERAL_WEI}" \
    --out "${WORK}/register" >"${WORK}/register.log" 2>&1 || true
LISTING="${WORK}/register/record.json"
[ "$(jq -r .outcome "${LISTING}")" = registered ] || die "register: $(outcome "${LISTING}")"
TX_ID_DEC="$(cast to-dec "$(jq -r .submission.event.txId "${LISTING}")")"
check "register: listing registered" registered "$(jq -r .outcome "${LISTING}")" true

# ------------------------------------------------------------------ Apply

APPLY=("${SESSION[@]}" --listing "${LISTING}" --deposit-wei "${DEPOSIT_WEI}")

run apply apply "${APPLY[@]}" --account "${TENANT_ACCOUNT}" --password "${TENANT_PASSWORD}" \
    --key-file "${WORK}/account2.key"
A="${WORK}/apply/record.json"
[ "$(jq -r .outcome "${A}")" = included ] || die "apply: $(outcome "${A}")"
APP_ID_DEC="$(cast to-dec "$(jq -r .submission.event.appId "${A}")")"
check "apply: Applied" included "$(jq -r .outcome "${A}")" true
ev="$(jq -r .submission.event.cB "${A}")"
check "apply: Applied.cB is the submitted c_B" "$(jq -r .payload.cB "${A}")" "${ev}" "$(eq "${ev}" "$(jq -r .payload.cB "${A}")")"
status="$(cast call "${PPREV_ADDRESS}" "applications(uint256)(uint256,address,uint8,uint256,bytes32)" "${APP_ID_DEC}" --rpc-url "${RPC}" | sed -n 3p)"
check "apply: application Pending (1)" 1 "${status}" "$(eq "${status}" 1)"
consumed="$(cast call "${PPREV_ADDRESS}" "consumed(bytes32)(bool)" "$(jq -r .eta "${A}")" --rpc-url "${RPC}")"
check "apply: consumed(eta_A)" true "${consumed}" "$(eq "${consumed}" true)"

run apply-poor apply "${APPLY[@]}" --account "${POOR_ACCOUNT}" --password "${POOR_PASSWORD}" \
    --key-file "${WORK}/account0.key" --proof-from "${WORK}/apply/proof.json"
N="${WORK}/apply-poor/record.json"
w="$(jq -r .witness.satisfied "${N}")"
check "apply-poor: phi_A has no witness below the income multiple" false \
    "${w} ($(jq -r '.witness.failedAssertion // ""' "${N}"))" "$(eq "${w}" false)"
o="$(outcome "${N}")"
check "apply-poor: borrowed proof refused" "refused: ...does not verify..." "${o}" \
    "$(both "$(starts "${o}" refused)" "$(has "${o}" "does not verify")")"

run apply-identity apply "${APPLY[@]}" --account "${TENANT_ACCOUNT}" --password "${TENANT_PASSWORD}" \
    --key-file "${WORK}/account2.key" --identifier "${POOR_ACCOUNT}"
N="${WORK}/apply-identity/record.json"
o="$(outcome "${N}")"
check "apply-identity: c_B naming another account has no witness" "noWitness: ...PhiA..." "${o}" \
    "$(both "$(starts "${o}" noWitness)" "$(has "${o}" "template PhiA")")"

run apply-nonce apply "${APPLY[@]}" --account "${TENANT_ACCOUNT}" --password "${TENANT_PASSWORD}" \
    --key-file "${WORK}/account2.key" --eta "$(jq -r .eta "${A}")"
o="$(outcome "${WORK}/apply-nonce/record.json")"
check "apply-nonce: policy verifier refuses a signed nonce" "refused: ...already been signed..." "${o}" \
    "$(both "$(starts "${o}" refused)" "$(has "${o}" "already been signed")")"

send apply-replay submit-apply "${WORK}/apply/payload.json" "${WORK}/account2.key"
o="$(jq -r '.outcome + ": " + (.error // "")' "${WORK}/apply-replay.json")"
check "apply-replay: same payload reverts" "reverted: NonceConsumed" "${o}" "$(starts "${o}" "reverted: NonceConsumed")"

# ------------------------------------------------------------------ Engage

log "engage"
"${BIN}/pprev-prover" engage --application "${A}" --rpc-url "${RPC}" --contract "${PPREV_ADDRESS}" \
    --key-file "${WORK}/account1.key" --out "${WORK}/engage.json" >"${WORK}/engage.log" 2>&1 || true
[ "$(jq -r .outcome "${WORK}/engage.json")" = included ] || die "engage: $(jq -r .error "${WORK}/engage.json")"
expires="$(cast to-dec "$(jq -r .event.expiresAt "${WORK}/engage.json")")"
block_ts="$(jq -r .blockTimestamp "${WORK}/engage.json")"
check "engage: expiresAt = block time + tau_lock" "$((block_ts + TAU_LOCK))" "${expires}" "$(eq "${expires}" "$((block_ts + TAU_LOCK))")"
state="$(cast call "${PPREV_ADDRESS}" "txState(uint256)(uint8)" "${TX_ID_DEC}" --rpc-url "${RPC}")"
check "engage: txState(txId) == Locked (2)" 2 "${state}" "$(eq "${state}" 2)"

# ------------------------------------------------------------------ Settle

SETTLE=("${SESSION[@]}" --listing "${LISTING}" --application "${A}" --engagement "${WORK}/engage.json"
    --account "${OWNER_ACCOUNT}" --password "${OWNER_PASSWORD}" --key-file "${WORK}/account1.key")

run settle settle "${SETTLE[@]}" --notation N-0001 --no-submit
S="${WORK}/settle/record.json"
[ "$(jq -r .outcome "${S}")" = signed ] || die "settle: $(outcome "${S}")"
check "settle: sigma_S for the notation of the engagement day" signed "$(jq -r .outcome "${S}")" true

run settle-stale settle "${SETTLE[@]}" --notation N-0002 --no-submit --proof-from "${WORK}/settle/proof.json"
N="${WORK}/settle-stale/record.json"
w="$(jq -r '.witness.failedAssertion // ""' "${N}")"
check "settle-stale: phi_S has no witness before the engagement day" "template PhiS ..." "${w}" "$(starts "${w}" "template PhiS")"
o="$(outcome "${N}")"
check "settle-stale: borrowed proof refused" "refused: ...does not verify..." "${o}" \
    "$(both "$(starts "${o}" refused)" "$(has "${o}" "does not verify")")"

run settle-property settle "${SETTLE[@]}" --notation N-0003 --no-submit
o="$(outcome "${WORK}/settle-property/record.json")"
check "settle-property: notation on another property has no witness" "noWitness: ...PhiS..." "${o}" \
    "$(both "$(starts "${o}" noWitness)" "$(has "${o}" "template PhiS")")"

run settle-tenant settle "${SETTLE[@]}" --notation N-0004 --no-submit
o="$(outcome "${WORK}/settle-tenant/record.json")"
check "settle-tenant: notation of another tenant has no witness" "noWitness: ...PhiS..." "${o}" \
    "$(both "$(starts "${o}" noWitness)" "$(has "${o}" "template PhiS")")"

send settle-other submit-settle "${WORK}/settle/payload.json" "${WORK}/account2.key"
o="$(jq -r '.outcome + ": " + (.error // "")' "${WORK}/settle-other.json")"
check "settle-other: payload from another account reverts" "reverted: NotListingOwner" "${o}" "$(starts "${o}" "reverted: NotListingOwner")"

owner_before="$(cast balance "${OWNER_ADDRESS}" --rpc-url "${RPC}")"
tenant_before="$(cast balance "${TENANT_ADDRESS}" --rpc-url "${RPC}")"
send settle-submit submit-settle "${WORK}/settle/payload.json" "${WORK}/account1.key"
SS="${WORK}/settle-submit.json"
check "settle-submit: Settled" included "$(jq -r .outcome "${SS}")" "$(eq "$(jq -r .outcome "${SS}")" included)"
state="$(cast call "${PPREV_ADDRESS}" "txState(uint256)(uint8)" "${TX_ID_DEC}" --rpc-url "${RPC}")"
check "settle-submit: txState(txId) == Settled (3)" 3 "${state}" "$(eq "${state}" 3)"
to_owner="$(cast to-dec "$(jq -r .event.toOwner "${SS}")")"
to_tenant="$(cast to-dec "$(jq -r .event.toCounterparty "${SS}")")"
check "settle-submit: owner receives the collateral (share 0)" "${COLLATERAL_WEI}" "${to_owner}" "$(eq "${to_owner}" "${COLLATERAL_WEI}")"
check "settle-submit: tenant receives the deposit" "${DEPOSIT_WEI}" "${to_tenant}" "$(eq "${to_tenant}" "${DEPOSIT_WEI}")"
tenant_after="$(cast balance "${TENANT_ADDRESS}" --rpc-url "${RPC}")"
gained="$(python3 -c 'import sys; print(int(sys.argv[2]) - int(sys.argv[1]))' "${tenant_before}" "${tenant_after}")"
check "settle-submit: tenant balance grows by the deposit" "${DEPOSIT_WEI}" "${gained}" "$(eq "${gained}" "${DEPOSIT_WEI}")"
balance="$(cast balance "${PPREV_ADDRESS}" --rpc-url "${RPC}")"
check "settle-submit: contract holds nothing" 0 "${balance}" "$(eq "${balance}" 0)"
: "${owner_before}"

send settle-replay submit-settle "${WORK}/settle/payload.json" "${WORK}/account1.key"
o="$(jq -r '.outcome + ": " + (.error // "")' "${WORK}/settle-replay.json")"
check "settle-replay: same payload reverts" "reverted: NotLocked" "${o}" "$(starts "${o}" "reverted: NotLocked")"

stop_all

# ------------------------------------------------------------------ record

RUNS="{}"
for name in register apply apply-poor apply-identity apply-nonce settle settle-stale settle-property settle-tenant; do
    RUNS="$(jq -c --arg n "${name}" --slurpfile r "${WORK}/${name}/record.json" '. + {($n): $r[0]}' <<<"${RUNS}")"
done
TXS="{}"
for name in apply-replay engage settle-other settle-submit settle-replay; do
    TXS="$(jq -c --arg n "${name}" --slurpfile r "${WORK}/${name}.json" '. + {($n): $r[0]}' <<<"${TXS}")"
done
CIRCUITS_JSON="$(jq -n \
    --slurpfile r "${CIRCUITS}/setup/setup.json" \
    --slurpfile a "${CIRCUITS}/setup/phi_a/setup.json" \
    --slurpfile s "${CIRCUITS}/setup/phi_s/setup.json" \
    '{phiR: {zkeySha256: $r[0].zkeySha256, verificationKeySha256: $r[0].verificationKeySha256},
      phiA: {constraints: $a[0].constraints, zkeySha256: $a[0].zkeySha256, verificationKeySha256: $a[0].verificationKeySha256, phase2: $a[0].phase2.trust},
      phiS: {constraints: $s[0].constraints, zkeySha256: $s[0].zkeySha256, verificationKeySha256: $s[0].verificationKeySha256, phase2: $s[0].phase2.trust}}')"

jq -n \
    --arg runId "${RUN_ID}" \
    --argjson prov "$(provenance_json)" \
    --argjson delta "${DELTA}" --argjson tauLock "${TAU_LOCK}" --argjson utcOffset "${UTC_OFFSET_SECS}" \
    --arg today "${TODAY}" \
    --argjson checks "${CHECKS}" \
    --argjson runs "${RUNS}" \
    --argjson txs "${TXS}" \
    --argjson circuits "${CIRCUITS_JSON}" \
    --slurpfile events "${WORK}/notary-events.jsonl" \
    --arg pprev "${PPREV_ADDRESS}" --arg vkNotary "${VK_NOTARY}" --arg policy "${POLICY}" \
    --arg property "${PROPERTY}" --arg amount "${AMOUNT_WEI}" --arg collateral "${COLLATERAL_WEI}" \
    --arg deposit "${DEPOSIT_WEI}" \
    '
    def ms(x): if x == null then null else (x * 1000 | round) / 1000 end;
    def phase(p): {
        tProveMs: ms(p.timings.insideDelta.tProveMs),
        tVerifyMs: ms(p.timings.insideDelta.tVerifyMs),
        tSignMs: ms(p.timings.insideDelta.tSignMs),
        tInclMs: ms(p.timings.insideDelta.tInclMs),
        mpcTlsMs: ms(p.timings.outsideDelta.mpcTlsMs),
        groth16VerifyMs: ms(p.timings.verifier.groth16Ms),
        gasUsed: p.submission.gasUsed,
        attempts: p.notarization.attempts
    };
    {
        runId: $runId,
        commit: $prov.commit,
        workingTreeDirty: $prov.workingTreeDirty,
        passed: ($checks | all(.pass)),
        machine: $prov.machine,
        tools: $prov.tools,
        circuits: $circuits,
        deployment: {chainId: 31337, pprev: $pprev, vkNotary: $vkNotary, deltaS: $delta, tauLockS: $tauLock,
            policy: $policy, registryUtcOffsetS: $utcOffset, notationDate: $today,
            blockProduction: "anvil automine (one block per transaction)"},
        statement: {property: $property, amountWei: $amount, collateralWei: $collateral, depositWei: $deposit},
        singleRun: {
            note: "one run per phase; not a timing distribution",
            register: phase($runs.register),
            apply: phase($runs.apply),
            settle: (phase($runs.settle) + {gasUsed: $txs["settle-submit"].gasUsed, tInclMs: ms($txs["settle-submit"].tInclMs)}),
            engage: {gasUsed: $txs.engage.gasUsed, tInclMs: ms($txs.engage.tInclMs)}
        },
        checks: $checks,
        runs: $runs,
        transactions: $txs,
        notaryEvents: $events
    }' >"${OUT}"

log "record: ${OUT#"${ROOT}/"}"
jq -r '"checks: \([.checks[] | select(.pass)] | length)/\(.checks | length) passed"' "${OUT}" >&2
[ "$(jq -r .passed "${OUT}")" = true ] || die "some checks failed"
