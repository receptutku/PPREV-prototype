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

LOG_TAG=e2e
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

PROPERTY="TR-06-CANKAYA-000123"
OWNER_ACCOUNT="ACC-000000000001"
OWNER_PASSWORD="owner-one"
TENANT_ACCOUNT="ACC-000000000003"
TENANT_PASSWORD="tenant"
AMOUNT_WEI="1000000000000000000"    # txData.amount: 1 ETH monthly rent
SETTLEMENT_SHARE_BPS=0              # rental (D18)
COLLATERAL_WEI="500000000000000000" # 0.5 ETH, within [minCollateral, maxCollateral]

OUT_DIR="${MEASUREMENTS_DIR:?}/e2e_register"

preflight
check_ports_free
init_run e2e
mkdir -p "${OUT_DIR:?}"
OUT="${OUT_DIR:?}/${RUN_ID:?}.json"
build_all
start_stack
OWNER_ADDRESS="$(cast wallet address --private-key "$(cat "${WORK}/account1.key")")"
ATTACKER_ADDRESS="$(cast wallet address --private-key "$(cat "${WORK}/account2.key")")"

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
    --argjson prov "$(provenance_json)" \
    --argjson delta "${DELTA}" \
    --argjson checks "${CHECKS}" \
    --argjson runs "${RUNS}" \
    --argjson submits "${SUBMITS}" \
    --slurpfile events "${WORK}/notary-events.jsonl" \
    --arg pprev "${PPREV_ADDRESS}" --arg verifier "${VERIFIER_ADDRESS}" --arg vkNotary "${VK_NOTARY}" \
    --arg policy "${POLICY}" --arg property "${PROPERTY}" \
    --arg amount "${AMOUNT_WEI}" --arg collateral "${COLLATERAL_WEI}" --arg share "${SETTLEMENT_SHARE_BPS}" \
    --arg zkey "${ZKEY_SHA256}" --arg vk "${VK_SHA256}" \
    '
    def ms(x): if x == null then null else (x * 1000 | round) / 1000 end;
    ($runs.positive) as $p
    | ($p.timings.insideDelta) as $in
    | ([$in.presentationMs, $in.readTAttMs, $in.tProveMs, $in.tVerifyMs, $in.tSignMs, $in.tInclMs] | add) as $sum
    | ([$in.tProveMs, $in.tVerifyMs, $in.tSignMs, $in.tInclMs] | add) as $formula
    | {
        runId: $runId,
        commit: $prov.commit,
        workingTreeDirty: $prov.workingTreeDirty,
        passed: ($checks | all(.pass)),
        machine: $prov.machine,
        tools: $prov.tools,
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
