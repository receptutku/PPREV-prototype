//! The policy verifier's Apply and Settle paths (Section V-B, step (d), for psi in {A, S}) on real
//! notarised sessions with the mock registry: presentation checks against the phase's layout, the
//! digest of x_psi, Groth16 verification with public inputs from the attestation and from x_psi,
//! the phase's own policy and key, the engagement day from the deployment's tau_lock, the
//! attestation day from t_att, one signature per nonce across phases (D20), one signed statement per
//! attestation, and one engagement per settlement notation (M2).
//!
//! Requires the proving keys of `script/circuits_setup_as.sh`.

// Dates are written Y_MM_DD, as phi_S encodes them.
#![allow(clippy::inconsistent_digit_grouping)]

mod common;

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use common::{
    ATTESTATION_KEY, MAX_RECV, MAX_SENT, TEST_PREPROCESS_TIMEOUT, attestation_verifying_key,
    fixtures, layout, provider, spawn_notary, workspace_path,
};
use mock_registry::{PhaseLayouts, RunningRegistry};
use pprev_notary::attestations::AttestationStore;
use pprev_notary::mock::counterparty_commitment;
use pprev_notary::nonces::NonceStore;
use pprev_notary::notations::NotationStore;
use pprev_notary::phases::{ApplyPolicy, ApplyRequest, SettlePolicy, SettleRequest};
use pprev_notary::presentation::t_att_of;
use pprev_notary::register::PolicyVerifier;
use pprev_notary::{
    DEFAULT_MAX_SESSION_SECS, Groth16Proof, Groth16Verifier, NotaryConfig, StatementKey,
};
use pprev_prover::circuit::{CircuitFiles, PhiAInput, PhiSInput, Unsatisfied, commitment, prove};
use pprev_prover::{DEFAULT_MAX_RETRIES, FieldOpening, NotarizedShape, ShapeSetup};
use pprev_types::calendar::{attestation_day, engagement_day};
use pprev_types::circuit::{PhiAPublic, PhiSPublic};
use pprev_types::field::bn254_r;
use pprev_types::statement::{Apply, Settle, TxData, digest, domain};
use pprev_types::{HeaderTemplate, RecordLayout};

const CHAIN_ID: u64 = 31337;
const TENANT: (&str, &str) = ("ACC-000000000003", "tenant");
const OWNER: (&str, &str) = ("ACC-000000000001", "owner-one");
const TAU_LOCK: u64 = 14 * 86_400;
/// Engaged at 2026-10-21T09:00:00Z, the day of the fixture notations N-0001, N-0003, N-0004.
const ENGAGED: u64 = 1_792_573_200;
const UTC_OFFSET: i64 = 3 * 3600;

fn contract() -> Address {
    Address::repeat_byte(0x5a)
}

fn policy_a() -> B256 {
    keccak256("rental-v1/A")
}

/// A second Apply policy whose key is not phi_A's.
fn policy_a2() -> B256 {
    keccak256("rental-v2/A")
}

fn policy_s() -> B256 {
    keccak256("rental-v1/S")
}

fn key() -> StatementKey {
    StatementKey::from_bytes(&keccak256("pprev.notary.statement-key.test").0).unwrap()
}

fn record_layout(name: &str) -> RecordLayout {
    RecordLayout::load(workspace_path(&format!("policies/layouts/{name}.json"))).unwrap()
}

fn phi_a_files() -> CircuitFiles {
    let files = CircuitFiles::phi_a(workspace_path("circuits"));
    assert!(files.zkey().exists(), "run script/circuits_setup_as.sh");
    files
}

fn phi_s_files() -> CircuitFiles {
    let files = CircuitFiles::phi_s(workspace_path("circuits"));
    assert!(files.zkey().exists(), "run script/circuits_setup_as.sh");
    files
}

fn verifier_of(files: &CircuitFiles) -> Groth16Verifier {
    Groth16Verifier::from_snarkjs_json(&std::fs::read_to_string(files.verification_key()).unwrap())
        .unwrap()
}

/// phi_A's key with gamma and delta exchanged: well-formed, seven public inputs, not the proofs' key.
fn other_phi_a_verifier() -> Groth16Verifier {
    let mut vk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(phi_a_files().verification_key()).unwrap())
            .unwrap();
    let gamma = vk["vk_gamma_2"].clone();
    vk["vk_gamma_2"] = vk["vk_delta_2"].clone();
    vk["vk_delta_2"] = gamma;
    Groth16Verifier::from_snarkjs_json(&vk.to_string()).unwrap()
}

/// A new directory for the records of one policy verifier.
fn ledger_dir() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pprev-phase-verifier-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn policy_verifier(ca_der: &[u8], tau_lock: Option<u64>) -> PolicyVerifier {
    policy_verifier_at(&ledger_dir(), &[ca_der], tau_lock, contract())
}

/// A policy verifier with its nonce, attestation, and notation records in `dir`, as the notary
/// opens them at start, trusting the registry CAs `cas`, for the PPREV deployment `contract`.
fn policy_verifier_at(
    dir: &std::path::Path,
    cas: &[&[u8]],
    tau_lock: Option<u64>,
    contract: Address,
) -> PolicyVerifier {
    let apply = HashMap::from([
        (
            policy_a(),
            ApplyPolicy {
                layout: record_layout("income-v1"),
                verifier: verifier_of(&phi_a_files()),
            },
        ),
        (
            policy_a2(),
            ApplyPolicy {
                layout: record_layout("income-v1"),
                verifier: other_phi_a_verifier(),
            },
        ),
    ]);
    let settle = HashMap::from([(
        policy_s(),
        SettlePolicy {
            layout: record_layout("tenancy-v1"),
            verifier: verifier_of(&phi_s_files()),
            utc_offset_secs: UTC_OFFSET,
        },
    )]);
    PolicyVerifier::new(
        HashMap::new(),
        attestation_verifying_key(),
        cas.iter().map(|ca| ca.to_vec()).collect(),
        DEFAULT_MAX_SESSION_SECS,
        key(),
        domain(CHAIN_ID, contract),
        NonceStore::open(dir.join("nonces.log")).unwrap(),
        AttestationStore::open(dir.join("attestations.log")).unwrap(),
    )
    .with_phases(
        apply,
        settle,
        tau_lock,
        NotationStore::open(dir.join("notations.log")).unwrap(),
    )
}

/// One notarised session of a phase source, with the registry's CA.
struct Session {
    notarized: NotarizedShape,
    ca_der: Vec<u8>,
    t_att: u64,
}

async fn notarize(account: (&str, &str), layout: &RecordLayout, subject: &str) -> Session {
    common::init_test_log();
    let registry = RunningRegistry::start_with_phases(
        common::layout(),
        PhaseLayouts {
            income: Some(record_layout("income-v1")),
            tenancy: Some(record_layout("tenancy-v1")),
        },
        fixtures(),
        "127.0.0.1:0",
    )
    .await
    .unwrap();
    let ca_der = registry.certs.ca_der.clone();
    let token = pprev_prover::login(
        registry.addr,
        &layout.server_name,
        &ca_der,
        account.0,
        account.1,
    )
    .await
    .unwrap();
    let setup = ShapeSetup {
        shape: layout.shape(subject).unwrap(),
        registry_addr: registry.addr,
        root_certs: vec![ca_der.clone()],
        token,
        max_sent: MAX_SENT,
        max_recv: MAX_RECV,
        preprocess_timeout: TEST_PREPROCESS_TIMEOUT,
        eth_attestation: false,
    };
    let mut config = NotaryConfig::new(ATTESTATION_KEY, vec![ca_der.clone()]);
    config.preprocess_timeout = TEST_PREPROCESS_TIMEOUT;
    let mut tasks = Vec::new();
    let (notarized, _) = pprev_prover::notarize_shape_with_retries(
        |_attempt| {
            let io = spawn_notary(&config, &mut tasks);
            async move { anyhow::Ok(io) }
        },
        &setup,
        DEFAULT_MAX_RETRIES,
    )
    .await
    .unwrap();
    tasks.pop().unwrap().await.unwrap().unwrap();
    let output = pprev_prover::present_shape(&notarized, false)
        .unwrap()
        .verify(&provider(&ca_der))
        .unwrap();
    Session {
        t_att: t_att_of(&output).unwrap(),
        notarized,
        ca_der,
    }
}

fn notarize_blocking(account: (&str, &str), layout: &RecordLayout, subject: &str) -> Session {
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(notarize(account, layout, subject))
}

fn salt() -> [u8; 32] {
    let mut salt = keccak256("pprev.test.salt").0;
    salt[0] &= 0x1f;
    salt
}

fn c_b() -> B256 {
    counterparty_commitment(TENANT.0.as_bytes(), &salt()).unwrap()
}

/// s_P, the salt of the owner's c_P from Register.
fn salt_p() -> [u8; 32] {
    let mut salt = keccak256("pprev.test.salt.p").0;
    salt[0] &= 0x1f;
    salt
}

/// c_P = H_c(identifier, s_P).
fn c_p(identifier: &str) -> B256 {
    counterparty_commitment(identifier.as_bytes(), &salt_p()).unwrap()
}

fn tx_data() -> TxData {
    TxData {
        propertyId: B256::from(layout().property_id_word("TR-06-CANKAYA-000123").unwrap()),
        amount: U256::from(10u64).pow(U256::from(18)),
        settlementShare: U256::ZERO,
    }
}

/// A named change to a statement.
type Change<X> = (&'static str, Box<dyn Fn(&mut X)>);

fn work_dir() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pprev-phase-proof-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn proof_of(files: &CircuitFiles, input: &impl serde::Serialize) -> Groth16Proof {
    let dir = work_dir();
    let proof = prove(files, input, &dir).expect("proving");
    let _ = std::fs::remove_dir_all(&dir);
    Groth16Proof::from_snarkjs_json(&proof.proof_json).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Apply

fn apply_session() -> &'static Session {
    static RUN: OnceLock<Session> = OnceLock::new();
    RUN.get_or_init(|| notarize_blocking(TENANT, &record_layout("income-v1"), ""))
}

fn apply_statement(session: &Session, policy_id: B256, eta: u8) -> Apply {
    Apply {
        txId: U256::from(1),
        cTx: keccak256("C_tx"),
        txData: tx_data(),
        cB: c_b(),
        policyId: policy_id,
        submitter: Address::repeat_byte(0x22),
        eta: B256::repeat_byte(eta),
        tAtt: session.t_att,
    }
}

fn apply_proof(session: &Session, x: &Apply) -> Groth16Proof {
    let openings = &session.notarized.openings;
    let public = PhiAPublic::new(
        commitment(&openings[0]),
        commitment(&openings[1]),
        x.cB.0,
        x.txData.amount,
        digest(x, &domain(CHAIN_ID, contract())).0,
    )
    .unwrap();
    proof_of(
        &phi_a_files(),
        &PhiAInput::new(&public, openings, &salt()).unwrap(),
    )
}

fn honest_apply() -> &'static (Apply, Groth16Proof) {
    static HONEST: OnceLock<(Apply, Groth16Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let session = apply_session();
        let x = apply_statement(session, policy_a(), 1);
        let proof = apply_proof(session, &x);
        (x, proof)
    })
}

fn apply_request(session: &Session, statement: Apply, proof: Groth16Proof) -> ApplyRequest {
    ApplyRequest {
        presentation: pprev_prover::present_shape(&session.notarized, false).unwrap(),
        statement,
        proof,
    }
}

fn apply_refused(pv: &mut PolicyVerifier, req: ApplyRequest, reason: &str) {
    let err = format!(
        "{:#}",
        pv.sign_apply(req).expect_err("the policy verifier signed")
    );
    assert!(err.contains(reason), "expected {reason:?}, got: {err}");
}

fn recovers_to_vk_notary(sigma: &[u8; 65], digest: B256) -> bool {
    Signature::from_raw(sigma)
        .unwrap()
        .recover_address_from_prehash(&digest)
        .unwrap()
        == key().vk_notary()
}

#[test]
fn signs_an_honest_apply_request_once() {
    let session = apply_session();
    let (x, proof) = honest_apply().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    let sigma = pv
        .sign_apply(apply_request(session, x.clone(), proof.clone()))
        .unwrap();
    assert!(recovers_to_vk_notary(
        &sigma,
        digest(&x, &domain(CHAIN_ID, contract()))
    ));
    apply_refused(
        &mut pv,
        apply_request(session, x, proof),
        "has already been signed",
    );
}

#[test]
fn refuses_an_apply_statement_changed_after_proving() {
    let session = apply_session();
    let (x, proof) = honest_apply().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    let changes: [Change<Apply>; 6] = [
        ("txId", Box::new(|x| x.txId = U256::from(2))),
        ("cTx", Box::new(|x| x.cTx = keccak256("other"))),
        ("amount", Box::new(|x| x.txData.amount -= U256::from(1))),
        (
            "propertyId",
            Box::new(|x| x.txData.propertyId = B256::repeat_byte(1)),
        ),
        (
            "submitter",
            Box::new(|x| x.submitter = Address::repeat_byte(0x33)),
        ),
        (
            "cB",
            Box::new(|x| x.cB = counterparty_commitment(b"ACC-000000000002", &salt()).unwrap()),
        ),
    ];
    for (name, change) in changes {
        let mut changed = x.clone();
        change(&mut changed);
        let err = format!(
            "{:#}",
            pv.sign_apply(apply_request(session, changed, proof.clone()))
                .expect_err(name)
        );
        assert!(err.contains("does not verify"), "{name}: {err}");
    }
}

#[test]
fn refuses_apply_inputs_outside_the_circuit_range() {
    let session = apply_session();
    let (x, proof) = honest_apply().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    // c_B = c_B + r would alias the honest c_B in the field.
    let aliased = num_bigint::BigUint::from_bytes_be(&x.cB.0) + bn254_r();
    let mut changed = x.clone();
    changed.cB = B256::left_padding_from(&aliased.to_bytes_be());
    apply_refused(
        &mut pv,
        apply_request(session, changed, proof.clone()),
        "c_B is not below the field order",
    );
    let mut changed = x.clone();
    changed.txData.amount = U256::from(1u8) << 96usize;
    apply_refused(
        &mut pv,
        apply_request(session, changed, proof),
        "exceeds 96 bits",
    );
}

#[test]
fn refuses_an_apply_statement_under_another_phase_or_key() {
    let session = apply_session();
    let (x, proof) = honest_apply().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    for (policy, reason) in [
        (policy_s(), "is not an Apply policy"),
        (keccak256("rental-v1/R"), "is not an Apply policy"),
        (policy_a2(), "does not verify"),
    ] {
        let mut changed = x.clone();
        changed.policyId = policy;
        apply_refused(
            &mut pv,
            apply_request(session, changed, proof.clone()),
            reason,
        );
    }
    let mut changed = x.clone();
    changed.tAtt += 1;
    apply_refused(
        &mut pv,
        apply_request(session, changed, proof),
        "is not the attested time",
    );
}

// ---------------------------------------------------------------------------------------------
// Settle

fn settle_session(notation: &'static str) -> &'static Session {
    static RUNS: OnceLock<std::sync::Mutex<HashMap<&'static str, &'static Session>>> =
        OnceLock::new();
    let runs = RUNS.get_or_init(Default::default);
    let mut runs = runs.lock().unwrap();
    runs.entry(notation).or_insert_with(|| {
        Box::leak(Box::new(notarize_blocking(
            OWNER,
            &record_layout("tenancy-v1"),
            notation,
        )))
    })
}

fn settle_statement(session: &Session, eta: u8) -> Settle {
    Settle {
        engId: U256::from(1),
        txId: U256::from(1),
        cTx: keccak256("C_tx"),
        txData: tx_data(),
        cP: c_p(OWNER.0),
        cB: c_b(),
        expiresAt: U256::from(ENGAGED + TAU_LOCK),
        policyId: policy_s(),
        submitter: Address::repeat_byte(0x11),
        eta: B256::repeat_byte(eta),
        tAtt: session.t_att,
    }
}

fn settle_proof(session: &Session, x: &Settle, tau_lock: u64) -> Groth16Proof {
    settle_proof_of(&session.notarized.openings, x, tau_lock).expect("proving")
}

/// A phi_S proof for `x` from the given openings, with public inputs recomputed from them.
fn settle_proof_of(
    openings: &[FieldOpening],
    x: &Settle,
    tau_lock: u64,
) -> anyhow::Result<Groth16Proof> {
    let day = engagement_day(x.expiresAt.try_into().unwrap(), tau_lock, UTC_OFFSET).unwrap();
    let attested = attestation_day(x.tAtt, UTC_OFFSET).unwrap();
    Ok(settle_proof_with(openings, x, [day, attested])?.0)
}

/// A phi_S proof for `x` from the given openings under the given engagement and attestation days,
/// and the public inputs it proves.
fn settle_proof_with(
    openings: &[FieldOpening],
    x: &Settle,
    days: [u32; 2],
) -> anyhow::Result<(Groth16Proof, PhiSPublic)> {
    let public = PhiSPublic::new(
        [
            commitment(&openings[0]),
            commitment(&openings[1]),
            commitment(&openings[2]),
            commitment(&openings[3]),
        ],
        x.txData.propertyId.0,
        [x.cP.0, x.cB.0],
        days,
        digest(x, &domain(CHAIN_ID, contract())).0,
    )
    .unwrap();
    let input = PhiSInput::new(&public, openings, &salt(), &salt_p()).unwrap();
    let dir = work_dir();
    let proof = prove(&phi_s_files(), &input, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    Ok((
        Groth16Proof::from_snarkjs_json(&proof?.proof_json).unwrap(),
        public,
    ))
}

fn honest_settle() -> &'static (Settle, Groth16Proof) {
    static HONEST: OnceLock<(Settle, Groth16Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let session = settle_session("N-0001");
        let x = settle_statement(session, 0x51);
        let proof = settle_proof(session, &x, TAU_LOCK);
        (x, proof)
    })
}

fn settle_request(
    session: &Session,
    notation: &str,
    statement: Settle,
    proof: Groth16Proof,
) -> SettleRequest {
    SettleRequest {
        presentation: pprev_prover::present_shape(&session.notarized, false).unwrap(),
        notation_id: notation.into(),
        statement,
        proof,
    }
}

fn settle_refused(pv: &mut PolicyVerifier, req: SettleRequest, reason: &str) {
    let err = format!(
        "{:#}",
        pv.sign_settle(req).expect_err("the policy verifier signed")
    );
    assert!(err.contains(reason), "expected {reason:?}, got: {err}");
}

#[test]
fn signs_an_honest_settle_request_once() {
    let session = settle_session("N-0001");
    let (x, proof) = honest_settle().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    let sigma = pv
        .sign_settle(settle_request(session, "N-0001", x.clone(), proof.clone()))
        .unwrap();
    assert!(recovers_to_vk_notary(
        &sigma,
        digest(&x, &domain(CHAIN_ID, contract()))
    ));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", x, proof),
        "has already been signed",
    );
}

#[test]
fn the_engagement_day_follows_the_deployment_tau_lock() {
    let session = settle_session("N-0001");
    let (x, proof) = honest_settle().clone();
    // A notary configured with another tau_lock derives another engagement day and refuses.
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK + 86_400));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", x.clone(), proof.clone()),
        "does not verify",
    );
    let mut pv = policy_verifier(&session.ca_der, None);
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", x, proof),
        "has no tau_lock",
    );
}

#[test]
fn a_stale_notation_cannot_pass_for_an_earlier_engagement() {
    // N-0002 is dated 2025-01-15. A proof for it under an engagement day that early verifies only
    // for a statement with that expiresAt, which the contract would not accept for this engagement.
    let session = settle_session("N-0002");
    let mut x = settle_statement(session, 0x52);
    let early = settle_proof(
        session,
        &{
            let mut early = x.clone();
            early.expiresAt = U256::from(1_736_899_200u64 + TAU_LOCK); // 2025-01-15T00:00:00Z
            early
        },
        TAU_LOCK,
    );
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0002", x.clone(), early),
        "does not verify",
    );
    // With the engagement's own expiresAt, phi_S has no witness for the stale notation; another
    // session's honest proof does not verify for it either.
    x.eta = B256::repeat_byte(0x53);
    settle_refused(
        &mut pv,
        settle_request(session, "N-0002", x, honest_settle().1.clone()),
        "does not verify",
    );
}

#[test]
fn refuses_a_settle_statement_changed_after_proving() {
    let session = settle_session("N-0001");
    let (x, proof) = honest_settle().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    let changes: [Change<Settle>; 6] = [
        ("engId", Box::new(|x| x.engId = U256::from(2))),
        ("expiresAt", Box::new(|x| x.expiresAt += U256::from(1))),
        (
            "propertyId",
            Box::new(|x| x.txData.propertyId = B256::repeat_byte(1)),
        ),
        (
            "submitter",
            Box::new(|x| x.submitter = Address::repeat_byte(0x33)),
        ),
        (
            "cB",
            Box::new(|x| x.cB = counterparty_commitment(b"ACC-000000000002", &salt()).unwrap()),
        ),
        // c_P of another listing: the proof was made for the owner's c_P.
        ("cP", Box::new(|x| x.cP = c_p("ACC-000000000002"))),
    ];
    for (name, change) in changes {
        let mut changed = x.clone();
        change(&mut changed);
        let err = format!(
            "{:#}",
            pv.sign_settle(settle_request(session, "N-0001", changed, proof.clone()))
                .expect_err(name)
        );
        assert!(err.contains("does not verify"), "{name}: {err}");
    }
}

#[test]
fn refuses_settle_inputs_outside_the_circuit_range() {
    let session = settle_session("N-0001");
    let (x, proof) = honest_settle().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    // c_P = c_P + r would alias the honest c_P in the field.
    let aliased = num_bigint::BigUint::from_bytes_be(&x.cP.0) + bn254_r();
    let mut changed = x.clone();
    changed.cP = B256::left_padding_from(&aliased.to_bytes_be());
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", changed, proof),
        "c_P is not below the field order",
    );
}

#[test]
fn refuses_a_settle_proof_for_another_account_hash() {
    // The owner proves phi_S for its own session, but against an account commitment of its own
    // making (the same account under another blinder): the proof holds for those public inputs,
    // and the policy verifier, which takes the account hash from the attestation, refuses it.
    let session = settle_session("N-0001");
    let (x, _) = honest_settle().clone();
    let mut openings = session.notarized.openings.clone();
    openings[0].blinder[0] ^= 1;
    let tampered = settle_proof_of(&openings, &x, TAU_LOCK).expect("proving");
    let day = engagement_day(x.expiresAt.try_into().unwrap(), TAU_LOCK, UTC_OFFSET).unwrap();
    let attested = attestation_day(x.tAtt, UTC_OFFSET).unwrap();
    let claimed = PhiSPublic::new(
        [
            commitment(&openings[0]),
            commitment(&openings[1]),
            commitment(&openings[2]),
            commitment(&openings[3]),
        ],
        x.txData.propertyId.0,
        [x.cP.0, x.cB.0],
        [day, attested],
        digest(&x, &domain(CHAIN_ID, contract())).0,
    )
    .unwrap();
    assert!(
        verifier_of(&phi_s_files())
            .verify(&tampered, &claimed.inputs())
            .unwrap()
    );
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", x.clone(), tampered),
        "does not verify",
    );
    // The honest proof is still accepted.
    pv.sign_settle(settle_request(
        session,
        "N-0001",
        x,
        honest_settle().1.clone(),
    ))
    .unwrap();
}

#[test]
fn phi_s_has_no_witness_for_a_session_of_another_account() {
    // The tenancy notation retrieved in a session of the tenant's account, not of the owner who
    // registered the listing: no phi_S proof exists for the listing's c_P.
    static RUN: OnceLock<Session> = OnceLock::new();
    let session =
        RUN.get_or_init(|| notarize_blocking(TENANT, &record_layout("tenancy-v1"), "N-0001"));
    assert_eq!(session.notarized.openings[0].plaintext, TENANT.0.as_bytes());
    let x = settle_statement(session, 0x55);
    let err = settle_proof_of(&session.notarized.openings, &x, TAU_LOCK)
        .expect_err("phi_S has a witness for another account's session");
    let unsatisfied = err
        .downcast_ref::<Unsatisfied>()
        .unwrap_or_else(|| panic!("proving failed for another reason: {err:#}"));
    assert_eq!(unsatisfied.template, "PhiS");
    // Its only proof is one for the tenant's own c_P, which is not the listing's statement.
    let mut own = x.clone();
    own.cP = c_p(TENANT.0);
    let proof = settle_proof_of(&session.notarized.openings, &own, TAU_LOCK).expect("proving");
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", x, proof),
        "does not verify",
    );
}

#[test]
fn refuses_a_settle_request_for_another_notation_or_phase() {
    let session = settle_session("N-0001");
    let (x, proof) = honest_settle().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0003", x.clone(), proof.clone()),
        "revealed request line",
    );
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001 HTTP/1.1", x.clone(), proof.clone()),
        "is not a record identifier",
    );
    let mut changed = x.clone();
    changed.policyId = policy_a();
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", changed, proof.clone()),
        "is not a Settle policy",
    );
    // An eligibility session presented for Settle does not have the tenancy layout. Each session
    // ran against its own registry, so the verifier trusts the eligibility registry's CA here.
    let apply = apply_session();
    let mut pv = policy_verifier(&apply.ca_der, Some(TAU_LOCK));
    let mut changed = x.clone();
    changed.tAtt = apply.t_att;
    changed.eta = B256::repeat_byte(0x54);
    settle_refused(
        &mut pv,
        SettleRequest {
            presentation: pprev_prover::present_shape(&apply.notarized, false).unwrap(),
            notation_id: "N-0001".into(),
            statement: changed,
            proof,
        },
        "the layout has",
    );
}

#[test]
fn one_nonce_is_signed_once_across_phases() {
    let apply = apply_session();
    let settle = settle_session("N-0001");
    let (xa, pa) = honest_apply().clone();
    let (xs, ps) = honest_settle().clone();
    let mut pv = policy_verifier(&apply.ca_der, Some(TAU_LOCK));
    pv.sign_apply(apply_request(apply, xa.clone(), pa)).unwrap();
    let mut reused = xs.clone();
    reused.eta = xa.eta;
    // The nonce check precedes the presentation check, so the other CA does not matter here.
    settle_refused(
        &mut pv,
        settle_request(settle, "N-0001", reused, ps),
        "has already been signed",
    );
}

// ---------------------------------------------------------------------------------------------
// One signed statement per attestation, one engagement per notation, and the attestation day (M2)

#[test]
fn one_attestation_backs_one_apply_statement() {
    let session = apply_session();
    let (x, proof) = honest_apply().clone();
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    pv.sign_apply(apply_request(session, x.clone(), proof))
        .unwrap();
    // The same eligibility session behind another listing, with a fresh nonce and a valid proof.
    let mut other = apply_statement(session, policy_a(), 2);
    other.txId = U256::from(2);
    let other_proof = apply_proof(session, &other);
    for _ in 0..2 {
        // Refused the second time for the same reason: the refusal left the nonce unused.
        apply_refused(
            &mut pv,
            apply_request(session, other.clone(), other_proof.clone()),
            "has already backed a signed statement",
        );
    }
}

/// Another notarised session of `notation`, with an attestation of its own, shared by the tests
/// under `tag`.
fn another_settle_session(tag: &'static str, notation: &'static str) -> &'static Session {
    static RUNS: OnceLock<std::sync::Mutex<HashMap<&'static str, &'static Session>>> =
        OnceLock::new();
    let runs = RUNS.get_or_init(Default::default);
    let mut runs = runs.lock().unwrap();
    runs.entry(tag).or_insert_with(|| {
        Box::leak(Box::new(notarize_blocking(
            OWNER,
            &record_layout("tenancy-v1"),
            notation,
        )))
    })
}

/// The honest Settle statement of the same engagement as [`honest_settle`] on a second session of
/// N-0001, with nonce 0x61, and its proof.
fn second_settle() -> &'static (Settle, Groth16Proof) {
    static HONEST: OnceLock<(Settle, Groth16Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let session = another_settle_session("second", "N-0001");
        let x = settle_statement(session, 0x61);
        let proof = settle_proof(session, &x, TAU_LOCK);
        (x, proof)
    })
}

#[test]
fn one_attestation_backs_one_settle_statement() {
    let first = settle_session("N-0001");
    let second = another_settle_session("second", "N-0001");
    let (x, proof) = honest_settle().clone();
    let mut pv = policy_verifier_at(
        &ledger_dir(),
        &[&first.ca_der, &second.ca_der],
        Some(TAU_LOCK),
        contract(),
    );
    pv.sign_settle(settle_request(first, "N-0001", x, proof))
        .unwrap();
    // The same settlement session for another statement of the same engagement (so that the notation
    // nullifier does not refuse it), with a fresh nonce and a valid proof.
    let mut other = settle_statement(first, 0x61);
    other.submitter = Address::repeat_byte(0x33);
    let other_proof = settle_proof(first, &other, TAU_LOCK);
    for _ in 0..2 {
        settle_refused(
            &mut pv,
            settle_request(first, "N-0001", other.clone(), other_proof.clone()),
            "has already backed a signed statement",
        );
    }
    // The refusals left nonce 0x61 unused: a statement with it on a fresh attestation is signed.
    let (fresh, fresh_proof) = second_settle().clone();
    assert_eq!(fresh.eta, other.eta);
    pv.sign_settle(settle_request(second, "N-0001", fresh, fresh_proof))
        .unwrap();
}

#[test]
fn a_nonce_refusal_does_not_consume_the_attestation() {
    let first = settle_session("N-0001");
    let second = another_settle_session("second", "N-0001");
    let (x, proof) = honest_settle().clone();
    let mut pv = policy_verifier_at(
        &ledger_dir(),
        &[&first.ca_der, &second.ca_der],
        Some(TAU_LOCK),
        contract(),
    );
    pv.sign_settle(settle_request(first, "N-0001", x.clone(), proof))
        .unwrap();
    // The second session with the nonce that was just signed: refused for the nonce.
    let (fresh, fresh_proof) = second_settle().clone();
    let mut reused = fresh.clone();
    reused.eta = x.eta;
    settle_refused(
        &mut pv,
        settle_request(second, "N-0001", reused, fresh_proof.clone()),
        "has already been signed",
    );
    // Its attestation is still unused.
    pv.sign_settle(settle_request(second, "N-0001", fresh, fresh_proof))
        .unwrap();
}

#[test]
fn a_request_outside_the_template_consumes_no_nonce_attestation_or_notation() {
    // A settlement session of N-0001 whose request carries a header the policy's template does not
    // have (M3); the registry answers it with the ordinary record, so the proof is valid. Submitted
    // for a second engagement with nonce 0x61, it is refused by the request check alone.
    static RUN: OnceLock<Session> = OnceLock::new();
    let off_template = RUN.get_or_init(|| {
        let mut layout = record_layout("tenancy-v1");
        layout.request.headers.insert(
            1,
            HeaderTemplate {
                name: "range".into(),
                value: "bytes=0-15".into(),
                credential_width: None,
            },
        );
        notarize_blocking(OWNER, &layout, "N-0001")
    });
    let second = another_settle_session("second", "N-0001");
    let dir = ledger_dir();
    let mut pv = policy_verifier_at(
        &dir,
        &[&off_template.ca_der, &second.ca_der],
        Some(TAU_LOCK),
        contract(),
    );
    let records = || {
        ["nonces.log", "attestations.log", "notations.log"]
            .map(|name| std::fs::read(dir.join(name)).unwrap())
    };
    let before = records();
    let mut other = settle_statement(off_template, 0x61);
    other.engId = U256::from(2);
    other.txId = U256::from(2);
    other.cTx = keccak256("C_tx 2");
    let other_proof = settle_proof(off_template, &other, TAU_LOCK);
    settle_refused(
        &mut pv,
        settle_request(off_template, "N-0001", other, other_proof),
        "the request template has",
    );
    assert_eq!(records(), before);
    // Nonce 0x61 is unused and N-0001 is bound to no engagement: the honest statement of the first
    // engagement with that nonce, on a session of the template, is signed.
    let (fresh, fresh_proof) = second_settle().clone();
    assert_eq!(fresh.eta, B256::repeat_byte(0x61));
    pv.sign_settle(settle_request(second, "N-0001", fresh, fresh_proof))
        .unwrap();
}

#[test]
fn a_notation_settles_one_engagement_across_restarts() {
    let first = settle_session("N-0001");
    let second = another_settle_session("second", "N-0001");
    let third = another_settle_session("third", "N-0001");
    let cas: [&[u8]; 3] = [&first.ca_der, &second.ca_der, &third.ca_der];
    let dir = ledger_dir();
    {
        let mut pv = policy_verifier_at(&dir, &cas, Some(TAU_LOCK), contract());
        let (x, proof) = honest_settle().clone();
        pv.sign_settle(settle_request(first, "N-0001", x, proof))
            .unwrap();
        // The same notation, on a fresh session with a fresh nonce and a valid proof, for a second
        // engagement (another listing of the property, engaged with the same tenant).
        let mut other = settle_statement(second, 0x62);
        other.engId = U256::from(2);
        other.txId = U256::from(2);
        other.cTx = keccak256("C_tx 2");
        let other_proof = settle_proof(second, &other, TAU_LOCK);
        settle_refused(
            &mut pv,
            settle_request(second, "N-0001", other, other_proof),
            "notation N-0001 has already settled engagement 1",
        );
        // sigma_S re-issued for the first engagement, on that fresh session and another fresh nonce;
        // the refusal used up neither the session's attestation nor anything else.
        let (again, again_proof) = second_settle().clone();
        pv.sign_settle(settle_request(second, "N-0001", again, again_proof))
            .unwrap();
    }
    // A restart reloads the three records from their files.
    let lines = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .unwrap()
            .lines()
            .count()
    };
    assert_eq!(
        (
            lines("nonces.log"),
            lines("attestations.log"),
            lines("notations.log")
        ),
        (2, 2, 1)
    );
    let mut pv = policy_verifier_at(&dir, &cas, Some(TAU_LOCK), contract());
    let mut other = settle_statement(third, 0x63);
    other.engId = U256::from(2);
    settle_refused(
        &mut pv,
        settle_request(third, "N-0001", other, honest_settle().1.clone()),
        "notation N-0001 has already settled engagement 1",
    );
    // The second session's attestation, used before the restart, stays used.
    settle_refused(
        &mut pv,
        settle_request(
            second,
            "N-0001",
            settle_statement(second, 0x64),
            honest_settle().1.clone(),
        ),
        "has already backed a signed statement",
    );
    // The same engagement id under another PPREV deployment is another engagement.
    {
        let mut elsewhere =
            policy_verifier_at(&dir, &cas, Some(TAU_LOCK), Address::repeat_byte(0x5b));
        settle_refused(
            &mut elsewhere,
            settle_request(
                third,
                "N-0001",
                settle_statement(third, 0x65),
                honest_settle().1.clone(),
            ),
            "has already settled engagement 1",
        );
    }
    // The first engagement can still have sigma_S re-issued after the restart.
    let x = settle_statement(third, 0x66);
    let proof = settle_proof(third, &x, TAU_LOCK);
    pv.sign_settle(settle_request(third, "N-0001", x, proof))
        .unwrap();
}

#[test]
fn a_notation_dated_after_the_attestation_day_is_refused() {
    // N-0005 is dated 2099-12-31: on the property, naming the tenant, after the engagement day, and
    // after any attestation day of these tests.
    let session = settle_session("N-0005");
    let x = settle_statement(session, 0x57);
    let err = settle_proof_of(&session.notarized.openings, &x, TAU_LOCK)
        .expect_err("phi_S has a witness for a notation dated after the attestation day");
    let unsatisfied = err
        .downcast_ref::<Unsatisfied>()
        .unwrap_or_else(|| panic!("proving failed for another reason: {err:#}"));
    assert_eq!(unsatisfied.template, "PhiS");
    let phi_s_source =
        std::fs::read_to_string(workspace_path("circuits/src/phi_s.circom")).unwrap();
    let not_after = phi_s_source
        .lines()
        .position(|l| l.contains("notAfter.out === 1;"))
        .unwrap() as u32
        + 1;
    assert_eq!(unsatisfied.line, not_after, "{unsatisfied}");
    // A proof under an attestation day of the owner's choosing holds for its own public inputs; the
    // policy verifier, which derives the attestation day from t_att, refuses it.
    let day = engagement_day(x.expiresAt.try_into().unwrap(), TAU_LOCK, UTC_OFFSET).unwrap();
    let (forged, claimed) =
        settle_proof_with(&session.notarized.openings, &x, [day, 2099_12_31]).expect("proving");
    assert!(
        verifier_of(&phi_s_files())
            .verify(&forged, &claimed.inputs())
            .unwrap()
    );
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0005", x, forged),
        "does not verify",
    );
}

#[test]
fn refuses_a_settle_proof_for_another_attestation_day() {
    let session = settle_session("N-0001");
    let (x, proof) = honest_settle().clone();
    let day = engagement_day(x.expiresAt.try_into().unwrap(), TAU_LOCK, UTC_OFFSET).unwrap();
    let attested = attestation_day(x.tAtt, UTC_OFFSET).unwrap();
    // N-0001 is dated on the engagement day, before the attestation day; the honest proof binds the
    // attestation day of t_att and no other.
    assert!(day < attested);
    let verifier = verifier_of(&phi_s_files());
    let public = |days: [u32; 2]| {
        let o = &session.notarized.openings;
        PhiSPublic::new(
            [
                commitment(&o[0]),
                commitment(&o[1]),
                commitment(&o[2]),
                commitment(&o[3]),
            ],
            x.txData.propertyId.0,
            [x.cP.0, x.cB.0],
            days,
            digest(&x, &domain(CHAIN_ID, contract())).0,
        )
        .unwrap()
    };
    assert!(
        verifier
            .verify(&proof, &public([day, attested]).inputs())
            .unwrap()
    );
    for tampered in [attested + 1, attested - 1, day, 2099_12_31] {
        assert!(
            !verifier
                .verify(&proof, &public([day, tampered]).inputs())
                .unwrap(),
            "{tampered}"
        );
    }
    // A valid proof under another attestation day (here the next one, which the notation also
    // satisfies) is refused by the policy verifier.
    let (shifted, claimed) =
        settle_proof_with(&session.notarized.openings, &x, [day, attested + 1]).expect("proving");
    assert!(verifier.verify(&shifted, &claimed.inputs()).unwrap());
    let mut pv = policy_verifier(&session.ca_der, Some(TAU_LOCK));
    settle_refused(
        &mut pv,
        settle_request(session, "N-0001", x.clone(), shifted),
        "does not verify",
    );
    // The honest proof, for the engagement day on which N-0001 is dated, is signed.
    pv.sign_settle(settle_request(session, "N-0001", x, proof))
        .unwrap();
}
