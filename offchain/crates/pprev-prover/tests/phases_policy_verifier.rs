//! The policy verifier's Apply and Settle paths (Section V-B, step (d), for psi in {A, S}) on real
//! notarised sessions with the mock registry: presentation checks against the phase's layout, the
//! digest of x_psi, Groth16 verification with public inputs from the attestation and from x_psi,
//! the phase's own policy and key, the engagement day from the deployment's tau_lock, and one
//! signature per nonce across phases (D20).
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
use pprev_notary::mock::counterparty_commitment;
use pprev_notary::nonces::NonceStore;
use pprev_notary::phases::{ApplyPolicy, ApplyRequest, SettlePolicy, SettleRequest};
use pprev_notary::presentation::t_att_of;
use pprev_notary::register::PolicyVerifier;
use pprev_notary::{
    DEFAULT_MAX_SESSION_SECS, Groth16Proof, Groth16Verifier, NotaryConfig, StatementKey,
};
use pprev_prover::circuit::{CircuitFiles, PhiAInput, PhiSInput, commitment, prove};
use pprev_prover::{DEFAULT_MAX_RETRIES, NotarizedShape, ShapeSetup};
use pprev_types::RecordLayout;
use pprev_types::calendar::engagement_day;
use pprev_types::circuit::{PhiAPublic, PhiSPublic};
use pprev_types::field::bn254_r;
use pprev_types::statement::{Apply, Settle, TxData, digest, domain};

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

fn policy_verifier(ca_der: &[u8], tau_lock: Option<u64>) -> PolicyVerifier {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pprev-phase-verifier-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let nonces = dir.join("nonces.log");
    let _ = std::fs::remove_file(&nonces);
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
        vec![ca_der.to_vec()],
        DEFAULT_MAX_SESSION_SECS,
        key(),
        domain(CHAIN_ID, contract()),
        NonceStore::open(nonces).unwrap(),
    )
    .with_phases(apply, settle, tau_lock)
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
        cB: c_b(),
        expiresAt: U256::from(ENGAGED + TAU_LOCK),
        policyId: policy_s(),
        submitter: Address::repeat_byte(0x11),
        eta: B256::repeat_byte(eta),
        tAtt: session.t_att,
    }
}

fn settle_proof(session: &Session, x: &Settle, tau_lock: u64) -> Groth16Proof {
    let openings = &session.notarized.openings;
    let day = engagement_day(x.expiresAt.try_into().unwrap(), tau_lock, UTC_OFFSET).unwrap();
    let public = PhiSPublic::new(
        [
            commitment(&openings[1]),
            commitment(&openings[2]),
            commitment(&openings[3]),
        ],
        x.txData.propertyId.0,
        x.cB.0,
        day,
        digest(x, &domain(CHAIN_ID, contract())).0,
    )
    .unwrap();
    proof_of(
        &phi_s_files(),
        &PhiSInput::new(&public, openings, &salt()).unwrap(),
    )
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
    let changes: [Change<Settle>; 5] = [
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
