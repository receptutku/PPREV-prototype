//! The policy verifier's Register path (Section V-B, step (d)): presentation checks, the digest of
//! x_R, Groth16 verification with public inputs from the attestation, the policy's own verifying
//! key, and one signature per nonce (D20).
//!
//! Requires the proving key of `script/circuits_setup.sh`.

mod common;

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use common::{
    OWNER, PROPERTY, Run, TENANT, attestation_verifying_key, notarize_blocking, provider,
    workspace_path,
};
use pprev_notary::nonces::NonceStore;
use pprev_notary::presentation::t_att_of;
use pprev_notary::register::{PolicyVerifier, RegisterPolicy, RegisterRequest};
use pprev_notary::{DEFAULT_MAX_SESSION_SECS, Groth16Proof, Groth16Verifier, StatementKey};
use pprev_prover::circuit::{CircuitFiles, PhiRInput, prove, public_of};
use pprev_types::statement::{Register, TxData, digest, domain};

const CHAIN_ID: u64 = 31337;

fn contract() -> Address {
    Address::repeat_byte(0x5a)
}

fn policy_r() -> B256 {
    keccak256("rental-v1/R")
}

/// A second Register policy whose circuit has another verifying key.
fn policy_r2() -> B256 {
    keccak256("rental-v2/R")
}

fn key() -> StatementKey {
    StatementKey::from_bytes(&keccak256("pprev.notary.statement-key.test").0).unwrap()
}

fn files() -> CircuitFiles {
    let files = CircuitFiles::new(workspace_path("circuits"));
    assert!(
        files.zkey().exists(),
        "{} is missing; run script/circuits_setup.sh",
        files.zkey().display()
    );
    files
}

fn vk_json() -> String {
    std::fs::read_to_string(files().verification_key()).expect("verification key")
}

/// The phi_R key with gamma and delta exchanged: well-formed, but not the key the proofs use.
fn other_vk_json() -> String {
    let mut vk: serde_json::Value = serde_json::from_str(&vk_json()).unwrap();
    let gamma = vk["vk_gamma_2"].clone();
    vk["vk_gamma_2"] = vk["vk_delta_2"].clone();
    vk["vk_delta_2"] = gamma;
    vk.to_string()
}

fn policy_verifier(ca_der: &[u8]) -> PolicyVerifier {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pprev-policy-verifier-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let nonces = dir.join("nonces.log");
    let _ = std::fs::remove_file(&nonces);
    let layout = common::layout();
    let policies = HashMap::from([
        (
            policy_r(),
            RegisterPolicy {
                layout: layout.clone(),
                verifier: Groth16Verifier::from_snarkjs_json(&vk_json()).unwrap(),
            },
        ),
        (
            policy_r2(),
            RegisterPolicy {
                layout,
                verifier: Groth16Verifier::from_snarkjs_json(&other_vk_json()).unwrap(),
            },
        ),
    ]);
    PolicyVerifier::new(
        policies,
        attestation_verifying_key(),
        vec![ca_der.to_vec()],
        DEFAULT_MAX_SESSION_SECS,
        key(),
        domain(CHAIN_ID, contract()),
        NonceStore::open(nonces).unwrap(),
    )
}

fn run_of(account: (&'static str, &'static str)) -> &'static Run {
    static OWNER_RUN: OnceLock<Run> = OnceLock::new();
    static TENANT_RUN: OnceLock<Run> = OnceLock::new();
    let cell = if account == OWNER {
        &OWNER_RUN
    } else {
        &TENANT_RUN
    };
    cell.get_or_init(|| notarize_blocking(account, PROPERTY))
}

/// t_att as the owner reads it from its own verified presentation.
fn attested_t_att(run: &Run) -> u64 {
    let output = pprev_prover::present(&run.notarized, false)
        .expect("presentation")
        .verify(&provider(&run.ca_der))
        .expect("verification");
    t_att_of(&output).expect("t_att")
}

/// x_R as the owner builds it after the session: t_att from the attestation.
fn statement(run: &Run, policy_id: B256, eta: u8) -> Register {
    Register {
        cTx: keccak256("C_tx"),
        txData: TxData {
            propertyId: B256::from(run.layout.property_id_word(PROPERTY).unwrap()),
            amount: U256::from(10u64).pow(U256::from(18)),
            settlementShare: U256::ZERO,
        },
        policyId: policy_id,
        submitter: Address::repeat_byte(0x11),
        eta: B256::repeat_byte(eta),
        tAtt: attested_t_att(run),
    }
}

/// The owner's proof for `x`, made from the openings of its own session.
fn proof_for(run: &Run, x: &Register) -> Groth16Proof {
    let d = digest(x, &domain(CHAIN_ID, contract()));
    let public = public_of(&run.notarized.openings, x.txData.propertyId.0, d.0);
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pprev-pv-proof-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let proof = prove(
        &files(),
        &PhiRInput::new(&public, &run.notarized.openings),
        &dir,
    )
    .expect("proving");
    let _ = std::fs::remove_dir_all(&dir);
    Groth16Proof::from_snarkjs_json(&proof.proof_json).unwrap()
}

/// The honest statement for policy R with nonce 1 and its proof, shared by the tests.
fn honest() -> &'static (Register, Groth16Proof) {
    static HONEST: OnceLock<(Register, Groth16Proof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let run = run_of(OWNER);
        let x = statement(run, policy_r(), 1);
        let proof = proof_for(run, &x);
        (x, proof)
    })
}

fn request(run: &Run, statement: Register, proof: Groth16Proof) -> RegisterRequest {
    RegisterRequest {
        presentation: pprev_prover::present(&run.notarized, false).expect("presentation"),
        property_id: PROPERTY.into(),
        statement,
        proof,
    }
}

fn refused(pv: &mut PolicyVerifier, req: RegisterRequest, reason: &str) {
    let err = format!(
        "{:#}",
        pv.sign_register(req)
            .expect_err("the policy verifier signed")
    );
    assert!(err.contains(reason), "expected {reason:?}, got: {err}");
}

#[test]
fn signs_an_honest_register_request() {
    let run = run_of(OWNER);
    let (x, proof) = honest().clone();
    let mut pv = policy_verifier(&run.ca_der);
    let sigma = pv.sign_register(request(run, x.clone(), proof)).unwrap();
    let d = digest(&x, &domain(CHAIN_ID, contract()));
    let signer = Signature::from_raw(&sigma)
        .unwrap()
        .recover_address_from_prehash(&d)
        .unwrap();
    assert_eq!(signer, key().vk_notary());
}

#[test]
fn signs_a_nonce_once() {
    let run = run_of(OWNER);
    let (x, proof) = honest().clone();
    let mut pv = policy_verifier(&run.ca_der);
    pv.sign_register(request(run, x.clone(), proof.clone()))
        .unwrap();
    refused(&mut pv, request(run, x, proof), "already been signed");
}

#[test]
fn refuses_a_statement_changed_after_proving() {
    let run = run_of(OWNER);
    let (x, proof) = honest().clone();
    let mut pv = policy_verifier(&run.ca_der);
    let mut changed = x.clone();
    changed.submitter = Address::repeat_byte(0x99);
    refused(
        &mut pv,
        request(run, changed, proof.clone()),
        "does not verify",
    );
    let mut changed = x.clone();
    changed.txData.amount += U256::from(1);
    refused(
        &mut pv,
        request(run, changed, proof.clone()),
        "does not verify",
    );
    // A refused request leaves its nonce unused.
    pv.sign_register(request(run, x, proof)).unwrap();
}

#[test]
fn refuses_a_t_att_other_than_the_attested_time() {
    let run = run_of(OWNER);
    let (x, proof) = honest().clone();
    let mut pv = policy_verifier(&run.ca_der);
    let mut changed = x;
    changed.tAtt -= 1;
    refused(
        &mut pv,
        request(run, changed, proof),
        "is not the attested time",
    );
}

#[test]
fn checks_each_proof_under_its_own_policy_key() {
    let run = run_of(OWNER);
    let mut pv = policy_verifier(&run.ca_der);
    // A valid phi_R proof for a statement under policy R2, whose verifying key is another one.
    let x2 = statement(run, policy_r2(), 2);
    let proof2 = proof_for(run, &x2);
    refused(&mut pv, request(run, x2, proof2), "does not verify");
    let mut unknown = honest().0.clone();
    unknown.policyId = keccak256("unknown/R");
    refused(
        &mut pv,
        request(run, unknown, honest().1.clone()),
        "not a Register policy",
    );
}

#[test]
fn refuses_a_proof_from_another_session() {
    let (x, proof) = honest().clone();
    let tenant = run_of(TENANT);
    let mut pv = policy_verifier(&tenant.ca_der);
    let mut x = x;
    x.tAtt = attested_t_att(tenant);
    refused(&mut pv, request(tenant, x, proof), "does not verify");
}

#[test]
fn refuses_a_property_other_than_the_notarised_one() {
    let run = run_of(OWNER);
    let (x, proof) = honest().clone();
    let mut pv = policy_verifier(&run.ca_der);
    let mut req = request(run, x.clone(), proof.clone());
    req.property_id = "TR-34-KADIKOY-004567".into();
    refused(&mut pv, req, "txData.propertyId");
    let mut changed = x;
    changed.txData.propertyId =
        B256::from(run.layout.property_id_word("TR-34-KADIKOY-004567").unwrap());
    let mut req = request(run, changed, proof);
    req.property_id = "TR-34-KADIKOY-004567".into();
    // The presentation's request line names the notarised property.
    assert!(pv.sign_register(req).is_err());
}
