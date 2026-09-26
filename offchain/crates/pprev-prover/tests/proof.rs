//! Groth16 proofs of phi_R made with snarkjs (D22) from real attested sessions and checked with the
//! Rust verifier, which agrees with `snarkjs groth16 verify`.
//!
//! Requires the proving key of `script/circuits_setup.sh`.

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{
    OWNER, PROPERTY, Run, TENANT, attestation_verifying_key, notarize_blocking, workspace_path,
};
use pprev_notary::{
    DEFAULT_MAX_SESSION_SECS, Expectation, Groth16Proof, Groth16Verifier, check_presentation,
};
use pprev_prover::circuit::{CircuitFiles, PhiRInput, PhiRProof, prove};
use pprev_types::circuit::PhiRPublic;

/// Register digest of `test-vectors/eip712.json`, standing in for x_R.
const DIGEST: [u8; 32] = [
    0xb9, 0xcb, 0x90, 0xd4, 0x31, 0xdf, 0xd4, 0x32, 0xc5, 0x2a, 0xe7, 0x89, 0x63, 0x54, 0x58, 0xde,
    0x8a, 0xcd, 0xec, 0x66, 0xe1, 0x81, 0x7a, 0x1a, 0xa3, 0x59, 0xbc, 0x97, 0x9a, 0x15, 0x15, 0x64,
];

/// A fresh directory under the system temp directory.
fn work_dir(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pprev-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

fn verifier() -> Groth16Verifier {
    let vk = std::fs::read_to_string(files().verification_key()).expect("verification key");
    Groth16Verifier::from_snarkjs_json(&vk).unwrap()
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

/// Public inputs as the policy verifier derives them from a checked presentation.
fn verifier_public(run: &Run, digest: [u8; 32]) -> PhiRPublic {
    let presentation = pprev_prover::present(&run.notarized, false).expect("presentation");
    check_presentation(
        presentation,
        &Expectation {
            layout: &run.layout,
            attestation_key: &attestation_verifying_key(),
            root_certs: std::slice::from_ref(&run.ca_der),
            property_id: PROPERTY,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
        },
    )
    .expect("policy checks")
    .phi_r_public(run.layout.property_id_word(PROPERTY).unwrap(), digest)
    .expect("public inputs")
}

/// One proof from the owner's session, shared by the tests.
fn owner_proof() -> &'static (PhiRPublic, PhiRProof) {
    static PROOF: OnceLock<(PhiRPublic, PhiRProof)> = OnceLock::new();
    PROOF.get_or_init(|| {
        let run = run_of(OWNER);
        let public = verifier_public(run, DIGEST);
        let dir = work_dir("proof");
        let proof = prove(
            &files(),
            &PhiRInput::new(&public, &run.notarized.openings),
            &dir,
        )
        .expect("proving");
        let _ = std::fs::remove_dir_all(&dir);
        (public, proof)
    })
}

fn parsed(proof: &PhiRProof) -> Groth16Proof {
    Groth16Proof::from_snarkjs_json(&proof.proof_json).unwrap()
}

/// `snarkjs groth16 verify` on a proof with the given public inputs.
fn snarkjs_accepts(proof: &PhiRProof, public: &[String]) -> bool {
    let dir = work_dir("snarkjs-verify");
    let (proof_path, public_path) = (dir.join("proof.json"), dir.join("public.json"));
    std::fs::write(&proof_path, &proof.proof_json).unwrap();
    std::fs::write(&public_path, serde_json::to_string(public).unwrap()).unwrap();
    let out = Command::new(files().snarkjs())
        .args(["groth16", "verify"])
        .arg(files().verification_key())
        .arg(&public_path)
        .arg(&proof_path)
        .output()
        .expect("snarkjs");
    let _ = std::fs::remove_dir_all(&dir);
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    if text.contains("OK!") {
        true
    } else {
        assert!(
            text.contains("Invalid proof"),
            "unexpected snarkjs output: {text}"
        );
        false
    }
}

#[test]
fn owner_proof_verifies_with_the_attested_public_inputs() {
    let (public, proof) = owner_proof();
    // snarkjs writes the public inputs in the order the policy verifier computes them.
    assert_eq!(proof.public, public.inputs());
    assert!(verifier().verify(&parsed(proof), &public.inputs()).unwrap());
    assert!(proof.timings.witness_ms > 0.0 && proof.timings.prove_ms > 0.0);
}

#[test]
fn snarkjs_and_the_rust_verifier_agree() {
    let (public, proof) = owner_proof();
    assert!(snarkjs_accepts(proof, &public.inputs()));
    let mut changed = public.clone();
    changed.digest[31] ^= 1;
    assert!(!snarkjs_accepts(proof, &changed.inputs()));
    assert!(
        !verifier()
            .verify(&parsed(proof), &changed.inputs())
            .unwrap()
    );
}

#[test]
fn a_proof_is_bound_to_its_statement() {
    let (public, proof) = owner_proof();
    let v = verifier();
    let mut other = public.clone();
    other.digest = [0x42; 32];
    // Only bind differs.
    assert_eq!(other.inputs()[..8], public.inputs()[..8]);
    assert!(!v.verify(&parsed(proof), &other.inputs()).unwrap());
}

#[test]
fn a_proof_does_not_transfer_to_another_session() {
    let (_, proof) = owner_proof();
    let tenant = verifier_public(run_of(TENANT), DIGEST);
    assert!(!verifier().verify(&parsed(proof), &tenant.inputs()).unwrap());
}
