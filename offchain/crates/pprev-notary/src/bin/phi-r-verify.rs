//! Verifies a phi_R proof as the policy verifier does and prints the result with the wall-clock time
//! of reading the key and of the Groth16 check, in milliseconds. The measurement scripts call it to
//! time verification.
//!
//! Usage: phi-r-verify <verification_key.json> <proof.json> <public.json>

use std::time::Instant;

use anyhow::{Context, Result, bail};
use pprev_notary::groth16::public_from_snarkjs_json;
use pprev_notary::{Groth16Proof, Groth16Verifier};

fn read(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, vk, proof, public] = args.as_slice() else {
        bail!("usage: phi-r-verify <verification_key.json> <proof.json> <public.json>");
    };
    let (vk, proof, public) = (read(vk)?, read(proof)?, read(public)?);

    let started = Instant::now();
    let verifier = Groth16Verifier::from_snarkjs_json(&vk)?;
    let key_ms = started.elapsed().as_secs_f64() * 1000.0;

    let started = Instant::now();
    let proof = Groth16Proof::from_snarkjs_json(&proof)?;
    let public = public_from_snarkjs_json(&public)?;
    let valid = verifier.verify(&proof, &public)?;
    let verify_ms = started.elapsed().as_secs_f64() * 1000.0;

    println!(
        "{}",
        serde_json::json!({ "valid": valid, "keyMs": key_ms, "verifyMs": verify_ms })
    );
    if !valid {
        bail!("the proof does not verify");
    }
    Ok(())
}
