//! The committed sample proof (`circuits/setup/sample`, made by `script/circuits_setup.sh` with the
//! committed verification key) verifies with the Rust verifier, and its public inputs are the
//! phi_R encoding of the register statement of `test-vectors/eip712.json`.

use pprev_notary::groth16::public_from_snarkjs_json;
use pprev_notary::{Groth16Proof, Groth16Verifier};
use pprev_types::field::{bind_value, limbs};
use serde_json::Value;

fn read(rel: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../").to_string() + rel;
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn verifier() -> Groth16Verifier {
    Groth16Verifier::from_snarkjs_json(&read("circuits/setup/verification_key.json")).unwrap()
}

fn proof() -> Groth16Proof {
    Groth16Proof::from_snarkjs_json(&read("circuits/setup/sample/proof.json")).unwrap()
}

fn public() -> Vec<String> {
    public_from_snarkjs_json(&read("circuits/setup/sample/public.json")).unwrap()
}

fn word(v: &Value) -> [u8; 32] {
    let bytes = hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    bytes.try_into().unwrap()
}

#[test]
fn sample_proof_verifies() {
    let v = verifier();
    assert_eq!(v.n_public(), 9);
    assert!(v.verify(&proof(), &public()).unwrap());
}

#[test]
fn sample_public_inputs_encode_the_register_statement() {
    let vectors: Value = serde_json::from_str(&read("test-vectors/eip712.json")).unwrap();
    let register = &vectors["register"];
    let public = public();
    // txData.propertyId and bind = digest mod r; the commitments come from the sample input.
    assert_eq!(
        public[6..8],
        limbs(&word(&register["message"]["txData"]["propertyId"]))
    );
    assert_eq!(public[8], bind_value(&word(&register["digest"])));
    let input: Value = serde_json::from_str(&read("circuits/setup/sample/input.json")).unwrap();
    let from_input: Vec<String> = ["accountHash", "ownersHash", "propertyHash", "propertyId"]
        .iter()
        .flat_map(|k| {
            input[k]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
        })
        .chain(std::iter::once(input["bind"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(public, from_input);
}

#[test]
fn changing_any_public_input_breaks_the_proof() {
    let v = verifier();
    let p = proof();
    for i in 0..9 {
        let mut public = public();
        let changed: num_bigint::BigUint = public[i].parse::<num_bigint::BigUint>().unwrap() + 1u32;
        public[i] = changed.to_string();
        assert!(!v.verify(&p, &public).unwrap(), "input {i}");
    }
}

#[test]
fn a_changed_proof_is_rejected() {
    let v = verifier();
    let json: Value = serde_json::from_str(&read("circuits/setup/sample/proof.json")).unwrap();
    // A and C swapped: both valid points, not a valid proof.
    let mut swapped = json.clone();
    swapped["pi_a"] = json["pi_c"].clone();
    swapped["pi_c"] = json["pi_a"].clone();
    let p = Groth16Proof::from_snarkjs_json(&swapped.to_string()).unwrap();
    assert!(!v.verify(&p, &public()).unwrap());
    // A coordinate off the curve is rejected when the proof is read.
    let mut off_curve = json.clone();
    off_curve["pi_a"][1] = Value::String("1".into());
    assert!(Groth16Proof::from_snarkjs_json(&off_curve.to_string()).is_err());
}
