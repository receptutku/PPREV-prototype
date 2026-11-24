//! The committed sample proof (`circuits/setup/sample`, made by `script/circuits_setup.sh` with the
//! committed verification key) verifies with the Rust verifier, and its public inputs are the
//! phi_R encoding of the register statement of `test-vectors/eip712.json`, with c_P replaced by a
//! commitment to the sample owner's account (the vector's c_P is not a field element).

use alloy_primitives::{Address, B256};
use num_bigint::BigUint;
use pprev_notary::groth16::public_from_snarkjs_json;
use pprev_notary::mock::counterparty_commitment;
use pprev_notary::{Groth16Proof, Groth16Verifier};
use pprev_types::field::{bind_value, limbs};
use pprev_types::statement::{Register, TxData, digest, domain};
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
    assert_eq!(v.n_public(), 10);
    assert!(v.verify(&proof(), &public()).unwrap());
}

#[test]
fn sample_public_inputs_encode_the_register_statement() {
    let vectors: Value = serde_json::from_str(&read("test-vectors/eip712.json")).unwrap();
    let register = &vectors["register"];
    let public = public();
    let m = &register["message"];
    let input: Value = serde_json::from_str(&read("circuits/setup/sample/input.json")).unwrap();
    // c_P opens to the sample's account under the sample's salt.
    let dec = |v: &Value| v.as_str().unwrap().parse::<BigUint>().unwrap();
    let bytes32 = |n: BigUint| {
        let b = n.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        out
    };
    let account: Vec<u8> = input["account"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    let c_p = counterparty_commitment(&account, &bytes32(dec(&input["salt"]))).unwrap();
    assert_eq!(public[8], BigUint::from_bytes_be(&c_p.0).to_string());
    // txData.propertyId and bind = digest mod r of the vector's statement with that c_P.
    assert_eq!(public[6..8], limbs(&word(&m["txData"]["propertyId"])));
    let s = |v: &Value| v.as_str().unwrap().to_string();
    let d = &vectors["domain"];
    let x = Register {
        cTx: B256::from(word(&m["cTx"])),
        txData: TxData {
            propertyId: B256::from(word(&m["txData"]["propertyId"])),
            amount: s(&m["txData"]["amount"]).parse().unwrap(),
            settlementShare: s(&m["txData"]["settlementShare"]).parse().unwrap(),
        },
        cP: c_p,
        policyId: B256::from(word(&m["policyId"])),
        submitter: s(&m["submitter"]).parse::<Address>().unwrap(),
        eta: B256::from(word(&m["eta"])),
        tAtt: s(&m["tAtt"]).parse().unwrap(),
    };
    let eip712 = domain(
        s(&d["chainId"]).parse().unwrap(),
        s(&d["verifyingContract"]).parse().unwrap(),
    );
    assert_eq!(public[9], bind_value(&digest(&x, &eip712).0));
    // With the vector's own c_P the statement is another one.
    assert_ne!(word(&m["cP"]), c_p.0);
    let from_input: Vec<String> = ["accountHash", "ownersHash", "propertyHash", "propertyId"]
        .iter()
        .flat_map(|k| {
            input[k]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
        })
        .chain(["cP", "bind"].map(|k| input[k].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(public, from_input);
}

#[test]
fn changing_any_public_input_breaks_the_proof() {
    let v = verifier();
    let p = proof();
    for i in 0..10 {
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
