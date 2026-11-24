//! Writes the phi_R witness input behind the sample proof of `script/circuits_setup.sh`: the owner
//! ACC-000000000001 of TR-06-CANKAYA-000123, for the register statement of
//! `test-vectors/eip712.json` with c_P replaced by the commitment of that owner under a fixed salt
//! ([`sample_salt_p`]), with blinders derived from fixed labels.
//!
//! Usage: gen-phi-r-sample <layout.json> <eip712.json> <out.json>

use alloy_primitives::{Address, B256};
use anyhow::{Context, Result, bail, ensure};
use pprev_notary::mock::counterparty_commitment;
use pprev_prover::circuit::{PhiRInput, label_blinder, public_of, rendered_openings};
use pprev_types::statement::{Register, TxData, digest, domain};
use pprev_types::{Layout, TitleRecord};
use serde_json::Value;

fn parse<T: std::str::FromStr>(v: &Value) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    let text = v.as_str().context("expected a string")?;
    text.parse().map_err(|e| anyhow::anyhow!("{text}: {e}"))
}

/// s_P of the sample: a field element derived from a fixed label.
fn sample_salt_p() -> [u8; 32] {
    let mut salt: [u8; 32] = alloy_primitives::keccak256("pprev.sample.salt.p").0;
    salt[0] &= 0x1f;
    salt
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, layout, vectors, out] = args.as_slice() else {
        bail!("usage: gen-phi-r-sample <layout.json> <eip712.json> <out.json>");
    };
    let layout = Layout::load(layout)?;
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(vectors)?)?;
    let d = &vectors["domain"];
    let eip712 = domain(
        parse(&d["chainId"])?,
        parse::<Address>(&d["verifyingContract"])?,
    );
    let m = &vectors["register"]["message"];
    let property_id: B256 = parse(&m["txData"]["propertyId"])?;

    let record = TitleRecord {
        property_id: "TR-06-CANKAYA-000123".into(),
        owners: vec!["ACC-000000000001".into(), "ACC-000000000002".into()],
        encumbrance: "N".into(),
        assessed_value: "000000012500000".into(),
        record_date: "2026-09-24".into(),
    };
    ensure!(
        layout.property_id_word(&record.property_id)? == property_id.0,
        "the statement's txData.propertyId is not the sample record's property"
    );
    let openings = rendered_openings(
        &layout,
        "ACC-000000000001",
        &record,
        ["sample.account", "sample.owners", "sample.propertyId"].map(label_blinder),
    )?;
    let salt_p = sample_salt_p();
    let c_p = counterparty_commitment(&openings.account.plaintext, &salt_p)?;
    let x = Register {
        cTx: parse(&m["cTx"])?,
        txData: TxData {
            propertyId: property_id,
            amount: parse(&m["txData"]["amount"])?,
            settlementShare: parse(&m["txData"]["settlementShare"])?,
        },
        cP: c_p,
        policyId: parse(&m["policyId"])?,
        submitter: parse(&m["submitter"])?,
        eta: parse(&m["eta"])?,
        tAtt: parse(&m["tAtt"])?,
    };
    let public = public_of(&openings, property_id.0, c_p.0, digest(&x, &eip712).0);
    let input = PhiRInput::new(&public, &openings, &salt_p);
    std::fs::write(out, serde_json::to_string_pretty(&input)? + "\n")?;
    Ok(())
}
