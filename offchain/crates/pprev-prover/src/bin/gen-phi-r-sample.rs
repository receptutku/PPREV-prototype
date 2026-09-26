//! Writes the phi_R witness input behind the sample proof of `script/circuits_setup.sh`: the owner
//! ACC-000000000001 of TR-06-CANKAYA-000123, for the register statement of
//! `test-vectors/eip712.json`, with blinders derived from fixed labels.
//!
//! Usage: gen-phi-r-sample <layout.json> <eip712.json> <out.json>

use anyhow::{Context, Result, bail, ensure};
use pprev_prover::circuit::{PhiRInput, label_blinder, public_of, rendered_openings};
use pprev_types::{Layout, TitleRecord};

fn word(value: &serde_json::Value) -> Result<[u8; 32]> {
    let text = value.as_str().context("expected a hex string")?;
    let bytes = hex::decode(text.trim_start_matches("0x")).context("hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{text} is not 32 bytes"))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, layout, vectors, out] = args.as_slice() else {
        bail!("usage: gen-phi-r-sample <layout.json> <eip712.json> <out.json>");
    };
    let layout = Layout::load(layout)?;
    let vectors: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(vectors)?)?;
    let register = &vectors["register"];
    let digest = word(&register["digest"])?;
    let property_id = word(&register["message"]["txData"]["propertyId"])?;

    let record = TitleRecord {
        property_id: "TR-06-CANKAYA-000123".into(),
        owners: vec!["ACC-000000000001".into(), "ACC-000000000002".into()],
        encumbrance: "N".into(),
        assessed_value: "000000012500000".into(),
        record_date: "2026-09-24".into(),
    };
    ensure!(
        layout.property_id_word(&record.property_id)? == property_id,
        "the statement's txData.propertyId is not the sample record's property"
    );
    let openings = rendered_openings(
        &layout,
        "ACC-000000000001",
        &record,
        ["sample.account", "sample.owners", "sample.propertyId"].map(label_blinder),
    )?;
    let input = PhiRInput::new(&public_of(&openings, property_id, digest), &openings);
    std::fs::write(out, serde_json::to_string_pretty(&input)? + "\n")?;
    Ok(())
}
