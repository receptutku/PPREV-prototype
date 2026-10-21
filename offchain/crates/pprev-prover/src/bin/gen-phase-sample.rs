//! Writes the phi_A or phi_S witness input behind the sample proofs of `script/circuits_setup_as.sh`:
//! the apply or settle statement of `test-vectors/eip712.json`, with c_B replaced by the commitment
//! of the tenant ACC-000000000003 under a fixed salt, for fixture records of the mock registry, with
//! blinders derived from fixed labels. The engagement day of phi_S is taken from the statement's
//! expiresAt with the deployment's tau_lock of 14 days and the policy's time zone.
//!
//! Usage: gen-phase-sample <apply|settle> <policy.json> <root> <eip712.json> <out.json>

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, bail};
use pprev_notary::mock::counterparty_commitment;
use pprev_prover::circuit::{PhiAInput, PhiSInput, commitment, label_blinder, record_openings};
use pprev_types::calendar::engagement_day;
use pprev_types::circuit::{PhiAPublic, PhiSPublic};
use pprev_types::statement::{Apply, Settle, TxData, digest, domain};
use pprev_types::{PolicyBundle, RecordLayout};
use serde_json::Value;

const USAGE: &str =
    "usage: gen-phase-sample <apply|settle> <policy.json> <root> <eip712.json> <out.json>";
const TENANT: &str = "ACC-000000000003";
const LANDLORD: &str = "ACC-000000000001";
/// tau_lock of the D18 deployment (contracts/script/Deploy.s.sol).
const TAU_LOCK: u64 = 14 * 86_400;

fn parse<T: std::str::FromStr>(v: &Value) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    let text = v.as_str().context("expected a string")?;
    text.parse().map_err(|e| anyhow::anyhow!("{text}: {e}"))
}

fn tx_data(v: &Value) -> Result<TxData> {
    Ok(TxData {
        propertyId: parse(&v["propertyId"])?,
        amount: parse(&v["amount"])?,
        settlementShare: parse(&v["settlementShare"])?,
    })
}

fn salt() -> [u8; 32] {
    let mut salt: [u8; 32] = alloy_primitives::keccak256("pprev.sample.salt").0;
    salt[0] &= 0x1f;
    salt
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [phase, policy, root, vectors, out] = args.as_slice() else {
        bail!(USAGE);
    };
    let policy = PolicyBundle::load(policy)?;
    let root = std::path::Path::new(root);
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(vectors)?)?;
    let d = &vectors["domain"];
    let eip712 = domain(
        parse(&d["chainId"])?,
        parse::<Address>(&d["verifyingContract"])?,
    );
    let salt = salt();
    let c_b = counterparty_commitment(TENANT.as_bytes(), &salt)?;

    let input = match phase.as_str() {
        "apply" => {
            let source = policy.apply.context("the policy has no apply source")?;
            let layout = RecordLayout::load(root.join(&source.layout))?;
            let m = &vectors["apply"]["message"];
            let x = Apply {
                txId: parse::<U256>(&m["txId"])?,
                cTx: parse::<B256>(&m["cTx"])?,
                txData: tx_data(&m["txData"])?,
                cB: c_b,
                policyId: parse(&m["policyId"])?,
                submitter: parse(&m["submitter"])?,
                eta: parse(&m["eta"])?,
                tAtt: parse(&m["tAtt"])?,
            };
            let openings = record_openings(
                &layout,
                TENANT,
                &["03500000000000000000"],
                &["sample.account", "sample.monthlyIncome"].map(label_blinder),
            )?;
            let public = PhiAPublic::new(
                commitment(&openings[0]),
                commitment(&openings[1]),
                c_b.0,
                x.txData.amount,
                digest(&x, &eip712).0,
            )?;
            serde_json::to_value(PhiAInput::new(&public, &openings, &salt)?)?
        }
        "settle" => {
            let source = policy.settle.context("the policy has no settle source")?;
            let layout = RecordLayout::load(root.join(&source.layout))?;
            let m = &vectors["settle"]["message"];
            let x = Settle {
                engId: parse(&m["engId"])?,
                txId: parse(&m["txId"])?,
                cTx: parse(&m["cTx"])?,
                txData: tx_data(&m["txData"])?,
                cB: c_b,
                expiresAt: parse(&m["expiresAt"])?,
                policyId: parse(&m["policyId"])?,
                submitter: parse(&m["submitter"])?,
                eta: parse(&m["eta"])?,
                tAtt: parse(&m["tAtt"])?,
            };
            let day = engagement_day(x.expiresAt.try_into()?, TAU_LOCK, source.utc_offset_secs)?;
            let date = format!(
                "{:04}-{:02}-{:02}",
                day / 10_000,
                day / 100 % 100,
                day % 100
            );
            let openings = record_openings(
                &layout,
                LANDLORD,
                &["TR-06-CANKAYA-000123", TENANT, &date],
                &[
                    "sample.account",
                    "sample.propertyId",
                    "sample.tenant",
                    "sample.recordDate",
                ]
                .map(label_blinder),
            )?;
            let public = PhiSPublic::new(
                [
                    commitment(&openings[1]),
                    commitment(&openings[2]),
                    commitment(&openings[3]),
                ],
                x.txData.propertyId.0,
                c_b.0,
                day,
                digest(&x, &eip712).0,
            )?;
            serde_json::to_value(PhiSInput::new(&public, &openings, &salt)?)?
        }
        _ => bail!(USAGE),
    };
    std::fs::write(out, serde_json::to_string_pretty(&input)? + "\n")?;
    Ok(())
}
