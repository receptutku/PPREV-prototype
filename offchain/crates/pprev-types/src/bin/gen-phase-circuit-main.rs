//! Writes the phi_A or phi_S main component of a policy bundle:
//! `gen-phase-circuit-main <apply|settle> <policy.json> <root> <out.circom>`.

use anyhow::{Context, Result, bail};
use pprev_types::circuit::{main_circom_phi_a, main_circom_phi_s};
use pprev_types::{PolicyBundle, RecordLayout};

const USAGE: &str =
    "usage: gen-phase-circuit-main <apply|settle> <policy.json> <root> <out.circom>";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [phase, policy, root, out] = args.as_slice() else {
        bail!(USAGE);
    };
    let bundle = PolicyBundle::load(policy)?;
    let root = std::path::Path::new(root);
    let source = match phase.as_str() {
        "apply" => {
            let apply = bundle.apply.context("the policy has no apply source")?;
            main_circom_phi_a(
                &RecordLayout::load(root.join(&apply.layout))?,
                apply.income_multiple,
            )?
        }
        "settle" => {
            let settle = bundle.settle.context("the policy has no settle source")?;
            main_circom_phi_s(&RecordLayout::load(root.join(&settle.layout))?)?
        }
        _ => bail!(USAGE),
    };
    std::fs::write(out, source).with_context(|| format!("writing {out}"))?;
    Ok(())
}
