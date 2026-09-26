//! Writes the phi_R main component for a layout: `gen-circuit-main <layout.json> <out.circom>`.

use anyhow::{Context, Result};
use pprev_types::{Layout, circuit::main_circom};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let layout = args
        .next()
        .context("usage: gen-circuit-main <layout.json> <out.circom>")?;
    let out = args
        .next()
        .context("usage: gen-circuit-main <layout.json> <out.circom>")?;
    std::fs::write(&out, main_circom(&Layout::load(&layout)?)?)
        .with_context(|| format!("writing {out}"))?;
    Ok(())
}
