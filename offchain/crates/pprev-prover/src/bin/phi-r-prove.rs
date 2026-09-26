//! Proves phi_R for a witness input and writes `proof.json`, `public.json`, and `timings.json`
//! (wall-clock time of witness generation and of `snarkjs groth16 prove`, in milliseconds) into the
//! output directory. The measurement scripts call it to time proving apart from the TLSNotary session.
//!
//! Usage: phi-r-prove <circuits-dir> <input.json> <out-dir>

use std::path::Path;

use anyhow::{Context, Result, bail};
use pprev_prover::circuit::{CircuitFiles, PhiRInput, prove};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, circuits, input, out] = args.as_slice() else {
        bail!("usage: phi-r-prove <circuits-dir> <input.json> <out-dir>");
    };
    let input: PhiRInput = serde_json::from_str(
        &std::fs::read_to_string(input).with_context(|| format!("reading {input}"))?,
    )
    .context("parsing the witness input")?;
    let out = Path::new(out);
    std::fs::create_dir_all(out)?;
    let proof = prove(&CircuitFiles::new(circuits), &input, out)?;
    std::fs::write(
        out.join("timings.json"),
        serde_json::to_string_pretty(&proof.timings)? + "\n",
    )?;
    println!("{}", serde_json::to_string(&proof.timings)?);
    Ok(())
}
