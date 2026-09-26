//! Witness of phi_R (Section VI-A) and the circom witness generator (D22).

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use pprev_types::circuit::PhiRPublic;
use pprev_types::{Layout, TitleRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::session::{FieldOpening, HiddenOpenings};

/// Name of the compiled main component for the title-v1 layout.
pub const CIRCUIT_NAME: &str = "main_title_v1";

/// SHA-256(plaintext || blinder): the TLSNotary plaintext hash that phi_R opens.
pub fn commitment(opening: &FieldOpening) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&opening.plaintext);
    hasher.update(opening.blinder);
    hasher.finalize().into()
}

/// The public side of phi_R as the prover computes it: commitments recomputed from the openings
/// (they equal the attested ones, see `tests/opening.rs`), `txData.propertyId`, and the EIP-712
/// digest of x_R.
pub fn public_of(openings: &HiddenOpenings, property_id: [u8; 32], digest: [u8; 32]) -> PhiRPublic {
    PhiRPublic {
        account_hash: commitment(&openings.account),
        owners_hash: commitment(&openings.owners),
        property_hash: commitment(&openings.property_id),
        property_id,
        digest,
    }
}

/// A blinder derived from a label, for samples and tests.
pub fn label_blinder(label: &str) -> [u8; 16] {
    Sha256::digest(label.as_bytes())[..16]
        .try_into()
        .expect("16 bytes")
}

/// Openings of the hidden fields of the response that `layout` renders for `account` viewing
/// `record`, with the blinders of account, owners, and propertyId in that order. For samples and
/// tests, where no notarised session exists.
pub fn rendered_openings(
    layout: &Layout,
    account: &str,
    record: &TitleRecord,
    blinders: [[u8; 16]; 3],
) -> Result<HiddenOpenings> {
    let rendered = layout.render_response(account, record)?;
    let open = |range: Range<usize>, blinder: [u8; 16]| FieldOpening {
        plaintext: rendered.bytes[range.clone()].to_vec(),
        range,
        blinder,
    };
    let [account_blinder, owners_blinder, property_blinder] = blinders;
    let r = &rendered.ranges;
    Ok(HiddenOpenings {
        account: open(r.account.clone(), account_blinder),
        owners: open(r.owners.clone(), owners_blinder),
        property_id: open(r.property_id.clone(), property_blinder),
    })
}

/// Input of the phi_R circuit in the JSON form that circom's witness generator reads. Field names
/// are the signal names of `circuits/src/phi_r.circom`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhiRInput {
    pub account_hash: [String; 2],
    pub owners_hash: [String; 2],
    pub property_hash: [String; 2],
    pub property_id: [String; 2],
    pub bind: String,
    pub account: Vec<u8>,
    pub owners: Vec<u8>,
    pub property: Vec<u8>,
    pub account_blinder: [u8; 16],
    pub owners_blinder: [u8; 16],
    pub property_blinder: [u8; 16],
}

impl PhiRInput {
    pub fn new(public: &PhiRPublic, openings: &HiddenOpenings) -> Self {
        let p = public.inputs();
        Self {
            account_hash: [p[0].clone(), p[1].clone()],
            owners_hash: [p[2].clone(), p[3].clone()],
            property_hash: [p[4].clone(), p[5].clone()],
            property_id: [p[6].clone(), p[7].clone()],
            bind: p[8].clone(),
            account: openings.account.plaintext.clone(),
            owners: openings.owners.plaintext.clone(),
            property: openings.property_id.plaintext.clone(),
            account_blinder: openings.account.blinder,
            owners_blinder: openings.owners.blinder,
            property_blinder: openings.property_id.blinder,
        }
    }
}

/// Files of the compiled circuit (`script/circuits_build.sh`) under the `circuits/` directory.
#[derive(Clone, Debug)]
pub struct CircuitFiles {
    pub circuits_dir: PathBuf,
    /// Run the witness generator and snarkjs under `/usr/bin/time -l` and report their peak
    /// resident set size.
    pub measure_rss: bool,
}

impl CircuitFiles {
    pub fn new(circuits_dir: impl Into<PathBuf>) -> Self {
        Self {
            circuits_dir: circuits_dir.into(),
            measure_rss: false,
        }
    }

    pub fn with_rss_measurement(mut self) -> Self {
        self.measure_rss = true;
        self
    }

    /// A command for `program`, under `/usr/bin/time -l` when the peak RSS is measured.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        if self.measure_rss {
            let mut command = Command::new("/usr/bin/time");
            command.arg("-l").arg(program);
            command
        } else {
            Command::new(program)
        }
    }

    pub fn build_dir(&self) -> PathBuf {
        self.circuits_dir.join("build")
    }

    pub fn wasm(&self) -> PathBuf {
        self.build_dir()
            .join(format!("{CIRCUIT_NAME}_js/{CIRCUIT_NAME}.wasm"))
    }

    pub fn witness_generator(&self) -> PathBuf {
        self.build_dir()
            .join(format!("{CIRCUIT_NAME}_js/generate_witness.js"))
    }

    pub fn snarkjs(&self) -> PathBuf {
        self.circuits_dir.join("node_modules/.bin/snarkjs")
    }

    /// Proving key of `script/circuits_setup.sh`.
    pub fn zkey(&self) -> PathBuf {
        self.build_dir().join("phi_r.zkey")
    }

    pub fn verification_key(&self) -> PathBuf {
        self.circuits_dir.join("setup/verification_key.json")
    }
}

/// An assertion of the circuit failed during witness generation: no witness exists for the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsatisfied {
    /// Circom template of the failed assertion, without the compiler's numeric suffix.
    pub template: String,
    /// Line of the assertion in the template's source file.
    pub line: u32,
}

impl fmt::Display for Unsatisfied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "phi_R has no witness for this input: assertion failed in template {} at line {}",
            self.template, self.line
        )
    }
}

impl std::error::Error for Unsatisfied {}

/// Reads circom's report of a failed assertion, `Error in template PhiR_113 line: 94`.
fn parse_unsatisfied(stderr: &str) -> Option<Unsatisfied> {
    if !stderr.contains("Assert Failed") {
        return None;
    }
    let rest = &stderr[stderr.find("Error in template ")? + "Error in template ".len()..];
    let (name, rest) = rest.split_once(" line: ")?;
    let template = match name.rsplit_once('_') {
        Some((base, suffix)) if suffix.chars().all(|c| c.is_ascii_digit()) => base,
        _ => name,
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some(Unsatisfied {
        template: template.to_string(),
        line: digits.parse().ok()?,
    })
}

/// Peak resident set size in bytes from the report of `/usr/bin/time -l` (macOS), which ends the
/// child's stderr: `  123456789  maximum resident set size`.
fn peak_rss(stderr: &str) -> Option<u64> {
    stderr
        .lines()
        .find(|line| line.trim_end().ends_with("maximum resident set size"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Writes `input` as `input.json` in `dir` and runs circom's witness generator, which writes
/// `witness.wtns`. Fails with [`Unsatisfied`] when an assertion of the circuit does not hold.
pub fn generate_witness(
    files: &CircuitFiles,
    input: &impl Serialize,
    dir: &Path,
) -> Result<PathBuf> {
    Ok(generate_witness_measured(files, input, dir)?.0)
}

/// As [`generate_witness`], with the peak RSS of the witness generator when it is measured.
fn generate_witness_measured(
    files: &CircuitFiles,
    input: &impl Serialize,
    dir: &Path,
) -> Result<(PathBuf, Option<u64>)> {
    for path in [files.wasm(), files.witness_generator()] {
        if !path.exists() {
            bail!(
                "{} is missing; build the circuit with script/circuits_build.sh",
                path.display()
            );
        }
    }
    let input_path = dir.join("input.json");
    std::fs::write(&input_path, serde_json::to_vec(input)?)
        .with_context(|| format!("writing {}", input_path.display()))?;
    let witness = dir.join("witness.wtns");
    let out = files
        .command("node")
        .arg(files.witness_generator())
        .arg(files.wasm())
        .arg(&input_path)
        .arg(&witness)
        .output()
        .context("running node (is Node.js installed?)")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if let Some(unsatisfied) = parse_unsatisfied(&stderr) {
            return Err(unsatisfied.into());
        }
        bail!("witness generation failed: {stderr}");
    }
    let rss = files
        .measure_rss
        .then(|| peak_rss(&String::from_utf8_lossy(&out.stderr)))
        .flatten();
    Ok((witness, rss))
}

/// Wall-clock time of each proving phase, in milliseconds.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveTimings {
    pub witness_ms: f64,
    pub prove_ms: f64,
    /// Peak RSS of the witness generator and of snarkjs, when measured.
    pub witness_peak_rss_bytes: Option<u64>,
    pub prove_peak_rss_bytes: Option<u64>,
}

/// A phi_R proof as snarkjs writes it, with the public inputs and the phase timings.
#[derive(Clone, Debug)]
pub struct PhiRProof {
    /// Contents of snarkjs' `proof.json`.
    pub proof_json: String,
    /// Contents of snarkjs' `public.json`: the public inputs in the circuit's order.
    pub public: Vec<String>,
    pub timings: ProveTimings,
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Generates the witness with circom's wasm and a Groth16 proof with `snarkjs groth16 prove`, each
/// as a child process (D22), writing intermediate files into `dir`.
pub fn prove(files: &CircuitFiles, input: &PhiRInput, dir: &Path) -> Result<PhiRProof> {
    let zkey = files.zkey();
    ensure!(
        zkey.exists(),
        "{} is missing; run script/circuits_setup.sh",
        zkey.display()
    );
    let started = Instant::now();
    let (witness, witness_rss) = generate_witness_measured(files, input, dir)?;
    let witness_time = started.elapsed();

    let (proof_path, public_path) = (dir.join("proof.json"), dir.join("public.json"));
    let started = Instant::now();
    let out = files
        .command(files.snarkjs())
        .args(["groth16", "prove"])
        .arg(&zkey)
        .arg(&witness)
        .arg(&proof_path)
        .arg(&public_path)
        .output()
        .context("running snarkjs")?;
    let prove_time = started.elapsed();
    ensure!(
        out.status.success(),
        "snarkjs groth16 prove failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let public: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(&public_path).context("reading public.json")?,
    )
    .context("parsing public.json")?;
    Ok(PhiRProof {
        proof_json: std::fs::read_to_string(&proof_path).context("reading proof.json")?,
        public,
        timings: ProveTimings {
            witness_ms: millis(witness_time),
            prove_ms: millis(prove_time),
            witness_peak_rss_bytes: witness_rss,
            prove_peak_rss_bytes: files
                .measure_rss
                .then(|| peak_rss(&String::from_utf8_lossy(&out.stderr)))
                .flatten(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_peak_rss_of_time_l() {
        let stderr = "some output\n        0.35 real         0.30 user         0.04 sys\n\
                      96256000  maximum resident set size\n               0  average shared memory size\n";
        assert_eq!(peak_rss(stderr), Some(96_256_000));
        assert_eq!(peak_rss("no report"), None);
    }

    #[test]
    fn reads_the_failed_assertion() {
        let stderr =
            "Error: Error: Assert Failed.\nError in template PhiR_113 line: 94\n\n    at ...";
        assert_eq!(
            parse_unsatisfied(stderr),
            Some(Unsatisfied {
                template: "PhiR".into(),
                line: 94
            })
        );
        let stderr = "Error: Assert Failed.\nError in template Num2Bits_3 line: 38\n";
        assert_eq!(parse_unsatisfied(stderr).unwrap().template, "Num2Bits");
        assert_eq!(parse_unsatisfied("Error: ENOENT"), None);
    }
}
