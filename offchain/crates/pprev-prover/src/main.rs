use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
use pprev_prover::chain::{
    ApplyPayload, PhaseOutcome, RegisterPayload, SettlePayload, SubmitOutcome, read_private_key,
    submit_apply, submit_engage, submit_register, submit_settle,
};
use pprev_prover::circuit::CircuitFiles;
use pprev_prover::counting::{ByteCounts, CountingStream};
use pprev_prover::phases::{self, ApplyConfig, Engagement, Listing, SessionConfig, SettleConfig};
use pprev_prover::register::{self, Outcome, RegisterConfig};
use pprev_prover::{
    DEFAULT_MAX_RETRIES, DEFAULT_PREPROCESS_TIMEOUT, ProverSetup, login, notarize_with_retries,
    present,
};
use pprev_types::RecordLayout;
use pprev_types::statement::TxData;
use pprev_types::{Layout, PolicyBundle};
use serde_json::Value;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Logs in to the registry, runs one MPC-TLS session with the notary, and writes the
    /// attestation, its secrets, and the presentation (bincode) to `--out`.
    Notarize(NotarizeArgs),
    /// Runs Register end to end and writes `record.json` (and `payload.json` once sigma_R is held)
    /// to `--out`. Exits with an error unless the listing is registered, or signed with
    /// `--no-submit`.
    Register(Box<RegisterArgs>),
    /// Sends the `register` transaction of a payload written by `register` and writes the result as
    /// JSON to `--out`. Exits with an error unless the transaction is included.
    Submit(SubmitArgs),
    /// Runs Apply end to end for a listing that `register` recorded and writes `record.json` (and
    /// `payload.json`, with the opening of c_B, once sigma_A is held) to `--out`.
    Apply(Box<ApplyArgs>),
    /// Sends `engage` for an application that `apply` recorded and writes the result as JSON to
    /// `--out`. Exits with an error unless the transaction is included.
    Engage(EngageArgs),
    /// Runs Settle end to end for an engagement that `engage` recorded and writes `record.json` (and
    /// `payload.json` once sigma_S is held) to `--out`.
    Settle(Box<SettleArgs>),
    /// Sends the `applyFor` transaction of a payload written by `apply`; as `submit`.
    SubmitApply(SubmitArgs),
    /// Sends the `settle` transaction of a payload written by `settle`; as `submit`.
    SubmitSettle(SubmitArgs),
}

/// Registry and notary options of `apply` and `settle`.
#[derive(ClapArgs)]
struct PhaseSessionArgs {
    #[arg(long)]
    notary: SocketAddr,
    /// Policy verifier of the notary.
    #[arg(long)]
    verifier: SocketAddr,
    #[arg(long)]
    registry: SocketAddr,
    /// Registry CA certificate (DER).
    #[arg(long)]
    ca: PathBuf,
    #[arg(long)]
    account: String,
    #[arg(long)]
    password: String,
    #[arg(long, default_value_t = 1024)]
    max_sent: usize,
    #[arg(long, default_value_t = 1024)]
    max_recv: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_RETRIES)]
    max_retries: u32,
    #[arg(long, default_value_t = DEFAULT_PREPROCESS_TIMEOUT.as_secs())]
    preprocess_timeout_secs: u64,
    /// Policy bundle; its paths are relative to `--root`.
    #[arg(long, default_value = "policies/rental-v1.json")]
    policy: PathBuf,
    /// Repository root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    rpc_url: String,
    /// PPREV contract.
    #[arg(long)]
    contract: Address,
    /// File with the submitter's private key (hex).
    #[arg(long)]
    key_file: PathBuf,
    /// `record.json` of the `register` run that created the listing.
    #[arg(long)]
    listing: PathBuf,
    #[arg(long, default_value = "circuits")]
    circuits: PathBuf,
    #[arg(long)]
    out: PathBuf,
    /// Nonce to use instead of a fresh one.
    #[arg(long)]
    eta: Option<B256>,
    /// `proof.json` to submit instead of the submitter's own proof.
    #[arg(long)]
    proof_from: Option<PathBuf>,
    /// Stop after sigma_psi; leave the payload in `--out`.
    #[arg(long)]
    no_submit: bool,
    /// Report the peak RSS of the witness generator and snarkjs.
    #[arg(long)]
    measure_rss: bool,
}

impl PhaseSessionArgs {
    fn session(&self) -> Result<SessionConfig> {
        Ok(SessionConfig {
            notary: self.notary,
            verifier: self.verifier,
            registry: self.registry,
            ca_der: std::fs::read(&self.ca)
                .with_context(|| format!("reading {}", self.ca.display()))?,
            account: self.account.clone(),
            password: self.password.clone(),
            max_sent: self.max_sent,
            max_recv: self.max_recv,
            max_retries: self.max_retries,
            preprocess_timeout: std::time::Duration::from_secs(self.preprocess_timeout_secs),
        })
    }

    fn circuits(&self, files: fn(PathBuf) -> CircuitFiles) -> CircuitFiles {
        let files = files(self.root.join(&self.circuits));
        if self.measure_rss {
            files.with_rss_measurement()
        } else {
            files
        }
    }
}

#[derive(ClapArgs)]
struct ApplyArgs {
    #[command(flatten)]
    session: PhaseSessionArgs,
    /// Escrow deposit sent with `applyFor`, in wei.
    #[arg(long)]
    deposit_wei: U256,
    /// Identifier for c_B instead of the session's account.
    #[arg(long)]
    identifier: Option<String>,
}

#[derive(ClapArgs)]
struct EngageArgs {
    /// `record.json` of the `apply` run.
    #[arg(long)]
    application: PathBuf,
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    contract: Address,
    /// File with the owner's private key (hex).
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(ClapArgs)]
struct SettleArgs {
    #[command(flatten)]
    session: PhaseSessionArgs,
    /// `record.json` of the `apply` run: c_B and its opening.
    #[arg(long)]
    application: PathBuf,
    /// Output of `engage`: engID and expiresAt.
    #[arg(long)]
    engagement: PathBuf,
    /// The tenancy notation to retrieve.
    #[arg(long)]
    notation: String,
}

/// Registry session options shared by `notarize` and `register`.
#[derive(ClapArgs)]
struct SessionArgs {
    #[arg(long)]
    notary: SocketAddr,
    #[arg(long)]
    registry: SocketAddr,
    /// Registry CA certificate (DER).
    #[arg(long)]
    ca: PathBuf,
    #[arg(long)]
    account: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    property: String,
    #[arg(long, default_value_t = 1024)]
    max_sent: usize,
    #[arg(long, default_value_t = 1024)]
    max_recv: usize,
    /// Retries after a stalled MPC-TLS preprocessing (tlsnotary/tlsn#1173).
    #[arg(long, default_value_t = DEFAULT_MAX_RETRIES)]
    max_retries: u32,
    #[arg(long, default_value_t = DEFAULT_PREPROCESS_TIMEOUT.as_secs())]
    preprocess_timeout_secs: u64,
}

#[derive(ClapArgs)]
struct NotarizeArgs {
    #[command(flatten)]
    session: SessionArgs,
    #[arg(long, default_value = "policies/layouts/title-v1.json")]
    layout: PathBuf,
    #[arg(long)]
    out: PathBuf,
    /// Also write attempts, stalls, timings, and traffic of the session as JSON to this file.
    #[arg(long)]
    report: Option<PathBuf>,
}

#[derive(ClapArgs)]
struct RegisterArgs {
    #[command(flatten)]
    session: SessionArgs,
    /// Policy verifier of the notary.
    #[arg(long)]
    verifier: SocketAddr,
    /// Policy bundle; its paths are relative to `--root`.
    #[arg(long, default_value = "policies/rental-v1.json")]
    policy: PathBuf,
    /// Repository root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    rpc_url: String,
    /// PPREV contract.
    #[arg(long)]
    contract: Address,
    /// File with the owner's private key (hex).
    #[arg(long)]
    key_file: PathBuf,
    /// txData.amount, in wei.
    #[arg(long)]
    amount_wei: U256,
    /// txData.settlementShare, in basis points.
    #[arg(long, default_value_t = U256::ZERO)]
    settlement_share_bps: U256,
    /// Collateral sent with `register`, in wei.
    #[arg(long)]
    collateral_wei: U256,
    #[arg(long, default_value = "circuits")]
    circuits: PathBuf,
    #[arg(long)]
    out: PathBuf,
    /// Nonce to use instead of a fresh one.
    #[arg(long)]
    eta: Option<B256>,
    /// `proof.json` to submit instead of the owner's own proof.
    #[arg(long)]
    proof_from: Option<PathBuf>,
    /// Stop after sigma_R; leave the payload in `--out`.
    #[arg(long)]
    no_submit: bool,
    /// Report the peak RSS of the witness generator and snarkjs (runs them under /usr/bin/time -l).
    #[arg(long)]
    measure_rss: bool,
}

#[derive(ClapArgs)]
struct SubmitArgs {
    #[arg(long)]
    payload: PathBuf,
    #[arg(long)]
    rpc_url: String,
    /// File with the sender's private key (hex).
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        Command::Notarize(args) => notarize(args).await,
        Command::Register(args) => register(args).await,
        Command::Submit(args) => submit(args).await,
        Command::Apply(args) => apply(*args).await,
        Command::Engage(args) => engage(args).await,
        Command::Settle(args) => settle(*args).await,
        Command::SubmitApply(args) => {
            let payload: ApplyPayload = serde_json::from_value(read_json(&args.payload)?)?;
            let key = read_private_key(&args.key_file)?;
            let outcome = submit_apply(&args.rpc_url, &key, &payload).await?;
            write_phase_outcome(&args.out, outcome)
        }
        Command::SubmitSettle(args) => {
            let payload: SettlePayload = serde_json::from_value(read_json(&args.payload)?)?;
            let key = read_private_key(&args.key_file)?;
            let outcome = submit_settle(&args.rpc_url, &key, &payload).await?;
            write_phase_outcome(&args.out, outcome)
        }
    }
}

/// Writes the outcome of a phase transaction and fails unless it was included.
fn write_phase_outcome<E: serde::Serialize>(
    out: &std::path::Path,
    outcome: PhaseOutcome<E>,
) -> Result<()> {
    write_json(out, &outcome)?;
    match outcome {
        PhaseOutcome::Included { tx_hash, .. } => {
            println!("included: {tx_hash}");
            Ok(())
        }
        PhaseOutcome::Reverted { error } => anyhow::bail!("reverted: {error}"),
    }
}

fn read_json(path: &std::path::Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn field<T: std::str::FromStr>(value: &Value, pointer: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    let v = value
        .pointer(pointer)
        .with_context(|| format!("{pointer} is missing"))?;
    let text = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    text.parse().map_err(|e| anyhow::anyhow!("{pointer}: {e}"))
}

/// The listing from the record of a `register` run.
fn listing_of(record: &std::path::Path) -> Result<Listing> {
    let v = read_json(record)?;
    Ok(Listing {
        tx_id: field(&v, "/submission/event/txId")?,
        tx_data: TxData {
            propertyId: field(&v, "/payload/propertyId")?,
            amount: field(&v, "/payload/amount")?,
            settlementShare: field(&v, "/payload/settlementShare")?,
        },
        r: field(&v, "/payload/r")?,
    })
}

/// Writes a phase record and fails unless the run reached `expected`.
fn finish_phase<P: serde::Serialize, E: serde::Serialize>(
    out: &std::path::Path,
    result: Result<phases::PhaseRecord<P, E>>,
    submit: bool,
) -> Result<()> {
    let record_path = out.join("record.json");
    let record = match result {
        Ok(record) => record,
        Err(e) => {
            std::fs::create_dir_all(out)?;
            write_json(
                &record_path,
                &serde_json::json!({ "outcome": "error", "reason": format!("{e:#}") }),
            )?;
            return Err(e);
        }
    };
    write_json(&record_path, &record)?;
    println!(
        "{}: {:?}{}",
        record.phase,
        record.outcome,
        record
            .reason
            .as_deref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );
    let expected = if submit {
        phases::Outcome::Included
    } else {
        phases::Outcome::Signed
    };
    anyhow::ensure!(
        record.outcome == expected,
        "{} did not complete",
        record.phase
    );
    Ok(())
}

async fn apply(args: ApplyArgs) -> Result<()> {
    let s = &args.session;
    let policy = PolicyBundle::load(&s.policy)?;
    let source = policy
        .apply
        .as_ref()
        .context("the policy has no apply source")?;
    let config = ApplyConfig {
        session: s.session()?,
        layout: RecordLayout::load(s.root.join(&source.layout))?,
        rpc_url: s.rpc_url.clone(),
        contract: s.contract,
        key: read_private_key(&s.key_file)?,
        listing: listing_of(&s.listing)?,
        deposit: args.deposit_wei,
        circuits: s.circuits(CircuitFiles::phi_a),
        out: s.out.clone(),
        eta: s.eta,
        identifier: args.identifier.clone(),
        proof_from: s.proof_from.clone(),
        submit: !s.no_submit,
        policy,
    };
    finish_phase(&s.out, phases::run_apply(&config).await, config.submit)
}

async fn engage(args: EngageArgs) -> Result<()> {
    let v = read_json(&args.application)?;
    let outcome = submit_engage(
        &args.rpc_url,
        &read_private_key(&args.key_file)?,
        args.contract,
        field(&v, "/submission/event/txId")?,
        field(&v, "/submission/event/appId")?,
    )
    .await?;
    write_phase_outcome(&args.out, outcome)
}

async fn settle(args: SettleArgs) -> Result<()> {
    let s = &args.session;
    let policy = PolicyBundle::load(&s.policy)?;
    let source = policy
        .settle
        .as_ref()
        .context("the policy has no settle source")?;
    let application = read_json(&args.application)?;
    let engagement = read_json(&args.engagement)?;
    let config = SettleConfig {
        session: s.session()?,
        layout: RecordLayout::load(s.root.join(&source.layout))?,
        rpc_url: s.rpc_url.clone(),
        contract: s.contract,
        key: read_private_key(&s.key_file)?,
        listing: listing_of(&s.listing)?,
        engagement: Engagement {
            eng_id: field(&engagement, "/event/engId")?,
            expires_at: field(&engagement, "/event/expiresAt")?,
        },
        c_b: field(&application, "/payload/cB")?,
        identifier: field(&application, "/payload/identifier")?,
        salt: field(&application, "/payload/salt")?,
        notation_id: args.notation.clone(),
        circuits: s.circuits(CircuitFiles::phi_s),
        out: s.out.clone(),
        eta: s.eta,
        proof_from: s.proof_from.clone(),
        submit: !s.no_submit,
        policy,
    };
    finish_phase(&s.out, phases::run_settle(&config).await, config.submit)
}

async fn notarize(args: NotarizeArgs) -> Result<()> {
    let s = args.session;
    let layout = Layout::load(&args.layout)?;
    let ca = std::fs::read(&s.ca)?;
    let started = Instant::now();
    let token = login(
        s.registry,
        &layout.server_name,
        &ca,
        &s.account,
        &s.password,
    )
    .await?;
    let login_ms = millis(started);
    let setup = ProverSetup {
        layout,
        registry_addr: s.registry,
        root_certs: vec![ca],
        token,
        property_id: s.property,
        max_sent: s.max_sent,
        max_recv: s.max_recv,
        preprocess_timeout: std::time::Duration::from_secs(s.preprocess_timeout_secs),
    };
    let notary_addr = s.notary;
    let mut attempt_started = Vec::new();
    let mut attempt_counts = Vec::new();
    let result = notarize_with_retries(
        |_attempt| {
            attempt_started.push(Instant::now());
            let counts = ByteCounts::default();
            attempt_counts.push(counts.clone());
            async move {
                let stream = tokio::net::TcpStream::connect(notary_addr).await?;
                anyhow::Ok(CountingStream::with_counts(stream, counts))
            }
        },
        &setup,
        s.max_retries,
    )
    .await;
    let (notarized, stats) = match result {
        Ok(ok) => ok,
        Err(e) => {
            if let Some(path) = &args.report {
                write_json(
                    path,
                    &serde_json::json!({
                        "outcome": "failed",
                        "attempts": attempt_started.len(),
                        "reason": format!("{e:#}"),
                    }),
                )?;
            }
            return Err(e);
        }
    };
    let mpc_tls_ms = millis(*attempt_started.last().expect("one attempt"));
    println!("notarised in {} attempt(s)", stats.attempts);
    if let Some(path) = &args.report {
        write_json(
            path,
            &serde_json::json!({
                "outcome": "attested",
                "attempts": stats.attempts,
                "stalls": stats.stalls,
                "loginMs": login_ms,
                "mpcTlsMs": mpc_tls_ms,
                "mpcTraffic": attempt_counts.last().expect("one attempt").traffic(),
            }),
        )?;
    }
    let presentation = present(&notarized, false)?;

    std::fs::create_dir_all(&args.out)?;
    std::fs::write(
        args.out.join("attestation.bin"),
        bincode::serialize(&notarized.attestation)?,
    )?;
    std::fs::write(
        args.out.join("secrets.bin"),
        bincode::serialize(&notarized.secrets)?,
    )?;
    std::fs::write(
        args.out.join("presentation.bin"),
        bincode::serialize(&presentation)?,
    )?;
    println!(
        "wrote attestation, secrets, and presentation to {}",
        args.out.display()
    );
    Ok(())
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")
        .with_context(|| format!("writing {}", path.display()))
}

async fn register(args: Box<RegisterArgs>) -> Result<()> {
    let args = *args;
    let s = args.session;
    let policy = PolicyBundle::load(&args.policy)?;
    let config = RegisterConfig {
        notary: s.notary,
        verifier: args.verifier,
        registry: s.registry,
        ca_der: std::fs::read(&s.ca).with_context(|| format!("reading {}", s.ca.display()))?,
        layout: Layout::load(args.root.join(&policy.register.layout))?,
        policy,
        account: s.account,
        password: s.password,
        property: s.property,
        rpc_url: args.rpc_url,
        contract: args.contract,
        key: read_private_key(&args.key_file)?,
        amount: args.amount_wei,
        settlement_share: args.settlement_share_bps,
        collateral: args.collateral_wei,
        circuits: {
            let files = CircuitFiles::new(args.root.join(&args.circuits));
            if args.measure_rss {
                files.with_rss_measurement()
            } else {
                files
            }
        },
        out: args.out.clone(),
        max_sent: s.max_sent,
        max_recv: s.max_recv,
        max_retries: s.max_retries,
        preprocess_timeout: std::time::Duration::from_secs(s.preprocess_timeout_secs),
        eta: args.eta,
        proof_from: args.proof_from,
        submit: !args.no_submit,
    };
    let record_path = args.out.join("record.json");
    let record = match register::run(&config).await {
        Ok(record) => record,
        Err(e) => {
            std::fs::create_dir_all(&args.out)?;
            write_json(
                &record_path,
                &serde_json::json!({ "outcome": "error", "reason": format!("{e:#}") }),
            )?;
            return Err(e);
        }
    };
    write_json(&record_path, &record)?;
    println!(
        "outcome: {:?}{}",
        record.outcome,
        record
            .reason
            .as_deref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );
    let expected = if config.submit {
        Outcome::Registered
    } else {
        Outcome::Signed
    };
    anyhow::ensure!(record.outcome == expected, "Register did not complete");
    Ok(())
}

async fn submit(args: SubmitArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.payload)
        .with_context(|| format!("reading {}", args.payload.display()))?;
    let payload: RegisterPayload = serde_json::from_str(&text).context("parsing the payload")?;
    let key = read_private_key(&args.key_file)?;
    let outcome = submit_register(&args.rpc_url, &key, &payload).await?;
    write_json(&args.out, &outcome)?;
    match outcome {
        SubmitOutcome::Included { tx_hash, .. } => {
            println!("included: {tx_hash}");
            Ok(())
        }
        SubmitOutcome::Reverted { error } => anyhow::bail!("reverted: {error}"),
    }
}
