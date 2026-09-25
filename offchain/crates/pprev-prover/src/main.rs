use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use pprev_prover::{
    DEFAULT_MAX_RETRIES, DEFAULT_PREPROCESS_TIMEOUT, ProverSetup, login, notarize_with_retries,
    present,
};
use pprev_types::Layout;

/// Logs in to the registry, runs one MPC-TLS session with the notary, and writes the attestation,
/// its secrets, and the presentation (bincode) to `--out`.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    notary: SocketAddr,
    #[arg(long)]
    registry: SocketAddr,
    /// Registry CA certificate (DER).
    #[arg(long)]
    ca: PathBuf,
    #[arg(long, default_value = "policies/layouts/title-v1.json")]
    layout: PathBuf,
    #[arg(long)]
    account: String,
    #[arg(long)]
    password: String,
    #[arg(long)]
    property: String,
    #[arg(long)]
    out: PathBuf,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let layout = Layout::load(&args.layout)?;
    let ca = std::fs::read(&args.ca)?;
    let token = login(
        args.registry,
        &layout.server_name,
        &ca,
        &args.account,
        &args.password,
    )
    .await?;
    let setup = ProverSetup {
        layout,
        registry_addr: args.registry,
        root_certs: vec![ca],
        token,
        property_id: args.property,
        max_sent: args.max_sent,
        max_recv: args.max_recv,
        preprocess_timeout: std::time::Duration::from_secs(args.preprocess_timeout_secs),
    };
    let notary_addr = args.notary;
    let (notarized, stats) = notarize_with_retries(
        |_attempt| async move { anyhow::Ok(tokio::net::TcpStream::connect(notary_addr).await?) },
        &setup,
        args.max_retries,
    )
    .await?;
    println!("notarised in {} attempt(s)", stats.attempts);
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
