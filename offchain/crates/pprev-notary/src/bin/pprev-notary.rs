//! The notary and policy verifier as one process (D2): an MPC-TLS listener that notarises sessions
//! and returns attestations, and a policy-verifier listener that answers Register submissions with
//! sigma_R (Section V-B, steps (b) and (d)).
//!
//! Every session and every Register request is appended as one JSON line to `--log`.

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy_primitives::Address;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use pprev_notary::wire::{RegisterReply, RegisterSubmission, read_message, write_message};
use pprev_notary::{
    DEFAULT_MAX_SESSION_SECS, DEFAULT_PREPROCESS_TIMEOUT, DEFAULT_SESSION_TIMEOUT, Groth16Verifier,
    NonceStore, NotaryConfig, PolicyVerifier, RegisterPolicy, SessionCut, StatementKey,
};
use pprev_types::statement::domain;
use pprev_types::{Layout, PolicyBundle};
use serde_json::{Value, json};
use tlsn::attestation::signing::{Secp256k1Signer, Signer};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    /// MPC-TLS listener.
    #[arg(long, default_value = "127.0.0.1:7047")]
    mpc_bind: SocketAddr,
    /// Policy-verifier listener.
    #[arg(long, default_value = "127.0.0.1:7048")]
    verifier_bind: SocketAddr,
    /// Registry CA certificate (DER), trusted for the server identity.
    #[arg(long)]
    registry_ca: PathBuf,
    /// Register policy bundles this notary serves; paths inside are relative to `--root`.
    #[arg(long, required = true)]
    policy: Vec<PathBuf>,
    /// Repository root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// File with the attestation key (D19), 32 bytes as hex.
    #[arg(long)]
    attestation_key: PathBuf,
    /// File with sk_notary (D19), 32 bytes as hex.
    #[arg(long)]
    statement_key: PathBuf,
    /// EIP-712 domain: chain ID and PPREV contract.
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    contract: Address,
    /// Nonce record (D20).
    #[arg(long)]
    nonces: PathBuf,
    /// Event log, one JSON object per line.
    #[arg(long)]
    log: PathBuf,
    /// Upper bound on t_att - ConnectionInfo.time (D29).
    #[arg(long, default_value_t = DEFAULT_MAX_SESSION_SECS)]
    max_session_secs: u64,
    /// Bounds after which a session is cut (D33).
    #[arg(long, default_value_t = DEFAULT_PREPROCESS_TIMEOUT.as_secs())]
    preprocess_timeout_secs: u64,
    #[arg(long, default_value_t = DEFAULT_SESSION_TIMEOUT.as_secs())]
    session_timeout_secs: u64,
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let text = text.trim();
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .with_context(|| format!("{}: not hex", path.display()))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| anyhow::anyhow!("{}: not 32 bytes", path.display()))
}

/// Appends JSON lines to the event log.
#[derive(Clone)]
struct EventLog(Arc<Mutex<std::fs::File>>);

impl EventLog {
    fn open(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        Ok(Self(Arc::new(Mutex::new(file))))
    }

    fn write(&self, mut event: Value) {
        event["unixMs"] = json!(unix_ms());
        let mut file = self.0.lock().expect("event log lock");
        if let Err(e) = writeln!(file, "{event}") {
            tracing::error!("writing the event log: {e}");
        }
    }
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_millis()
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn load_policies(args: &Args) -> Result<HashMap<alloy_primitives::B256, RegisterPolicy>> {
    let mut policies = HashMap::new();
    for path in &args.policy {
        let bundle = PolicyBundle::load(path)?;
        let layout = Layout::load(args.root.join(&bundle.register.layout))?;
        let vk_path = args.root.join(&bundle.register.verification_key);
        let vk = std::fs::read_to_string(&vk_path)
            .with_context(|| format!("reading {}", vk_path.display()))?;
        let verifier = Groth16Verifier::from_snarkjs_json(&vk)?;
        ensure!(
            policies
                .insert(bundle.policy_id_r(), RegisterPolicy { layout, verifier })
                .is_none(),
            "policy {} is listed twice",
            bundle.policy_id_r()
        );
        println!("policy {}: policyID_R {}", bundle.id, bundle.policy_id_r());
    }
    Ok(policies)
}

async fn serve_mpc(listener: TcpListener, config: NotaryConfig, log: EventLog) -> Result<()> {
    loop {
        let (socket, peer) = listener.accept().await?;
        let (config, log) = (config.clone(), log.clone());
        tokio::spawn(async move {
            let started = Instant::now();
            let event = match pprev_notary::notarize(socket, &config).await {
                Ok(report) => json!({
                    "event": "session",
                    "outcome": "attested",
                    "tAtt": report.t_att,
                    "connectionTime": report.connection_time,
                    "durationMs": millis(started),
                }),
                Err(e) => json!({
                    "event": "session",
                    "outcome": if e.downcast_ref::<SessionCut>().is_some() { "cut" } else { "failed" },
                    "reason": format!("{e:#}"),
                    "durationMs": millis(started),
                }),
            };
            tracing::info!(%peer, %event, "session ended");
            log.write(event);
        });
    }
}

async fn serve_verifier(
    listener: TcpListener,
    verifier: Arc<Mutex<PolicyVerifier>>,
    log: EventLog,
) -> Result<()> {
    loop {
        let (socket, peer) = listener.accept().await?;
        let (verifier, log) = (verifier.clone(), log.clone());
        tokio::spawn(async move {
            let (reader, writer) = socket.into_split();
            let reply = match read_message::<RegisterSubmission>(reader).await {
                Ok(submission) => tokio::task::spawn_blocking(move || {
                    let started = Instant::now();
                    let request = submission.into_request()?;
                    let decode_ms = millis(started);
                    let (sigma, timings) = verifier
                        .lock()
                        .expect("policy verifier lock")
                        .sign_register_timed(request)?;
                    anyhow::Ok(RegisterReply::Signed {
                        sigma: sigma.to_vec(),
                        decode_ms,
                        timings,
                    })
                })
                .await
                .map_err(anyhow::Error::from)
                .and_then(|r| r),
                Err(e) => Err(e),
            }
            .unwrap_or_else(|e| RegisterReply::Refused {
                reason: format!("{e:#}"),
            });
            let event = match &reply {
                RegisterReply::Signed {
                    decode_ms, timings, ..
                } => json!({
                    "event": "register",
                    "outcome": "signed",
                    "decodeMs": decode_ms,
                    "timings": timings,
                }),
                RegisterReply::Refused { reason } => json!({
                    "event": "register",
                    "outcome": "refused",
                    "reason": reason,
                }),
            };
            tracing::info!(%peer, %event, "register request");
            log.write(event);
            if let Err(e) = write_message(writer, &reply).await {
                tracing::warn!(%peer, "writing the reply: {e:#}");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let ca = std::fs::read(&args.registry_ca)
        .with_context(|| format!("reading {}", args.registry_ca.display()))?;
    let attestation_key = read_key(&args.attestation_key)?;
    let statement_key = StatementKey::from_bytes(&read_key(&args.statement_key)?)?;
    ensure!(
        statement_key.vk_notary() != Address::ZERO,
        "invalid statement key"
    );
    println!("vk_notary {}", statement_key.vk_notary());

    let mut config = NotaryConfig::new(attestation_key, vec![ca.clone()]);
    config.preprocess_timeout = Duration::from_secs(args.preprocess_timeout_secs);
    config.session_timeout = Duration::from_secs(args.session_timeout_secs);

    let verifier = PolicyVerifier::new(
        load_policies(&args)?,
        Secp256k1Signer::new(&attestation_key)?.verifying_key(),
        vec![ca],
        args.max_session_secs,
        statement_key,
        domain(args.chain_id, args.contract),
        NonceStore::open(&args.nonces)?,
    );
    let log = EventLog::open(&args.log)?;

    let mpc = TcpListener::bind(args.mpc_bind).await?;
    let pv = TcpListener::bind(args.verifier_bind).await?;
    println!(
        "notary listening on {} (MPC-TLS) and {} (policy verifier)",
        mpc.local_addr()?,
        pv.local_addr()?
    );
    tokio::select! {
        r = serve_mpc(mpc, config, log.clone()) => r,
        r = serve_verifier(pv, Arc::new(Mutex::new(verifier)), log) => r,
        r = tokio::signal::ctrl_c() => Ok(r?),
    }
}
