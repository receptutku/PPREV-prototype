//! Shared harness: a mock registry on a local port, login, and MPC-TLS sessions with a notary
//! running in the same process, one notary per attempt (D33).

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use mock_registry::{Fixtures, RunningRegistry};
use pprev_notary::{NotarizationReport, NotaryConfig};
use pprev_prover::{DEFAULT_MAX_RETRIES, NotarizeStats, Notarized, ProverSetup};
use pprev_types::Layout;
use tlsn::attestation::CryptoProvider;
use tlsn::attestation::signing::{Secp256k1Signer, Signer, VerifyingKey};
use tlsn::verifier::ServerCertVerifier;
use tlsn::webpki::{CertificateDer, RootCertStore};
use tokio::task::JoinHandle;

pub const OWNER: (&str, &str) = ("ACC-000000000001", "owner-one");
pub const TENANT: (&str, &str) = ("ACC-000000000003", "tenant");
pub const PROPERTY: &str = "TR-06-CANKAYA-000123";
/// Test-only attestation key of the notary (D19).
pub const ATTESTATION_KEY: [u8; 32] = [7u8; 32];
pub const MAX_SENT: usize = 1024;
pub const MAX_RECV: usize = 1024;

/// Preprocessing bound in tests; in-process preprocessing takes well under a second.
pub const TEST_PREPROCESS_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on one notarisation with its retries, so that a stuck test fails instead of hanging.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(90);

pub fn workspace_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel)
}

pub fn layout() -> Layout {
    Layout::load(workspace_path("policies/layouts/title-v1.json")).expect("layout")
}

pub fn fixtures() -> Fixtures {
    Fixtures::load(workspace_path("mock-registry/fixtures/records.json")).expect("fixtures")
}

pub fn attestation_verifying_key() -> VerifyingKey {
    Secp256k1Signer::new(&ATTESTATION_KEY)
        .expect("key")
        .verifying_key()
}

/// Crypto provider that trusts the given registry CA for server identity proofs.
pub fn provider(ca_der: &[u8]) -> CryptoProvider {
    let roots = RootCertStore {
        roots: vec![CertificateDer(ca_der.to_vec())],
    };
    CryptoProvider {
        cert: ServerCertVerifier::new(&roots).expect("verifier"),
        ..Default::default()
    }
}

/// With `PPREV_TEST_LOG=<file>`, writes the tracing output of the test process (tlsn included) to
/// that file; the level comes from `PPREV_TEST_LOG_FILTER` (default `debug`).
pub fn init_test_log() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let Some(path) = std::env::var_os("PPREV_TEST_LOG") else {
            return;
        };
        let file = std::fs::File::create(path).expect("test log file");
        let filter = std::env::var("PPREV_TEST_LOG_FILTER").unwrap_or_else(|_| "debug".into());
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .with_thread_names(true)
            .try_init();
    });
}

/// A running registry, a logged-in prover setup, and a notary configuration for one test.
pub struct Env {
    pub layout: Layout,
    pub registry: RunningRegistry,
    pub ca_der: Vec<u8>,
    pub setup: ProverSetup,
    pub notary_config: NotaryConfig,
}

pub async fn env(account: (&str, &str), property_id: &str) -> Result<Env> {
    init_test_log();
    let layout = layout();
    let registry = RunningRegistry::start(layout.clone(), fixtures(), "127.0.0.1:0").await?;
    let ca_der = registry.certs.ca_der.clone();
    let token = pprev_prover::login(
        registry.addr,
        &layout.server_name,
        &ca_der,
        account.0,
        account.1,
    )
    .await?;
    let setup = ProverSetup {
        layout: layout.clone(),
        registry_addr: registry.addr,
        root_certs: vec![ca_der.clone()],
        token,
        property_id: property_id.to_string(),
        max_sent: MAX_SENT,
        max_recv: MAX_RECV,
        preprocess_timeout: TEST_PREPROCESS_TIMEOUT,
    };
    let mut notary_config = NotaryConfig::new(ATTESTATION_KEY, vec![ca_der.clone()]);
    notary_config.preprocess_timeout = TEST_PREPROCESS_TIMEOUT;
    Ok(Env {
        layout,
        registry,
        ca_der,
        setup,
        notary_config,
    })
}

/// Opens an in-process connection to a new notary task that runs `config`; the task is recorded in
/// `tasks` so that the caller can collect its report.
pub fn spawn_notary(
    config: &NotaryConfig,
    tasks: &mut Vec<JoinHandle<Result<NotarizationReport>>>,
) -> tokio::io::DuplexStream {
    let (notary_io, prover_io) = tokio::io::duplex(1 << 23);
    let config = config.clone();
    tasks.push(tokio::spawn(async move {
        pprev_notary::notarize(notary_io, &config).await
    }));
    prover_io
}

/// Outputs of one notarisation.
pub struct Run {
    pub layout: Layout,
    pub notarized: Notarized,
    pub report: NotarizationReport,
    pub stats: NotarizeStats,
    pub ca_der: Vec<u8>,
    /// Exact bytes of every title response the registry sent.
    pub sent_log: Vec<Vec<u8>>,
    /// The notary's clock just before and just after the session.
    pub notary_clock: (u64, u64),
    /// Bearer token used in the notarised request.
    pub token: String,
}

/// Logs in as `account`, then notarises the title request for `property_id` with an in-process
/// notary, retrying stalled preprocessing (D33).
pub async fn notarize_once(account: (&str, &str), property_id: &str) -> Result<Run> {
    notarize_with_clock(account, property_id, pprev_notary::unix_now).await
}

/// As [`notarize_once`], with `notary_clock` as the notary's source of t_att.
pub async fn notarize_with_clock(
    account: (&str, &str),
    property_id: &str,
    notary_clock: fn() -> u64,
) -> Result<Run> {
    tokio::time::timeout(
        SESSION_TIMEOUT,
        notarize_inner(account, property_id, notary_clock),
    )
    .await
    .map_err(|_| anyhow::anyhow!("notarisation did not finish within {SESSION_TIMEOUT:?}"))?
}

async fn notarize_inner(
    account: (&str, &str),
    property_id: &str,
    notary_clock: fn() -> u64,
) -> Result<Run> {
    let mut env = env(account, property_id).await?;
    env.notary_config.clock = notary_clock;

    let before = pprev_notary::unix_now();
    let mut notary_tasks = Vec::new();
    let (notarized, stats) = pprev_prover::notarize_with_retries(
        |_attempt| {
            let io = spawn_notary(&env.notary_config, &mut notary_tasks);
            async move { anyhow::Ok(io) }
        },
        &env.setup,
        DEFAULT_MAX_RETRIES,
    )
    .await?;
    let report = notary_tasks
        .pop()
        .expect("one notary per attempt")
        .await??;
    for stalled in notary_tasks {
        stalled.abort();
    }
    let after = pprev_notary::unix_now();

    Ok(Run {
        layout: env.layout,
        notarized,
        report,
        stats,
        ca_der: env.ca_der,
        sent_log: env.registry.registry.sent_log(),
        notary_clock: (before, after),
        token: env.setup.token.clone(),
    })
}

/// Runs `notarize_once` on a fresh runtime; for synchronous tests that share one session.
pub fn notarize_blocking(account: (&str, &str), property_id: &str) -> Run {
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(notarize_once(account, property_id))
        .expect("notarisation")
}
