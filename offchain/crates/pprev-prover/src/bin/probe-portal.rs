//! Notarised sessions against public pages of production servers, without login or account:
//! `probe-portal --out <record.json> https://host/path ...`. See `pprev_prover::probe`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use pprev_prover::probe::{ProbeTarget, USER_AGENT, probe};

#[derive(Parser)]
struct Args {
    /// Public HTTPS URLs (no credentials, no query with personal data).
    #[arg(required = true)]
    urls: Vec<String>,
    /// Bytes added to the plain response's length for max_recv_data.
    #[arg(long, default_value_t = 2048)]
    margin: usize,
    /// Largest max_recv_data the probe uses.
    #[arg(long, default_value_t = 65536)]
    max_recv_cap: usize,
    #[arg(long, default_value_t = 180)]
    timeout_secs: u64,
    #[arg(long)]
    out: PathBuf,
}

fn target(url: &str) -> Result<ProbeTarget> {
    let rest = url.strip_prefix("https://").context("only https:// URLs")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    ensure!(
        !host.contains(['@', ':']),
        "{url}: no credentials or explicit port"
    );
    Ok(ProbeTarget {
        host: host.to_string(),
        path: path.to_string(),
        port: 443,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let mut records = Vec::new();
    for url in &args.urls {
        let target = target(url)?;
        eprintln!("probing {}{}", target.host, target.path);
        let record = probe(
            &target,
            args.margin,
            args.max_recv_cap,
            Duration::from_secs(args.timeout_secs),
        )
        .await;
        eprintln!(
            "  {}",
            match (&record.notarised, &record.error) {
                (Some(n), _) => format!(
                    "notarised: {} bytes, {:.0} ms MPC-TLS, presentation verified",
                    n.received_bytes, n.mpc_tls_ms
                ),
                (None, Some(e)) => format!("failed: {e}"),
                (None, None) => "no result".into(),
            }
        );
        records.push(record);
    }
    let out = serde_json::json!({
        "userAgent": USER_AGENT,
        "unixTime": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        "probes": records,
    });
    std::fs::write(&args.out, serde_json::to_string_pretty(&out)? + "\n")
        .with_context(|| format!("writing {}", args.out.display()))?;
    Ok(())
}
