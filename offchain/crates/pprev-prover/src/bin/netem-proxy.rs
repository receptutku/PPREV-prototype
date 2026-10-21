//! TCP proxy with an emulated link: `netem-proxy --listen A --upstream B --rtt-ms R [--mbps M]`.
//! The one-way delay is half the round-trip time in each direction; the bandwidth, when given,
//! applies to each direction separately. See `pprev_prover::netem`.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use pprev_prover::netem::{LinkParams, serve_logged};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long)]
    upstream: SocketAddr,
    /// Round-trip propagation delay, in milliseconds (half in each direction).
    #[arg(long, default_value_t = 0.0)]
    rtt_ms: f64,
    /// Bandwidth of each direction, in megabits per second; unlimited when absent.
    #[arg(long)]
    mbps: Option<f64>,
    /// Append one JSON line per ended connection (duration, bytes each way, outcome) to this file.
    #[arg(long)]
    log: Option<std::path::PathBuf>,
    /// Bound on the bytes queued per direction.
    #[arg(long, default_value_t = 16 << 20)]
    queue_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    anyhow::ensure!(
        args.rtt_ms.is_finite() && args.rtt_ms >= 0.0,
        "the round-trip time must be finite and non-negative"
    );
    if let Some(m) = args.mbps {
        anyhow::ensure!(
            m.is_finite() && m > 0.0,
            "the bandwidth must be finite and positive"
        );
    }
    let log = args
        .log
        .as_ref()
        .map(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map(|f| std::sync::Arc::new(std::sync::Mutex::new(f)))
        })
        .transpose()?;
    let params = LinkParams {
        delay: Duration::from_secs_f64(args.rtt_ms / 2000.0),
        bits_per_sec: args.mbps.map(|m| (m * 1e6).round() as u64),
        queue_bytes: args.queue_bytes,
    };
    let listener = TcpListener::bind(args.listen).await?;
    println!(
        "netem-proxy {} -> {} (rtt {} ms, {} per direction)",
        listener.local_addr()?,
        args.upstream,
        args.rtt_ms,
        args.mbps
            .map_or("unlimited".into(), |m| format!("{m} Mbit/s"))
    );
    serve_logged(listener, args.upstream, params, params, log).await
}
