//! Calibrates `netem-proxy`: starts an echo server, runs the proxy configuration in-process in
//! front of it (or connects directly with `--direct`, the baseline), and measures the round-trip
//! time of one-byte messages and the goodput of a one-way bulk transfer. Prints one JSON object
//! with every sample.
//!
//! `netem-calibrate [--direct] --rtt-ms R [--mbps M] [--pings N] [--bulk-mib S]`

use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use pprev_prover::netem::{LinkParams, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
struct Args {
    /// Connect to the echo server directly, without the proxy: the baseline of the machine.
    #[arg(long)]
    direct: bool,
    #[arg(long, default_value_t = 0.0)]
    rtt_ms: f64,
    #[arg(long)]
    mbps: Option<f64>,
    #[arg(long, default_value_t = 50)]
    pings: usize,
    /// Size of the bulk transfer, in MiB.
    #[arg(long, default_value_t = 32)]
    bulk_mib: u64,
    #[arg(long, default_value_t = 16 << 20)]
    queue_bytes: usize,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

#[tokio::main]
async fn main() -> Result<()> {
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
    anyhow::ensure!(args.pings >= 1, "at least one ping");
    anyhow::ensure!(
        args.bulk_mib >= 1,
        "the bulk transfer must be at least 1 MiB"
    );
    // Echo server: returns every byte; a bulk transfer is acknowledged with one byte at its end.
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = s.set_nodelay(true);
                let mut mode = [0u8; 1];
                if s.read_exact(&mut mode).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; 64 * 1024];
                if mode[0] == b'p' {
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                } else {
                    let mut len = [0u8; 8];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut left = u64::from_be_bytes(len);
                    while left > 0 {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => left -= n as u64,
                        }
                    }
                    let _ = s.write_all(b"k").await;
                }
            });
        }
    });
    let params = LinkParams {
        delay: Duration::from_secs_f64(args.rtt_ms / 2000.0),
        bits_per_sec: args.mbps.map(|m| (m * 1e6).round() as u64),
        queue_bytes: args.queue_bytes,
    };
    let proxy_addr = if args.direct {
        echo_addr
    } else {
        pprev_prover::netem::validate(&params)?;
        let proxy = TcpListener::bind("127.0.0.1:0").await?;
        let addr = proxy.local_addr()?;
        tokio::spawn(serve(proxy, echo_addr, params, params));
        addr
    };

    // Ping-pong: one byte each way, after the connection is up.
    let mut s = TcpStream::connect(proxy_addr).await?;
    s.set_nodelay(true)?;
    s.write_all(b"p").await?;
    let mut rtts = Vec::with_capacity(args.pings);
    let mut b = [0u8; 1];
    for _ in 0..args.pings {
        let t = Instant::now();
        s.write_all(b"x").await?;
        s.read_exact(&mut b).await?;
        rtts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    drop(s);

    // Bulk: S MB in one direction only (client to echo server), timed until the one-byte
    // acknowledgement.
    let bytes = args.bulk_mib << 20;
    let mut s = TcpStream::connect(proxy_addr).await?;
    s.set_nodelay(true)?;
    s.write_all(b"b").await?;
    s.write_all(&bytes.to_be_bytes()).await?;
    let chunk = vec![0x5au8; 64 * 1024];
    let t = Instant::now();
    let mut sent = 0u64;
    while sent < bytes {
        let n = chunk.len().min((bytes - sent) as usize);
        s.write_all(&chunk[..n]).await?;
        sent += n as u64;
    }
    s.read_exact(&mut b).await?;
    let bulk_s = t.elapsed().as_secs_f64();
    let rtt_median = median(rtts.clone());
    // Goodput over the whole timed interval, and an estimate that removes the one measured round
    // trip of the acknowledgement (the measured median, not the target).
    let goodput_mbps = bytes as f64 * 8.0 / bulk_s / 1e6;
    let corrected_s = bulk_s - rtt_median / 1000.0;
    let corrected_mbps = (corrected_s > 0.0).then(|| bytes as f64 * 8.0 / corrected_s / 1e6);

    println!(
        "{}",
        serde_json::json!({
            "mode": if args.direct { "direct" } else { "proxy" },
            "targetRttMs": args.rtt_ms,
            "targetMbps": args.mbps,
            "pings": args.pings,
            "rttMs": {
                "median": rtt_median,
                "min": rtts.iter().cloned().fold(f64::MAX, f64::min),
                "max": rtts.iter().cloned().fold(0.0, f64::max),
                "samples": rtts,
            },
            "bulkBytes": bytes,
            "bulkDirection": "one way, client to server",
            "queueBytes": args.queue_bytes,
            "bulkSeconds": bulk_s,
            "goodputMbps": goodput_mbps,
            "goodputMbpsWithoutAckRtt": corrected_mbps,
        })
    );
    Ok(())
}
