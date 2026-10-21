//! An emulated network link for the network-conditions experiment: a TCP proxy whose two directions
//! are each a delay line with a fixed one-way propagation delay and a bandwidth.
//!
//! Each direction serialises the bytes it reads at the link's bandwidth, one after another, and
//! delivers each chunk the propagation delay after its last byte left: chunks in flight travel
//! together, in order, as on a pipe (not a sleep per chunk, which would serialise the delay too).
//! The bytes queued in a direction are bounded, so a sender that outruns the link is held back by
//! TCP flow control on its side of the proxy. The link loses, reorders, and corrupts nothing; it
//! models neither jitter nor congestion.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;

/// One direction of the link.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkParams {
    /// One-way propagation delay.
    pub delay: Duration,
    /// Bandwidth in bits per second; `None` is unlimited.
    pub bits_per_sec: Option<u64>,
    /// Bound on the bytes queued in the direction (read from the sender, not yet delivered).
    pub queue_bytes: usize,
}

impl LinkParams {
    /// Time to put `bytes` on the link.
    pub fn serialisation(&self, bytes: usize) -> Duration {
        match self.bits_per_sec {
            Some(bps) => Duration::from_secs_f64(bytes as f64 * 8.0 / bps as f64),
            None => Duration::ZERO,
        }
    }
}

/// Delivery schedule of one direction: when each chunk arrives at the far side.
#[derive(Debug)]
pub struct Schedule {
    params: LinkParams,
    /// When the link finishes serialising what it holds.
    link_free_at: Option<Instant>,
}

impl Schedule {
    pub fn new(params: LinkParams) -> Self {
        Self {
            params,
            link_free_at: None,
        }
    }

    /// Delivery time of a chunk of `bytes` that the proxy read at `now`.
    pub fn deliver_at(&mut self, now: Instant, bytes: usize) -> Instant {
        let start = match self.link_free_at {
            Some(free) if free > now => free,
            _ => now,
        };
        let sent = start + self.params.serialisation(bytes);
        self.link_free_at = Some(sent);
        sent + self.params.delay
    }
}

/// Chunks a direction has read and not yet delivered, with their delivery times.
type Queue = Arc<Mutex<VecDeque<(Instant, Vec<u8>)>>>;

/// Largest chunk read at once.
const CHUNK: usize = 16 * 1024;

/// Forwards `from` to `to` through one direction of the link. The reader and the writer run as one
/// future: when either fails, the other is dropped, so no part of a direction outlives it.
async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    params: LinkParams,
    delivered: &std::sync::atomic::AtomicU64,
) -> Result<()> {
    let queue: Queue = Arc::default();
    let ready = Notify::new();
    let room = Semaphore::new(params.queue_bytes);
    let writer = async {
        loop {
            let next = queue.lock().expect("queue").pop_front();
            match next {
                Some((at, bytes)) => {
                    // A sleep rounds up to the timer's resolution; skip it when already due.
                    if at > Instant::now() {
                        tokio::time::sleep_until(at).await;
                    }
                    if bytes.is_empty() {
                        to.shutdown().await?;
                        return anyhow::Ok(());
                    }
                    to.write_all(&bytes).await?;
                    delivered.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    room.add_permits(bytes.len());
                }
                None => ready.notified().await,
            }
        }
    };
    let reader = async {
        let mut schedule = Schedule::new(params);
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = from.read(&mut buf).await?;
            if n == 0 {
                // End of stream travels behind the last chunk.
                let at = schedule.deliver_at(Instant::now(), 0);
                queue.lock().expect("queue").push_back((at, Vec::new()));
                ready.notify_one();
                return anyhow::Ok(());
            }
            room.acquire_many(n as u32).await?.forget();
            let at = schedule.deliver_at(Instant::now(), n);
            queue
                .lock()
                .expect("queue")
                .push_back((at, buf[..n].to_vec()));
            ready.notify_one();
        }
    };
    tokio::try_join!(reader, writer)?;
    Ok(())
}

/// Checks a link's parameters: a positive bandwidth when one is set, and a queue that holds at
/// least one chunk.
pub fn validate(params: &LinkParams) -> Result<()> {
    anyhow::ensure!(
        params.bits_per_sec != Some(0),
        "the bandwidth must be positive"
    );
    anyhow::ensure!(
        (CHUNK..=1 << 30).contains(&params.queue_bytes),
        "the queue must hold between {CHUNK} bytes and 1 GiB"
    );
    Ok(())
}

/// Bytes one proxied connection delivered in each direction.
#[derive(Debug, Default)]
pub struct Counters {
    pub forward: std::sync::atomic::AtomicU64,
    pub reverse: std::sync::atomic::AtomicU64,
}

/// Proxies one connection: both directions until each has ended. A direction that ends normally
/// (half-close) leaves the other running; an error in either ends both.
pub async fn proxy_connection(
    client: TcpStream,
    upstream: SocketAddr,
    forward: LinkParams,
    reverse: LinkParams,
) -> Result<()> {
    proxy_connection_counted(client, upstream, forward, reverse, &Counters::default()).await
}

/// As [`proxy_connection`], counting the bytes delivered in each direction.
pub async fn proxy_connection_counted(
    client: TcpStream,
    upstream: SocketAddr,
    forward: LinkParams,
    reverse: LinkParams,
    counters: &Counters,
) -> Result<()> {
    client.set_nodelay(true)?;
    let server = TcpStream::connect(upstream).await?;
    server.set_nodelay(true)?;
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();
    tokio::try_join!(
        pump(client_read, server_write, forward, &counters.forward),
        pump(server_read, client_write, reverse, &counters.reverse)
    )?;
    Ok(())
}

/// Runs the proxy: every connection to `listener` is forwarded to `upstream`, with `forward` applied
/// to the client's bytes and `reverse` to the upstream's. Each connection gets its own link, with
/// the full bandwidth in each direction; the experiment's MPC-TLS session uses one connection.
pub async fn serve(
    listener: TcpListener,
    upstream: SocketAddr,
    forward: LinkParams,
    reverse: LinkParams,
) -> Result<()> {
    serve_logged(listener, upstream, forward, reverse, None).await
}

/// As [`serve`], appending one JSON line per ended connection to `log`: start time, duration,
/// bytes delivered in each direction, and how it ended.
pub async fn serve_logged(
    listener: TcpListener,
    upstream: SocketAddr,
    forward: LinkParams,
    reverse: LinkParams,
    log: Option<Arc<Mutex<std::fs::File>>>,
) -> Result<()> {
    validate(&forward)?;
    validate(&reverse)?;
    // The connections belong to this future: dropping it (for example when the experiment stops
    // the proxy) aborts every connection still open.
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let client = tokio::select! {
            accepted = listener.accept() => accepted?.0,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let log = log.clone();
        connections.spawn(async move {
            let started = Instant::now();
            let start_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis());
            let counters = Counters::default();
            let result =
                proxy_connection_counted(client, upstream, forward, reverse, &counters).await;
            if let Err(e) = &result {
                tracing::debug!("proxied connection ended: {e:#}");
            }
            if let Some(log) = log {
                use std::io::Write;
                use std::sync::atomic::Ordering::Relaxed;
                let line = serde_json::json!({
                    "startUnixMs": start_unix_ms,
                    "durationMs": started.elapsed().as_secs_f64() * 1000.0,
                    "forwardBytes": counters.forward.load(Relaxed),
                    "reverseBytes": counters.reverse.load(Relaxed),
                    "outcome": match &result { Ok(()) => "closed".to_string(), Err(e) => format!("error: {e:#}") },
                });
                let _ = writeln!(log.lock().expect("log"), "{line}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(delay_ms: u64, mbps: Option<u64>) -> LinkParams {
        LinkParams {
            delay: Duration::from_millis(delay_ms),
            bits_per_sec: mbps.map(|m| m * 1_000_000),
            queue_bytes: 1 << 20,
        }
    }

    #[test]
    fn chunks_in_flight_share_the_delay() {
        let t0 = Instant::now();
        let mut s = Schedule::new(params(50, None));
        // Without a bandwidth limit, back-to-back chunks all arrive one delay after they were read.
        assert_eq!(s.deliver_at(t0, 1000), t0 + Duration::from_millis(50));
        assert_eq!(
            s.deliver_at(t0 + Duration::from_millis(1), 1000),
            t0 + Duration::from_millis(51)
        );
    }

    #[test]
    fn bandwidth_serialises_back_to_back_chunks() {
        let t0 = Instant::now();
        // 8 Mbit/s: 1,000 bytes take 1 ms.
        let mut s = Schedule::new(params(10, Some(8)));
        assert_eq!(s.deliver_at(t0, 1000), t0 + Duration::from_millis(11));
        // Read at the same instant: waits for the first to leave, then 1 ms more.
        assert_eq!(s.deliver_at(t0, 1000), t0 + Duration::from_millis(12));
        // Read after the link went idle: starts at once.
        let later = t0 + Duration::from_millis(100);
        assert_eq!(s.deliver_at(later, 1000), later + Duration::from_millis(11));
    }

    #[test]
    fn parameters_are_validated() {
        assert!(validate(&params(0, Some(1))).is_ok());
        let mut p = params(0, None);
        p.bits_per_sec = Some(0);
        assert!(validate(&p).is_err());
        p = params(0, None);
        p.queue_bytes = 1;
        assert!(validate(&p).is_err());
        p.queue_bytes = 2 << 30;
        assert!(validate(&p).is_err());
    }

    async fn through_proxy<F, Fut>(
        link: LinkParams,
        server: F,
    ) -> (TcpStream, tokio::task::JoinHandle<Result<()>>)
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = upstream.accept().await.unwrap();
            server(s).await;
        });
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (c, _) = front.accept().await?;
            proxy_connection(c, upstream_addr, link, link).await
        });
        (TcpStream::connect(front_addr).await.unwrap(), proxy)
    }

    #[tokio::test]
    async fn a_half_close_keeps_the_other_direction_open() {
        let (mut client, proxy) = through_proxy(params(10, None), |mut s| async move {
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"hello");
            s.write_all(b"world").await.unwrap();
        })
        .await;
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut back = Vec::new();
        client.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"world");
        tokio::time::timeout(Duration::from_secs(5), proxy)
            .await
            .expect("the proxy ends")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn an_early_downstream_close_with_a_full_queue_ends_the_connection() {
        let mut link = params(5, Some(8));
        link.queue_bytes = CHUNK;
        let (full_tx, full_rx) = tokio::sync::oneshot::channel::<()>();
        // The upstream reads nothing until the client is blocked, then closes.
        let (mut client, proxy) = through_proxy(link, |s| async move {
            let _ = full_rx.await;
            drop(s);
        })
        .await;
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let writer = {
            let written = written.clone();
            tokio::spawn(async move {
                let chunk = vec![0u8; 64 * 1024];
                loop {
                    if client.write_all(&chunk).await.is_err() {
                        return;
                    }
                    written.fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };
        // Wait until the client's writes stall (no progress over 500 ms): the proxy's queue and
        // both socket buffers are full.
        let mut last = u64::MAX;
        let mut stalled = 0;
        while stalled < 5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = written.load(std::sync::atomic::Ordering::Relaxed);
            stalled = if now == last { stalled + 1 } else { 0 };
            last = now;
        }
        assert!(!writer.is_finished(), "the client stopped writing");
        assert!(
            last > CHUNK as u64,
            "the client wrote less than the queue holds"
        );
        full_tx.send(()).unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(10), proxy)
            .await
            .expect("the proxied connection did not end");
        // The connection ends with an error (the upstream is gone), not with a panic.
        assert!(ended.expect("the proxy task panicked").is_err());
        writer.abort();
    }

    #[tokio::test]
    async fn dropping_the_server_aborts_open_connections() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut sink = Vec::new();
            // Ends when the proxy drops its side of the connection.
            let _ = s.read_to_end(&mut sink).await;
            let _ = seen_tx.send(());
        });
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let server = tokio::spawn(serve(
            front,
            upstream_addr,
            params(5, None),
            params(5, None),
        ));
        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"open").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        server.abort();
        tokio::time::timeout(Duration::from_secs(5), seen_rx)
            .await
            .expect("the open connection outlived the server")
            .unwrap();
        drop(client);
    }

    #[tokio::test]
    async fn a_client_disconnect_ends_the_connection() {
        let (mut client, proxy) = through_proxy(params(5, None), |mut s| async move {
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink).await;
        })
        .await;
        client.write_all(&[1u8; 100_000]).await.unwrap();
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), proxy)
            .await
            .expect("the proxy ends")
            .unwrap()
            .ok();
    }

    #[test]
    fn total_time_of_a_bulk_transfer_is_size_over_bandwidth_plus_delay() {
        let t0 = Instant::now();
        let mut s = Schedule::new(params(30, Some(100)));
        let mut last = t0;
        for _ in 0..1000 {
            last = s.deliver_at(t0, 10_000);
        }
        // 10 MB at 100 Mbit/s is 0.8 s, plus 30 ms.
        let total = last - t0;
        assert!((total.as_secs_f64() - 0.83).abs() < 1e-6, "{total:?}");
    }
}
