//! Byte counts of a connection, for the traffic between prover and notary in an MPC-TLS session.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bytes written to and read from a [`CountingStream`], readable while the stream is in use.
#[derive(Clone, Debug, Default)]
pub struct ByteCounts {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Traffic {
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

impl ByteCounts {
    pub fn traffic(&self) -> Traffic {
        Traffic {
            sent_bytes: self.sent.load(Ordering::Relaxed),
            received_bytes: self.received.load(Ordering::Relaxed),
        }
    }
}

/// Wraps a stream and counts the bytes that pass through it.
pub struct CountingStream<S> {
    inner: S,
    counts: ByteCounts,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S) -> (Self, ByteCounts) {
        let counts = ByteCounts::default();
        (Self::with_counts(inner, counts.clone()), counts)
    }

    /// Counts into `counts`, which the caller created before the stream existed.
    pub fn with_counts(inner: S, counts: ByteCounts) -> Self {
        Self { inner, counts }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        self.counts.received.fetch_add(read, Ordering::Relaxed);
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.counts.sent.fetch_add(*n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn counts_both_directions() {
        let (a, mut b) = tokio::io::duplex(64);
        let (mut a, counts) = CountingStream::new(a);
        a.write_all(b"hello").await.unwrap();
        b.write_all(b"world!!").await.unwrap();
        let mut buf = [0u8; 7];
        a.read_exact(&mut buf).await.unwrap();
        let mut got = [0u8; 5];
        b.read_exact(&mut got).await.unwrap();
        let t = counts.traffic();
        assert_eq!((t.sent_bytes, t.received_bytes), (5, 7));
    }
}
