//! A notarised session against a public HTTPS page of a production server (no login, no account).
//!
//! It is a transport experiment: whether TLSNotary's MPC mode completes against a production server
//! (TLS 1.2, ECDHE over P-256, AES-128-GCM, a certificate chain to a public root), how large the
//! response is against the session's `max_recv_data`, and whether repeated identical requests got
//! responses of the same length and bytes, and where they differed. Equal responses for these
//! requests say nothing general about layout stability, and differing ones do not rule out fixed
//! field offsets. The probe keeps no response content: the record holds lengths, positions of
//! differences, the status line, the Content-Type, and timings.
//!
//! The notary runs in the same process with a fixed, public attestation key and the Mozilla root
//! store, so the run is no evidence of an independent notary deployment. The prover commits to the
//! request line (revealed) and to the whole response (hidden), obtains an attestation, and checks a
//! presentation of it as the policy verifier would: attestation key, server identity, and t_att.
//! tlsn's API does not expose the negotiated cipher suite; its MPC mode offers only
//! `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_128_GCM_SHA256`, so a completed session used one of these.

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use pprev_notary::presentation::t_att_of;
use pprev_notary::{NotaryConfig, notarize as notary_session};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tlsn::Session;
use tlsn::attestation::request::{Request as AttestationRequest, RequestConfig};
use tlsn::attestation::signing::{Secp256k1Signer, Signer};
use tlsn::attestation::{Attestation, CryptoProvider};
use tlsn::config::prove::ProveConfig;
use tlsn::config::prover::ProverConfig;
use tlsn::config::tls::TlsClientConfig;
use tlsn::config::tls_commit::mpc::MpcTlsConfig;
use tlsn::connection::{HandshakeData, ServerName};
use tlsn::hash::HashAlgId;
use tlsn::prover::ProverOutput;
use tlsn::transcript::{TranscriptCommitConfig, TranscriptCommitmentKind};
use tlsn::verifier::ServerCertVerifier;
use tlsn::webpki::{CertificateDer, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// The probe's own notary key: the attestation it signs proves nothing beyond this run.
const PROBE_ATTESTATION_KEY: [u8; 32] = [0x70; 32];

/// User-Agent of every request, so that the server's operators can tell what sent it.
pub const USER_AGENT: &str = "pprev-probe/0.1 (research prototype; one request per run)";

const SHA256: TranscriptCommitmentKind = TranscriptCommitmentKind::Hash {
    alg: HashAlgId::SHA256,
};

/// The Mozilla root certificates (webpki-root-certs), as DER.
pub fn mozilla_roots() -> Vec<Vec<u8>> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|cert| cert.to_vec())
        .collect()
}

#[derive(Clone, Debug)]
pub struct ProbeTarget {
    pub host: String,
    pub path: String,
    pub port: u16,
}

/// A plain HTTPS response, reduced to what the record may hold.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observed {
    pub bytes: usize,
    pub status_line: String,
    pub content_type: Option<String>,
    /// SHA-256 of the full response, to compare two responses without keeping either.
    #[serde(skip)]
    pub digest: [u8; 32],
}

/// What one probe of a target recorded.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRecord {
    pub host: String,
    pub path: String,
    /// Two ordinary requests (rustls, outside MPC) before the notarised one.
    pub plain: Vec<Observed>,
    /// The two plain responses have the same length and the same bytes.
    pub plain_identical: bool,
    /// Where two responses of the same length differ, as positions only: no byte is kept.
    pub plain_difference: Option<Difference>,
    pub max_sent: usize,
    pub max_recv: usize,
    pub notarised: Option<Notarised>,
    pub error: Option<String>,
}

/// Positions at which two equally long responses differ.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Difference {
    /// Length of the head (status line and headers, through the blank line).
    pub head_bytes: usize,
    pub differing_bytes: usize,
    pub differing_in_head: usize,
    pub differing_in_body: usize,
    /// Maximal runs of differing bytes, as half-open byte ranges.
    pub runs: Vec<[usize; 2]>,
}

fn difference(a: &[u8], b: &[u8]) -> Option<Difference> {
    if a.len() != b.len() {
        return None;
    }
    let head_bytes = a
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(a.len(), |i| i + 4);
    let mut runs: Vec<[usize; 2]> = Vec::new();
    for i in (0..a.len()).filter(|&i| a[i] != b[i]) {
        match runs.last_mut() {
            Some(run) if run[1] == i => run[1] = i + 1,
            _ => runs.push([i, i + 1]),
        }
    }
    let differing_bytes: usize = runs.iter().map(|r| r[1] - r[0]).sum();
    let differing_in_head = runs
        .iter()
        .map(|r| r[1].min(head_bytes).saturating_sub(r[0]))
        .sum();
    Some(Difference {
        head_bytes,
        differing_bytes,
        differing_in_head,
        differing_in_body: differing_bytes - differing_in_head,
        runs,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Notarised {
    pub tls_version: String,
    /// Not exposed by tlsn's API; see the module documentation.
    pub cipher_suite: Option<String>,
    pub cert_chain_len: usize,
    pub sent_bytes: usize,
    pub received_bytes: usize,
    pub status_line: String,
    /// The notarised response has the length of the first plain one.
    pub same_length_as_plain: bool,
    /// The notarised response has the bytes of the first plain one.
    pub same_bytes_as_plain: bool,
    /// Where the notarised response differs from the first plain one, when equally long.
    pub difference_from_plain: Option<Difference>,
    pub mpc_tls_ms: f64,
    pub attestation_ms: f64,
    /// A presentation of the attestation verified against the Mozilla roots and the probe's
    /// attestation key, with the server identity of the target.
    pub presentation_verified: bool,
    pub t_att: u64,
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

/// The request bytes both paths send: the same line and headers.
fn request(target: &ProbeTarget) -> Result<Request<Empty<Bytes>>> {
    Ok(Request::builder()
        .method("GET")
        .uri(&target.path)
        .header("Host", &target.host)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())?)
}

fn request_line(target: &ProbeTarget) -> String {
    format!("GET {} HTTP/1.1", target.path)
}

/// The status line and Content-Type of raw response bytes.
fn observe(bytes: &[u8]) -> Observed {
    let head_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(bytes.len());
    let head = String::from_utf8_lossy(&bytes[..head_end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default().to_string();
    let content_type = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.trim().to_string());
    Observed {
        bytes: bytes.len(),
        status_line,
        content_type,
        digest: Sha256::digest(bytes).into(),
    }
}

/// One ordinary HTTPS request with rustls and the Mozilla roots; returns the raw response bytes,
/// failing above `cap` bytes.
async fn plain_fetch(target: &ProbeTarget, cap: usize) -> Result<Vec<u8>> {
    let mut roots = rustls::RootCertStore::empty();
    for der in mozilla_roots() {
        roots.add(rustls_pki_types::CertificateDer::from(der))?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls_pki_types::ServerName::try_from(target.host.clone())?,
            tcp,
        )
        .await?;
    let raw = format!(
        "{}\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        request_line(target),
        target.host
    );
    tls.write_all(raw.as_bytes()).await?;
    let mut out = Vec::new();
    // Servers often close without close_notify; the bytes read until then are the response.
    match (&mut tls).take(cap as u64 + 1).read_to_end(&mut out).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !out.is_empty() => {}
        Err(e) => return Err(e.into()),
    }
    ensure!(out.len() <= cap, "the response exceeds {cap} bytes");
    Ok(out)
}

/// Probes `target`: two plain requests, then one notarised request with `max_recv` set from the
/// plain response's length plus `margin`, capped at `max_recv_cap`.
pub async fn probe(
    target: &ProbeTarget,
    margin: usize,
    max_recv_cap: usize,
    timeout: Duration,
) -> ProbeRecord {
    let mut record = ProbeRecord {
        host: target.host.clone(),
        path: target.path.clone(),
        plain: Vec::new(),
        plain_identical: false,
        plain_difference: None,
        max_sent: 0,
        max_recv: 0,
        notarised: None,
        error: None,
    };
    let mut plain = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(timeout, plain_fetch(target, max_recv_cap)).await {
            Ok(Ok(bytes)) => {
                record.plain.push(observe(&bytes));
                plain.push(bytes);
            }
            Ok(Err(e)) => {
                record.error = Some(format!("plain request: {e:#}"));
                return record;
            }
            Err(_) => {
                record.error = Some(format!("plain request: no response within {timeout:?}"));
                return record;
            }
        }
    }
    record.plain_identical = record.plain[0].digest == record.plain[1].digest;
    record.plain_difference = difference(&plain[0], &plain[1]);
    let first = plain.swap_remove(0);
    record.max_sent = 1024;
    record.max_recv = first.len().saturating_add(margin);
    if record.max_recv > max_recv_cap {
        record.error = Some(format!(
            "the response has {} bytes; with the margin it exceeds the cap of {max_recv_cap}",
            first.len()
        ));
        return record;
    }
    match tokio::time::timeout(
        timeout,
        notarised_fetch(target, record.max_sent, record.max_recv),
    )
    .await
    {
        Ok(Ok((mut notarised, received))) => {
            notarised.same_length_as_plain = received.len() == first.len();
            notarised.same_bytes_as_plain = received == first;
            notarised.difference_from_plain = difference(&first, &received);
            record.notarised = Some(notarised);
        }
        Ok(Err(e)) => record.error = Some(format!("notarised request: {e:#}")),
        Err(_) => record.error = Some(format!("notarised request: no result within {timeout:?}")),
    }
    record
}

/// One notarised request with an in-process notary; returns the record and the received bytes,
/// which the caller compares and drops.
async fn notarised_fetch(
    target: &ProbeTarget,
    max_sent: usize,
    max_recv: usize,
) -> Result<(Notarised, Vec<u8>)> {
    let roots = mozilla_roots();
    let (notary_io, prover_io) = tokio::io::duplex(1 << 23);
    let notary_config = NotaryConfig::new(PROBE_ATTESTATION_KEY, roots.clone());
    let notary = tokio::spawn(async move { notary_session(notary_io, &notary_config).await });

    let started = Instant::now();
    let session = Session::new(prover_io.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(max_sent)
                .max_recv_data(max_recv)
                .build()?,
        )
        .await?;
    let server_name = ServerName::Dns(target.host.as_str().try_into()?);
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(server_name.clone())
            .root_store(RootCertStore {
                roots: roots
                    .iter()
                    .map(|der| CertificateDer(der.clone()))
                    .collect(),
            })
            .build()?,
        tcp.compat(),
    )?;
    let prover_task = tokio::spawn(prover.into_future());
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat())).await?;
    tokio::spawn(connection);
    let response = sender.send_request(request(target)?).await?;
    response.into_body().collect().await?;
    let mut prover = prover_task.await??;
    let mpc_tls_ms = millis(started);

    let attestation_started = Instant::now();
    let transcript = prover.transcript().clone();
    let line = request_line(target);
    ensure!(
        transcript
            .sent()
            .starts_with(format!("{line}\r\n").as_bytes()),
        "request does not start with {line:?}"
    );
    let received = transcript.received().to_vec();
    let mut builder = TranscriptCommitConfig::builder(&transcript);
    builder.default_kind(SHA256);
    builder.commit_sent(&(0..line.len()))?;
    builder.commit_recv(&(0..received.len()))?;
    let commit = builder.build()?;
    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(commit.clone());
    let request_config = request_config.build()?;
    let mut prove_config = ProveConfig::builder(&transcript);
    prove_config.transcript_commit(commit);
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config.build()?).await?;
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut attestation_request = AttestationRequest::builder(&request_config);
    attestation_request
        .server_name(server_name)
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("no server certificate chain")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("no server signature")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (attestation_request, secrets) = attestation_request.build(&CryptoProvider::default())?;
    handle.close();
    let mut socket = driver_task.await??;
    socket
        .write_all(&bincode::serialize(&attestation_request)?)
        .await?;
    socket.close().await?;
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await?;
    let attestation: Attestation = bincode::deserialize(&bytes)?;
    attestation_request.validate(&attestation, &CryptoProvider::default())?;
    notary.await??;
    let attestation_ms = millis(attestation_started);

    // The policy verifier's view: a presentation that reveals the request line only.
    let mut proof = secrets.transcript_proof_builder();
    proof.commitment_kinds(&[SHA256]);
    proof.reveal_sent(&(0..line.len()))?;
    let provider = CryptoProvider::default();
    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(proof.build()?);
    let presentation = presentation.build()?;
    ensure!(
        presentation.verifying_key()
            == &Secp256k1Signer::new(&PROBE_ATTESTATION_KEY)?.verifying_key(),
        "attestation key is not the probe's"
    );
    let output = presentation.verify(&CryptoProvider {
        cert: ServerCertVerifier::new(&RootCertStore {
            roots: roots
                .iter()
                .map(|der| CertificateDer(der.clone()))
                .collect(),
        })?,
        ..Default::default()
    })?;
    match &output.server_name {
        Some(ServerName::Dns(name)) if name.as_str() == target.host => {}
        other => bail!("server identity {other:?} is not {}", target.host),
    }

    let observed = observe(&received);
    Ok((
        Notarised {
            tls_version: format!("{:?}", tls_transcript.version()),
            cipher_suite: None,
            cert_chain_len: tls_transcript.server_cert_chain().map_or(0, |c| c.len()),
            sent_bytes: output.connection_info.transcript_length.sent as usize,
            received_bytes: received.len(),
            status_line: observed.status_line,
            same_length_as_plain: false,
            same_bytes_as_plain: false,
            difference_from_plain: None,
            mpc_tls_ms,
            attestation_ms,
            presentation_verified: true,
            t_att: t_att_of(&output)?,
        },
        received,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differences_are_positions_split_at_the_head() {
        let a = b"HTTP/1.1 200 OK\r\nDate: 1\r\n\r\nabcdef";
        let b = b"HTTP/1.1 200 OK\r\nDate: 2\r\n\r\nabXdeY";
        let d = difference(a, b).unwrap();
        assert_eq!(d.head_bytes, 28);
        assert_eq!(d.runs, vec![[23, 24], [30, 31], [33, 34]]);
        assert_eq!((d.differing_in_head, d.differing_in_body), (1, 2));
        assert!(difference(a, &b[1..]).is_none());
        assert_eq!(difference(a, a).unwrap().differing_bytes, 0);
    }
}
