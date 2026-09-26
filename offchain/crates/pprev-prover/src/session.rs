//! Prover side of the MPC-TLS session, commitments, attestation request, and presentation.

use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use pprev_types::{Layout, ResponseRanges};
use tlsn::Session;
use tlsn::attestation::presentation::Presentation;
use tlsn::attestation::request::{Request as AttestationRequest, RequestConfig};
use tlsn::attestation::{Attestation, CryptoProvider, Secrets};
use tlsn::config::prove::ProveConfig;
use tlsn::config::prover::ProverConfig;
use tlsn::config::tls::TlsClientConfig;
use tlsn::config::tls_commit::mpc::MpcTlsConfig;
use tlsn::connection::{HandshakeData, ServerName};
use tlsn::hash::HashAlgId;
use tlsn::prover::ProverOutput;
use tlsn::rangeset::set::RangeSet;
use tlsn::transcript::{
    Direction, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind, TranscriptSecret,
};
use tlsn::webpki::{CertificateDer, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Owns the session driver task and aborts it if the session ends early, so that the peer sees the
/// connection close instead of waiting on it.
struct DriverGuard<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> DriverGuard<T> {
    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        self.0.take().expect("driver joined once").await
    }

    fn running(&mut self) -> &mut tokio::task::JoinHandle<T> {
        self.0.as_mut().expect("driver not joined")
    }
}

impl<T> Drop for DriverGuard<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

const SHA256: TranscriptCommitmentKind = TranscriptCommitmentKind::Hash {
    alg: HashAlgId::SHA256,
};

/// Default bound on MPC-TLS preprocessing (D33).
pub const DEFAULT_PREPROCESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of retries after a stalled preprocessing (D33).
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// MPC-TLS preprocessing did not complete: the prover's timeout fired, or the notary closed the
/// session before preprocessing finished. tlsn 0.1.0-alpha.15 deadlocks there intermittently
/// (tlsnotary/tlsn#1173); a new session usually succeeds, so this is the one retried failure.
#[derive(Debug)]
pub struct PreprocessingStalled(pub String);

impl std::fmt::Display for PreprocessingStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MPC-TLS preprocessing stalled: {}", self.0)
    }
}

impl std::error::Error for PreprocessingStalled {}

/// Attempts one notarisation took (D33). Failed attempts are logged and listed, and are not part
/// of any timing.
#[derive(Clone, Debug, Default)]
pub struct NotarizeStats {
    pub attempts: u32,
    /// Why each abandoned attempt was abandoned, in order.
    pub stalls: Vec<String>,
}

/// Everything the prover needs for one notarised request.
#[derive(Clone)]
pub struct ProverSetup {
    pub layout: Layout,
    pub registry_addr: SocketAddr,
    /// Roots trusted for the registry certificate.
    pub root_certs: Vec<Vec<u8>>,
    /// Bearer token from [`crate::login`].
    pub token: String,
    pub property_id: String,
    /// MPC-TLS preprocessing limits; they bound the request and response sizes.
    pub max_sent: usize,
    pub max_recv: usize,
    /// Bound on MPC-TLS preprocessing before the attempt counts as stalled (D33).
    pub preprocess_timeout: Duration,
}

/// Plaintext and blinder of one hidden commitment (D3). SHA-256(plaintext || blinder) is the hash
/// that the attestation records; the circuit opens it privately.
#[derive(Clone)]
pub struct FieldOpening {
    pub range: Range<usize>,
    pub plaintext: Vec<u8>,
    pub blinder: [u8; 16],
}

/// Openings of the three hidden fields, in layout order.
#[derive(Clone)]
pub struct HiddenOpenings {
    pub account: FieldOpening,
    pub owners: FieldOpening,
    pub property_id: FieldOpening,
}

/// A completed notarisation.
pub struct Notarized {
    pub attestation: Attestation,
    pub secrets: Secrets,
    pub openings: HiddenOpenings,
    pub request_line_len: usize,
    pub ranges: ResponseRanges,
}

/// Runs the prover's half of one MPC-TLS session with the notary on `notary`, sends the title
/// request, commits to the layout's ranges, and returns the attestation with its secrets.
pub async fn notarize<S>(notary: S, setup: &ProverSetup) -> Result<Notarized>
where
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    let ranges = setup.layout.ranges()?;
    let request_line = setup.layout.request_line(&setup.property_id);

    let session = Session::new(notary.compat());
    let (driver, mut handle) = session.split();
    let mut driver_task = DriverGuard(Some(tokio::spawn(driver)));

    // tlsn 0.1.0-alpha.15 does not fail the MPC-TLS leader when the notary closes the session, for
    // example after rejecting the handshake time; the session driver ending first is that failure.
    let preprocessed = AtomicBool::new(false);
    let (request, secrets, openings) = tokio::select! {
        result = run_mpc(&mut handle, setup, &ranges, &request_line, &preprocessed) => result?,
        ended = driver_task.running() => {
            let reason = match ended {
                Ok(Ok(_)) => "connection closed".to_string(),
                Ok(Err(e)) => format!("{e:#}"),
                Err(e) => format!("{e:#}"),
            };
            if !preprocessed.load(Ordering::SeqCst) {
                return Err(PreprocessingStalled(format!("the notary closed the session: {reason}")).into());
            }
            anyhow::bail!("the notary closed the session before notarisation completed: {reason}");
        }
    };

    handle.close();
    let mut socket = driver_task.join().await??;
    socket.write_all(&bincode::serialize(&request)?).await?;
    socket.close().await?;
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;
    request.validate(&attestation, &CryptoProvider::default())?;

    Ok(Notarized {
        attestation,
        secrets,
        openings,
        request_line_len: request_line.len(),
        ranges,
    })
}

/// MPC-TLS part of a notarisation: preprocessing, the TLS session with the registry, the title
/// request, commitments, and the attestation request.
async fn run_mpc(
    handle: &mut tlsn::SessionHandle,
    setup: &ProverSetup,
    ranges: &ResponseRanges,
    request_line: &str,
    preprocessed: &AtomicBool,
) -> Result<(AttestationRequest, Secrets, HiddenOpenings)> {
    let preprocessing = handle.new_prover(ProverConfig::builder().build()?)?.commit(
        MpcTlsConfig::builder()
            .max_sent_data(setup.max_sent)
            .max_recv_data(setup.max_recv)
            .build()?,
    );
    let prover = tokio::time::timeout(setup.preprocess_timeout, preprocessing)
        .await
        .map_err(|_| {
            PreprocessingStalled(format!(
                "did not finish within {:?}",
                setup.preprocess_timeout
            ))
        })??;
    preprocessed.store(true, Ordering::SeqCst);

    let server_name = ServerName::Dns(setup.layout.server_name.as_str().try_into()?);
    let tcp = tokio::net::TcpStream::connect(setup.registry_addr).await?;
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(server_name.clone())
            .root_store(RootCertStore {
                roots: setup
                    .root_certs
                    .iter()
                    .map(|der| CertificateDer(der.clone()))
                    .collect(),
            })
            .build()?,
        tcp.compat(),
    )?;
    let mut prover_task = tokio::spawn(prover.into_future());

    let request = Request::builder()
        .method("GET")
        .uri(setup.layout.path(&setup.property_id))
        .header("Host", &setup.layout.server_name)
        .header("Authorization", format!("Bearer {}", setup.token))
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())?;
    let exchange = async {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat())).await?;
        tokio::spawn(connection);
        let response = sender.send_request(request).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "registry answered {}",
            response.status()
        );
        response.into_body().collect().await?;
        anyhow::Ok(())
    };
    // If the MPC-TLS session fails (for example, the notary rejects the handshake), the HTTP exchange
    // would wait on a connection that never closes; the prover task ending first is the failure.
    tokio::select! {
        result = exchange => result?,
        ended = &mut prover_task => {
            return Err(match ended {
                Ok(Ok(_)) => anyhow::anyhow!("MPC-TLS connection closed before the response"),
                Ok(Err(e)) => anyhow::Error::new(e).context("MPC-TLS session failed"),
                Err(e) => anyhow::Error::new(e).context("prover task failed"),
            });
        }
    }

    let mut prover = prover_task.await??;

    // The transcript must follow the layout before anything is committed.
    let transcript = prover.transcript();
    ensure!(
        transcript
            .sent()
            .starts_with(format!("{request_line}\r\n").as_bytes()),
        "request does not start with {request_line:?}"
    );
    ensure!(
        transcript.received().len() == ranges.len,
        "response has {} bytes, the layout has {}",
        transcript.received().len(),
        ranges.len
    );

    // D3 and D26: the request line and the response structure are committed to be opened; the three
    // field values are committed and stay hidden.
    let mut builder = TranscriptCommitConfig::builder(transcript);
    builder.default_kind(SHA256);
    builder.commit_sent(&(0..request_line.len()))?;
    builder.commit_recv(RangeSet::from(ranges.revealed()))?;
    for r in ranges.hidden() {
        builder.commit_recv(&r)?;
    }
    let transcript_commit = builder.build()?;

    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(transcript_commit);
    let request_config = request_config.build()?;

    let mut prove_config = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_config.transcript_commit(config.clone());
    }
    let prove_config = prove_config.build()?;
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;
    let [account, owners, property_id] = ranges.hidden();
    let openings = HiddenOpenings {
        account: opening(&prover_transcript, &transcript_secrets, account)?,
        owners: opening(&prover_transcript, &transcript_secrets, owners)?,
        property_id: opening(&prover_transcript, &transcript_secrets, property_id)?,
    };

    let mut builder = AttestationRequest::builder(&request_config);
    builder
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
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (request, secrets) = builder.build(&CryptoProvider::default())?;
    Ok((request, secrets, openings))
}

/// Plaintext and blinder of the received-direction hash commitment to `range`.
fn opening(
    transcript: &Transcript,
    secrets: &[TranscriptSecret],
    range: Range<usize>,
) -> Result<FieldOpening> {
    let idx = RangeSet::from(range.clone());
    let blinder = secrets
        .iter()
        .find_map(|secret| match secret {
            TranscriptSecret::Hash(h) if h.direction == Direction::Received && h.idx == idx => {
                <[u8; 16]>::try_from(h.blinder.as_bytes()).ok()
            }
            _ => None,
        })
        .with_context(|| format!("no hash commitment secret for {range:?}"))?;
    Ok(FieldOpening {
        plaintext: transcript.received()[range.clone()].to_vec(),
        range,
        blinder,
    })
}

/// Runs [`notarize`] on a new notary connection from `connect` until it succeeds, retrying at most
/// `max_retries` times when preprocessing stalls (D33). Every other failure is returned at once.
pub async fn notarize_with_retries<C, F, S>(
    mut connect: C,
    setup: &ProverSetup,
    max_retries: u32,
) -> Result<(Notarized, NotarizeStats)>
where
    C: FnMut(u32) -> F,
    F: Future<Output = Result<S>>,
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    let mut stats = NotarizeStats::default();
    loop {
        stats.attempts += 1;
        let notary = connect(stats.attempts).await?;
        match notarize(notary, setup).await {
            Ok(notarized) => return Ok((notarized, stats)),
            Err(e) if e.downcast_ref::<PreprocessingStalled>().is_some() => {
                let reason = format!("{e:#}");
                stats.stalls.push(reason.clone());
                if stats.attempts > max_retries {
                    anyhow::bail!(
                        "preprocessing stalled on all {} attempts: {}",
                        stats.attempts,
                        stats.stalls.join("; ")
                    );
                }
                tracing::warn!(
                    attempt = stats.attempts,
                    max_retries,
                    %reason,
                    "retrying with a new MPC-TLS session (tlsnotary/tlsn#1173)"
                );
            }
            Err(e) => {
                return Err(e.context(format!("notarisation failed on attempt {}", stats.attempts)));
            }
        }
    }
}

/// Builds the presentation for the policy verifier (D26): server identity, the request line, and the
/// response structure. The field values stay hidden unless `reveal_hidden` is set, which only the
/// gate test G2 uses.
pub fn present(notarized: &Notarized, reveal_hidden: bool) -> Result<Presentation> {
    let mut builder = notarized.secrets.transcript_proof_builder();
    builder.commitment_kinds(&[SHA256]);
    builder.reveal_sent(&(0..notarized.request_line_len))?;
    builder.reveal_recv(RangeSet::from(notarized.ranges.revealed()))?;
    if reveal_hidden {
        for r in notarized.ranges.hidden() {
            builder.reveal_recv(&r)?;
        }
    }
    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut presentation = notarized.attestation.presentation_builder(&provider);
    presentation
        .identity_proof(notarized.secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(presentation.build()?)
}
