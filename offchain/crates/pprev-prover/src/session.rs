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
use pprev_types::{Layout, ResponseRanges, ResponseShape};
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

/// Everything the prover needs for one notarised request of any layout: the exchange's shape.
#[derive(Clone)]
pub struct ShapeSetup {
    pub shape: ResponseShape,
    pub registry_addr: SocketAddr,
    /// Roots trusted for the registry certificate.
    pub root_certs: Vec<Vec<u8>>,
    /// Bearer token from [`crate::login`].
    pub token: String,
    /// MPC-TLS preprocessing limits; they bound the request and response sizes.
    pub max_sent: usize,
    pub max_recv: usize,
    /// Bound on MPC-TLS preprocessing before the attempt counts as stalled (D33).
    pub preprocess_timeout: Duration,
    /// Request an attestation signed with the Ethereum-compatible algorithm (secp256k1 over
    /// Keccak-256) and a Keccak-256 Merkle tree over its fields, which a contract can check; the
    /// notary must accept it. Otherwise tlsn's defaults (secp256k1 over SHA-256, BLAKE3).
    pub eth_attestation: bool,
}

impl ProverSetup {
    fn shape_setup(&self) -> Result<ShapeSetup> {
        Ok(ShapeSetup {
            shape: self.layout.shape(&self.property_id)?,
            registry_addr: self.registry_addr,
            root_certs: self.root_certs.clone(),
            token: self.token.clone(),
            max_sent: self.max_sent,
            max_recv: self.max_recv,
            preprocess_timeout: self.preprocess_timeout,
            eth_attestation: false,
        })
    }
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

/// A completed notarisation of any layout, with the openings of the hidden fields in the shape's
/// order.
pub struct NotarizedShape {
    pub attestation: Attestation,
    pub secrets: Secrets,
    pub openings: Vec<FieldOpening>,
    pub shape: ResponseShape,
    /// Openings of the two revealed commitments: the request line, and the response structure (the
    /// revealed ranges, concatenated in order). A verifier that checks the commitments itself, as
    /// the integrated on-chain baseline does, needs their blinders.
    pub request: CommittedOpening,
    pub structure: CommittedOpening,
}

/// Plaintext and blinder of one commitment to a set of ranges: SHA-256(plaintext || blinder).
#[derive(Clone, Debug)]
pub struct CommittedOpening {
    pub plaintext: Vec<u8>,
    pub blinder: [u8; 16],
}

/// Runs the prover's half of one MPC-TLS session with the notary on `notary`, sends the title
/// request, commits to the layout's ranges, and returns the attestation with its secrets.
pub async fn notarize<S>(notary: S, setup: &ProverSetup) -> Result<Notarized>
where
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    let ranges = setup.layout.ranges()?;
    let notarized = notarize_shape(notary, &setup.shape_setup()?).await?;
    let [account, owners, property_id]: [FieldOpening; 3] = notarized
        .openings
        .try_into()
        .map_err(|_| anyhow::anyhow!("the title layout has three hidden fields"))?;
    Ok(Notarized {
        attestation: notarized.attestation,
        secrets: notarized.secrets,
        openings: HiddenOpenings {
            account,
            owners,
            property_id,
        },
        request_line_len: notarized.shape.request_line.len(),
        ranges,
    })
}

/// Runs the prover's half of one MPC-TLS session for the exchange `setup.shape`: sends its request,
/// commits to its revealed and hidden ranges, and returns the attestation with its secrets.
pub async fn notarize_shape<S>(notary: S, setup: &ShapeSetup) -> Result<NotarizedShape>
where
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    let session = Session::new(notary.compat());
    let (driver, mut handle) = session.split();
    let mut driver_task = DriverGuard(Some(tokio::spawn(driver)));

    // tlsn 0.1.0-alpha.15 does not fail the MPC-TLS leader when the notary closes the session, for
    // example after rejecting the handshake time; the session driver ending first is that failure.
    // A cut during preprocessing shows either way, in either order: as the driver ending, or as
    // preprocessing failing. Before preprocessing completes nothing has reached the registry, so a
    // cut there is retried; see `decide` for what counts as one.
    let preprocessed = AtomicBool::new(false);
    let (request, secrets, (openings, request_opening, structure)) = {
        let mpc = run_mpc(&mut handle, setup, &preprocessed);
        tokio::pin!(mpc);
        tokio::select! {
            // A result that is ready wins over the driver's end, so a rejection is not lost.
            biased;
            result = &mut mpc => match result {
                Err(e) if !preprocessed.load(Ordering::SeqCst)
                    && e.downcast_ref::<PreprocessingStalled>().is_none() =>
                {
                    let failure = failure_of(&e);
                    let ended = match failure {
                        Failure::Lossy => tokio::time::timeout(CUT_GRACE, driver_task.running())
                            .await
                            .ok(),
                        Failure::Final | Failure::Closure => None,
                    };
                    return Err(decide(Some((e, failure)), ended.as_ref()));
                }
                result => result?,
            },
            ended = driver_task.running() => {
                return Err(after_driver_end(ended, &mut mpc, &preprocessed).await);
            }
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

    Ok(NotarizedShape {
        attestation,
        secrets,
        openings,
        shape: setup.shape.clone(),
        request: request_opening,
        structure,
    })
}

/// How long a failed preprocessing waits for the session driver to show whether the notary closed
/// the connection.
const CUT_GRACE: Duration = Duration::from_secs(2);

type DriverOutput<S> = Result<Result<S, tlsn::Error>, tokio::task::JoinError>;

/// The error of a session whose driver ended before the prover finished. Before preprocessing
/// completed, the prover's own failure, if it follows within CUT_GRACE, decides with the driver's
/// end (a hung leader leaves the driver alone); the phase is read again after that wait, since
/// preprocessing may complete during it. After preprocessing, the session is lost.
async fn after_driver_end<S, T, F>(
    ended: DriverOutput<S>,
    mpc: F,
    preprocessed: &AtomicBool,
) -> anyhow::Error
where
    F: Future<Output = Result<T>>,
{
    let lost = |ended: &DriverOutput<S>| {
        anyhow::anyhow!(
            "the notary closed the session before notarisation completed: {}",
            describe(ended)
        )
    };
    if preprocessed.load(Ordering::SeqCst) {
        return lost(&ended);
    }
    let outcome = tokio::time::timeout(CUT_GRACE, mpc).await;
    if preprocessed.load(Ordering::SeqCst) {
        return match outcome {
            Ok(Err(e)) => e.context(lost(&ended)),
            _ => lost(&ended),
        };
    }
    let failed = match outcome {
        Ok(Err(e)) if e.downcast_ref::<PreprocessingStalled>().is_some() => return e,
        Ok(Err(e)) => {
            let failure = failure_of(&e);
            Some((e, failure))
        }
        Ok(Ok(_)) => return anyhow::anyhow!("the session ended while the prover still ran"),
        Err(_) => None,
    };
    decide(failed, Some(&ended))
}

/// How a failure before preprocessing completed bears on a cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// A rejection, a configuration error, or any failure that is not a transport's: never a cut.
    Final,
    /// The failure shows the connection closing.
    Closure,
    /// tlsn's internal error, which is how it reports an OT setup whose peer went away ("insufficient
    /// RCOTs setup"), without a transport source or a public discriminator: an ambiguous internal
    /// failure, taken as a cut only if the driver independently shows the closure within CUT_GRACE.
    /// A genuine internal fault accompanied by a closure is then retried too, within the bound.
    Lossy,
}

fn failure_of(e: &anyhow::Error) -> Failure {
    let tlsn = e
        .chain()
        .find_map(|link| link.downcast_ref::<tlsn::Error>());
    if tlsn.is_some_and(|t| t.is_user() || t.is_config()) {
        return Failure::Final;
    }
    if e.chain().any(is_closure) {
        return Failure::Closure;
    }
    if tlsn.is_some_and(tlsn::Error::is_internal) {
        return Failure::Lossy;
    }
    Failure::Final
}

/// The error of a session that failed before preprocessing completed, from the prover's failure (if
/// it came) and the driver's end (if it came): a retryable stall if the notary closed the connection,
/// and the failure itself otherwise. A final failure stays final whatever the driver did.
fn decide<S>(
    failed: Option<(anyhow::Error, Failure)>,
    ended: Option<&DriverOutput<S>>,
) -> anyhow::Error {
    let stall = |reason: String| -> anyhow::Error {
        PreprocessingStalled(format!("the notary closed the session: {reason}")).into()
    };
    let closed = ended.and_then(closure);
    // A driver that panicked or failed otherwise than by a closure is final, whatever the prover saw.
    if let (Some(ended), None) = (ended, &closed) {
        let driver = anyhow::anyhow!("the session driver failed: {}", describe(ended));
        return match failed {
            Some((e, _)) => e.context(driver),
            None => driver,
        };
    }
    match (failed, closed) {
        (Some((e, Failure::Final)), _) => e,
        (Some((e, Failure::Closure)), _) => stall(format!("{e:#}")),
        (Some((e, Failure::Lossy)), Some(reason)) => stall(format!(
            "{reason}, with an ambiguous internal preprocessing failure: {e:#}"
        )),
        (Some((e, Failure::Lossy)), None) => e,
        (None, Some(reason)) => stall(reason),
        (None, None) => anyhow::anyhow!("preprocessing failed without an error"),
    }
}

/// Why the session driver's end is a closed connection, if it is: it ended cleanly, or with a
/// closure in its error. A panic or any other driver error is not a closure.
fn closure<S>(ended: &DriverOutput<S>) -> Option<String> {
    match ended {
        Ok(Ok(_)) => Some("connection closed".to_string()),
        Ok(Err(e)) if error_chain(e).any(is_closure) => Some(format!("{e:#}")),
        _ => None,
    }
}

fn describe<S>(ended: &DriverOutput<S>) -> String {
    match ended {
        Ok(Ok(_)) => "connection closed".to_string(),
        Ok(Err(e)) => format!("{e:#}"),
        Err(e) => format!("{e:#}"),
    }
}

fn error_chain<'a>(
    e: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(e), |e| e.source())
}

/// One link of an error chain that shows the connection closing: an end of stream, reset, abort,
/// broken pipe, or missing connection; a write to a closed connection, which the multiplexer reports
/// as WriteZero (from a stream, and from its frame writer when the socket accepts nothing); or the
/// multiplexer's closed connection.
fn is_closure(e: &(dyn std::error::Error + 'static)) -> bool {
    use std::io::ErrorKind::*;
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        return matches!(
            io.kind(),
            UnexpectedEof
                | ConnectionReset
                | ConnectionAborted
                | BrokenPipe
                | NotConnected
                | WriteZero
        );
    }
    matches!(
        e.downcast_ref::<tlsn_mux::ConnectionError>(),
        Some(tlsn_mux::ConnectionError::Closed)
    )
}

/// MPC-TLS part of a notarisation: preprocessing, the TLS session with the registry, the request,
/// commitments, and the attestation request.
async fn run_mpc(
    handle: &mut tlsn::SessionHandle,
    setup: &ShapeSetup,
    preprocessed: &AtomicBool,
) -> Result<(
    AttestationRequest,
    Secrets,
    (Vec<FieldOpening>, CommittedOpening, CommittedOpening),
)> {
    let shape = &setup.shape;
    let request_line = shape.request_line.as_str();
    let preprocessing = handle.new_prover(ProverConfig::builder().build()?)?.commit(
        MpcTlsConfig::builder()
            .max_sent_data(setup.max_sent)
            .max_recv_data(setup.max_recv)
            .build()?,
    );
    let prover = match tokio::time::timeout(setup.preprocess_timeout, preprocessing).await {
        Err(_) => {
            return Err(PreprocessingStalled(format!(
                "did not finish within {:?}",
                setup.preprocess_timeout
            ))
            .into());
        }
        Ok(result) => result?,
    };
    preprocessed.store(true, Ordering::SeqCst);

    let server_name = ServerName::Dns(shape.server_name.as_str().try_into()?);
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
        .uri(&shape.path)
        .header("Host", &shape.server_name)
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
        transcript.received().len() == shape.len,
        "response has {} bytes, the layout has {}",
        transcript.received().len(),
        shape.len
    );

    // D3 and D26: the request line and the response structure are committed to be opened; the three
    // field values are committed and stay hidden.
    let mut builder = TranscriptCommitConfig::builder(transcript);
    builder.default_kind(SHA256);
    builder.commit_sent(&(0..request_line.len()))?;
    builder.commit_recv(RangeSet::from(shape.revealed.clone()))?;
    for r in &shape.hidden {
        builder.commit_recv(r)?;
    }
    let transcript_commit = builder.build()?;

    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(transcript_commit);
    if setup.eth_attestation {
        request_config
            .signature_alg(tlsn::attestation::signing::SignatureAlgId::SECP256K1ETH)
            .hash_alg(HashAlgId::KECCAK256);
    }
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
    let openings = shape
        .hidden
        .iter()
        .map(|r| opening(&prover_transcript, &transcript_secrets, r.clone()))
        .collect::<Result<Vec<_>>>()?;
    let request_opening = committed_opening(
        &prover_transcript,
        &transcript_secrets,
        Direction::Sent,
        &RangeSet::from(0..request_line.len()),
    )?;
    let structure = committed_opening(
        &prover_transcript,
        &transcript_secrets,
        Direction::Received,
        &RangeSet::from(shape.revealed.clone()),
    )?;

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
    Ok((request, secrets, (openings, request_opening, structure)))
}

/// Plaintext (the ranges of `idx`, concatenated in order) and blinder of the hash commitment to
/// `idx` in `direction`.
fn committed_opening(
    transcript: &Transcript,
    secrets: &[TranscriptSecret],
    direction: Direction,
    idx: &RangeSet<usize>,
) -> Result<CommittedOpening> {
    let blinder = secrets
        .iter()
        .find_map(|secret| match secret {
            TranscriptSecret::Hash(h) if h.direction == direction && &h.idx == idx => {
                <[u8; 16]>::try_from(h.blinder.as_bytes()).ok()
            }
            _ => None,
        })
        .with_context(|| format!("no hash commitment secret for {direction:?} {idx:?}"))?;
    let data = match direction {
        Direction::Sent => transcript.sent(),
        Direction::Received => transcript.received(),
    };
    let plaintext = idx.iter_values().map(|i| data[i]).collect();
    Ok(CommittedOpening { plaintext, blinder })
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
    connect: C,
    setup: &ProverSetup,
    max_retries: u32,
) -> Result<(Notarized, NotarizeStats)>
where
    C: FnMut(u32) -> F,
    F: Future<Output = Result<S>>,
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    with_retries(connect, |notary| notarize(notary, setup), max_retries).await
}

/// As [`notarize_with_retries`], for [`notarize_shape`].
pub async fn notarize_shape_with_retries<C, F, S>(
    connect: C,
    setup: &ShapeSetup,
    max_retries: u32,
) -> Result<(NotarizedShape, NotarizeStats)>
where
    C: FnMut(u32) -> F,
    F: Future<Output = Result<S>>,
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    with_retries(connect, |notary| notarize_shape(notary, setup), max_retries).await
}

async fn with_retries<C, F, S, N, NF, T>(
    mut connect: C,
    mut notarize_one: N,
    max_retries: u32,
) -> Result<(T, NotarizeStats)>
where
    C: FnMut(u32) -> F,
    F: Future<Output = Result<S>>,
    N: FnMut(S) -> NF,
    NF: Future<Output = Result<T>>,
{
    let mut stats = NotarizeStats::default();
    loop {
        stats.attempts += 1;
        let notary = connect(stats.attempts).await?;
        match notarize_one(notary).await {
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
    build_presentation(
        &notarized.attestation,
        &notarized.secrets,
        notarized.request_line_len,
        notarized.ranges.revealed(),
        reveal_hidden.then(|| notarized.ranges.hidden().to_vec()),
    )
}

/// As [`present`], for a notarisation of any layout.
pub fn present_shape(notarized: &NotarizedShape, reveal_hidden: bool) -> Result<Presentation> {
    build_presentation(
        &notarized.attestation,
        &notarized.secrets,
        notarized.shape.request_line.len(),
        notarized.shape.revealed.clone(),
        reveal_hidden.then(|| notarized.shape.hidden.clone()),
    )
}

fn build_presentation(
    attestation: &Attestation,
    secrets: &Secrets,
    request_line_len: usize,
    revealed: Vec<Range<usize>>,
    hidden: Option<Vec<Range<usize>>>,
) -> Result<Presentation> {
    let mut builder = secrets.transcript_proof_builder();
    builder.commitment_kinds(&[SHA256]);
    builder.reveal_sent(&(0..request_line_len))?;
    builder.reveal_recv(RangeSet::from(revealed))?;
    for r in hidden.unwrap_or_default() {
        builder.reveal_recv(&r)?;
    }
    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(presentation.build()?)
}

#[cfg(test)]
mod tests {
    use std::io::{Error as IoError, ErrorKind};

    use tlsn_mux::ConnectionError;

    use super::*;

    fn io(kind: ErrorKind) -> IoError {
        IoError::from(kind)
    }

    fn closed(e: anyhow::Error) -> bool {
        e.chain().any(is_closure)
    }

    fn driver<F>(output: F) -> DriverGuard<Result<(), tlsn::Error>>
    where
        F: Future<Output = Result<(), tlsn::Error>> + Send + 'static,
    {
        DriverGuard(Some(tokio::spawn(output)))
    }

    fn stalled(e: &anyhow::Error) -> bool {
        e.downcast_ref::<PreprocessingStalled>().is_some()
    }

    #[test]
    fn closures_are_recognised_through_wrappers() {
        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
            ErrorKind::WriteZero,
        ] {
            assert!(closed(anyhow::Error::from(io(kind))), "{kind:?}");
            assert!(closed(
                Err::<(), _>(io(kind)).context("preprocessing").unwrap_err()
            ));
            assert!(
                closed(tlsn::Error::from(io(kind)).into()),
                "{kind:?} in tlsn"
            );
            assert!(closed(
                tlsn::Error::from(ConnectionError::Io(io(kind))).into()
            ));
        }
        assert!(closed(tlsn::Error::from(ConnectionError::Closed).into()));
    }

    #[test]
    fn other_failures_are_not_closures() {
        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::InvalidInput,
            ErrorKind::PermissionDenied,
            ErrorKind::TimedOut,
            ErrorKind::Other,
        ] {
            assert!(!closed(anyhow::Error::from(io(kind))), "{kind:?}");
            assert!(
                !closed(tlsn::Error::from(io(kind)).into()),
                "{kind:?} in tlsn"
            );
        }
        assert!(!closed(
            tlsn::Error::from(ConnectionError::TooManyStreams).into()
        ));
        assert!(!closed(
            tlsn::Error::from(ConnectionError::DuplicateStreamId).into()
        ));
        assert!(!closed(anyhow::anyhow!(
            "commitment protocol rejected by verifier"
        )));
        assert!(!closed(PreprocessingStalled("x".into()).into()));
    }

    #[tokio::test]
    async fn the_driver_ending_cleanly_or_with_a_closure_is_a_cut() {
        let ok: DriverOutput<()> = driver(async { Ok(()) }).join().await;
        assert!(closure(&ok).is_some());
        let eof = driver(async { Err(io(ErrorKind::UnexpectedEof).into()) })
            .join()
            .await;
        assert!(closure(&eof).is_some());
        let mux = driver(async { Err(ConnectionError::Closed.into()) })
            .join()
            .await;
        assert!(closure(&mux).is_some());
    }

    #[tokio::test]
    async fn a_driver_panic_or_protocol_error_is_not_a_cut() {
        let panicked = driver(async { panic!("driver bug") }).join().await;
        assert!(closure(&panicked).is_none());
        let streams = driver(async { Err(ConnectionError::TooManyStreams.into()) })
            .join()
            .await;
        assert!(closure(&streams).is_none());
        let data = driver(async { Err(io(ErrorKind::InvalidData).into()) })
            .join()
            .await;
        assert!(closure(&data).is_none());
    }

    #[test]
    fn failures_are_classified_by_type() {
        assert_eq!(
            failure_of(&io(ErrorKind::UnexpectedEof).into()),
            Failure::Closure
        );
        assert_eq!(
            failure_of(&tlsn::Error::from(ConnectionError::Closed).into()),
            Failure::Closure
        );
        assert_eq!(
            failure_of(&tlsn::Error::from(io(ErrorKind::InvalidData)).into()),
            Failure::Final
        );
        assert_eq!(
            failure_of(&tlsn::Error::from(ConnectionError::TooManyStreams).into()),
            Failure::Final
        );
        assert_eq!(failure_of(&anyhow::anyhow!("bad config")), Failure::Final);
    }

    fn final_error() -> (anyhow::Error, Failure) {
        let e = anyhow::anyhow!("commitment protocol rejected by verifier");
        (e, Failure::Final)
    }

    fn lossy() -> (anyhow::Error, Failure) {
        let e = anyhow::anyhow!("insufficient RCOTs setup");
        (e, Failure::Lossy)
    }

    #[tokio::test]
    async fn a_final_failure_stays_final_even_when_the_driver_ended_cleanly() {
        let clean = driver(async { Ok(()) }).join().await;
        let e = decide(Some(final_error()), Some(&clean));
        assert!(!stalled(&e), "{e:#}");
        assert_eq!(format!("{e}"), "commitment protocol rejected by verifier");
    }

    #[tokio::test]
    async fn a_closure_failure_is_a_stall_without_the_driver() {
        let e: anyhow::Error = tlsn::Error::from(io(ErrorKind::UnexpectedEof)).into();
        let e = decide::<()>(Some((e, Failure::Closure)), None);
        assert!(stalled(&e), "{e:#}");
    }

    #[tokio::test]
    async fn a_lossy_failure_is_a_stall_only_if_the_driver_shows_the_closure() {
        let clean = driver(async { Ok(()) }).join().await;
        assert!(stalled(&decide(Some(lossy()), Some(&clean))));
        let streams = driver(async { Err(ConnectionError::TooManyStreams.into()) })
            .join()
            .await;
        assert!(!stalled(&decide(Some(lossy()), Some(&streams))));
        let panicked = driver(async { panic!("driver bug") }).join().await;
        assert!(!stalled(&decide(Some(lossy()), Some(&panicked))));
        assert!(!stalled(&decide::<()>(Some(lossy()), None)));
    }

    #[tokio::test]
    async fn a_closure_failure_with_a_failed_driver_is_final() {
        let closure_failure = || {
            let e: anyhow::Error = tlsn::Error::from(io(ErrorKind::UnexpectedEof)).into();
            (e, Failure::Closure)
        };
        let panicked = driver(async { panic!("driver bug") }).join().await;
        assert!(!stalled(&decide(Some(closure_failure()), Some(&panicked))));
        let streams = driver(async { Err(ConnectionError::TooManyStreams.into()) })
            .join()
            .await;
        assert!(!stalled(&decide(Some(closure_failure()), Some(&streams))));
        let clean = driver(async { Ok(()) }).join().await;
        assert!(stalled(&decide(Some(closure_failure()), Some(&clean))));
    }

    #[tokio::test]
    async fn after_the_driver_ends_a_prover_failure_before_preprocessing_is_classified() {
        let flag = AtomicBool::new(false);
        let clean = driver(async { Ok(()) }).join().await;
        let mpc = async { Err::<(), _>(anyhow::Error::from(io(ErrorKind::UnexpectedEof))) };
        let e = after_driver_end(clean, mpc, &flag).await;
        assert!(stalled(&e), "{e:#}");
    }

    #[tokio::test]
    async fn preprocessing_completing_while_waiting_on_the_prover_makes_the_failure_final() {
        // The prover finishes preprocessing during the wait and then fails, as it would after
        // reaching the registry: not a stall, although the failure is a closure and the driver
        // ended cleanly.
        let flag = AtomicBool::new(false);
        let clean = driver(async { Ok(()) }).join().await;
        let mpc = async {
            tokio::task::yield_now().await;
            flag.store(true, Ordering::SeqCst);
            Err::<(), _>(anyhow::Error::from(io(ErrorKind::UnexpectedEof)))
        };
        let e = after_driver_end(clean, mpc, &flag).await;
        assert!(!stalled(&e), "{e:#}");
        assert!(
            format!("{e:#}").contains("before notarisation completed"),
            "{e:#}"
        );
    }

    #[tokio::test]
    async fn a_hung_prover_leaves_the_decision_to_the_driver() {
        let flag = AtomicBool::new(false);
        let clean = driver(async { Ok(()) }).join().await;
        let e = after_driver_end(clean, std::future::pending::<Result<()>>(), &flag).await;
        assert!(stalled(&e), "{e:#}");
        let panicked = driver(async { panic!("driver bug") }).join().await;
        let e = after_driver_end(panicked, std::future::pending::<Result<()>>(), &flag).await;
        assert!(!stalled(&e), "{e:#}");
    }

    #[tokio::test]
    async fn a_driver_end_without_a_prover_failure_is_a_stall_only_if_it_is_a_closure() {
        let clean = driver(async { Ok(()) }).join().await;
        assert!(stalled(&decide(None, Some(&clean))));
        let panicked = driver(async { panic!("driver bug") }).join().await;
        assert!(!stalled(&decide(None, Some(&panicked))));
        let data = driver(async { Err(io(ErrorKind::InvalidData).into()) })
            .join()
            .await;
        assert!(!stalled(&decide(None, Some(&data))));
    }
}
