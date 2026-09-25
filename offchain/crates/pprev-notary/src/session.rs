//! Notary side of the MPC-TLS session and attestation signing.

use std::time::Duration;

use anyhow::{Result, bail};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tlsn::Session;
use tlsn::attestation::request::Request as AttestationRequest;
use tlsn::attestation::signing::Secp256k1Signer;
use tlsn::attestation::{Attestation, AttestationConfig, CryptoProvider, Extension};
use tlsn::config::verifier::VerifierConfig;
use tlsn::connection::{CertBinding, ConnectionInfo, TranscriptLength};
use tlsn::transcript::ContentType;
use tlsn::verifier::{VerifierCommitStart, VerifierOutput};
use tlsn::webpki::{CertificateDer, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{T_ATT_EXTENSION_ID, unix_now};

/// Owns the session driver task and aborts it if the session ends early, so that the peer sees the
/// connection close instead of waiting on it.
struct DriverGuard<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> DriverGuard<T> {
    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        self.0.take().expect("driver joined once").await
    }
}

impl<T> Drop for DriverGuard<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Default bound on MPC-TLS preprocessing before the notary cuts the session (D33).
pub const DEFAULT_PREPROCESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Default bound on a whole session before the notary cuts it (D33).
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// The notary cut a session that did not progress (D33). tlsn 0.1.0-alpha.15 deadlocks in MPC-TLS
/// preprocessing intermittently (tlsnotary/tlsn#1173); cutting the session lets the prover retry.
#[derive(Debug)]
pub struct SessionCut(pub String);

impl std::fmt::Display for SessionCut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session cut: {}", self.0)
    }
}

impl std::error::Error for SessionCut {}

#[derive(Clone)]
pub struct NotaryConfig {
    /// secp256k1 key that signs attestations (D19). Distinct from the key that signs statements.
    pub attestation_key: [u8; 32],
    /// Roots the notary trusts for the server certificate during the MPC-TLS handshake.
    pub root_certs: Vec<Vec<u8>>,
    /// Source of t_att (D29): the notary's clock, in Unix seconds.
    pub clock: fn() -> u64,
    /// Bound on MPC-TLS preprocessing (D33).
    pub preprocess_timeout: Duration,
    /// Bound on the whole session (D33).
    pub session_timeout: Duration,
}

impl NotaryConfig {
    pub fn new(attestation_key: [u8; 32], root_certs: Vec<Vec<u8>>) -> Self {
        Self {
            attestation_key,
            root_certs,
            clock: unix_now,
            preprocess_timeout: DEFAULT_PREPROCESS_TIMEOUT,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
        }
    }
}

/// What the notary recorded about one session.
#[derive(Clone, Debug)]
pub struct NotarizationReport {
    /// The notary's clock when it built the attestation; signed as `pprev.t_att`.
    pub t_att: u64,
    /// `ConnectionInfo.time`: the prover's handshake time, accepted by tlsn within 5 s of the notary.
    pub connection_time: u64,
}

/// Runs the notary's half of one MPC-TLS session on `socket` and returns the attestation to the
/// prover over the same socket. Proxy mode is rejected (D2). A session that exceeds the
/// preprocessing or the session bound is cut with [`SessionCut`] (D33).
pub async fn notarize<S>(socket: S, config: &NotaryConfig) -> Result<NotarizationReport>
where
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    match tokio::time::timeout(config.session_timeout, notarize_session(socket, config)).await {
        Ok(result) => result,
        Err(_) => {
            let reason = format!("did not finish within {:?}", config.session_timeout);
            tracing::warn!(%reason, "cutting MPC-TLS session");
            Err(SessionCut(reason).into())
        }
    }
}

async fn notarize_session<S>(socket: S, config: &NotaryConfig) -> Result<NotarizationReport>
where
    S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = DriverGuard(Some(tokio::spawn(driver)));

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: config
                .root_certs
                .iter()
                .map(|der| CertificateDer(der.clone()))
                .collect(),
        })
        .build()?;
    let preprocessing = async {
        match handle.new_verifier(verifier_config)?.commit().await? {
            VerifierCommitStart::Mpc(verifier) => Ok(verifier.accept().await?),
            VerifierCommitStart::Proxy(verifier) => {
                verifier.reject(Some("expecting MPC-TLS")).await?;
                bail!("prover requested proxy mode");
            }
        }
    };
    let verifier = match tokio::time::timeout(config.preprocess_timeout, preprocessing).await {
        Ok(accepted) => accepted?,
        Err(_) => {
            let reason = format!(
                "preprocessing did not finish within {:?} (tlsnotary/tlsn#1173)",
                config.preprocess_timeout
            );
            tracing::warn!(%reason, "cutting MPC-TLS session");
            return Err(SessionCut(reason).into());
        }
    };
    let verifier = verifier.run().await?;
    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let app_data_len = |records: &[tlsn::transcript::Record]| -> usize {
        records
            .iter()
            .filter(|r| r.typ == ContentType::ApplicationData)
            .map(|r| r.ciphertext.len())
            .sum()
    };
    let sent_len = app_data_len(tls_transcript.sent());
    let recv_len = app_data_len(tls_transcript.recv());

    handle.close();
    let mut socket = driver_task.join().await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    let mut provider = CryptoProvider::default();
    provider
        .signer
        .set_signer(Box::new(Secp256k1Signer::new(&config.attestation_key)?));
    let mut att_config = AttestationConfig::builder();
    att_config.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config.build()?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        bail!("unsupported certificate binding (TLS 1.2 only)");
    };

    let connection_time = tls_transcript.time();
    // D29: t_att is the notary's own clock at attestation time, signed as an extension.
    let t_att = (config.clock)();
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: connection_time,
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments)
        .extension(Extension {
            id: T_ATT_EXTENSION_ID.to_vec(),
            value: t_att.to_be_bytes().to_vec(),
        });
    let attestation = builder.build(&provider)?;

    socket.write_all(&bincode::serialize(&attestation)?).await?;
    socket.close().await?;
    Ok(NotarizationReport {
        t_att,
        connection_time,
    })
}
