//! Messages between a submitter and the policy verifier (Section V-B, step (d)). One request per TCP
//! connection: the submitter writes one bincode [`Submission`] and closes its write half; the policy
//! verifier answers with one bincode [`RegisterReply`] and closes the connection.

use std::net::SocketAddr;

use alloy_sol_types::SolValue;
use anyhow::{Context, Result, ensure};
use pprev_types::statement::{Apply, Register, Settle};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tlsn::attestation::presentation::Presentation;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::groth16::Groth16Proof;
use crate::phases::{ApplyRequest, SettleRequest};
use crate::register::{RegisterRequest, RegisterTimings};

/// Upper bound on one message; a presentation of the title response is a few kilobytes.
pub const MAX_MESSAGE_BYTES: u64 = 16 << 20;

/// [`RegisterRequest`] as the owner sends it.
#[derive(Serialize, Deserialize)]
pub struct RegisterSubmission {
    pub presentation: Presentation,
    pub property_id: String,
    /// x_R, ABI-encoded.
    pub statement: Vec<u8>,
    /// The phi_R proof as snarkjs writes it (`proof.json`).
    pub proof_json: String,
}

impl RegisterSubmission {
    pub fn new(
        presentation: Presentation,
        property_id: String,
        statement: &Register,
        proof_json: String,
    ) -> Self {
        Self {
            presentation,
            property_id,
            statement: statement.abi_encode(),
            proof_json,
        }
    }

    pub fn into_request(self) -> Result<RegisterRequest> {
        let statement =
            <Register as SolValue>::abi_decode(&self.statement).context("decoding x_R")?;
        Ok(RegisterRequest {
            presentation: self.presentation,
            property_id: self.property_id,
            statement,
            proof: Groth16Proof::from_snarkjs_json(&self.proof_json)?,
        })
    }
}

/// [`ApplyRequest`] as the counterparty sends it.
#[derive(Serialize, Deserialize)]
pub struct ApplySubmission {
    pub presentation: Presentation,
    /// x_A, ABI-encoded.
    pub statement: Vec<u8>,
    /// The phi_A proof as snarkjs writes it (`proof.json`).
    pub proof_json: String,
}

impl ApplySubmission {
    pub fn new(presentation: Presentation, statement: &Apply, proof_json: String) -> Self {
        Self {
            presentation,
            statement: statement.abi_encode(),
            proof_json,
        }
    }

    pub fn into_request(self) -> Result<ApplyRequest> {
        let statement = <Apply as SolValue>::abi_decode(&self.statement).context("decoding x_A")?;
        Ok(ApplyRequest {
            presentation: self.presentation,
            statement,
            proof: Groth16Proof::from_snarkjs_json(&self.proof_json)?,
        })
    }
}

/// [`SettleRequest`] as the owner sends it.
#[derive(Serialize, Deserialize)]
pub struct SettleSubmission {
    pub presentation: Presentation,
    pub notation_id: String,
    /// x_S, ABI-encoded.
    pub statement: Vec<u8>,
    /// The phi_S proof as snarkjs writes it (`proof.json`).
    pub proof_json: String,
}

impl SettleSubmission {
    pub fn new(
        presentation: Presentation,
        notation_id: String,
        statement: &Settle,
        proof_json: String,
    ) -> Self {
        Self {
            presentation,
            notation_id,
            statement: statement.abi_encode(),
            proof_json,
        }
    }

    pub fn into_request(self) -> Result<SettleRequest> {
        let statement =
            <Settle as SolValue>::abi_decode(&self.statement).context("decoding x_S")?;
        Ok(SettleRequest {
            presentation: self.presentation,
            notation_id: self.notation_id,
            statement,
            proof: Groth16Proof::from_snarkjs_json(&self.proof_json)?,
        })
    }
}

/// One request to the policy verifier.
#[derive(Serialize, Deserialize)]
pub enum Submission {
    Register(RegisterSubmission),
    Apply(ApplySubmission),
    Settle(SettleSubmission),
}

impl Submission {
    /// The phase, as the event log names it.
    pub fn phase(&self) -> &'static str {
        match self {
            Self::Register(_) => "register",
            Self::Apply(_) => "apply",
            Self::Settle(_) => "settle",
        }
    }
}

/// The policy verifier's answer to any [`Submission`].
#[derive(Serialize, Deserialize)]
pub enum RegisterReply {
    Signed {
        /// sigma_R: r || s || v.
        sigma: Vec<u8>,
        /// Decoding the submission (presentation, x_R, proof), in milliseconds.
        decode_ms: f64,
        timings: RegisterTimings,
    },
    Refused {
        reason: String,
    },
}

pub async fn read_message<T: DeserializeOwned>(reader: impl AsyncRead + Unpin) -> Result<T> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_MESSAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() as u64 <= MAX_MESSAGE_BYTES,
        "message exceeds {MAX_MESSAGE_BYTES} bytes"
    );
    bincode::deserialize(&bytes).context("decoding message")
}

/// Writes `message` and closes the write half.
pub async fn write_message<T: Serialize>(
    mut writer: impl AsyncWrite + Unpin,
    message: &T,
) -> Result<()> {
    writer.write_all(&bincode::serialize(message)?).await?;
    writer.shutdown().await?;
    Ok(())
}

/// Sends `submission` to the policy verifier at `addr` and returns its reply.
pub async fn submit(addr: SocketAddr, submission: &Submission) -> Result<RegisterReply> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to the policy verifier at {addr}"))?;
    let (reader, writer) = stream.into_split();
    write_message(writer, submission).await?;
    read_message(reader).await
}

/// Sends a Register submission to the policy verifier at `addr` and returns its reply.
pub async fn submit_register(
    addr: SocketAddr,
    submission: RegisterSubmission,
) -> Result<RegisterReply> {
    submit(addr, &Submission::Register(submission)).await
}
