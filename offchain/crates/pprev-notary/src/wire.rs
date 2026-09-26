//! Messages between the owner and the policy verifier for Register (Section V-B, step (d)). One
//! request per TCP connection: the owner writes one bincode message and closes its write half; the
//! policy verifier answers with one bincode message and closes the connection.

use std::net::SocketAddr;

use alloy_sol_types::SolValue;
use anyhow::{Context, Result, ensure};
use pprev_types::statement::Register;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tlsn::attestation::presentation::Presentation;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::groth16::Groth16Proof;
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
pub async fn submit_register(
    addr: SocketAddr,
    submission: &RegisterSubmission,
) -> Result<RegisterReply> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to the policy verifier at {addr}"))?;
    let (reader, writer) = stream.into_split();
    write_message(writer, submission).await?;
    read_message(reader).await
}
