//! Policy-verifier checks on a presentation (D3, D26, D29).

use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use pprev_types::circuit::PhiRPublic;
use pprev_types::{Layout, ResponseShape};
use serde::Deserialize;
use tlsn::attestation::presentation::{Presentation, PresentationOutput};
use tlsn::attestation::signing::VerifyingKey;
use tlsn::attestation::{Attestation, CryptoProvider};
use tlsn::connection::ServerName;
use tlsn::hash::HashAlgId;
use tlsn::rangeset::set::RangeSet;
use tlsn::transcript::{Direction, TranscriptCommitment};
use tlsn::verifier::ServerCertVerifier;
use tlsn::webpki::{CertificateDer, RootCertStore};

use crate::T_ATT_EXTENSION_ID;

/// What the policy verifier expects of a presentation for one statement.
pub struct Expectation<'a> {
    pub layout: &'a Layout,
    /// The notary's attestation key (D19).
    pub attestation_key: &'a VerifyingKey,
    /// Roots trusted for the registry's certificate.
    pub root_certs: &'a [Vec<u8>],
    /// `txData.propertyId` as the registry writes it.
    pub property_id: &'a str,
    /// Upper bound on `t_att - ConnectionInfo.time` (D29).
    pub max_session_secs: u64,
}

/// What the policy verifier expects of a presentation, for any response layout.
pub struct ShapeExpectation<'a> {
    /// Request line, response template, revealed and hidden ranges of the notarised exchange.
    pub shape: &'a ResponseShape,
    /// The notary's attestation key (D19).
    pub attestation_key: &'a VerifyingKey,
    /// Roots trusted for the registry's certificate.
    pub root_certs: &'a [Vec<u8>],
    /// Upper bound on `t_att - ConnectionInfo.time` (D29).
    pub max_session_secs: u64,
}

/// Values the policy verifier takes from an accepted presentation, for any response layout.
#[derive(Clone, Debug)]
pub struct AttestedShape {
    pub t_att: u64,
    pub connection_time: u64,
    /// SHA-256(value ‖ blinder) of the hidden fields, in the shape's order.
    pub hidden_hashes: Vec<[u8; 32]>,
}

/// A transcript commitment as the attestation body records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedHash {
    pub direction: Direction,
    pub idx: RangeSet<usize>,
    pub alg: HashAlgId,
    pub hash: Vec<u8>,
}

/// Values the policy verifier takes from an accepted presentation.
#[derive(Clone, Debug)]
pub struct Attested {
    pub t_att: u64,
    pub connection_time: u64,
    /// SHA-256(value ‖ blinder) of the hidden fields, in layout order.
    pub account_hash: Vec<u8>,
    pub owners_hash: Vec<u8>,
    pub property_id_hash: Vec<u8>,
}

impl Attested {
    /// The public side of phi_R: the attested commitments, `txData.propertyId`, and the EIP-712
    /// digest of x_R. The commitments come from the attestation, never from the prover.
    pub fn phi_r_public(&self, property_id: [u8; 32], digest: [u8; 32]) -> Result<PhiRPublic> {
        let word = |hash: &[u8]| -> Result<[u8; 32]> {
            hash.try_into().context("commitment is not 32 bytes")
        };
        Ok(PhiRPublic {
            account_hash: word(&self.account_hash)?,
            owners_hash: word(&self.owners_hash)?,
            property_hash: word(&self.property_id_hash)?,
            property_id,
            digest,
        })
    }
}

/// Transcript commitments of a verified attestation.
///
/// tlsn 0.1.0-alpha.15 keeps `Body::transcript_commitments` crate-private, so the commitments are
/// read from the serialised body. Call this only on the attestation that `Presentation::verify`
/// returned: its body has been checked against the Merkle root that the notary signed.
pub fn attested_commitments(attestation: &Attestation) -> Result<Vec<CommittedHash>> {
    #[derive(Deserialize)]
    struct FieldView<T> {
        data: T,
    }
    #[derive(Deserialize)]
    struct BodyView {
        transcript_commitments: Vec<FieldView<TranscriptCommitment>>,
    }
    let body: BodyView = serde_json::from_value(serde_json::to_value(&attestation.body)?)
        .context("reading transcript commitments from the attestation body")?;
    body.transcript_commitments
        .into_iter()
        .map(|field| match field.data {
            TranscriptCommitment::Hash(h) => Ok(CommittedHash {
                direction: h.direction,
                idx: h.idx,
                alg: h.hash.alg,
                hash: h.hash.value.as_bytes().to_vec(),
            }),
            #[allow(unreachable_patterns)]
            _ => bail!("unsupported transcript commitment kind"),
        })
        .collect()
}

/// Reads t_att from the notary's `pprev.t_att` extension (D29).
pub fn t_att_of(output: &PresentationOutput) -> Result<u64> {
    let mut values = output
        .extensions
        .iter()
        .filter(|e| e.id == T_ATT_EXTENSION_ID);
    let ext = values
        .next()
        .context("attestation has no t_att extension")?;
    ensure!(
        values.next().is_none(),
        "attestation has more than one t_att extension"
    );
    let bytes: [u8; 8] = ext
        .value
        .as_slice()
        .try_into()
        .context("t_att extension is not 8 bytes")?;
    Ok(u64::from_be_bytes(bytes))
}

/// How far the prover's handshake time may run ahead of the notary's clock, in seconds. tlsn's
/// MPC-TLS follower accepts `ConnectionInfo.time` only within this bound of its own clock, so a
/// prover whose clock is ahead by up to this much passes the handshake:
///
/// ```text
/// tlsn v0.1.0-alpha.15 (47aee45b), crates/mpc-tls/src/follower.rs:32-33, checked at :267
///     // Maximum handshake time difference in seconds.
///     const MAX_TIME_DIFF: u64 = 5;
/// ```
pub const TLSN_CLOCK_TOLERANCE: u64 = 5;

/// D29 consistency check between t_att (the notary's clock at attestation) and
/// `ConnectionInfo.time` (the prover's clock at handshake start): t_att may precede the connection
/// time by at most [`TLSN_CLOCK_TOLERANCE`] and follow it by at most `max_session_secs`.
pub fn check_times(t_att: u64, connection_time: u64, max_session_secs: u64) -> Result<()> {
    ensure!(
        t_att + TLSN_CLOCK_TOLERANCE >= connection_time,
        "t_att {t_att} precedes the connection time {connection_time} by more than {TLSN_CLOCK_TOLERANCE} s"
    );
    let gap = t_att.saturating_sub(connection_time);
    ensure!(
        gap <= max_session_secs,
        "t_att is {gap} s after the connection time, above the bound of {max_session_secs} s"
    );
    Ok(())
}

/// Checks a presentation against the policy's layout (Section 3.4 of the plan) and returns t_att and
/// the hashes of the hidden fields.
pub fn check_presentation(presentation: Presentation, exp: &Expectation<'_>) -> Result<Attested> {
    let shape = exp.layout.shape(exp.property_id)?;
    let attested = check_shape(
        presentation,
        &ShapeExpectation {
            shape: &shape,
            attestation_key: exp.attestation_key,
            root_certs: exp.root_certs,
            max_session_secs: exp.max_session_secs,
        },
    )?;
    let [account, owners, property_id] = attested
        .hidden_hashes
        .try_into()
        .map_err(|_| anyhow::anyhow!("the title layout has three hidden fields"))?;
    Ok(Attested {
        t_att: attested.t_att,
        connection_time: attested.connection_time,
        account_hash: account.to_vec(),
        owners_hash: owners.to_vec(),
        property_id_hash: property_id.to_vec(),
    })
}

/// Checks a presentation against a response shape: attestation key and signature, server identity,
/// t_att against the handshake time, response length, exactly the revealed request line and
/// response structure, and exactly one SHA-256 commitment per revealed and hidden range. Returns
/// t_att and the hashes of the hidden fields.
pub fn check_shape(
    presentation: Presentation,
    exp: &ShapeExpectation<'_>,
) -> Result<AttestedShape> {
    ensure!(
        presentation.verifying_key() == exp.attestation_key,
        "attestation key is not trusted"
    );
    let root_store = RootCertStore {
        roots: exp
            .root_certs
            .iter()
            .map(|der| CertificateDer(der.clone()))
            .collect(),
    };
    let provider = CryptoProvider {
        cert: ServerCertVerifier::new(&root_store)?,
        ..Default::default()
    };
    let output = presentation
        .verify(&provider)
        .context("presentation does not verify")?;

    let shape = exp.shape;

    // Source identity.
    match &output.server_name {
        Some(ServerName::Dns(name)) if name.as_str() == shape.server_name => {}
        other => bail!("server identity {other:?} is not {}", shape.server_name),
    }

    // t_att (D29): the notary's clock, consistent with the prover-reported handshake time.
    let t_att = t_att_of(&output)?;
    let connection_time = output.connection_info.time;
    check_times(t_att, connection_time, exp.max_session_secs)?;

    // The response has the layout's length.
    ensure!(
        output.connection_info.transcript_length.received as usize == shape.len,
        "received {} bytes, the layout has {}",
        output.connection_info.transcript_length.received,
        shape.len
    );

    // Revealed bytes (D26): exactly the request line and the response structure.
    let transcript = output
        .transcript
        .as_ref()
        .context("presentation reveals no transcript")?;
    let request_line = &shape.request_line;
    ensure!(
        transcript.sent_authed() == &RangeSet::from(0..request_line.len()),
        "revealed request ranges differ from the layout"
    );
    ensure!(
        &transcript.sent_unsafe()[..request_line.len()] == request_line.as_bytes(),
        "revealed request line is not {request_line:?}"
    );
    let revealed = shape.revealed.clone();
    ensure!(
        transcript.received_authed() == &RangeSet::from(revealed.clone()),
        "revealed response ranges differ from the layout"
    );
    for r in &revealed {
        ensure!(
            transcript.received_unsafe()[r.clone()] == shape.template[r.clone()],
            "revealed response bytes at {r:?} differ from the layout"
        );
    }

    // Commitments (D3): exactly the layout's, all SHA-256.
    let commitments = attested_commitments(&output.attestation)?;
    let mut expected: Vec<(Direction, RangeSet<usize>)> = vec![
        (Direction::Sent, RangeSet::from(0..request_line.len())),
        (Direction::Received, RangeSet::from(revealed)),
    ];
    expected.extend(
        shape
            .hidden
            .iter()
            .map(|r| (Direction::Received, RangeSet::from(r.clone()))),
    );
    ensure!(
        commitments.len() == expected.len(),
        "attestation has {} commitments, the layout has {}",
        commitments.len(),
        expected.len()
    );
    for (direction, idx) in &expected {
        let n = commitments
            .iter()
            .filter(|c| &c.direction == direction && &c.idx == idx)
            .count();
        ensure!(n == 1, "commitment {direction:?} {idx:?} appears {n} times");
    }
    ensure!(
        commitments.iter().all(|c| c.alg == HashAlgId::SHA256),
        "commitments must use SHA-256"
    );
    let hash_of = |r: &Range<usize>| -> Result<[u8; 32]> {
        let idx = RangeSet::from(r.clone());
        let hash = commitments
            .iter()
            .find(|c| c.direction == Direction::Received && c.idx == idx)
            .map(|c| c.hash.as_slice())
            .expect("presence checked above");
        hash.try_into().context("commitment is not 32 bytes")
    };

    Ok(AttestedShape {
        t_att,
        connection_time,
        hidden_hashes: shape.hidden.iter().map(hash_of).collect::<Result<_>>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_att_may_precede_the_connection_time_by_the_tlsn_tolerance() {
        let conn = 1_000_000;
        assert!(check_times(conn - TLSN_CLOCK_TOLERANCE, conn, 120).is_ok());
        assert!(check_times(conn - TLSN_CLOCK_TOLERANCE - 1, conn, 120).is_err());
    }

    #[test]
    fn t_att_may_follow_the_connection_time_by_the_session_bound() {
        let conn = 1_000_000;
        assert!(check_times(conn, conn, 120).is_ok());
        assert!(check_times(conn + 120, conn, 120).is_ok());
        assert!(check_times(conn + 121, conn, 120).is_err());
        assert!(check_times(conn + 121, conn, 300).is_ok());
    }
}
