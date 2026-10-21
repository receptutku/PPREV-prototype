//! Reference encoding of a TLSNotary attestation for the integrated on-chain verification baseline:
//! the bytes a contract receives and the values it must recompute from them.
//!
//! tlsn v0.1.0-alpha.15 signs the BCS encoding of the attestation header,
//! `id (16 bytes) || version (u32 LE) || root (alg u8, ULEB128 length, digest)`, and the header's
//! root is a Merkle tree over the body fields sorted by field id: each leaf is
//! `H(domain || BCS(field data))`, with `domain` the first 16 bytes of BLAKE3 of the field type's
//! name; each inner node is `H(left || right)`, and a node without a sibling moves up unhashed. With
//! the Ethereum-compatible algorithms (`SECP256K1ETH`, `KECCAK256`) the signature is an `ecrecover`
//! signature over `keccak256(BCS(header))` and `H` is Keccak-256, which a contract can check.
//!
//! The encoding here is checked against tlsn's own root and signature (`tests/e1_attestation.rs`);
//! it is pinned to tlsn v0.1.0-alpha.15, whose field order is not stable across versions.

use alloy_primitives::{Address, B256, Signature, keccak256};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tlsn::attestation::Attestation;
use tlsn::attestation::Extension;
use tlsn::attestation::connection::ServerCertCommitment;
use tlsn::attestation::signing::{SignatureAlgId, VerifyingKey};
use tlsn::connection::{ConnectionInfo, ServerEphemKey};
use tlsn::hash::HashAlgId;
use tlsn::transcript::TranscriptCommitment;

/// Kind of a body field, which fixes its domain separator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldKind {
    VerifyingKey,
    ConnectionInfo,
    ServerEphemeralKey,
    CertCommitment,
    Extension,
    TranscriptCommitment,
}

impl FieldKind {
    /// The type name tlsn derives the domain separator from (`impl_domain_separator!`).
    pub fn type_name(self) -> &'static str {
        match self {
            Self::VerifyingKey => "VerifyingKey",
            Self::ConnectionInfo => "tlsn_core::connection::ConnectionInfo",
            Self::ServerEphemeralKey => "tlsn_core::connection::ServerEphemKey",
            Self::CertCommitment => "ServerCertCommitment",
            Self::Extension => "Extension",
            Self::TranscriptCommitment => "tlsn_core::transcript::TranscriptCommitment",
        }
    }

    /// First 16 bytes of BLAKE3 of the type name.
    pub fn domain(self) -> [u8; 16] {
        blake3::hash(self.type_name().as_bytes()).as_bytes()[..16]
            .try_into()
            .expect("16 bytes")
    }
}

/// One body field as the contract receives it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedField {
    pub id: u32,
    pub kind: FieldKind,
    /// BCS encoding of the field's data.
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
    /// keccak256(domain || data).
    pub leaf: B256,
}

/// An attestation as the contract receives it, with the values it must recompute.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedAttestation {
    /// BCS of the header: the signed message.
    #[serde(with = "hex_bytes")]
    pub header: Vec<u8>,
    /// `r || s || v` over keccak256(header).
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// The notary's attestation key as an Ethereum address.
    pub signer: Address,
    /// Fields sorted by id.
    pub fields: Vec<EncodedField>,
    /// The Merkle root of the leaves, equal to the header's.
    pub root: B256,
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }
}

#[derive(Deserialize)]
struct FieldView<T> {
    id: u32,
    data: T,
}

/// The attestation body with tlsn's public field types (its fields are crate-private).
#[derive(Deserialize)]
struct BodyView {
    verifying_key: FieldView<VerifyingKey>,
    connection_info: FieldView<ConnectionInfo>,
    server_ephemeral_key: FieldView<ServerEphemKey>,
    cert_commitment: FieldView<ServerCertCommitment>,
    extensions: Vec<FieldView<Extension>>,
    transcript_commitments: Vec<FieldView<TranscriptCommitment>>,
}

fn encoded<T: Serialize>(id: u32, kind: FieldKind, data: &T) -> Result<EncodedField> {
    let data = bcs::to_bytes(data).context("BCS")?;
    let mut preimage = kind.domain().to_vec();
    preimage.extend_from_slice(&data);
    Ok(EncodedField {
        id,
        kind,
        leaf: keccak256(&preimage),
        data,
    })
}

/// Root of tlsn's Merkle tree over `leaves` with Keccak-256.
pub fn merkle_root(leaves: &[B256]) -> Result<B256> {
    ensure!(!leaves.is_empty(), "a tree has at least one leaf");
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => keccak256([left.as_slice(), right.as_slice()].concat()),
                [single] => *single,
                _ => unreachable!("chunks of two"),
            })
            .collect();
    }
    Ok(layer[0])
}

/// Encodes an attestation signed with `SECP256K1ETH` over a `KECCAK256` tree.
pub fn encode(attestation: &Attestation) -> Result<EncodedAttestation> {
    ensure!(
        attestation.signature.alg == SignatureAlgId::SECP256K1ETH,
        "the attestation is not signed with SECP256K1ETH"
    );
    ensure!(
        attestation.header.root.alg == HashAlgId::KECCAK256,
        "the attestation's Merkle tree is not KECCAK256"
    );
    let header = bcs::to_bytes(&attestation.header).context("BCS of the header")?;
    let body: BodyView = serde_json::from_value(serde_json::to_value(&attestation.body)?)
        .context("reading the attestation body")?;
    let mut fields = vec![
        encoded(
            body.verifying_key.id,
            FieldKind::VerifyingKey,
            &body.verifying_key.data,
        )?,
        encoded(
            body.connection_info.id,
            FieldKind::ConnectionInfo,
            &body.connection_info.data,
        )?,
        encoded(
            body.server_ephemeral_key.id,
            FieldKind::ServerEphemeralKey,
            &body.server_ephemeral_key.data,
        )?,
        encoded(
            body.cert_commitment.id,
            FieldKind::CertCommitment,
            &body.cert_commitment.data,
        )?,
    ];
    for f in &body.extensions {
        fields.push(encoded(f.id, FieldKind::Extension, &f.data)?);
    }
    for f in &body.transcript_commitments {
        fields.push(encoded(f.id, FieldKind::TranscriptCommitment, &f.data)?);
    }
    fields.sort_by_key(|f| f.id);
    let root = merkle_root(&fields.iter().map(|f| f.leaf).collect::<Vec<_>>())?;
    let signature = attestation.signature.data.clone();
    ensure!(signature.len() == 65, "an ecrecover signature has 65 bytes");
    let mut sig = signature.clone();
    // tlsn writes v as 0 or 1.
    if sig[64] < 27 {
        sig[64] += 27;
    }
    let signer = Signature::from_raw(&sig)?.recover_address_from_prehash(&keccak256(&header))?;
    let header_root = attestation.header.root.value.as_bytes();
    if header_root != root.as_slice() {
        bail!(
            "recomputed root 0x{} differs from the header's 0x{}",
            hex::encode(root),
            hex::encode(header_root)
        );
    }
    Ok(EncodedAttestation {
        header,
        signature,
        signer,
        fields,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_odd_node_moves_up_unhashed() {
        let a = B256::repeat_byte(1);
        let b = B256::repeat_byte(2);
        let c = B256::repeat_byte(3);
        let ab = keccak256([a.as_slice(), b.as_slice()].concat());
        assert_eq!(merkle_root(&[a]).unwrap(), a);
        assert_eq!(merkle_root(&[a, b]).unwrap(), ab);
        assert_eq!(
            merkle_root(&[a, b, c]).unwrap(),
            keccak256([ab.as_slice(), c.as_slice()].concat())
        );
        assert!(merkle_root(&[]).is_err());
    }
}
