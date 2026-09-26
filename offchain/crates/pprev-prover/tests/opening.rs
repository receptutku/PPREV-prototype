//! The blinder opening computed in Rust yields the hash that the attestation records (D3). The phi_R
//! circuit repeats this computation: SHA-256(plaintext || blinder), TLSNotary's convention
//! (tlsn `core/src/transcript/hash.rs`, `hash_plaintext`, with a 16-byte blinder).

mod common;

use std::sync::OnceLock;

use common::{OWNER, PROPERTY, Run, notarize_blocking, provider};
use pprev_notary::{CommittedHash, attested_commitments};
use pprev_prover::FieldOpening;
use sha2::{Digest, Sha256};
use tlsn::rangeset::set::RangeSet;
use tlsn::transcript::Direction;

fn run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| notarize_blocking(OWNER, PROPERTY))
}

fn attested() -> Vec<CommittedHash> {
    let output = pprev_prover::present(&run().notarized, false)
        .expect("presentation")
        .verify(&provider(&run().ca_der))
        .expect("verification");
    attested_commitments(&output.attestation).expect("commitments")
}

fn openings() -> [(&'static str, &'static FieldOpening); 3] {
    let o = &run().notarized.openings;
    [
        ("account", &o.account),
        ("owners", &o.owners),
        ("propertyId", &o.property_id),
    ]
}

fn attested_hash(commitments: &[CommittedHash], opening: &FieldOpening) -> Vec<u8> {
    let idx = RangeSet::from(opening.range.clone());
    commitments
        .iter()
        .find(|c| c.direction == Direction::Received && c.idx == idx)
        .expect("commitment for the opening's range")
        .hash
        .clone()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

#[test]
fn blinder_opening_yields_the_attested_hash() {
    let commitments = attested();
    let sent = &run().sent_log[0];
    for (name, opening) in openings() {
        assert_eq!(
            sha256(&[&opening.plaintext, &opening.blinder]),
            attested_hash(&commitments, opening),
            "{name}"
        );
        // The opened plaintext is the registry's bytes at the committed range.
        assert_eq!(
            &opening.plaintext[..],
            &sent[opening.range.clone()],
            "{name}"
        );
    }
    let o = &run().notarized.openings;
    assert_eq!(o.account.plaintext, OWNER.0.as_bytes());
    assert_eq!(o.property_id.plaintext, PROPERTY.as_bytes());
    assert_eq!(o.owners.plaintext.len(), 73);
}

#[test]
fn order_and_blinder_matter() {
    let commitments = attested();
    for (name, opening) in openings() {
        let expected = attested_hash(&commitments, opening);
        assert_ne!(
            sha256(&[&opening.blinder, &opening.plaintext]),
            expected,
            "{name}: blinder first"
        );
        let mut flipped = opening.blinder;
        flipped[0] ^= 1;
        assert_ne!(
            sha256(&[&opening.plaintext, &flipped]),
            expected,
            "{name}: altered blinder"
        );
        assert_ne!(
            sha256(&[&opening.plaintext]),
            expected,
            "{name}: no blinder"
        );
    }
}
