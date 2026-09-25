//! D26: what the presentation reveals, and the policy checks of `check_presentation`.

mod common;

use std::sync::OnceLock;

use common::{OWNER, PROPERTY, Run, attestation_verifying_key, notarize_blocking, provider};
use mock_registry::Certs;
use pprev_notary::{
    DEFAULT_MAX_SESSION_SECS, Expectation, attested_commitments, check_presentation,
};
use pprev_types::Layout;
use tlsn::attestation::presentation::Presentation;
use tlsn::attestation::signing::{Secp256k1Signer, Signer, VerifyingKey};
use tlsn::rangeset::set::RangeSet;
use tlsn::transcript::Direction;

fn run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| notarize_blocking(OWNER, PROPERTY))
}

fn presentation() -> Presentation {
    pprev_prover::present(&run().notarized, false).expect("presentation")
}

fn check(
    p: Presentation,
    layout: &Layout,
    key: &VerifyingKey,
    roots: &[Vec<u8>],
    property_id: &str,
) -> anyhow::Result<pprev_notary::Attested> {
    check_presentation(
        p,
        &Expectation {
            layout,
            attestation_key: key,
            root_certs: roots,
            property_id,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
        },
    )
}

fn check_default(p: Presentation) -> anyhow::Result<pprev_notary::Attested> {
    check(
        p,
        &run().layout,
        &attestation_verifying_key(),
        &[run().ca_der.clone()],
        PROPERTY,
    )
}

fn err_text(r: anyhow::Result<pprev_notary::Attested>) -> String {
    format!("{:#}", r.expect_err("presentation must be rejected"))
}

#[test]
fn presentation_reveals_exactly_the_d26_set() {
    let run = run();
    let output = presentation()
        .verify(&provider(&run.ca_der))
        .expect("verification");
    let transcript = output.transcript.expect("transcript");
    let request_line = run.layout.request_line(PROPERTY);
    assert_eq!(
        transcript.sent_authed(),
        &RangeSet::from(0..request_line.len())
    );
    assert_eq!(
        &transcript.sent_unsafe()[..request_line.len()],
        request_line.as_bytes()
    );
    let ranges = &run.notarized.ranges;
    assert_eq!(
        transcript.received_authed(),
        &RangeSet::from(ranges.revealed())
    );
    let template = run.layout.template().unwrap();
    for r in ranges.revealed() {
        assert_eq!(
            &transcript.received_unsafe()[r.clone()],
            &template.bytes[r.clone()]
        );
    }
    let revealed: Vec<String> = ranges
        .revealed()
        .iter()
        .map(|r| String::from_utf8_lossy(&transcript.received_unsafe()[r.clone()]).into_owned())
        .collect();
    assert_eq!(revealed[0], "HTTP/1.1 200 OK");
    assert_eq!(revealed[1], "Content-Type: application/json");
    assert!(
        revealed[2..]
            .iter()
            .all(|k| k.starts_with('"') && k.ends_with("\":"))
    );
}

#[test]
fn hidden_values_headers_and_token_are_absent_from_the_serialised_presentation() {
    // The presentation carries only the opened bytes; the hidden field values, the other response
    // values, the request headers, and the bearer token must not appear anywhere in it.
    let run = run();
    let bytes = bincode::serialize(&presentation()).unwrap();
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    for secret in [
        "ACC-000000000001",
        "ACC-000000000002",
        "000000012500000",
        "2026-09-24",
        "Authorization",
        "Host:",
    ] {
        assert!(
            !contains(secret.as_bytes()),
            "{secret} appears in the presentation"
        );
    }
    assert!(
        !contains(run.token.as_bytes()),
        "bearer token appears in the presentation"
    );
    // The property identifier is public (txData) and appears in the revealed request line.
    assert!(contains(PROPERTY.as_bytes()));
}

#[test]
fn check_presentation_accepts_the_honest_presentation() {
    let run = run();
    let attested = check_default(presentation()).expect("accepted");
    assert_eq!(attested.t_att, run.report.t_att);
    let output = presentation().verify(&provider(&run.ca_der)).unwrap();
    let commitments = attested_commitments(&output.attestation).unwrap();
    let hash_of = |r: &std::ops::Range<usize>| {
        let idx = RangeSet::from(r.clone());
        commitments
            .iter()
            .find(|c| c.direction == Direction::Received && c.idx == idx)
            .unwrap()
            .hash
            .clone()
    };
    let [account, owners, property_id] = run.notarized.ranges.hidden();
    assert_eq!(attested.account_hash, hash_of(&account));
    assert_eq!(attested.owners_hash, hash_of(&owners));
    assert_eq!(attested.property_id_hash, hash_of(&property_id));
}

#[test]
fn check_presentation_rejects_an_untrusted_attestation_key() {
    let other = Secp256k1Signer::new(&[9u8; 32]).unwrap().verifying_key();
    let r = check(
        presentation(),
        &run().layout,
        &other,
        &[run().ca_der.clone()],
        PROPERTY,
    );
    assert!(err_text(r).contains("attestation key is not trusted"));
}

#[test]
fn check_presentation_rejects_an_untrusted_registry_ca() {
    let other_ca = Certs::generate("registry.pprev.test").unwrap().ca_der;
    let r = check(
        presentation(),
        &run().layout,
        &attestation_verifying_key(),
        &[other_ca],
        PROPERTY,
    );
    assert!(err_text(r).contains("presentation does not verify"));
}

#[test]
fn check_presentation_rejects_another_property_id() {
    let r = check(
        presentation(),
        &run().layout,
        &attestation_verifying_key(),
        &[run().ca_der.clone()],
        "TR-34-KADIKOY-004567",
    );
    assert!(err_text(r).contains("revealed request line"));
}

#[test]
fn check_presentation_rejects_another_server_name() {
    let mut layout = run().layout.clone();
    layout.server_name = "other.pprev.test".into();
    let r = check(
        presentation(),
        &layout,
        &attestation_verifying_key(),
        &[run().ca_der.clone()],
        PROPERTY,
    );
    assert!(err_text(r).contains("server identity"));
}

#[test]
fn check_presentation_rejects_another_response_length() {
    let mut layout = run().layout.clone();
    layout.account_width += 1;
    let r = check(
        presentation(),
        &layout,
        &attestation_verifying_key(),
        &[run().ca_der.clone()],
        PROPERTY,
    );
    assert!(err_text(r).contains("the layout has"));
}

#[test]
fn check_presentation_rejects_revealed_field_values() {
    let revealing = pprev_prover::present(&run().notarized, true).unwrap();
    assert!(err_text(check_default(revealing)).contains("revealed response ranges differ"));
}

#[test]
fn check_presentation_rejects_a_presentation_without_a_hidden_commitment() {
    let mut v = serde_json::to_value(presentation()).unwrap();
    v["attestation"]["body"]["body"]["transcript_commitments"]
        .as_array_mut()
        .unwrap()
        .pop();
    let tampered: Presentation = serde_json::from_value(v).unwrap();
    assert!(err_text(check_default(tampered)).contains("presentation does not verify"));
}
