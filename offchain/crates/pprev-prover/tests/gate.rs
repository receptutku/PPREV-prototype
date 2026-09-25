//! D3 gate. Before the circuit relies on field-range commitments, these tests establish that:
//!
//! - G1: each commitment's direction, index set, and hash are bound by the notary's signature, so
//!   altering them in a presentation fails `Presentation::verify`;
//! - G2: the committed bytes are the bytes the registry sent;
//! - G3: after verification, the verifier can read the index sets of the hidden commitments.
//!
//! All tests share one MPC-TLS session. G1 and G3 check tlsn's own verification, not the policy
//! checks in `check_presentation`, which compare index sets with the layout and would reject a
//! tampered presentation regardless of the signature.

mod common;

use std::ops::Range;
use std::sync::OnceLock;

use common::{OWNER, PROPERTY, Run, notarize_blocking, provider};
use pprev_notary::{T_ATT_EXTENSION_ID, attested_commitments};
use serde_json::Value;
use tlsn::attestation::presentation::Presentation;
use tlsn::hash::HashAlgId;
use tlsn::rangeset::set::RangeSet;
use tlsn::transcript::hash::PlaintextHash;
use tlsn::transcript::{Direction, TranscriptCommitment};

fn run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| notarize_blocking(OWNER, PROPERTY))
}

/// The presentation the policy verifier receives: field values hidden.
fn presentation() -> Presentation {
    pprev_prover::present(&run().notarized, false).expect("presentation")
}

fn verifies(p: Presentation) -> bool {
    p.verify(&provider(&run().ca_der)).is_ok()
}

/// True if verification fails at the attestation body's Merkle proof, the layer that binds every
/// body field to the root the notary signed.
fn rejected_by_body_proof(p: Presentation) -> bool {
    match p.verify(&provider(&run().ca_der)) {
        Ok(_) => false,
        Err(e) => {
            let msg = format!("{e:#}");
            msg.contains("body proof error") && msg.contains("invalid merkle proof")
        }
    }
}

fn to_json(p: &Presentation) -> Value {
    serde_json::to_value(p).expect("serialise presentation")
}

fn from_json(v: Value) -> Presentation {
    serde_json::from_value(v).expect("deserialise presentation")
}

fn body(v: &mut Value) -> &mut Value {
    &mut v["attestation"]["body"]["body"]
}

fn commitments(v: &mut Value) -> &mut Vec<Value> {
    body(v)["transcript_commitments"]
        .as_array_mut()
        .expect("transcript_commitments array")
}

/// Position of the commitment to `range` in the received direction.
fn position_of(v: &mut Value, range: &Range<usize>) -> usize {
    let idx = RangeSet::from(range.clone());
    commitments(v)
        .iter()
        .position(|field| {
            match serde_json::from_value::<TranscriptCommitment>(field["data"].clone()) {
                Ok(TranscriptCommitment::Hash(h)) => {
                    h.direction == Direction::Received && h.idx == idx
                }
                _ => false,
            }
        })
        .expect("commitment for range")
}

fn plaintext_hash(field: &Value) -> PlaintextHash {
    match serde_json::from_value::<TranscriptCommitment>(field["data"].clone()).expect("commitment")
    {
        TranscriptCommitment::Hash(h) => h,
        #[allow(unreachable_patterns)]
        _ => panic!("unexpected commitment kind"),
    }
}

fn replace(v: &mut Value, pos: usize, h: PlaintextHash) {
    commitments(v)[pos]["data"] =
        serde_json::to_value(TranscriptCommitment::Hash(h)).expect("serialise commitment");
}

fn hidden() -> [(&'static str, Range<usize>); 3] {
    let [account, owners, property_id] = run().notarized.ranges.hidden();
    [
        ("account", account),
        ("owners", owners),
        ("propertyId", property_id),
    ]
}

// ---------------------------------------------------------------------------------------- G1

#[test]
fn g1_control_untampered_presentation_verifies_after_json_round_trip() {
    assert!(verifies(from_json(to_json(&presentation()))));
}

#[test]
fn g1_shifted_index_set_is_rejected() {
    for (name, range) in hidden() {
        let mut v = to_json(&presentation());
        let pos = position_of(&mut v, &range);
        let mut h = plaintext_hash(&commitments(&mut v)[pos]);
        h.idx = RangeSet::from(range.start + 1..range.end + 1);
        replace(&mut v, pos, h);
        assert!(
            rejected_by_body_proof(from_json(v)),
            "shifted index set of {name} was not rejected by the body proof"
        );
    }
}

#[test]
fn g1_narrowed_index_set_is_rejected() {
    for (name, range) in hidden() {
        let mut v = to_json(&presentation());
        let pos = position_of(&mut v, &range);
        let mut h = plaintext_hash(&commitments(&mut v)[pos]);
        h.idx = RangeSet::from(range.start..range.end - 1);
        replace(&mut v, pos, h);
        assert!(
            rejected_by_body_proof(from_json(v)),
            "narrowed index set of {name} was not rejected by the body proof"
        );
    }
}

#[test]
fn g1_flipped_direction_is_rejected() {
    for (name, range) in hidden() {
        let mut v = to_json(&presentation());
        let pos = position_of(&mut v, &range);
        let mut h = plaintext_hash(&commitments(&mut v)[pos]);
        h.direction = Direction::Sent;
        replace(&mut v, pos, h);
        assert!(
            rejected_by_body_proof(from_json(v)),
            "flipped direction of {name} was not rejected by the body proof"
        );
    }
}

#[test]
fn g1_altered_hash_is_rejected() {
    for (name, range) in hidden() {
        let mut v = to_json(&presentation());
        let pos = position_of(&mut v, &range);
        let byte = &mut commitments(&mut v)[pos]["data"]["Hash"]["hash"]["value"][0];
        *byte = Value::from((byte.as_u64().expect("hash byte") + 1) % 256);
        assert!(
            rejected_by_body_proof(from_json(v)),
            "altered hash of {name} was not rejected by the body proof"
        );
    }
}

#[test]
fn g1_removed_commitment_is_rejected() {
    for (name, range) in hidden() {
        let mut v = to_json(&presentation());
        let pos = position_of(&mut v, &range);
        commitments(&mut v).remove(pos);
        assert!(
            rejected_by_body_proof(from_json(v)),
            "presentation without the {name} commitment was not rejected by the body proof"
        );
    }
}

#[test]
fn g1_altered_opened_commitment_index_is_rejected() {
    // The commitment that the presentation opens (response structure) is bound the same way.
    let mut v = to_json(&presentation());
    let revealed = RangeSet::from(run().notarized.ranges.revealed());
    let pos = commitments(&mut v)
        .iter()
        .position(|f| plaintext_hash(f).idx == revealed)
        .expect("opened commitment");
    let mut h = plaintext_hash(&commitments(&mut v)[pos]);
    let first = run().notarized.ranges.status_line.clone();
    h.idx = RangeSet::from(first.start + 1..first.end + 1);
    replace(&mut v, pos, h);
    assert!(rejected_by_body_proof(from_json(v)));
}

#[test]
fn g1_altered_t_att_extension_is_rejected() {
    let mut v = to_json(&presentation());
    let extensions = body(&mut v)["extensions"]
        .as_array_mut()
        .expect("extensions");
    let ext = extensions
        .iter_mut()
        .find(|e| {
            serde_json::from_value::<Vec<u8>>(e["data"]["id"].clone())
                .ok()
                .as_deref()
                == Some(T_ATT_EXTENSION_ID)
        })
        .expect("t_att extension");
    let last = ext["data"]["value"]
        .as_array_mut()
        .expect("value")
        .last_mut()
        .expect("byte");
    *last = Value::from((last.as_u64().expect("byte") + 1) % 256);
    assert!(rejected_by_body_proof(from_json(v)));
}

#[test]
fn g1_altered_connection_time_is_rejected() {
    let mut v = to_json(&presentation());
    let time = &mut body(&mut v)["connection_info"]["data"]["time"];
    *time = Value::from(time.as_u64().expect("time") - 1);
    assert!(rejected_by_body_proof(from_json(v)));
}

// ---------------------------------------------------------------------------------------- G2

#[test]
fn g2_committed_bytes_are_the_bytes_the_registry_sent() {
    let run = run();
    assert_eq!(run.sent_log.len(), 1, "one title response");
    let sent = &run.sent_log[0];
    // Opening the hidden commitments makes tlsn check SHA-256(bytes ‖ blinder) against the attested
    // hash; the opened bytes must then equal the registry's own record.
    let output = pprev_prover::present(&run.notarized, true)
        .expect("presentation")
        .verify(&provider(&run.ca_der))
        .expect("verification");
    let transcript = output.transcript.expect("transcript");
    for (name, range) in hidden() {
        assert!(
            range
                .clone()
                .all(|i| transcript.received_authed().contains(&i)),
            "{name} not opened"
        );
        assert_eq!(
            &transcript.received_unsafe()[range.clone()],
            &sent[range.clone()],
            "{name} differs from the registry's bytes"
        );
    }
    assert_eq!(
        &sent[run.notarized.ranges.account.clone()],
        OWNER.0.as_bytes()
    );
    assert_eq!(
        &sent[run.notarized.ranges.property_id.clone()],
        PROPERTY.as_bytes()
    );
}

#[test]
fn g2_opening_with_altered_bytes_is_rejected() {
    // A presentation that opens a hidden commitment with other bytes fails against the attested hash.
    // The serialised transcript carries only the opened bytes, concatenated in index order.
    let ranges = &run().notarized.ranges;
    let mut opened: Vec<Range<usize>> = ranges.revealed();
    opened.extend(ranges.hidden());
    opened.sort_by_key(|r| r.start);
    let account = ranges.account.clone();
    let pos: usize = opened
        .iter()
        .take_while(|r| r.start < account.start)
        .map(|r| r.len())
        .sum();
    let mut v = to_json(&pprev_prover::present(&run().notarized, true).expect("presentation"));
    let received = v["transcript"]["transcript"]["received_authed"]
        .as_array_mut()
        .expect("opened received bytes");
    assert_eq!(
        received[pos],
        Value::from(OWNER.0.as_bytes()[0]),
        "position of the account value"
    );
    received[pos] = Value::from(b'X');
    assert!(!verifies(from_json(v)));
}

// ---------------------------------------------------------------------------------------- G3

#[test]
fn g3_verifier_reads_the_hidden_index_sets() {
    let run = run();
    let output = presentation()
        .verify(&provider(&run.ca_der))
        .expect("verification");
    let commitments = attested_commitments(&output.attestation).expect("commitments");
    assert_eq!(commitments.len(), 5);
    for (name, range) in hidden() {
        let idx = RangeSet::from(range.clone());
        let c = commitments
            .iter()
            .find(|c| c.direction == Direction::Received && c.idx == idx)
            .unwrap_or_else(|| panic!("no commitment for {name}"));
        assert_eq!(c.alg, HashAlgId::SHA256, "{name} is not SHA-256");
        assert_eq!(c.hash.len(), 32);
        // The hidden value itself is not revealed.
        let transcript = output.transcript.as_ref().expect("transcript");
        assert!(
            range
                .clone()
                .all(|i| !transcript.received_authed().contains(&i)),
            "{name} is revealed"
        );
    }
    let request = RangeSet::from(0..run.notarized.request_line_len);
    assert!(
        commitments
            .iter()
            .any(|c| c.direction == Direction::Sent && c.idx == request)
    );
}

// ------------------------------------------------------------------ G3: tlsn layout golden test

const LAYOUT_CHANGED: &str = "tlsn internal layout changed, update attested_commitments \
     (offchain/crates/pprev-notary/src/presentation.rs), then regenerate \
     offchain/crates/pprev-prover/tests/golden/tlsn-body-layout.json with PPREV_UPDATE_GOLDEN=1";

fn golden_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/tlsn-body-layout.json")
}

/// The tlsn tag pinned in the workspace manifest.
fn pinned_tlsn_tag() -> String {
    let manifest =
        std::fs::read_to_string(common::workspace_path("Cargo.toml")).expect("Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("tlsn ="))
        .expect("tlsn dependency");
    let tag = line
        .split("tag = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next());
    tag.expect("tlsn tag").to_string()
}

fn sorted_keys(v: &Value) -> Value {
    let mut keys: Vec<&String> = v
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    keys.sort();
    serde_json::json!(keys)
}

/// What `attested_commitments` relies on in the serialised attestation body: the body's field names,
/// the keys of a commitment field and of a plaintext hash, and how the account commitment's
/// direction, index set, and hash appear.
fn body_layout(body: &Value, account: &Range<usize>) -> Value {
    let commitments = body["transcript_commitments"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let first = commitments.first().cloned().unwrap_or(Value::Null);
    let account_idx = RangeSet::from(account.clone());
    let account_commitment = commitments.iter().find(|field| {
        serde_json::from_value::<TranscriptCommitment>(field["data"].clone())
            .map(|c| matches!(c, TranscriptCommitment::Hash(h) if h.idx == account_idx))
            .unwrap_or(false)
    });
    let account_view = account_commitment.map(|field| {
        let h = &field["data"]["Hash"];
        serde_json::json!({
            "direction": h["direction"],
            "idx": h["idx"],
            "alg": h["hash"]["alg"],
            "valueLength": h["hash"]["value"].as_array().map(|a| a.len()),
        })
    });
    serde_json::json!({
        "tlsnTag": pinned_tlsn_tag(),
        "bodyFields": sorted_keys(body),
        "commitmentFieldKeys": sorted_keys(&first),
        "commitmentVariants": sorted_keys(&first["data"]),
        "plaintextHashKeys": sorted_keys(&first["data"]["Hash"]),
        "typedHashKeys": sorted_keys(&first["data"]["Hash"]["hash"]),
        "accountCommitment": account_view,
    })
}

#[test]
fn g3_attestation_body_layout_matches_golden() {
    let run = run();
    let output = presentation()
        .verify(&provider(&run.ca_der))
        .expect("verification");
    let body = serde_json::to_value(&output.attestation.body).expect("serialise body");
    let actual = body_layout(&body, &run.notarized.ranges.account);

    if std::env::var_os("PPREV_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden_path().parent().unwrap()).unwrap();
        std::fs::write(
            golden_path(),
            serde_json::to_string_pretty(&actual).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let expected: Value = std::fs::read_to_string(golden_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| panic!("{LAYOUT_CHANGED}: golden file missing or unreadable"));
    assert!(
        actual == expected,
        "{LAYOUT_CHANGED}\nexpected: {}\nactual:   {}",
        serde_json::to_string(&expected).unwrap(),
        serde_json::to_string(&actual).unwrap()
    );
    // The reader agrees with the layout it depends on.
    let commitments = attested_commitments(&output.attestation)
        .unwrap_or_else(|e| panic!("{LAYOUT_CHANGED}: {e:#}"));
    assert_eq!(
        commitments.len(),
        body["transcript_commitments"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
    );
}
