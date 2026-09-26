//! phi_R (Section VI-A) on crafted witnesses and on the openings of real attested sessions.
//!
//! circom's witness generator stops at the first assertion that fails. Every rejection test names
//! the assertion it expects, so a witness rejected for an unrelated reason (a malformed input, a
//! different constraint) fails the test.
//!
//! Requires the compiled circuit (`script/circuits_build.sh`).

mod common;

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{
    OWNER, PROPERTY, Run, TENANT, attestation_verifying_key, layout, notarize_blocking,
    workspace_path,
};
use num_bigint::BigUint;
use pprev_notary::{DEFAULT_MAX_SESSION_SECS, Expectation, check_presentation};
use pprev_prover::HiddenOpenings;
use pprev_prover::circuit::{
    CircuitFiles, PhiRInput, Unsatisfied, generate_witness, label_blinder, public_of,
    rendered_openings,
};
use pprev_types::TitleRecord;
use pprev_types::circuit::{PHI_R_PUBLIC_INPUTS, PhiRPublic};
use pprev_types::field::bn254_r;
use serde::Serialize;
use serde_json::Value;

const PHI_R: &str = "circuits/src/phi_r.circom";
const BITIFY: &str = "circuits/node_modules/circomlib/circuits/bitify.circom";

// Assertions of phi_r.circom, by their source text.
const OPEN_ACCOUNT: &str = "openAccount.limbs[i] === accountHash[i];";
const OPEN_OWNERS: &str = "openOwners.limbs[i] === ownersHash[i];";
const OPEN_PROPERTY: &str = "openProperty.limbs[i] === propertyHash[i];";
const ACCOUNT_NOT_EMPTY: &str = "accountIsPadding.out === 0;";
const SEPARATOR_QUOTE_1: &str = "owners[k * OWNER_STRIDE + ACCOUNT_W] === 34;";
const SEPARATOR_COMMA: &str = "owners[k * OWNER_STRIDE + ACCOUNT_W + 1] === 44;";
const SEPARATOR_QUOTE_2: &str = "owners[k * OWNER_STRIDE + ACCOUNT_W + 2] === 34;";
const ACCOUNT_IS_OWNER: &str = "noMatchUpTo[OWNER_SLOTS] === 0;";
const PROPERTY_HI: &str = "propertyHi.out === propertyId[0];";
const PROPERTY_LO: &str = "propertyLo.out * (256 ** (32 - PROPERTY_W)) === propertyId[1];";
// Range check of each byte in Num2Bits(8) (circomlib).
const BYTE_RANGE: &str = "lc1 === in;";

/// Register digest of `test-vectors/eip712.json`; above r, so `bind` is a reduced value.
const DIGEST: &str = "b9cb90d431dfd432c52ae789635458de8acdec66e1817a1aa359bc979a151564";

fn digest() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&DIGEST[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// The compiled circuit, checked to be newer than its sources.
fn files() -> &'static CircuitFiles {
    static FILES: OnceLock<CircuitFiles> = OnceLock::new();
    FILES.get_or_init(|| {
        let files = CircuitFiles::new(workspace_path("circuits"));
        let built = std::fs::metadata(files.wasm())
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| {
                panic!(
                    "{} is missing; build the circuit with script/circuits_build.sh",
                    files.wasm().display()
                )
            });
        for src in [
            PHI_R,
            "circuits/src/lib/bytes.circom",
            "circuits/src/main_title_v1.circom",
        ] {
            let modified = std::fs::metadata(workspace_path(src))
                .and_then(|m| m.modified())
                .expect("circuit source");
            assert!(
                modified <= built,
                "{src} changed after the circuit was built; rerun script/circuits_build.sh"
            );
        }
        files
    })
}

/// A directory for one witness, removed on drop.
struct WorkDir(PathBuf);

impl WorkDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pprev-phi-r-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("work dir");
        Self(dir)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Values of a `.wtns` file (iden3 binary format, version 2): a header, section 1 with the field
/// element size, the prime, and the count, section 2 with the values, all little-endian.
fn read_wtns(bytes: &[u8]) -> Vec<BigUint> {
    assert_eq!(&bytes[..4], b"wtns");
    let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
    let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()) as usize;
    let (mut n8, mut count, mut values) = (0, 0, None);
    let mut pos = 12;
    for _ in 0..u32_at(8) {
        let (kind, size, body) = (u32_at(pos), u64_at(pos + 4), pos + 12);
        match kind {
            1 => {
                n8 = u32_at(body);
                assert_eq!(
                    BigUint::from_bytes_le(&bytes[body + 4..body + 4 + n8]),
                    bn254_r()
                );
                count = u32_at(body + 4 + n8);
            }
            2 => values = Some(body),
            _ => {}
        }
        pos = body + size;
    }
    let start = values.expect("witness section");
    (0..count)
        .map(|i| BigUint::from_bytes_le(&bytes[start + i * n8..start + (i + 1) * n8]))
        .collect()
}

fn witness(input: &impl Serialize) -> anyhow::Result<Vec<BigUint>> {
    let dir = WorkDir::new();
    let path = generate_witness(files(), input, &dir.0)?;
    Ok(read_wtns(&std::fs::read(path)?))
}

/// Line of `marker` in `file`, which must contain it once.
fn line_of(file: &str, marker: &str) -> u32 {
    let text = std::fs::read_to_string(workspace_path(file)).expect("source");
    let lines: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(marker))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(lines.len(), 1, "{marker:?} must occur once in {file}");
    lines[0] as u32
}

fn accepted(input: &impl Serialize, public: &PhiRPublic) {
    let w = witness(input).unwrap_or_else(|e| panic!("phi_R rejected the witness: {e:#}"));
    // The constant 1, then the public inputs in the order of PhiRPublic::inputs.
    assert_eq!(w[0], BigUint::from(1u32));
    let expected: Vec<BigUint> = public.inputs().iter().map(|s| s.parse().unwrap()).collect();
    assert_eq!(&w[1..=PHI_R_PUBLIC_INPUTS], &expected[..]);
}

fn rejected_at(input: &impl Serialize, file: &str, template: &str, marker: &str) {
    let err = witness(input).expect_err("phi_R accepted the witness");
    let unsatisfied = err
        .downcast_ref::<Unsatisfied>()
        .unwrap_or_else(|| panic!("witness generation failed for another reason: {err:#}"));
    assert_eq!(
        unsatisfied,
        &Unsatisfied {
            template: template.into(),
            line: line_of(file, marker),
        },
        "expected the assertion `{marker}`"
    );
}

fn rejected_by_phi_r(input: &impl Serialize, marker: &str) {
    rejected_at(input, PHI_R, "PhiR", marker);
}

/// Openings of the hidden fields of a response rendered with the registry's layout for `account`
/// viewing a record with `owners`, with fixed blinders.
fn crafted(account: &str, owners: &[&str], property: &str) -> HiddenOpenings {
    let record = TitleRecord {
        property_id: property.into(),
        owners: owners.iter().map(|s| s.to_string()).collect(),
        encumbrance: "N".into(),
        assessed_value: "000000012500000".into(),
        record_date: "2026-09-24".into(),
    };
    rendered_openings(
        &layout(),
        account,
        &record,
        ["account", "owners", "propertyId"].map(label_blinder),
    )
    .expect("render")
}

fn property_word(property: &str) -> [u8; 32] {
    layout().property_id_word(property).expect("property id")
}

/// Witness input whose public commitments are recomputed from the openings.
fn honest(openings: &HiddenOpenings, property: &str) -> (PhiRInput, PhiRPublic) {
    let public = public_of(openings, property_word(property), digest());
    (PhiRInput::new(&public, openings), public)
}

fn as_json(input: &PhiRInput) -> Value {
    serde_json::to_value(input).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Real sessions

fn run_of(account: (&'static str, &'static str)) -> &'static Run {
    static OWNER_RUN: OnceLock<Run> = OnceLock::new();
    static TENANT_RUN: OnceLock<Run> = OnceLock::new();
    let cell = if account == OWNER {
        &OWNER_RUN
    } else {
        &TENANT_RUN
    };
    cell.get_or_init(|| notarize_blocking(account, PROPERTY))
}

/// The public side as the policy verifier derives it: commitments from the checked presentation.
fn verifier_public(run: &Run) -> PhiRPublic {
    let presentation = pprev_prover::present(&run.notarized, false).expect("presentation");
    let attested = check_presentation(
        presentation,
        &Expectation {
            layout: &run.layout,
            attestation_key: &attestation_verifying_key(),
            root_certs: std::slice::from_ref(&run.ca_der),
            property_id: PROPERTY,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
        },
    )
    .expect("policy checks");
    attested
        .phi_r_public(property_word(PROPERTY), digest())
        .expect("public inputs")
}

#[test]
fn owner_session_satisfies_phi_r() {
    let run = run_of(OWNER);
    let public = verifier_public(run);
    // The prover's own view of the public side agrees with the verifier's.
    assert_eq!(
        public_of(&run.notarized.openings, property_word(PROPERTY), digest()),
        public
    );
    accepted(&PhiRInput::new(&public, &run.notarized.openings), &public);
}

#[test]
fn tenant_session_has_no_witness() {
    let run = run_of(TENANT);
    assert_eq!(
        run.notarized.openings.account.plaintext,
        TENANT.0.as_bytes()
    );
    let public = verifier_public(run);
    rejected_by_phi_r(
        &PhiRInput::new(&public, &run.notarized.openings),
        ACCOUNT_IS_OWNER,
    );
}

// ---------------------------------------------------------------------------------------------
// Crafted witnesses: accepted

#[test]
fn an_owner_in_any_slot_satisfies_phi_r() {
    let owners = [
        "ACC-000000000001",
        "ACC-000000000002",
        "ACC-000000000004",
        "ACC-000000000005",
    ];
    for account in owners {
        let (input, public) = honest(&crafted(account, &owners, PROPERTY), PROPERTY);
        accepted(&input, &public);
    }
    let (input, public) = honest(&crafted(OWNER.0, &[OWNER.0], PROPERTY), PROPERTY);
    accepted(&input, &public);
}

#[test]
fn a_short_identifier_matches_with_its_padding() {
    let (input, public) = honest(&crafted("ACC-7", &["ACC-7"], "TR-06-X"), "TR-06-X");
    accepted(&input, &public);
}

// ---------------------------------------------------------------------------------------------
// Crafted witnesses: rejected

#[test]
fn an_account_outside_the_owner_list_is_rejected() {
    let owners = [OWNER.0, "ACC-000000000002"];
    let (input, _) = honest(&crafted(TENANT.0, &owners, PROPERTY), PROPERTY);
    rejected_by_phi_r(&input, ACCOUNT_IS_OWNER);
    // A prefix of an owner's identifier is a different padded value.
    let (input, _) = honest(&crafted("ACC-00000000000", &owners, PROPERTY), PROPERTY);
    rejected_by_phi_r(&input, ACCOUNT_IS_OWNER);
}

#[test]
fn an_empty_account_does_not_match_an_empty_slot() {
    let (input, _) = honest(&crafted("", &[OWNER.0], PROPERTY), PROPERTY);
    rejected_by_phi_r(&input, ACCOUNT_NOT_EMPTY);
}

#[test]
fn another_property_id_is_rejected() {
    let openings = crafted(OWNER.0, &[OWNER.0], PROPERTY);
    // Differs in the first 16 bytes.
    let public = public_of(&openings, property_word("TR-34-KADIKOY-004567"), digest());
    rejected_by_phi_r(&PhiRInput::new(&public, &openings), PROPERTY_HI);
    // Differs only in the last 4 bytes.
    let public = public_of(&openings, property_word("TR-06-CANKAYA-000124"), digest());
    rejected_by_phi_r(&PhiRInput::new(&public, &openings), PROPERTY_LO);
    // Nonzero byte in the 12-byte tail.
    let mut word = property_word(PROPERTY);
    word[31] = 1;
    let public = public_of(&openings, word, digest());
    rejected_by_phi_r(&PhiRInput::new(&public, &openings), PROPERTY_LO);
}

#[test]
fn a_zero_padded_short_property_id_is_rejected() {
    let openings = crafted(OWNER.0, &[OWNER.0], "TR-06-X");
    let mut word = [0u8; 32];
    word[..7].copy_from_slice(b"TR-06-X");
    let public = public_of(&openings, word, digest());
    rejected_by_phi_r(&PhiRInput::new(&public, &openings), PROPERTY_HI);
}

#[test]
fn a_changed_value_does_not_open_its_commitment() {
    let tenant = crafted(TENANT.0, &[OWNER.0], PROPERTY);
    let (base, _) = honest(&tenant, PROPERTY);

    // The tenant writes itself into an empty owner slot.
    let mut input = base.clone();
    let slot = layout().ranges().unwrap().owner_slot_offsets[1];
    input.owners[slot..slot + TENANT.0.len()].copy_from_slice(TENANT.0.as_bytes());
    rejected_by_phi_r(&input, OPEN_OWNERS);

    // The tenant claims an owner's account identifier.
    let mut input = base.clone();
    input.account = OWNER.0.as_bytes().to_vec();
    rejected_by_phi_r(&input, OPEN_ACCOUNT);

    let mut input = base.clone();
    input.property[19] ^= 1;
    rejected_by_phi_r(&input, OPEN_PROPERTY);
}

#[test]
fn a_changed_blinder_does_not_open_its_commitment() {
    let (base, _) = honest(&crafted(OWNER.0, &[OWNER.0], PROPERTY), PROPERTY);
    let mut input = base.clone();
    input.account_blinder[0] ^= 1;
    rejected_by_phi_r(&input, OPEN_ACCOUNT);
    let mut input = base.clone();
    input.owners_blinder[15] ^= 0x80;
    rejected_by_phi_r(&input, OPEN_OWNERS);
    let mut input = base.clone();
    input.property_blinder[7] ^= 1;
    rejected_by_phi_r(&input, OPEN_PROPERTY);
}

#[test]
fn a_changed_public_commitment_is_rejected() {
    let (base, _) = honest(&crafted(OWNER.0, &[OWNER.0], PROPERTY), PROPERTY);
    let bump = |limb: &str| (limb.parse::<BigUint>().unwrap() ^ BigUint::from(1u32)).to_string();
    for (field, marker) in [
        ("accountHash", OPEN_ACCOUNT),
        ("ownersHash", OPEN_OWNERS),
        ("propertyHash", OPEN_PROPERTY),
    ] {
        for limb in 0..2 {
            let mut input = as_json(&base);
            let value = bump(input[field][limb].as_str().unwrap());
            input[field][limb] = Value::String(value);
            rejected_by_phi_r(&input, marker);
        }
    }
}

#[test]
fn misplaced_separators_are_rejected() {
    let openings = crafted(OWNER.0, &[OWNER.0, "ACC-000000000002"], PROPERTY);
    let slots = layout().ranges().unwrap().owner_slot_offsets;
    let width = layout().account_width;
    // Separators after the first and after the third slot.
    for k in [0, 2] {
        for (j, marker) in [SEPARATOR_QUOTE_1, SEPARATOR_COMMA, SEPARATOR_QUOTE_2]
            .into_iter()
            .enumerate()
        {
            let mut changed = openings.clone();
            changed.owners.plaintext[slots[k] + width + j] = b'X';
            // Commitments recomputed: only the separator assertion can fail.
            let (input, _) = honest(&changed, PROPERTY);
            rejected_by_phi_r(&input, marker);
        }
    }
}

#[test]
fn a_byte_above_255_is_rejected() {
    // account[14] - 1 and account[15] + 256 keep the packed account value, so only the byte range
    // check separates this witness from the honest one.
    let (base, _) = honest(&crafted(OWNER.0, &[OWNER.0], PROPERTY), PROPERTY);
    let mut input = as_json(&base);
    let a14 = input["account"][14].as_u64().unwrap();
    let a15 = input["account"][15].as_u64().unwrap();
    input["account"][14] = (a14 - 1).into();
    input["account"][15] = (a15 + 256).into();
    rejected_at(&input, BITIFY, "Num2Bits", BYTE_RANGE);
}
