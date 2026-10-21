//! phi_A and phi_S (Section VI-A) on crafted witnesses.
//!
//! circom's witness generator stops at the first assertion that fails. Every rejection test names
//! the assertion it expects, so a witness rejected for an unrelated reason fails the test. The
//! commitments are always recomputed from the openings, so a rejection comes from the predicate
//! itself and not from a stale commitment.
//!
//! Requires the compiled circuits (`script/circuits_build_as.sh`).

// Dates are written Y_MM_DD, as phi_S encodes them.
#![allow(clippy::inconsistent_digit_grouping)]

mod common;

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::U256;
use common::workspace_path;
use num_bigint::BigUint;
use pprev_notary::mock::counterparty_commitment;
use pprev_prover::FieldOpening;
use pprev_prover::circuit::{
    CircuitFiles, PhiAInput, PhiSInput, Unsatisfied, commitment, generate_witness, label_blinder,
    record_openings,
};
use pprev_types::RecordLayout;
use pprev_types::circuit::{PHI_A_PUBLIC_INPUTS, PHI_S_PUBLIC_INPUTS, PhiAPublic, PhiSPublic};
use pprev_types::field::bn254_r;
use serde::Serialize;
use serde_json::Value;

const PHI_A: &str = "circuits/src/phi_a.circom";
const PHI_S: &str = "circuits/src/phi_s.circom";
const DATE: &str = "circuits/src/lib/date.circom";
const DECIMAL: &str = "circuits/src/lib/decimal.circom";
const BITIFY: &str = "circuits/node_modules/circomlib/circuits/bitify.circom";

// Assertions, by their source text.
const A_OPEN_ACCOUNT: &str = "openAccount.limbs[i] === accountHash[i];";
const A_OPEN_INCOME: &str = "openIncome.limbs[i] === incomeHash[i];";
const A_ACCOUNT_NOT_EMPTY: &str = "accountIsPadding.out === 0;";
const A_C_B: &str = "commitment.out === cB;";
const A_ENOUGH: &str = "enough.out === 1;";
const S_OPEN_DATE: &str = "openDate.limbs[i] === dateHash[i];";
const S_PROPERTY_HI: &str = "propertyHi.out === propertyId[0];";
const S_PROPERTY_LO: &str = "propertyLo.out * (256 ** (32 - PROPERTY_W)) === propertyId[1];";
const S_TENANT_NOT_EMPTY: &str = "tenantIsPadding.out === 0;";
const S_C_B: &str = "commitment.out === cB;";
const S_NOT_BEFORE: &str = "notBefore.out === 1;";
const SEPARATOR_1: &str = "date[4] === 45;";
const SEPARATOR_2: &str = "date[7] === 45;";
const MONTH_NOT_ZERO: &str = "monthZero.out === 0;";
const MONTH_MAX: &str = "monthMax.out === 1;";
const DAY_NOT_ZERO: &str = "dayZero.out === 0;";
const DAY_MAX: &str = "dayMax.out === 1;";
const DIGIT_BELOW_10: &str = "below10.out === 1;";
// Range check of Num2Bits (circomlib).
const NUM2BITS: &str = "lc1 === in;";

const TENANT: &str = "ACC-000000000003";
const OTHER: &str = "ACC-000000000002";
const LANDLORD: &str = "ACC-000000000001";
const PROPERTY: &str = "TR-06-CANKAYA-000123";
const OTHER_PROPERTY: &str = "TR-34-KADIKOY-004567";
/// txData.amount: 1 ETH, in wei.
const RENT: u64 = 1_000_000_000_000_000_000;
const DIGEST: [u8; 32] = [0xd7; 32];

fn layout(name: &str) -> RecordLayout {
    RecordLayout::load(workspace_path(&format!("policies/layouts/{name}.json"))).expect("layout")
}

fn salt() -> [u8; 32] {
    let mut salt = [0x5a; 32];
    salt[0] = 0x01;
    salt
}

fn c_b(identifier: &str) -> [u8; 32] {
    counterparty_commitment(identifier.as_bytes(), &salt())
        .expect("c_B")
        .0
}

/// A compiled circuit, checked to be newer than its sources.
fn built(files: CircuitFiles, sources: &[&str]) -> CircuitFiles {
    let built = std::fs::metadata(files.wasm())
        .and_then(|m| m.modified())
        .unwrap_or_else(|_| {
            panic!(
                "{} is missing; build the circuits with script/circuits_build_as.sh",
                files.wasm().display()
            )
        });
    for src in sources {
        let modified = std::fs::metadata(workspace_path(src))
            .and_then(|m| m.modified())
            .expect("circuit source");
        assert!(
            modified <= built,
            "{src} changed after the circuit was built; rerun script/circuits_build_as.sh"
        );
    }
    files
}

fn phi_a_files() -> &'static CircuitFiles {
    static FILES: OnceLock<CircuitFiles> = OnceLock::new();
    FILES.get_or_init(|| {
        built(
            CircuitFiles::phi_a(workspace_path("circuits")),
            &[
                PHI_A,
                DECIMAL,
                "circuits/src/lib/bytes.circom",
                "circuits/src/main_income_v1.circom",
            ],
        )
    })
}

fn phi_s_files() -> &'static CircuitFiles {
    static FILES: OnceLock<CircuitFiles> = OnceLock::new();
    FILES.get_or_init(|| {
        built(
            CircuitFiles::phi_s(workspace_path("circuits")),
            &[
                PHI_S,
                DATE,
                DECIMAL,
                "circuits/src/lib/bytes.circom",
                "circuits/src/main_tenancy_v1.circom",
            ],
        )
    })
}

/// A directory for one witness, removed on drop.
struct WorkDir(PathBuf);

impl WorkDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pprev-phases-{}-{}",
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

/// Public inputs of a `.wtns` file (iden3 binary format, version 2): after the constant 1.
fn public_of_witness(bytes: &[u8], count: usize) -> Vec<BigUint> {
    assert_eq!(&bytes[..4], b"wtns");
    let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
    let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()) as usize;
    let (mut n8, mut values) = (0, None);
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
            }
            2 => values = Some(body),
            _ => {}
        }
        pos = body + size;
    }
    let start = values.expect("witness section");
    let value = |i: usize| BigUint::from_bytes_le(&bytes[start + i * n8..start + (i + 1) * n8]);
    assert_eq!(value(0), BigUint::from(1u32));
    (1..=count).map(value).collect()
}

fn witness(
    files: &CircuitFiles,
    input: &impl Serialize,
    count: usize,
) -> anyhow::Result<Vec<BigUint>> {
    let dir = WorkDir::new();
    let path = generate_witness(files, input, &dir.0)?;
    Ok(public_of_witness(&std::fs::read(path)?, count))
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

fn rejected_at(
    files: &CircuitFiles,
    input: &impl Serialize,
    file: &str,
    template: &str,
    marker: &str,
) {
    let err = witness(files, input, 0).expect_err("the circuit accepted the witness");
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

fn json(input: &impl Serialize) -> Value {
    serde_json::to_value(input).unwrap()
}

// ---------------------------------------------------------------------------------------------
// phi_A

fn income_openings(account: &str, income: &str) -> Vec<FieldOpening> {
    record_openings(
        &layout("income-v1"),
        account,
        &[income],
        &["account", "monthlyIncome"].map(label_blinder),
    )
    .expect("render")
}

fn phi_a(openings: &[FieldOpening], c_b: [u8; 32], amount: U256) -> (PhiAInput, PhiAPublic) {
    let public = PhiAPublic::new(
        commitment(&openings[0]),
        commitment(&openings[1]),
        c_b,
        amount,
        DIGEST,
    )
    .expect("public");
    (
        PhiAInput::new(&public, openings, &salt()).expect("input"),
        public,
    )
}

fn phi_a_accepted(input: &PhiAInput, public: &PhiAPublic) {
    let w = witness(phi_a_files(), input, PHI_A_PUBLIC_INPUTS)
        .unwrap_or_else(|e| panic!("phi_A rejected the witness: {e:#}"));
    let expected: Vec<BigUint> = public.inputs().iter().map(|s| s.parse().unwrap()).collect();
    assert_eq!(w, expected);
}

fn phi_a_rejected(input: &impl Serialize, marker: &str) {
    rejected_at(phi_a_files(), input, PHI_A, "PhiA", marker);
}

#[test]
fn phi_a_holds_at_exactly_the_income_multiple() {
    let openings = income_openings(TENANT, "03000000000000000000");
    let (input, public) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    phi_a_accepted(&input, &public);
    let openings = income_openings(TENANT, "03500000000000000000");
    let (input, public) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    phi_a_accepted(&input, &public);
}

#[test]
fn phi_a_fails_one_unit_below_the_income_multiple() {
    let openings = income_openings(TENANT, "02999999999999999999");
    let (input, _) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    phi_a_rejected(&input, A_ENOUGH);
}

#[test]
fn phi_a_fails_when_c_b_names_another_account() {
    let openings = income_openings(TENANT, "03500000000000000000");
    let (input, _) = phi_a(&openings, c_b(OTHER), U256::from(RENT));
    phi_a_rejected(&input, A_C_B);
    // The right identifier with another salt.
    let (mut input, _) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    input.salt = "7".into();
    phi_a_rejected(&input, A_C_B);
}

#[test]
fn phi_a_fails_for_an_empty_account() {
    let openings = income_openings("", "03500000000000000000");
    let blank = " ".repeat(16);
    let (input, _) = phi_a(&openings, c_b(&blank), U256::from(RENT));
    phi_a_rejected(&input, A_ACCOUNT_NOT_EMPTY);
}

#[test]
fn phi_a_fails_when_an_opening_does_not_match_its_commitment() {
    let openings = income_openings(TENANT, "03500000000000000000");
    let (input, _) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    let mut v = json(&input);
    v["accountHash"][1] = "1".into();
    phi_a_rejected(&v, A_OPEN_ACCOUNT);
    let mut v = json(&input);
    v["incomeHash"][0] = "1".into();
    phi_a_rejected(&v, A_OPEN_INCOME);
}

#[test]
fn phi_a_reads_decimal_digits_only() {
    // A padded value: the registry writes numbers zero-padded, never space-padded.
    let openings = income_openings(TENANT, "3500000000000000000");
    let (input, _) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    rejected_at(phi_a_files(), &input, BITIFY, "Num2Bits", NUM2BITS);
    // ':' follows '9': a digit value of 10.
    let openings = income_openings(TENANT, "0350000000000000000:");
    let (input, _) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    rejected_at(phi_a_files(), &input, DECIMAL, "Digit", DIGIT_BELOW_10);
}

#[test]
fn phi_a_bounds_the_amount() {
    let openings = income_openings(TENANT, "99999999999999999999");
    let max = (U256::from(1u8) << 96) - U256::from(1u8);
    // The largest amount the policy verifier accepts is in range (and the income is below 3x it).
    let (input, _) = phi_a(&openings, c_b(TENANT), max);
    phi_a_rejected(&input, A_ENOUGH);
    // One above it fails the range check, whatever the income.
    let (input, _) = phi_a(&openings, c_b(TENANT), U256::from(RENT));
    let mut v = json(&input);
    v["amount"] = Value::from((U256::from(1u8) << 96usize).to_string());
    rejected_at(phi_a_files(), &v, BITIFY, "Num2Bits", NUM2BITS);
}

// ---------------------------------------------------------------------------------------------
// phi_S

fn tenancy_openings(property: &str, tenant: &str, date: &str) -> Vec<FieldOpening> {
    record_openings(
        &layout("tenancy-v1"),
        LANDLORD,
        &[property, tenant, date],
        &["account", "propertyId", "tenant", "recordDate"].map(label_blinder),
    )
    .expect("render")
}

fn phi_s(openings: &[FieldOpening], c_b: [u8; 32], day: u32) -> (PhiSInput, PhiSPublic) {
    let public = PhiSPublic::new(
        [
            commitment(&openings[1]),
            commitment(&openings[2]),
            commitment(&openings[3]),
        ],
        layout("tenancy-v1")
            .word("propertyId", PROPERTY)
            .expect("word"),
        c_b,
        day,
        DIGEST,
    )
    .expect("public");
    (
        PhiSInput::new(&public, openings, &salt()).expect("input"),
        public,
    )
}

fn phi_s_accepted(input: &PhiSInput, public: &PhiSPublic) {
    let w = witness(phi_s_files(), input, PHI_S_PUBLIC_INPUTS)
        .unwrap_or_else(|e| panic!("phi_S rejected the witness: {e:#}"));
    let expected: Vec<BigUint> = public.inputs().iter().map(|s| s.parse().unwrap()).collect();
    assert_eq!(w, expected);
}

fn phi_s_rejected_at(input: &impl Serialize, file: &str, template: &str, marker: &str) {
    rejected_at(phi_s_files(), input, file, template, marker);
}

/// phi_S for a notation of the listed property and the tenant in c_B, dated `date`.
fn notation(date: &str, day: u32) -> (PhiSInput, PhiSPublic) {
    phi_s(&tenancy_openings(PROPERTY, TENANT, date), c_b(TENANT), day)
}

#[test]
fn phi_s_holds_on_and_after_the_engagement_day() {
    let (input, public) = notation("2026-10-21", 2026_10_21);
    phi_s_accepted(&input, &public);
    let (input, public) = notation("2027-01-05", 2026_10_21);
    phi_s_accepted(&input, &public);
}

#[test]
fn phi_s_fails_the_day_before_the_engagement_day() {
    let (input, _) = notation("2026-10-20", 2026_10_21);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_NOT_BEFORE);
    // Across a month and a year boundary.
    let (input, _) = notation("2026-09-30", 2026_10_01);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_NOT_BEFORE);
    let (input, _) = notation("2025-12-31", 2026_01_01);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_NOT_BEFORE);
}

#[test]
fn phi_s_fails_for_a_notation_on_another_property() {
    let openings = tenancy_openings(OTHER_PROPERTY, TENANT, "2026-10-21");
    let (input, _) = phi_s(&openings, c_b(TENANT), 2026_10_21);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_PROPERTY_HI);
    // A property that differs only after the first 16 bytes.
    let openings = tenancy_openings("TR-06-CANKAYA-000124", TENANT, "2026-10-21");
    let (input, _) = phi_s(&openings, c_b(TENANT), 2026_10_21);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_PROPERTY_LO);
}

#[test]
fn phi_s_fails_for_a_notation_of_another_tenant() {
    let openings = tenancy_openings(PROPERTY, OTHER, "2026-10-21");
    let (input, _) = phi_s(&openings, c_b(TENANT), 2026_10_21);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_C_B);
}

#[test]
fn phi_s_fails_for_an_empty_tenant() {
    let openings = tenancy_openings(PROPERTY, "", "2026-10-21");
    let (input, _) = phi_s(&openings, c_b(&" ".repeat(16)), 2026_10_21);
    phi_s_rejected_at(&input, PHI_S, "PhiS", S_TENANT_NOT_EMPTY);
}

#[test]
fn phi_s_fails_when_the_date_does_not_match_its_commitment() {
    let (input, _) = notation("2026-10-21", 2026_10_21);
    let mut v = json(&input);
    v["dateHash"][0] = "1".into();
    phi_s_rejected_at(&v, PHI_S, "PhiS", S_OPEN_DATE);
}

#[test]
fn phi_s_accepts_leap_days_of_leap_years_only() {
    for (date, day) in [("2024-02-29", 2024_02_29), ("2000-02-29", 2000_02_29)] {
        let (input, public) = notation(date, day);
        phi_s_accepted(&input, &public);
    }
    for date in ["2026-02-29", "2100-02-29", "1900-02-29"] {
        let (input, _) = notation(date, 1900_01_01);
        phi_s_rejected_at(&input, DATE, "CalendarDate", DAY_MAX);
    }
}

#[test]
fn phi_s_reads_canonical_calendar_dates_only() {
    for (date, marker) in [
        ("2026-04-31", DAY_MAX),
        ("2026-01-32", DAY_MAX),
        ("2026-10-00", DAY_NOT_ZERO),
        ("2026-00-10", MONTH_NOT_ZERO),
        ("2026-13-01", MONTH_MAX),
        ("2026/10-21", SEPARATOR_1),
        ("2026-10/21", SEPARATOR_2),
    ] {
        let (input, _) = notation(date, 2000_01_01);
        phi_s_rejected_at(&input, DATE, "CalendarDate", marker);
    }
    // Non-digits: '+' and ' ' wrap below '0'; ':' is one above '9'.
    for date in ["2026-+9-21", "2026-10- 1"] {
        let (input, _) = notation(date, 2000_01_01);
        phi_s_rejected_at(&input, BITIFY, "Num2Bits", NUM2BITS);
    }
    let (input, _) = notation("2026-1:-21", 2000_01_01);
    phi_s_rejected_at(&input, DECIMAL, "Digit", DIGIT_BELOW_10);
}

#[test]
fn phi_s_bounds_the_engagement_day() {
    let (input, _) = notation("2026-10-21", 2026_10_21);
    let mut v = json(&input);
    v["engagementDay"] = (1u32 << 27).to_string().into();
    phi_s_rejected_at(&v, BITIFY, "Num2Bits", NUM2BITS);
}
