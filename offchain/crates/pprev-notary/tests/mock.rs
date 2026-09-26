//! Mock notary for Apply and Settle (D23): the notary-side rules of Table VI's off-chain column,
//! that is, per-policy predicates with a matching phase, t_att from the notary's clock, phi_S's
//! check of c_B and of the record date, and one signature per nonce.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use pprev_notary::StatementKey;
use pprev_notary::mock::{
    ApplyPolicy, ApplyRequest, CommitmentOpening, EligibilityRecord, MockNotary, MockPolicy,
    SettlePolicy, SettleRequest, SettlementRecord, counterparty_commitment,
};
use pprev_notary::nonces::NonceStore;
use pprev_types::statement::{TxData, digest, domain};

const TENANT: &[u8; 16] = b"ACC-000000000003";
const OTHER: &[u8; 16] = b"ACC-000000000009";
const RENT: u64 = 1_000_000_000_000_000_000;
const TAU_LOCK: u64 = 14 * 86_400;
/// UTC+3, the registry's time zone in these tests.
const UTC_OFFSET: i64 = 3 * 3600;
/// Clock of the mock notary: 2026-09-25T12:00:00Z.
const NOW: u64 = 1_790_337_600;

fn policy_a() -> B256 {
    keccak256("rental-v1/A")
}

fn policy_s() -> B256 {
    keccak256("rental-v1/S")
}

fn key() -> StatementKey {
    StatementKey::from_bytes(&keccak256("pprev.notary.statement-key.test").0).unwrap()
}

fn notary() -> MockNotary {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "pprev-mock-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nonces.log");
    let _ = std::fs::remove_file(&path);
    let policies = HashMap::from([
        (
            policy_a(),
            MockPolicy::Apply(ApplyPolicy { income_multiple: 3 }),
        ),
        (
            policy_s(),
            MockPolicy::Settle(SettlePolicy {
                tau_lock: TAU_LOCK,
                utc_offset_secs: UTC_OFFSET,
            }),
        ),
    ]);
    MockNotary::new(
        policies,
        key(),
        domain(31337, Address::repeat_byte(0x5a)),
        NonceStore::open(path).unwrap(),
        || NOW,
    )
}

fn salt() -> [u8; 32] {
    // Below the field order: the top byte is small.
    let mut salt = keccak256("salt").0;
    salt[0] = 0x01;
    salt
}

fn opening(identifier: &[u8]) -> CommitmentOpening {
    CommitmentOpening {
        identifier: identifier.to_vec(),
        salt: salt(),
    }
}

fn c_b() -> B256 {
    counterparty_commitment(TENANT, &salt()).unwrap()
}

fn tx_data() -> TxData {
    TxData {
        propertyId: B256::repeat_byte(0x54),
        amount: U256::from(RENT),
        settlementShare: U256::ZERO,
    }
}

fn apply_request(eta: u8) -> ApplyRequest {
    ApplyRequest {
        tx_id: U256::from(1),
        c_tx: B256::repeat_byte(0xc7),
        tx_data: tx_data(),
        c_b: c_b(),
        policy_id: policy_a(),
        submitter: Address::repeat_byte(0x22),
        eta: B256::repeat_byte(eta),
    }
}

/// Engaged at 2026-09-24T21:30:00Z, which is 2026-09-25 00:30 in UTC+3.
const ENGAGED: u64 = 1_790_285_400;

fn settle_request(eta: u8) -> SettleRequest {
    SettleRequest {
        eng_id: U256::from(1),
        tx_id: U256::from(1),
        c_tx: B256::repeat_byte(0xc7),
        tx_data: tx_data(),
        c_b: c_b(),
        expires_at: U256::from(ENGAGED + TAU_LOCK),
        policy_id: policy_s(),
        submitter: Address::repeat_byte(0x11),
        eta: B256::repeat_byte(eta),
    }
}

fn income(multiple_of_rent_tenths: u64) -> U256 {
    U256::from(RENT) * U256::from(multiple_of_rent_tenths) / U256::from(10)
}

fn eligibility(account: &[u8], tenths: u64) -> EligibilityRecord {
    EligibilityRecord {
        account: account.to_vec(),
        monthly_income: income(tenths),
    }
}

fn settlement(tenant: &[u8], date: &str) -> SettlementRecord {
    SettlementRecord {
        tenant: tenant.to_vec(),
        record_date: date.into(),
    }
}

fn recovers_to_vk(digest: B256, sigma: &[u8; 65]) -> bool {
    Signature::from_raw(sigma)
        .unwrap()
        .recover_address_from_prehash(&digest)
        .unwrap()
        == key().vk_notary()
}

// Commitment c_B -------------------------------------------------------------------------------

/// circomlib's own test vector for its two-input Poseidon
/// (circomlib/test/poseidoncircuit.js: hash([1, 2])).
#[test]
fn h_c_is_circomlib_poseidon() {
    let mut two = [0u8; 32];
    two[31] = 2;
    let expected: U256 =
        "7853200120776062878684798364095072458815029376092732009249414926327459813530"
            .parse()
            .unwrap();
    assert_eq!(
        counterparty_commitment(&[1], &two).unwrap(),
        B256::from(expected)
    );
}

#[test]
fn h_c_rejects_a_salt_outside_the_field() {
    assert!(counterparty_commitment(TENANT, &[0xff; 32]).is_err());
}

// Apply ----------------------------------------------------------------------------------------

#[test]
fn apply_is_signed_when_phi_a_holds() {
    let mut n = notary();
    let (x, sigma) = n
        .sign_apply(
            &apply_request(1),
            &eligibility(TENANT, 30),
            &opening(TENANT),
        )
        .unwrap();
    // t_att comes from the notary's clock, not from the applicant.
    assert_eq!(x.tAtt, NOW);
    assert!(recovers_to_vk(
        digest(&x, &domain(31337, Address::repeat_byte(0x5a))),
        &sigma
    ));
    let mut shifted = x.clone();
    shifted.tAtt += 1;
    assert!(!recovers_to_vk(
        digest(&shifted, &domain(31337, Address::repeat_byte(0x5a))),
        &sigma
    ));
}

#[test]
fn apply_is_refused_below_the_income_threshold() {
    let mut n = notary();
    let err = n
        .sign_apply(
            &apply_request(1),
            &eligibility(TENANT, 29),
            &opening(TENANT),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("income"), "{err}");
}

#[test]
fn apply_is_refused_when_c_b_does_not_name_the_account_holder() {
    let mut n = notary();
    // c_B opens to TENANT, but the eligibility session is OTHER's.
    let err = n
        .sign_apply(&apply_request(1), &eligibility(OTHER, 50), &opening(TENANT))
        .unwrap_err()
        .to_string();
    assert!(err.contains("account holder"), "{err}");
    // The opening does not match c_B.
    let mut wrong_salt = opening(TENANT);
    wrong_salt.salt[31] ^= 1;
    let err = n
        .sign_apply(&apply_request(2), &eligibility(TENANT, 50), &wrong_salt)
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not open"), "{err}");
}

#[test]
fn a_statement_is_signed_only_under_a_policy_of_its_phase() {
    let mut n = notary();
    let mut request = apply_request(1);
    request.policy_id = policy_s();
    let err = n
        .sign_apply(&request, &eligibility(TENANT, 30), &opening(TENANT))
        .unwrap_err()
        .to_string();
    assert!(err.contains("not an Apply policy"), "{err}");
    let mut request = settle_request(2);
    request.policy_id = policy_a();
    let err = n
        .sign_settle(
            &request,
            &settlement(TENANT, "2026-10-01"),
            &opening(TENANT),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a Settle policy"), "{err}");
    let mut request = apply_request(3);
    request.policy_id = keccak256("unknown");
    assert!(
        n.sign_apply(&request, &eligibility(TENANT, 30), &opening(TENANT))
            .is_err()
    );
}

#[test]
fn a_nonce_is_signed_once_across_phases() {
    let mut n = notary();
    n.sign_apply(
        &apply_request(7),
        &eligibility(TENANT, 30),
        &opening(TENANT),
    )
    .unwrap();
    let err = n
        .sign_apply(
            &apply_request(7),
            &eligibility(TENANT, 30),
            &opening(TENANT),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("already been signed"), "{err}");
    let err = n
        .sign_settle(
            &settle_request(7),
            &settlement(TENANT, "2026-10-01"),
            &opening(TENANT),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("already been signed"), "{err}");
}

#[test]
fn a_refused_request_does_not_use_up_its_nonce() {
    let mut n = notary();
    assert!(
        n.sign_apply(
            &apply_request(9),
            &eligibility(TENANT, 10),
            &opening(TENANT)
        )
        .is_err()
    );
    n.sign_apply(
        &apply_request(9),
        &eligibility(TENANT, 30),
        &opening(TENANT),
    )
    .unwrap();
}

// Settle ---------------------------------------------------------------------------------------

#[test]
fn settle_is_signed_for_a_notation_on_or_after_the_engagement_day() {
    let mut n = notary();
    // The engagement day is 2026-09-25 in the registry's time zone, although it is 2026-09-24 in UTC.
    let (x, sigma) = n
        .sign_settle(
            &settle_request(1),
            &settlement(TENANT, "2026-09-25"),
            &opening(TENANT),
        )
        .unwrap();
    assert_eq!(x.tAtt, NOW);
    assert_eq!(x.cB, c_b());
    assert!(recovers_to_vk(
        digest(&x, &domain(31337, Address::repeat_byte(0x5a))),
        &sigma
    ));
    n.sign_settle(
        &settle_request(2),
        &settlement(TENANT, "2026-10-08"),
        &opening(TENANT),
    )
    .unwrap();
}

#[test]
fn settle_is_refused_for_a_notation_before_the_engagement_day() {
    let mut n = notary();
    let err = n
        .sign_settle(
            &settle_request(1),
            &settlement(TENANT, "2026-09-24"),
            &opening(TENANT),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("precedes the engagement day"), "{err}");
}

#[test]
fn settle_is_refused_when_the_notation_names_another_tenant() {
    let mut n = notary();
    let err = n
        .sign_settle(
            &settle_request(1),
            &settlement(OTHER, "2026-10-01"),
            &opening(TENANT),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not name the identity in c_B"), "{err}");
    // An opening of another identifier does not open c_B.
    let err = n
        .sign_settle(
            &settle_request(2),
            &settlement(OTHER, "2026-10-01"),
            &opening(OTHER),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not open"), "{err}");
}
