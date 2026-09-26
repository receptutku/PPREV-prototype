//! Mock notary for Apply and Settle (D23). It evaluates phi_A and phi_S natively on records given
//! in the clear, with no TLSNotary session and no circuit, and signs x_A and x_S with sk_notary.
//! It keeps the rules that the contract leaves to the notary (Table VI, off-chain column): the
//! predicate and phase of each policy, t_att from the notary's own clock, phi_S's check of c_B and
//! of the record date, and one signature per nonce.

use std::collections::HashMap;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::Eip712Domain;
use anyhow::{Context, Result, bail, ensure};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use pprev_types::statement::{Apply, Settle, TxData, digest};

use crate::nonces::NonceStore;
use crate::sigma::StatementKey;

/// c_B = H_c(identifier, salt) with H_c the two-input Poseidon of circomlib (Section V-D). The
/// identifier, padded to its layout width, is packed big-endian into one field element; the salt is
/// a field element given as 32 big-endian bytes.
pub fn counterparty_commitment(identifier: &[u8], salt: &[u8; 32]) -> Result<B256> {
    ensure!(
        identifier.len() <= 31,
        "an identifier must fit one field element"
    );
    let id = Fr::from_be_bytes_mod_order(identifier);
    let salt = Fr::from_bigint(ark_ff::BigInt::new(be_limbs(salt)))
        .context("the salt is not below the field order")?;
    let out = Poseidon::<Fr>::new_circom(2)?.hash(&[id, salt])?;
    let bytes = out.into_bigint().to_bytes_be();
    Ok(B256::from_slice(&bytes))
}

fn be_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 32 - 8 * (i + 1);
        *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    limbs
}

/// The opening of c_B that the witness carries.
#[derive(Clone, Debug)]
pub struct CommitmentOpening {
    /// The identifier under which the settlement registry names B, padded to its layout width.
    pub identifier: Vec<u8>,
    pub salt: [u8; 32],
}

/// phi_A's source record: the eligibility portal's view of B's session.
#[derive(Clone, Debug)]
pub struct EligibilityRecord {
    /// Identifier of the logged-in account, padded to its layout width.
    pub account: Vec<u8>,
    pub monthly_income: U256,
}

/// phi_S's source record: the tenancy notation of the settlement registry.
#[derive(Clone, Debug)]
pub struct SettlementRecord {
    /// Identifier of the registered tenant, padded to its layout width.
    pub tenant: Vec<u8>,
    /// Calendar day of the notation in the registry's time zone, `YYYY-MM-DD`.
    pub record_date: String,
}

/// phi_A of the rental instantiation (Section VI-A): monthly income of at least `income_multiple`
/// times the rent `txData.amount`.
#[derive(Clone, Debug)]
pub struct ApplyPolicy {
    pub income_multiple: u64,
}

/// phi_S of the rental instantiation: a tenancy notation that names the identifier in c_B and is
/// dated no earlier than the engagement day, the calendar day in the registry's time zone of
/// `expiresAt - tau_lock` (Section V-E).
#[derive(Clone, Debug)]
pub struct SettlePolicy {
    pub tau_lock: u64,
    /// Offset of the registry's time zone from UTC, in seconds.
    pub utc_offset_secs: i64,
}

#[derive(Clone, Debug)]
pub enum MockPolicy {
    Apply(ApplyPolicy),
    Settle(SettlePolicy),
}

/// x_A without t_att, which the notary sets.
#[derive(Clone, Debug)]
pub struct ApplyRequest {
    pub tx_id: U256,
    pub c_tx: B256,
    pub tx_data: TxData,
    pub c_b: B256,
    pub policy_id: B256,
    pub submitter: Address,
    pub eta: B256,
}

/// x_S without t_att, which the notary sets.
#[derive(Clone, Debug)]
pub struct SettleRequest {
    pub eng_id: U256,
    pub tx_id: U256,
    pub c_tx: B256,
    pub tx_data: TxData,
    pub c_b: B256,
    pub expires_at: U256,
    pub policy_id: B256,
    pub submitter: Address,
    pub eta: B256,
}

pub struct MockNotary {
    policies: HashMap<B256, MockPolicy>,
    key: StatementKey,
    domain: Eip712Domain,
    nonces: NonceStore,
    clock: fn() -> u64,
}

impl MockNotary {
    pub fn new(
        policies: HashMap<B256, MockPolicy>,
        key: StatementKey,
        domain: Eip712Domain,
        nonces: NonceStore,
        clock: fn() -> u64,
    ) -> Self {
        Self {
            policies,
            key,
            domain,
            nonces,
            clock,
        }
    }

    /// Checks phi_A for `request` and returns x_A, with t_att from the notary's clock, and sigma_A.
    pub fn sign_apply(
        &mut self,
        request: &ApplyRequest,
        record: &EligibilityRecord,
        opening: &CommitmentOpening,
    ) -> Result<(Apply, [u8; 65])> {
        let Some(MockPolicy::Apply(policy)) = self.policies.get(&request.policy_id) else {
            bail!(
                "0x{} is not an Apply policy of this notary",
                hex::encode(request.policy_id)
            );
        };
        ensure!(
            counterparty_commitment(&opening.identifier, &opening.salt)? == request.c_b,
            "c_B does not open to the given identifier and salt"
        );
        ensure!(
            record.account == opening.identifier,
            "c_B does not name the account holder of the session"
        );
        let threshold = request
            .tx_data
            .amount
            .checked_mul(U256::from(policy.income_multiple))
            .context("income threshold overflows")?;
        ensure!(
            record.monthly_income >= threshold,
            "income is below {} times the rent",
            policy.income_multiple
        );
        let statement = Apply {
            txId: request.tx_id,
            cTx: request.c_tx,
            txData: request.tx_data.clone(),
            cB: request.c_b,
            policyId: request.policy_id,
            submitter: request.submitter,
            eta: request.eta,
            tAtt: (self.clock)(),
        };
        let sigma = self.sign(request.eta, digest(&statement, &self.domain))?;
        Ok((statement, sigma))
    }

    /// Checks phi_S for `request` and returns x_S, with t_att from the notary's clock, and sigma_S.
    pub fn sign_settle(
        &mut self,
        request: &SettleRequest,
        record: &SettlementRecord,
        opening: &CommitmentOpening,
    ) -> Result<(Settle, [u8; 65])> {
        let Some(MockPolicy::Settle(policy)) = self.policies.get(&request.policy_id) else {
            bail!(
                "0x{} is not a Settle policy of this notary",
                hex::encode(request.policy_id)
            );
        };
        ensure!(
            counterparty_commitment(&opening.identifier, &opening.salt)? == request.c_b,
            "c_B does not open to the given identifier and salt"
        );
        ensure!(
            record.tenant == opening.identifier,
            "the settlement record does not name the identity in c_B"
        );
        let expires_at: u64 = request
            .expires_at
            .try_into()
            .context("expiresAt exceeds 64 bits")?;
        let engaged = expires_at
            .checked_sub(policy.tau_lock)
            .context("expiresAt precedes tau_lock")?;
        let engagement_day = (engaged as i64 + policy.utc_offset_secs).div_euclid(86_400);
        ensure!(
            day_number(&record.record_date)? >= engagement_day,
            "the record date {} precedes the engagement day",
            record.record_date
        );
        let statement = Settle {
            engId: request.eng_id,
            txId: request.tx_id,
            cTx: request.c_tx,
            txData: request.tx_data.clone(),
            cB: request.c_b,
            expiresAt: request.expires_at,
            policyId: request.policy_id,
            submitter: request.submitter,
            eta: request.eta,
            tAtt: (self.clock)(),
        };
        let sigma = self.sign(request.eta, digest(&statement, &self.domain))?;
        Ok((statement, sigma))
    }

    fn sign(&mut self, eta: B256, digest: B256) -> Result<[u8; 65]> {
        self.nonces.record(eta.0)?;
        self.key.sign(digest)
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian `YYYY-MM-DD` date (H. Hinnant's days_from_civil).
fn day_number(date: &str) -> Result<i64> {
    let parts: Vec<&str> = date.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
        bail!("{date:?} is not YYYY-MM-DD");
    };
    ensure!(
        y.len() == 4 && m.len() == 2 && d.len() == 2,
        "{date:?} is not YYYY-MM-DD"
    );
    let (y, m, d): (i64, i64, i64) = (y.parse()?, m.parse()?, d.parse()?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1..=12).contains(&m) && d >= 1 && d <= days_in_month[(m - 1) as usize],
        "{date:?} is not a calendar date"
    );
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_numbers_follow_the_calendar() {
        assert_eq!(day_number("1970-01-01").unwrap(), 0);
        assert_eq!(day_number("1970-01-02").unwrap(), 1);
        assert_eq!(day_number("1969-12-31").unwrap(), -1);
        assert_eq!(
            day_number("2000-03-01").unwrap() - day_number("2000-02-28").unwrap(),
            2
        );
        assert_eq!(
            day_number("2100-03-01").unwrap() - day_number("2100-02-28").unwrap(),
            1
        );
        // 2026-09-25T00:00:00Z is Unix time 1790294400.
        assert_eq!(day_number("2026-09-25").unwrap(), 1_790_294_400 / 86_400);
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-9-25",
            "20260925",
            "2026-09-31",
        ] {
            assert!(day_number(bad).is_err(), "{bad}");
        }
    }
}
