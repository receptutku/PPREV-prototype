//! Policy bundle files (`policies/*.json`, Section V-C): the identifiers policyID_R, policyID_A,
//! policyID_S, the escrow bounds that `registerPolicy` records on-chain, and what the policy
//! verifier holds for each phase: the response layout of the phase's source, the verifying key of
//! its predicate, and the predicate's parameters.
//!
//! Each identifier is keccak256 of its label, as in `contracts/test/utils/Fixture.sol`;
//! `contracts/script/Deploy.s.sol` derives the same values from the same file.

use std::path::{Path, PathBuf};

use alloy_primitives::{B256, U256, keccak256};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyLabels {
    pub register: String,
    pub apply: String,
    pub settle: String,
}

/// Paths are relative to the repository root.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterSource {
    pub layout: PathBuf,
    pub verification_key: PathBuf,
}

/// The eligibility source of phi_A. The policy fixes that the income is written in the
/// denomination and scale of txData.amount.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplySource {
    pub layout: PathBuf,
    pub verification_key: PathBuf,
    /// Required monthly income as a multiple of the rent txData.amount.
    pub income_multiple: u64,
    /// The unit in which the source writes the income and txData.amount is given, for example
    /// "wei". phi_A compares the two numbers as they are; no conversion takes place, so a policy
    /// is admissible only for a source that writes incomes in this unit.
    pub amount_unit: String,
}

/// The settlement source of phi_S.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettleSource {
    pub layout: PathBuf,
    pub verification_key: PathBuf,
    /// Offset of the registry's time zone from UTC, in seconds; the engagement day is taken there.
    pub utc_offset_secs: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBundle {
    pub id: String,
    pub labels: PolicyLabels,
    pub register: RegisterSource,
    /// Absent when the notary signs no Apply statements for this policy.
    #[serde(default)]
    pub apply: Option<ApplySource>,
    /// Absent when the notary signs no Settle statements for this policy.
    #[serde(default)]
    pub settle: Option<SettleSource>,
    pub req_escrow_wei: String,
    pub min_collateral_wei: String,
    pub max_collateral_wei: String,
}

impl PolicyBundle {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let bundle: Self =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        ensure!(
            bundle.min_collateral()? <= bundle.max_collateral()?,
            "minCollateralWei exceeds maxCollateralWei"
        );
        bundle.req_escrow()?;
        if let Some(apply) = &bundle.apply {
            ensure!(apply.income_multiple > 0, "incomeMultiple must be positive");
            ensure!(!apply.amount_unit.is_empty(), "amountUnit must name a unit");
        }
        if let Some(settle) = &bundle.settle {
            ensure!(
                (-14 * 3600..=14 * 3600).contains(&settle.utc_offset_secs),
                "utcOffsetSecs is not a time-zone offset"
            );
        }
        Ok(bundle)
    }

    pub fn policy_id_r(&self) -> B256 {
        keccak256(&self.labels.register)
    }

    pub fn policy_id_a(&self) -> B256 {
        keccak256(&self.labels.apply)
    }

    pub fn policy_id_s(&self) -> B256 {
        keccak256(&self.labels.settle)
    }

    pub fn req_escrow(&self) -> Result<U256> {
        wei(&self.req_escrow_wei, "reqEscrowWei")
    }

    pub fn min_collateral(&self) -> Result<U256> {
        wei(&self.min_collateral_wei, "minCollateralWei")
    }

    pub fn max_collateral(&self) -> Result<U256> {
        wei(&self.max_collateral_wei, "maxCollateralWei")
    }
}

fn wei(s: &str, name: &str) -> Result<U256> {
    ensure!(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        "{name} is not a decimal number"
    );
    s.parse()
        .with_context(|| format!("{name} is not a uint256"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rental() -> PolicyBundle {
        PolicyBundle::load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../policies/rental-v1.json"
        ))
        .unwrap()
    }

    /// The identifiers equal those of the contract test fixture.
    #[test]
    fn rental_identifiers_match_the_fixture() {
        let p = rental();
        assert_eq!(p.policy_id_r(), keccak256("pprev.rental.register"));
        assert_eq!(p.policy_id_a(), keccak256("pprev.rental.apply"));
        assert_eq!(p.policy_id_s(), keccak256("pprev.rental.settle"));
    }

    #[test]
    fn rental_names_its_apply_and_settle_sources() {
        let p = rental();
        let apply = p.apply.unwrap();
        assert_eq!(
            apply.layout,
            PathBuf::from("policies/layouts/income-v1.json")
        );
        assert_eq!(apply.income_multiple, 3);
        assert_eq!(apply.amount_unit, "wei");
        let settle = p.settle.unwrap();
        assert_eq!(
            settle.layout,
            PathBuf::from("policies/layouts/tenancy-v1.json")
        );
        assert_eq!(settle.utc_offset_secs, 3 * 3600);
    }

    #[test]
    fn utc_offsets_are_time_zone_offsets() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../policies/rental-v1.json"
        ))
        .unwrap();
        let dir = std::env::temp_dir().join(format!("pprev-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (offset, ok) in [
            (14 * 3600, true),
            (-14 * 3600, true),
            (14 * 3600 + 1, false),
            (-14 * 3600 - 1, false),
            (i64::MIN, false),
            (i64::MAX, false),
        ] {
            let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
            json["settle"]["utcOffsetSecs"] = offset.into();
            let path = dir.join("policy.json");
            std::fs::write(&path, json.to_string()).unwrap();
            assert_eq!(PolicyBundle::load(&path).is_ok(), ok, "{offset}");
        }
    }

    /// The escrow bounds equal D18.
    #[test]
    fn rental_bounds_are_d18() {
        let p = rental();
        let milli = U256::from(10u64).pow(U256::from(15));
        assert_eq!(p.req_escrow().unwrap(), U256::from(50) * milli);
        assert_eq!(p.min_collateral().unwrap(), U256::from(100) * milli);
        assert_eq!(p.max_collateral().unwrap(), U256::from(1000) * milli);
    }
}
