//! Policy bundle files (`policies/*.json`, Section V-C): the identifiers policyID_R, policyID_A,
//! policyID_S, the escrow bounds that `registerPolicy` records on-chain, and what the policy
//! verifier holds for Register: the response layout of the source and the verifying key of phi_R.
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBundle {
    pub id: String,
    pub labels: PolicyLabels,
    pub register: RegisterSource,
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
