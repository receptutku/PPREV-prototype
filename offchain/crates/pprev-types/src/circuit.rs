//! Parameters of the phi_R circuit, derived from the response layout, and the generated main
//! component (`circuits/src/main_title_v1.circom`).

use alloy_primitives::U256;
use anyhow::{Result, ensure};
use num_bigint::BigUint;

use crate::field::{bind_value, bn254_r, limbs};
use crate::layout::{KEY_PROPERTY_ID, KEY_RECORD_DATE};
use crate::{Layout, RecordLayout};

/// Number of public inputs of phi_R.
pub const PHI_R_PUBLIC_INPUTS: usize = 10;

/// What the policy verifier knows of a phi_R instance: the attested commitments, the statement's
/// `txData.propertyId` and c_P, and the EIP-712 digest of x_R.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiRPublic {
    /// SHA-256 commitments to the `account`, `owners`, and `propertyId` values.
    pub account_hash: [u8; 32],
    pub owners_hash: [u8; 32],
    pub property_hash: [u8; 32],
    /// `txData.propertyId`.
    pub property_id: [u8; 32],
    /// c_P of x_R; [`check_field_element`] it before use.
    pub c_p: [u8; 32],
    /// EIP-712 digest of x_R.
    pub digest: [u8; 32],
}

impl PhiRPublic {
    /// The public inputs in the circuit's order, as decimal strings (the form of snarkjs'
    /// `public.json`): two limbs per commitment, two limbs of `txData.propertyId`, c_P, `bind`.
    pub fn inputs(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(PHI_R_PUBLIC_INPUTS);
        for word in [
            &self.account_hash,
            &self.owners_hash,
            &self.property_hash,
            &self.property_id,
        ] {
            out.extend(limbs(word));
        }
        out.push(BigUint::from_bytes_be(&self.c_p).to_str_radix(10));
        out.push(bind_value(&self.digest));
        out
    }
}

/// Template parameters of `PhiR` in `circuits/src/phi_r.circom`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiRParams {
    pub account_width: usize,
    pub owner_slots: usize,
    pub owner_stride: usize,
    pub owners_len: usize,
    pub property_id_width: usize,
    pub padding: u8,
}

impl PhiRParams {
    pub fn from_layout(layout: &Layout) -> Result<Self> {
        let ranges = layout.ranges()?;
        let offsets = &ranges.owner_slot_offsets;
        let owner_stride = if offsets.len() > 1 {
            offsets[1] - offsets[0]
        } else {
            layout.account_width + 3
        };
        ensure!(
            offsets.windows(2).all(|w| w[1] - w[0] == owner_stride),
            "owner slots are not evenly spaced"
        );
        Ok(Self {
            account_width: layout.account_width,
            owner_slots: layout.owner_slots,
            owner_stride,
            owners_len: ranges.owners.len(),
            property_id_width: layout.property_id_width,
            padding: layout.padding_byte(),
        })
    }
}

/// Source of the main component for `layout`.
pub fn main_circom(layout: &Layout) -> Result<String> {
    let p = PhiRParams::from_layout(layout)?;
    Ok(format!(
        "// Generated from the {id} layout by `cargo run -p pprev-types --bin gen-circuit-main`.\n\
         // Do not edit by hand.\n\
         pragma circom 2.2.0;\n\
         \n\
         include \"phi_r.circom\";\n\
         \n\
         component main {{public [accountHash, ownersHash, propertyHash, propertyId, cP, bind]}} =\n    \
         PhiR({}, {}, {}, {}, {}, {});\n",
        p.account_width,
        p.owner_slots,
        p.owner_stride,
        p.owners_len,
        p.property_id_width,
        p.padding,
        id = layout.id,
    ))
}

/// Number of public inputs of phi_A and phi_S.
pub const PHI_A_PUBLIC_INPUTS: usize = 7;
pub const PHI_S_PUBLIC_INPUTS: usize = 15;

/// Bound on txData.amount in phi_A, in bits; the policy verifier refuses larger amounts.
pub const PHI_A_AMOUNT_BITS: usize = 96;

/// Field keys of the Apply and Settle layouts that the predicates read.
pub const KEY_MONTHLY_INCOME: &str = "monthlyIncome";
pub const KEY_TENANT: &str = "tenant";

/// c_B or c_P as a public input: the value it encodes, which must be a canonical field element.
/// c_B and c_P are Poseidon outputs, so an honest one is always below r; a value at or above r
/// would alias a smaller one.
fn field_element(word: &[u8; 32], name: &str) -> Result<String> {
    let value = BigUint::from_bytes_be(word);
    ensure!(value < bn254_r(), "{name} is not below the field order");
    Ok(value.to_str_radix(10))
}

/// Rejects a value at or above r, as [`PhiAPublic::new`] and [`PhiSPublic::new`] do for c_B.
pub fn check_field_element(word: &[u8; 32], name: &str) -> Result<()> {
    field_element(word, name).map(|_| ())
}

/// What the policy verifier knows of a phi_A instance: the attested commitments to the account and
/// the income, and c_B, txData.amount, and the EIP-712 digest of x_A.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiAPublic {
    pub account_hash: [u8; 32],
    pub income_hash: [u8; 32],
    c_b: String,
    amount: String,
    pub digest: [u8; 32],
}

impl PhiAPublic {
    /// Rejects a c_B at or above r and an amount of [`PHI_A_AMOUNT_BITS`] bits or more.
    pub fn new(
        account_hash: [u8; 32],
        income_hash: [u8; 32],
        c_b: [u8; 32],
        amount: U256,
        digest: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            amount < U256::from(1u8) << PHI_A_AMOUNT_BITS,
            "txData.amount {amount} exceeds {PHI_A_AMOUNT_BITS} bits"
        );
        Ok(Self {
            account_hash,
            income_hash,
            c_b: field_element(&c_b, "c_B")?,
            amount: amount.to_string(),
            digest,
        })
    }

    /// The public inputs in the circuit's order: two limbs per commitment, c_B, amount, bind.
    pub fn inputs(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(PHI_A_PUBLIC_INPUTS);
        out.extend(limbs(&self.account_hash));
        out.extend(limbs(&self.income_hash));
        out.push(self.c_b.clone());
        out.push(self.amount.clone());
        out.push(bind_value(&self.digest));
        out
    }
}

/// What the policy verifier knows of a phi_S instance: the attested commitments to the session's
/// account, the property, the tenant, and the record date, and txData.propertyId, c_P, c_B, the
/// engagement day, the attestation day (the calendar day of t_att), and the EIP-712 digest of x_S.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiSPublic {
    pub account_hash: [u8; 32],
    pub property_hash: [u8; 32],
    pub tenant_hash: [u8; 32],
    pub date_hash: [u8; 32],
    pub property_id: [u8; 32],
    c_p: String,
    c_b: String,
    /// Y * 10000 + M * 100 + D.
    pub engagement_day: u32,
    /// Y * 10000 + M * 100 + D.
    pub attestation_day: u32,
    pub digest: [u8; 32],
}

impl PhiSPublic {
    /// Rejects a c_P or c_B at or above r, and an engagement or attestation day of 27 bits or more.
    pub fn new(
        [account_hash, property_hash, tenant_hash, date_hash]: [[u8; 32]; 4],
        property_id: [u8; 32],
        [c_p, c_b]: [[u8; 32]; 2],
        [engagement_day, attestation_day]: [u32; 2],
        digest: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            engagement_day < 1 << 27,
            "engagement day {engagement_day} exceeds 27 bits"
        );
        ensure!(
            attestation_day < 1 << 27,
            "attestation day {attestation_day} exceeds 27 bits"
        );
        Ok(Self {
            account_hash,
            property_hash,
            tenant_hash,
            date_hash,
            property_id,
            c_p: field_element(&c_p, "c_P")?,
            c_b: field_element(&c_b, "c_B")?,
            engagement_day,
            attestation_day,
            digest,
        })
    }

    /// The public inputs in the circuit's order: two limbs per commitment, two limbs of
    /// txData.propertyId, c_P, c_B, the engagement day, the attestation day, bind.
    pub fn inputs(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(PHI_S_PUBLIC_INPUTS);
        for word in [
            &self.account_hash,
            &self.property_hash,
            &self.tenant_hash,
            &self.date_hash,
            &self.property_id,
        ] {
            out.extend(limbs(word));
        }
        out.push(self.c_p.clone());
        out.push(self.c_b.clone());
        out.push(self.engagement_day.to_string());
        out.push(self.attestation_day.to_string());
        out.push(bind_value(&self.digest));
        out
    }
}

/// Source of the phi_A main component for the eligibility layout and the policy's income multiple.
pub fn main_circom_phi_a(layout: &RecordLayout, income_multiple: u64) -> Result<String> {
    ensure!(
        layout.fields.len() == 1,
        "phi_A reads a layout with the one field {KEY_MONTHLY_INCOME:?}"
    );
    ensure!(income_multiple > 0, "the income multiple must be positive");
    Ok(format!(
        "// Generated from the {id} layout by `cargo run -p pprev-types --bin gen-phase-circuit-main`.\n\
         // Do not edit by hand.\n\
         pragma circom 2.2.0;\n\
         \n\
         include \"phi_a.circom\";\n\
         \n\
         component main {{public [accountHash, incomeHash, cB, amount, bind]}} =\n    \
         PhiA({}, {}, {}, {}, {});\n",
        layout.account_width,
        layout.width_of(KEY_MONTHLY_INCOME)?,
        layout.padding_byte(),
        income_multiple,
        PHI_A_AMOUNT_BITS,
        id = layout.id,
    ))
}

/// Source of the phi_S main component for the tenancy layout.
pub fn main_circom_phi_s(layout: &RecordLayout) -> Result<String> {
    let keys: Vec<&str> = layout.fields.iter().map(|f| f.key.as_str()).collect();
    ensure!(
        keys == [KEY_PROPERTY_ID, KEY_TENANT, KEY_RECORD_DATE],
        "phi_S reads a layout with the fields propertyId, tenant, recordDate in that order"
    );
    ensure!(
        layout.width_of(KEY_RECORD_DATE)? == 10,
        "recordDate is YYYY-MM-DD"
    );
    ensure!(
        layout.width_of(KEY_TENANT)? == layout.account_width,
        "a tenant identifier is an account identifier"
    );
    Ok(format!(
        "// Generated from the {id} layout by `cargo run -p pprev-types --bin gen-phase-circuit-main`.\n\
         // Do not edit by hand.\n\
         pragma circom 2.2.0;\n\
         \n\
         include \"phi_s.circom\";\n\
         \n\
         component main {{public [accountHash, propertyHash, tenantHash, dateHash, propertyId, cP, cB, engagementDay, attestationDay, bind]}} =\n    \
         PhiS({}, {}, {}, {});\n",
        layout.account_width,
        layout.width_of(KEY_PROPERTY_ID)?,
        layout.width_of(KEY_TENANT)?,
        layout.padding_byte(),
        id = layout.id,
    ))
}

#[cfg(test)]
// Dates are written Y_MM_DD, as phi_S encodes them.
#[allow(clippy::inconsistent_digit_grouping)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        Layout::from_json(include_str!("../../../../policies/layouts/title-v1.json")).unwrap()
    }

    #[test]
    fn committed_main_component_matches_the_layout() {
        let committed = include_str!("../../../../circuits/src/main_title_v1.circom");
        assert_eq!(
            committed,
            main_circom(&layout()).unwrap(),
            "circuits/src/main_title_v1.circom is out of date; regenerate it with script/circuits_build.sh"
        );
    }

    #[test]
    fn public_inputs_follow_the_circuit_order() {
        let public = PhiRPublic {
            account_hash: [1; 32],
            owners_hash: [2; 32],
            property_hash: [3; 32],
            property_id: [4; 32],
            c_p: {
                let mut c_p = [0u8; 32];
                c_p[31] = 7;
                c_p
            },
            digest: [5; 32],
        };
        let inputs = public.inputs();
        assert_eq!(inputs.len(), PHI_R_PUBLIC_INPUTS);
        let limb = |b: u8| u128::from_be_bytes([b; 16]).to_string();
        for (i, b) in [1u8, 1, 2, 2, 3, 3, 4, 4].into_iter().enumerate() {
            assert_eq!(inputs[i], limb(b), "input {i}");
        }
        assert_eq!(inputs[8], "7");
        assert_eq!(inputs[9], bind_value(&[5; 32]));
    }

    #[test]
    fn phi_r_refuses_non_canonical_c_p() {
        let r: [u8; 32] = bn254_r().to_bytes_be().try_into().unwrap();
        let mut r_minus_1 = r;
        r_minus_1[31] -= 1;
        assert!(check_field_element(&r_minus_1, "c_P").is_ok());
        assert!(check_field_element(&r, "c_P").is_err());
        assert!(check_field_element(&[0xff; 32], "c_P").is_err());
    }

    fn record_layout(name: &str) -> RecordLayout {
        RecordLayout::load(format!(
            "{}/../../../policies/layouts/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn committed_phase_main_components_match_their_layouts() {
        let policy = crate::PolicyBundle::load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../policies/rental-v1.json"
        ))
        .unwrap();
        let multiple = policy.apply.as_ref().unwrap().income_multiple;
        assert_eq!(
            include_str!("../../../../circuits/src/main_income_v1.circom"),
            main_circom_phi_a(&record_layout("income-v1"), multiple).unwrap(),
            "circuits/src/main_income_v1.circom is out of date; regenerate it with script/circuits_build_as.sh"
        );
        assert_eq!(
            include_str!("../../../../circuits/src/main_tenancy_v1.circom"),
            main_circom_phi_s(&record_layout("tenancy-v1")).unwrap(),
            "circuits/src/main_tenancy_v1.circom is out of date; regenerate it with script/circuits_build_as.sh"
        );
    }

    #[test]
    fn phase_layouts_are_checked_against_their_predicates() {
        assert!(main_circom_phi_a(&record_layout("tenancy-v1"), 3).is_err());
        assert!(main_circom_phi_a(&record_layout("income-v1"), 0).is_err());
        assert!(main_circom_phi_s(&record_layout("income-v1")).is_err());
    }

    #[test]
    fn phi_a_public_inputs_follow_the_circuit_order() {
        let mut c_b = [0u8; 32];
        c_b[31] = 9;
        let public = PhiAPublic::new([1; 32], [2; 32], c_b, U256::from(1000u64), [5; 32]).unwrap();
        let inputs = public.inputs();
        assert_eq!(inputs.len(), PHI_A_PUBLIC_INPUTS);
        let limb = |b: u8| u128::from_be_bytes([b; 16]).to_string();
        assert_eq!(&inputs[..4], [limb(1), limb(1), limb(2), limb(2)]);
        assert_eq!(inputs[4], "9");
        assert_eq!(inputs[5], "1000");
        assert_eq!(inputs[6], bind_value(&[5; 32]));
    }

    #[test]
    fn phi_a_refuses_non_canonical_c_b_and_wide_amounts() {
        let r: [u8; 32] = bn254_r().to_bytes_be().try_into().unwrap();
        let mut r_minus_1 = r;
        r_minus_1[31] -= 1;
        assert!(PhiAPublic::new([0; 32], [0; 32], r_minus_1, U256::ZERO, [0; 32]).is_ok());
        assert!(PhiAPublic::new([0; 32], [0; 32], r, U256::ZERO, [0; 32]).is_err());
        assert!(PhiAPublic::new([0; 32], [0; 32], [0xff; 32], U256::ZERO, [0; 32]).is_err());
        let max = (U256::from(1u8) << PHI_A_AMOUNT_BITS) - U256::from(1u8);
        assert!(PhiAPublic::new([0; 32], [0; 32], [0; 32], max, [0; 32]).is_ok());
        assert!(
            PhiAPublic::new([0; 32], [0; 32], [0; 32], max + U256::from(1u8), [0; 32]).is_err()
        );
    }

    #[test]
    fn phi_s_public_inputs_follow_the_circuit_order() {
        let mut c_p = [0u8; 32];
        c_p[31] = 6;
        let public = PhiSPublic::new(
            [[9; 32], [1; 32], [2; 32], [3; 32]],
            [4; 32],
            [c_p, [0; 32]],
            [2026_10_21, 2026_11_24],
            [5; 32],
        )
        .unwrap();
        let inputs = public.inputs();
        assert_eq!(inputs.len(), PHI_S_PUBLIC_INPUTS);
        let limb = |b: u8| u128::from_be_bytes([b; 16]).to_string();
        for (i, b) in [9u8, 9, 1, 1, 2, 2, 3, 3, 4, 4].into_iter().enumerate() {
            assert_eq!(inputs[i], limb(b), "input {i}");
        }
        assert_eq!(inputs[10], "6");
        assert_eq!(inputs[11], "0");
        assert_eq!(inputs[12], "20261021");
        assert_eq!(inputs[13], "20261124");
        assert_eq!(inputs[14], bind_value(&[5; 32]));
        let new = |c: [[u8; 32]; 2], days: [u32; 2]| {
            PhiSPublic::new([[0; 32]; 4], [0; 32], c, days, [0; 32])
        };
        assert!(new([[0; 32], [0xff; 32]], [0, 0]).is_err());
        assert!(new([[0xff; 32], [0; 32]], [0, 0]).is_err());
        assert!(new([[0; 32]; 2], [1 << 27, 0]).is_err());
        assert!(new([[0; 32]; 2], [0, 1 << 27]).is_err());
        assert!(new([[0; 32]; 2], [(1 << 27) - 1, (1 << 27) - 1]).is_ok());
    }

    #[test]
    fn owner_stride_follows_the_rendered_offsets() {
        let p = PhiRParams::from_layout(&layout()).unwrap();
        assert_eq!(p.owner_stride, p.account_width + 3);
        assert_eq!(
            p.owners_len,
            (p.owner_slots - 1) * p.owner_stride + p.account_width
        );
    }
}
