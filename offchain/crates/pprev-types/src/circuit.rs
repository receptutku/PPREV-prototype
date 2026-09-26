//! Parameters of the phi_R circuit, derived from the response layout, and the generated main
//! component (`circuits/src/main_title_v1.circom`).

use anyhow::{Result, ensure};

use crate::Layout;
use crate::field::{bind_value, limbs};

/// Number of public inputs of phi_R.
pub const PHI_R_PUBLIC_INPUTS: usize = 9;

/// What the policy verifier knows of a phi_R instance: the attested commitments, the statement's
/// `txData.propertyId`, and the EIP-712 digest of x_R.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiRPublic {
    /// SHA-256 commitments to the `account`, `owners`, and `propertyId` values.
    pub account_hash: [u8; 32],
    pub owners_hash: [u8; 32],
    pub property_hash: [u8; 32],
    /// `txData.propertyId`.
    pub property_id: [u8; 32],
    /// EIP-712 digest of x_R.
    pub digest: [u8; 32],
}

impl PhiRPublic {
    /// The public inputs in the circuit's order, as decimal strings (the form of snarkjs'
    /// `public.json`): two limbs per commitment, two limbs of `txData.propertyId`, `bind`.
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
         component main {{public [accountHash, ownersHash, propertyHash, propertyId, bind]}} =\n    \
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

#[cfg(test)]
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
            digest: [5; 32],
        };
        let inputs = public.inputs();
        assert_eq!(inputs.len(), PHI_R_PUBLIC_INPUTS);
        let limb = |b: u8| u128::from_be_bytes([b; 16]).to_string();
        for (i, b) in [1u8, 1, 2, 2, 3, 3, 4, 4].into_iter().enumerate() {
            assert_eq!(inputs[i], limb(b), "input {i}");
        }
        assert_eq!(inputs[8], bind_value(&[5; 32]));
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
