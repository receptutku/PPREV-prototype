//! 32-byte values as public inputs of phi_R, which are elements of the BN254 scalar field.

use num_bigint::BigUint;

/// Order r of the BN254 scalar field, the field of the circom witness and of Groth16 public inputs.
pub const BN254_R: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

pub fn bn254_r() -> BigUint {
    BN254_R.parse().expect("BN254_R is a decimal number")
}

/// The two 128-bit halves of a big-endian 32-byte value, most significant first, as decimal
/// strings. Each half is below r, so the encoding is injective.
pub fn limbs(word: &[u8; 32]) -> [String; 2] {
    let (hi, lo) = word.split_at(16);
    [
        u128::from_be_bytes(hi.try_into().expect("16 bytes")).to_string(),
        u128::from_be_bytes(lo.try_into().expect("16 bytes")).to_string(),
    ]
}

/// The `bind` public input: the EIP-712 digest of x_R read as a big-endian uint256, modulo r.
pub fn bind_value(digest: &[u8; 32]) -> String {
    (BigUint::from_bytes_be(digest) % bn254_r()).to_str_radix(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn limbs_split_big_endian() {
        let w = word("000000000000000000000000000000ff00000000000000000000000000000102");
        assert_eq!(limbs(&w), ["255".to_string(), "258".to_string()]);
        assert_eq!(
            limbs(&[0xff; 32]),
            [u128::MAX.to_string(), u128::MAX.to_string()]
        );
    }

    // Reference values computed with Python integers.
    #[test]
    fn bind_reduces_modulo_r() {
        assert_eq!(bind_value(&[0; 32]), "0");
        let r = word("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
        assert_eq!(bind_value(&r), "0");
        let r_minus_1 = word("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
        assert_eq!(bind_value(&r_minus_1), (bn254_r() - 1u32).to_str_radix(10));
        assert_eq!(
            bind_value(&[0xff; 32]),
            "6350874878119819312338956282401532410528162663560392320966563075034087161850"
        );
        // Register digest of test-vectors/eip712.json.
        let digest = word("b9cb90d431dfd432c52ae789635458de8acdec66e1817a1aa359bc979a151564");
        assert_eq!(
            bind_value(&digest),
            "18372817898771479638737153300393225663588808110949469759857382314700889724257"
        );
    }
}
