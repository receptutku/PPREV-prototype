//! Groth16 verification of phi_R proofs (D22): snarkjs' JSON verification key, proof, and public
//! inputs, checked with arkworks on BN254. snarkjs and arkworks check the same pairing equation,
//! e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta), so a proof that `snarkjs groth16 verify`
//! accepts is accepted here.

use anyhow::{Context, Result, bail, ensure};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger256, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key};
use num_bigint::BigUint;
use serde::Deserialize;

/// A decimal string as an element of the prime field `F`, rejecting values at or above its modulus.
fn field<F: PrimeField<BigInt = BigInteger256>>(s: &str) -> Result<F> {
    ensure!(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        "{s:?} is not a decimal number"
    );
    let n: BigUint = s.parse().context("decimal number")?;
    let repr = BigInteger256::try_from(n).map_err(|_| anyhow::anyhow!("{s} exceeds 256 bits"))?;
    F::from_bigint(repr).with_context(|| format!("{s} is not below the field modulus"))
}

/// A G1 point in snarkjs' affine form `[x, y, "1"]`, on the curve.
fn g1(p: &[String]) -> Result<G1Affine> {
    ensure!(
        p.len() == 3 && p[2] == "1",
        "expected an affine G1 point [x, y, \"1\"]"
    );
    let point = G1Affine::new_unchecked(field::<Fq>(&p[0])?, field::<Fq>(&p[1])?);
    ensure!(point.is_on_curve(), "G1 point is not on the curve");
    // BN254 G1 has cofactor 1: every point on the curve is in the group.
    Ok(point)
}

/// A G2 point in snarkjs' affine form `[[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]`, on the curve and
/// in the prime-order subgroup. snarkjs writes each Fq2 element real part first (c0, c1); the
/// Solidity verifier and the EIP-197 precompile take them the other way round.
fn g2(p: &[Vec<String>]) -> Result<G2Affine> {
    ensure!(
        p.len() == 3 && p.iter().all(|c| c.len() == 2) && p[2][0] == "1" && p[2][1] == "0",
        "expected an affine G2 point [[x0, x1], [y0, y1], [\"1\", \"0\"]]"
    );
    let fq2 = |c: &[String]| -> Result<Fq2> { Ok(Fq2::new(field(&c[0])?, field(&c[1])?)) };
    let point = G2Affine::new_unchecked(fq2(&p[0])?, fq2(&p[1])?);
    ensure!(point.is_on_curve(), "G2 point is not on the curve");
    ensure!(
        point.is_in_correct_subgroup_assuming_on_curve(),
        "G2 point is not in the prime-order subgroup"
    );
    Ok(point)
}

#[derive(Deserialize)]
struct VkJson {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: usize,
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct ProofJson {
    protocol: String,
    curve: String,
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

fn check_scheme(protocol: &str, curve: &str) -> Result<()> {
    ensure!(
        protocol == "groth16",
        "protocol {protocol:?} is not groth16"
    );
    ensure!(curve == "bn128", "curve {curve:?} is not bn128 (BN254)");
    Ok(())
}

/// A phi_R verifying key from snarkjs' `verification_key.json`, prepared for verification.
pub struct Groth16Verifier {
    pvk: PreparedVerifyingKey<Bn254>,
    n_public: usize,
}

impl Groth16Verifier {
    pub fn from_snarkjs_json(json: &str) -> Result<Self> {
        let vk: VkJson = serde_json::from_str(json).context("parsing the verification key")?;
        check_scheme(&vk.protocol, &vk.curve)?;
        ensure!(
            vk.ic.len() == vk.n_public + 1,
            "IC has {} points for {} public inputs",
            vk.ic.len(),
            vk.n_public
        );
        let key = VerifyingKey::<Bn254> {
            alpha_g1: g1(&vk.vk_alpha_1)?,
            beta_g2: g2(&vk.vk_beta_2)?,
            gamma_g2: g2(&vk.vk_gamma_2)?,
            delta_g2: g2(&vk.vk_delta_2)?,
            gamma_abc_g1: vk.ic.iter().map(|p| g1(p)).collect::<Result<_>>()?,
        };
        Ok(Self {
            pvk: prepare_verifying_key(&key),
            n_public: vk.n_public,
        })
    }

    pub fn n_public(&self) -> usize {
        self.n_public
    }

    /// Checks `proof` against `public`, decimal strings below the scalar field order in the
    /// circuit's order.
    pub fn verify(&self, proof: &Groth16Proof, public: &[String]) -> Result<bool> {
        if public.len() != self.n_public {
            bail!(
                "{} public inputs, the key expects {}",
                public.len(),
                self.n_public
            );
        }
        let inputs: Vec<Fr> = public.iter().map(|s| field(s)).collect::<Result<_>>()?;
        Groth16::<Bn254>::verify_proof(&self.pvk, &proof.0, &inputs).context("Groth16 verification")
    }
}

/// A proof from snarkjs' `proof.json`.
#[derive(Clone, Debug, PartialEq)]
pub struct Groth16Proof(pub Proof<Bn254>);

impl Groth16Proof {
    pub fn from_snarkjs_json(json: &str) -> Result<Self> {
        let p: ProofJson = serde_json::from_str(json).context("parsing the proof")?;
        check_scheme(&p.protocol, &p.curve)?;
        let (a, b, c) = (g1(&p.pi_a)?, g2(&p.pi_b)?, g1(&p.pi_c)?);
        ensure!(
            !a.is_zero() && !b.is_zero() && !c.is_zero(),
            "proof has a point at infinity"
        );
        Ok(Self(Proof { a, b, c }))
    }
}

/// Public inputs from snarkjs' `public.json`.
pub fn public_from_snarkjs_json(json: &str) -> Result<Vec<String>> {
    let public: Vec<String> = serde_json::from_str(json).context("parsing the public inputs")?;
    for s in &public {
        field::<Fr>(s)?;
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use ark_ec::short_weierstrass::Affine;
    use ark_ff::UniformRand;

    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // G2 generator from EIP-197, which lists it as (x_im * i + x_re, y_im * i + y_re).
    const G2_X_RE: &str =
        "10857046999023057135944570762232829481370756359578518086990519993285655852781";
    const G2_X_IM: &str =
        "11559732032986387107991004021392285783925812861821192530917403151452391805634";
    const G2_Y_RE: &str =
        "8495653923123431417604973247489272438418190587263600148770280649306958101930";
    const G2_Y_IM: &str =
        "4082367875863433681332203403145435568316851327593401208105741076214120093531";
    const Q: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    const R: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    #[test]
    fn field_elements_must_be_canonical_decimals() {
        assert_eq!(field::<Fr>("0").unwrap(), Fr::from(0u32));
        assert!(field::<Fr>(&(R.parse::<BigUint>().unwrap() - 1u32).to_string()).is_ok());
        assert!(field::<Fr>(R).is_err());
        assert!(field::<Fq>(Q).is_err());
        assert!(field::<Fr>("").is_err());
        assert!(field::<Fr>("-1").is_err());
        assert!(field::<Fr>("0x01").is_err());
        assert!(field::<Fr>(&"9".repeat(80)).is_err());
    }

    #[test]
    fn g1_points_must_be_affine_and_on_the_curve() {
        assert_eq!(g1(&s(&["1", "2", "1"])).unwrap(), G1Affine::generator());
        assert!(g1(&s(&["1", "3", "1"])).is_err());
        assert!(g1(&s(&["0", "1", "0"])).is_err());
        assert!(g1(&s(&["1", "2"])).is_err());
    }

    #[test]
    fn g2_coordinates_are_read_real_part_first() {
        let point = |x: [&str; 2], y: [&str; 2]| vec![s(&x), s(&y), s(&["1", "0"])];
        assert_eq!(
            g2(&point([G2_X_RE, G2_X_IM], [G2_Y_RE, G2_Y_IM])).unwrap(),
            G2Affine::generator()
        );
        // The order of the Solidity verifier and EIP-197 is not snarkjs' order.
        assert!(g2(&point([G2_X_IM, G2_X_RE], [G2_Y_IM, G2_Y_RE])).is_err());
    }

    #[test]
    fn g2_points_outside_the_subgroup_are_rejected() {
        let mut rng = ark_std::test_rng();
        let outside = loop {
            let x = Fq2::rand(&mut rng);
            if let Some(p) = Affine::<ark_bn254::g2::Config>::get_point_from_x_unchecked(x, true)
                && !p.is_in_correct_subgroup_assuming_on_curve()
            {
                break p;
            }
        };
        let dec = |f: Fq| f.to_string();
        let json = vec![
            vec![dec(outside.x.c0), dec(outside.x.c1)],
            vec![dec(outside.y.c0), dec(outside.y.c1)],
            s(&["1", "0"]),
        ];
        let err = g2(&json).unwrap_err().to_string();
        assert!(err.contains("subgroup"), "{err}");
        // Sanity: the point is on the curve, so only the subgroup check rejects it.
        assert!(outside.is_on_curve());
    }

    #[test]
    fn scheme_and_key_shape_are_checked() {
        let g1s = s(&["1", "2", "1"]);
        let g2s = vec![
            s(&[G2_X_RE, G2_X_IM]),
            s(&[G2_Y_RE, G2_Y_IM]),
            s(&["1", "0"]),
        ];
        let vk = |protocol: &str, curve: &str, n: usize, ic: usize| {
            serde_json::json!({
                "protocol": protocol, "curve": curve, "nPublic": n,
                "vk_alpha_1": g1s, "vk_beta_2": g2s, "vk_gamma_2": g2s, "vk_delta_2": g2s,
                "IC": vec![g1s.clone(); ic],
            })
            .to_string()
        };
        assert!(Groth16Verifier::from_snarkjs_json(&vk("groth16", "bn128", 2, 3)).is_ok());
        assert!(Groth16Verifier::from_snarkjs_json(&vk("plonk", "bn128", 2, 3)).is_err());
        assert!(Groth16Verifier::from_snarkjs_json(&vk("groth16", "bls12381", 2, 3)).is_err());
        assert!(Groth16Verifier::from_snarkjs_json(&vk("groth16", "bn128", 2, 2)).is_err());
        let verifier = Groth16Verifier::from_snarkjs_json(&vk("groth16", "bn128", 2, 3)).unwrap();
        let proof = Groth16Proof(Proof {
            a: G1Affine::generator(),
            b: G2Affine::generator(),
            c: G1Affine::generator(),
        });
        assert!(verifier.verify(&proof, &s(&["1"])).is_err());
        assert!(verifier.verify(&proof, &s(&["1", R])).is_err());
    }
}
