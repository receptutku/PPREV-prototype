//! sigma: the notary's signature over enc(tag_psi, x_psi, chainID, addr_SC) with sk_notary (D19).
//!
//! The notary holds two keys: the attestation key signs TLSNotary attestations (prov), and
//! sk_notary signs statements. Only vk_notary goes on-chain, as the Ethereum address that
//! `EcdsaNotaryVerifier` holds.

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result};

pub struct StatementKey {
    signer: PrivateKeySigner,
}

impl StatementKey {
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self> {
        let signer =
            PrivateKeySigner::from_bytes(&B256::from(*secret)).context("invalid statement key")?;
        Ok(Self { signer })
    }

    /// vk_notary as `EcdsaNotaryVerifier` holds it.
    pub fn vk_notary(&self) -> Address {
        self.signer.address()
    }

    /// sigma in the form `EcdsaNotaryVerifier.verify` reads: r || s || v with v in {27, 28}. The
    /// signer normalises s to the lower half of the curve order (EIP-2).
    pub fn sign(&self, digest: B256) -> Result<[u8; 65]> {
        let signature = self
            .signer
            .sign_hash_sync(&digest)
            .context("signing the statement digest")?;
        Ok(signature.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Signature, U256, keccak256};
    use serde_json::{Value, json};

    use super::*;

    /// Test-only statement key; the vector file records how it is derived.
    const TEST_KEY_LABEL: &str = "pprev.notary.statement-key.test";

    fn test_key() -> StatementKey {
        StatementKey::from_bytes(&keccak256(TEST_KEY_LABEL).0).unwrap()
    }

    fn register_digest() -> B256 {
        let v: Value =
            serde_json::from_str(include_str!("../../../../test-vectors/eip712.json")).unwrap();
        v["register"]["digest"].as_str().unwrap().parse().unwrap()
    }

    fn half_order() -> U256 {
        "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
            .parse()
            .unwrap()
    }

    #[test]
    fn sigma_recovers_to_vk_notary() {
        let key = test_key();
        for digest in [register_digest(), keccak256("other statement")] {
            let sigma = key.sign(digest).unwrap();
            assert!(sigma[64] == 27 || sigma[64] == 28, "v = {}", sigma[64]);
            assert!(
                U256::from_be_slice(&sigma[32..64]) <= half_order(),
                "high s"
            );
            let recovered = Signature::from_raw(&sigma)
                .unwrap()
                .recover_address_from_prehash(&digest)
                .unwrap();
            assert_eq!(recovered, key.vk_notary());
        }
    }

    /// `test-vectors/notary-signature.json` holds sigma over the register digest of
    /// `test-vectors/eip712.json`; `contracts/test/EcdsaNotaryVerifier.t.sol` verifies it on-chain.
    /// RFC 6979 makes the signature deterministic. Regenerate with `PPREV_UPDATE_GOLDEN=1`.
    #[test]
    fn notary_signature_vector_is_current() {
        let key = test_key();
        let digest = register_digest();
        let expected = json!({
            "description": "sigma over the register digest of eip712.json, signed with a test-only statement key",
            "secretKey": format!("keccak256(\"{TEST_KEY_LABEL}\")"),
            "vkNotary": key.vk_notary().to_checksum(None),
            "digest": digest.to_string(),
            "sigma": format!("0x{}", hex::encode(key.sign(digest).unwrap())),
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../test-vectors/notary-signature.json"
        );
        let rendered = serde_json::to_string_pretty(&expected).unwrap() + "\n";
        if std::env::var_os("PPREV_UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &rendered).unwrap();
        }
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(
            committed, rendered,
            "test-vectors/notary-signature.json is out of date; regenerate it with PPREV_UPDATE_GOLDEN=1"
        );
    }
}
