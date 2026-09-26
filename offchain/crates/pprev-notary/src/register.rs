//! Policy verifier for Register (Section V-B, step (d); D1). It checks the presentation against the
//! policy's layout, recomputes the EIP-712 digest of x_R, verifies the phi_R proof under the
//! policy's verifying key with the public inputs taken from the attestation, and signs x_R with
//! sk_notary at most once per nonce.

use std::collections::HashMap;

use alloy_primitives::B256;
use alloy_sol_types::Eip712Domain;
use anyhow::{Context, Result, ensure};
use pprev_types::Layout;
use pprev_types::statement::{Register, digest};
use tlsn::attestation::presentation::Presentation;
use tlsn::attestation::signing::VerifyingKey;

use crate::groth16::{Groth16Proof, Groth16Verifier};
use crate::nonces::NonceStore;
use crate::presentation::{Expectation, check_presentation};
use crate::sigma::StatementKey;

/// What the notary holds for one Register policy: the response layout of its source and the
/// verifying key of its circuit.
pub struct RegisterPolicy {
    pub layout: Layout,
    pub verifier: Groth16Verifier,
}

/// What the owner submits to the policy verifier: the presentation, x_R, and the proof.
pub struct RegisterRequest {
    pub presentation: Presentation,
    /// The property identifier as the registry writes it; `txData.propertyId` must be its word.
    pub property_id: String,
    pub statement: Register,
    pub proof: Groth16Proof,
}

pub struct PolicyVerifier {
    policies: HashMap<B256, RegisterPolicy>,
    attestation_key: VerifyingKey,
    root_certs: Vec<Vec<u8>>,
    max_session_secs: u64,
    key: StatementKey,
    domain: Eip712Domain,
    nonces: NonceStore,
}

impl PolicyVerifier {
    pub fn new(
        policies: HashMap<B256, RegisterPolicy>,
        attestation_key: VerifyingKey,
        root_certs: Vec<Vec<u8>>,
        max_session_secs: u64,
        key: StatementKey,
        domain: Eip712Domain,
        nonces: NonceStore,
    ) -> Self {
        Self {
            policies,
            attestation_key,
            root_certs,
            max_session_secs,
            key,
            domain,
            nonces,
        }
    }

    /// Returns sigma_R for the request, or the reason for refusing it.
    pub fn sign_register(&mut self, request: RegisterRequest) -> Result<[u8; 65]> {
        let x = &request.statement;
        let policy = self.policies.get(&x.policyId).with_context(|| {
            format!(
                "0x{} is not a Register policy of this notary",
                hex::encode(x.policyId)
            )
        })?;
        ensure!(
            !self.nonces.contains(&x.eta.0),
            "nonce 0x{} has already been signed",
            hex::encode(x.eta)
        );
        ensure!(
            policy.layout.property_id_word(&request.property_id)? == x.txData.propertyId.0,
            "txData.propertyId is not the property of the notarised request"
        );
        let attested = check_presentation(
            request.presentation,
            &Expectation {
                layout: &policy.layout,
                attestation_key: &self.attestation_key,
                root_certs: &self.root_certs,
                property_id: &request.property_id,
                max_session_secs: self.max_session_secs,
            },
        )?;
        ensure!(
            x.tAtt == attested.t_att,
            "tAtt {} is not the attested time {}",
            x.tAtt,
            attested.t_att
        );
        let digest = digest(x, &self.domain);
        let public = attested.phi_r_public(x.txData.propertyId.0, digest.0)?;
        ensure!(
            policy.verifier.verify(&request.proof, &public.inputs())?,
            "the phi_R proof does not verify for this statement and attestation"
        );
        self.nonces.record(x.eta.0)?;
        self.key.sign(digest)
    }
}
