//! Policy verifier for Register (Section V-B, step (d); D1). It checks the presentation against the
//! policy's layout, recomputes the EIP-712 digest of x_R, verifies the phi_R proof under the
//! policy's verifying key with the public inputs taken from the attestation, and signs x_R with
//! sk_notary at most once per nonce.

use std::collections::HashMap;
use std::time::Instant;

use alloy_primitives::B256;
use alloy_sol_types::Eip712Domain;
use anyhow::{Context, Result, ensure};
use pprev_types::Layout;
use pprev_types::statement::{Register, digest};
use serde::{Deserialize, Serialize};
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

/// Wall-clock time of the policy verifier's steps for one accepted request, in milliseconds.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTimings {
    /// `check_presentation`: attestation signature, server identity, layout, t_att.
    pub presentation_ms: f64,
    /// Groth16 verification of the phi_R proof.
    pub groth16_ms: f64,
    /// Every check before signing, the two above included.
    pub verify_ms: f64,
    /// Recording the nonce (D20) and signing x_R with sk_notary.
    pub sign_ms: f64,
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
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
        Ok(self.sign_register_timed(request)?.0)
    }

    /// As [`Self::sign_register`], with the time of each step.
    pub fn sign_register_timed(
        &mut self,
        request: RegisterRequest,
    ) -> Result<([u8; 65], RegisterTimings)> {
        let started = Instant::now();
        let mut timings = RegisterTimings::default();
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
        let presentation_started = Instant::now();
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
        timings.presentation_ms = millis(presentation_started);
        ensure!(
            x.tAtt == attested.t_att,
            "tAtt {} is not the attested time {}",
            x.tAtt,
            attested.t_att
        );
        let digest = digest(x, &self.domain);
        let public = attested.phi_r_public(x.txData.propertyId.0, digest.0)?;
        let groth16_started = Instant::now();
        let valid = policy.verifier.verify(&request.proof, &public.inputs())?;
        timings.groth16_ms = millis(groth16_started);
        ensure!(
            valid,
            "the phi_R proof does not verify for this statement and attestation"
        );
        timings.verify_ms = millis(started);

        let sign_started = Instant::now();
        self.nonces.record(x.eta.0)?;
        let sigma = self.key.sign(digest)?;
        timings.sign_ms = millis(sign_started);
        Ok((sigma, timings))
    }
}
