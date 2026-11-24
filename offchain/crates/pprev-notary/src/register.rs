//! Policy verifier for Register (Section V-B, step (d); D1). It checks the presentation against the
//! policy's layout, recomputes the EIP-712 digest of x_R, verifies the phi_R proof under the
//! policy's verifying key with the public inputs taken from the attestation and from x_R (its
//! txData.propertyId and c_P), and signs x_R with sk_notary at most once per nonce and at most once
//! per attestation (M2).

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

use crate::attestations::AttestationStore;
use crate::groth16::{Groth16Proof, Groth16Verifier};
use crate::nonces::NonceStore;
use crate::notations::{Engagement, NotationStore};
use crate::phases::{ApplyPolicy, SettlePolicy};
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
    /// Recording the nonce (D20), the attestation, and for Settle the notation (M2), and signing
    /// x_psi with sk_notary.
    pub sign_ms: f64,
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

pub struct PolicyVerifier {
    policies: HashMap<B256, RegisterPolicy>,
    pub(crate) apply_policies: HashMap<B256, ApplyPolicy>,
    pub(crate) settle_policies: HashMap<B256, SettlePolicy>,
    /// The deployment's lock window, which fixes the engagement day of phi_S.
    pub(crate) tau_lock: Option<u64>,
    pub(crate) attestation_key: VerifyingKey,
    pub(crate) root_certs: Vec<Vec<u8>>,
    pub(crate) max_session_secs: u64,
    key: StatementKey,
    pub(crate) domain: Eip712Domain,
    pub(crate) nonces: NonceStore,
    /// Attestations that have backed a signed statement, in any phase (M2).
    pub(crate) attestations: AttestationStore,
    /// The engagement each settlement notation was first signed for (M2); set with the phases.
    pub(crate) notations: Option<NotationStore>,
}

impl PolicyVerifier {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policies: HashMap<B256, RegisterPolicy>,
        attestation_key: VerifyingKey,
        root_certs: Vec<Vec<u8>>,
        max_session_secs: u64,
        key: StatementKey,
        domain: Eip712Domain,
        nonces: NonceStore,
        attestations: AttestationStore,
    ) -> Self {
        Self {
            policies,
            apply_policies: HashMap::new(),
            settle_policies: HashMap::new(),
            tau_lock: None,
            attestation_key,
            root_certs,
            max_session_secs,
            key,
            domain,
            nonces,
            attestations,
            notations: None,
        }
    }

    /// Adds the Apply and Settle policies, each keyed by its own identifier, the deployment's lock
    /// window, and the record of settlement notations. A statement is signed only under a policy of
    /// its own phase.
    pub fn with_phases(
        mut self,
        apply: HashMap<B256, ApplyPolicy>,
        settle: HashMap<B256, SettlePolicy>,
        tau_lock: Option<u64>,
        notations: NotationStore,
    ) -> Self {
        self.apply_policies = apply;
        self.settle_policies = settle;
        self.tau_lock = tau_lock;
        self.notations = Some(notations);
        self
    }

    /// Refuses an attestation that has already backed a signed statement (M2). Called once the
    /// presentation has verified under the attestation key.
    pub(crate) fn ensure_unused_attestation(&self, id: &[u8; 32]) -> Result<()> {
        ensure!(
            !self.attestations.contains(id),
            "attestation 0x{} has already backed a signed statement",
            hex::encode(id)
        );
        Ok(())
    }

    /// Records the nonce (D20), the attestation, and for Settle the notation's engagement (M2), in
    /// that order, and signs the digest with sk_notary. Every record is durable before the signature
    /// exists. The caller has checked all of them, so a refusal never records anything.
    pub(crate) fn record_and_sign(
        &mut self,
        eta: B256,
        attestation_id: [u8; 32],
        notation: Option<(B256, &str, Engagement)>,
        digest: B256,
    ) -> Result<[u8; 65]> {
        self.nonces.record(eta.0)?;
        self.attestations.record(attestation_id)?;
        if let Some((policy_id, notation_id, engagement)) = notation {
            self.notations
                .as_mut()
                .context("the notary has no notation record for Settle")?
                .record(policy_id, notation_id, engagement)?;
        }
        self.key.sign(digest)
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
        self.ensure_unused_attestation(&attested.attestation_id)?;
        let digest = digest(x, &self.domain);
        let public = attested.phi_r_public(x.txData.propertyId.0, x.cP.0, digest.0)?;
        let groth16_started = Instant::now();
        let valid = policy.verifier.verify(&request.proof, &public.inputs())?;
        timings.groth16_ms = millis(groth16_started);
        ensure!(
            valid,
            "the phi_R proof does not verify for this statement and attestation"
        );
        timings.verify_ms = millis(started);

        let sign_started = Instant::now();
        let sigma = self.record_and_sign(x.eta, attested.attestation_id, None, digest)?;
        timings.sign_ms = millis(sign_started);
        Ok((sigma, timings))
    }
}
