//! Policy verifier for Apply and Settle (Section V-B, step (d), for psi in {A, S}). As for Register,
//! it checks the presentation against the policy's layout, recomputes the EIP-712 digest of x_psi,
//! verifies the predicate proof under the policy's verifying key with every public input taken from
//! the attestation and from x_psi, never from the submitter, and signs x_psi at most once per nonce.
//!
//! phi_A's public inputs are the attested commitments to the account and the income, c_B, and
//! txData.amount. phi_S's are the attested commitments to the property, the tenant, and the record
//! date, txData.propertyId, c_B, and the engagement day, which the notary derives from expiresAt,
//! the deployment's tau_lock, and the policy's time zone.

use std::time::Instant;

use alloy_primitives::B256;
use anyhow::{Context, Result, ensure};
use pprev_types::RecordLayout;
use pprev_types::calendar::engagement_day;
use pprev_types::circuit::{PhiAPublic, PhiSPublic};
use pprev_types::statement::{Apply, Settle, digest};
use tlsn::attestation::presentation::Presentation;

use crate::groth16::{Groth16Proof, Groth16Verifier};
use crate::presentation::{ShapeExpectation, check_shape};
use crate::register::{PolicyVerifier, RegisterTimings};

/// What the notary holds for one Apply policy: the eligibility source's layout and phi_A's key.
pub struct ApplyPolicy {
    pub layout: RecordLayout,
    pub verifier: Groth16Verifier,
}

/// What the notary holds for one Settle policy: the settlement source's layout, phi_S's key, and the
/// registry's time zone.
pub struct SettlePolicy {
    pub layout: RecordLayout,
    pub verifier: Groth16Verifier,
    /// Offset of the registry's time zone from UTC, in seconds.
    pub utc_offset_secs: i64,
}

/// What the counterparty submits for Apply: the presentation of its eligibility session, x_A, and
/// the phi_A proof.
pub struct ApplyRequest {
    pub presentation: Presentation,
    pub statement: Apply,
    pub proof: Groth16Proof,
}

/// What the owner submits for Settle: the presentation of the tenancy notation, the notation's
/// identifier (the request target), x_S, and the phi_S proof.
pub struct SettleRequest {
    pub presentation: Presentation,
    pub notation_id: String,
    pub statement: Settle,
    pub proof: Groth16Proof,
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

/// A request target segment: letters, digits, and '-' only, so that it cannot change the request
/// line around it.
fn check_subject(subject: &str) -> Result<()> {
    ensure!(
        !subject.is_empty()
            && subject.len() <= 64
            && subject
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "{subject:?} is not a record identifier"
    );
    Ok(())
}

impl PolicyVerifier {
    /// Returns sigma_A for the request, with the time of each step, or the reason for refusing it.
    pub fn sign_apply_timed(
        &mut self,
        request: ApplyRequest,
    ) -> Result<([u8; 65], RegisterTimings)> {
        let started = Instant::now();
        let mut timings = RegisterTimings::default();
        let x = &request.statement;
        let policy = self.apply_policies.get(&x.policyId).with_context(|| {
            format!(
                "0x{} is not an Apply policy of this notary",
                hex::encode(x.policyId)
            )
        })?;
        self.ensure_unsigned(x.eta)?;
        let presentation_started = Instant::now();
        let shape = policy.layout.shape("")?;
        let attested = check_shape(
            request.presentation,
            &ShapeExpectation {
                shape: &shape,
                attestation_key: &self.attestation_key,
                root_certs: &self.root_certs,
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
        let [account_hash, income_hash] = attested.hidden_hashes[..] else {
            anyhow::bail!("the eligibility layout has two hidden fields");
        };
        let digest = digest(x, &self.domain);
        let public = PhiAPublic::new(account_hash, income_hash, x.cB.0, x.txData.amount, digest.0)?;
        let groth16_started = Instant::now();
        let valid = policy.verifier.verify(&request.proof, &public.inputs())?;
        timings.groth16_ms = millis(groth16_started);
        ensure!(
            valid,
            "the phi_A proof does not verify for this statement and attestation"
        );
        timings.verify_ms = millis(started);
        let sign_started = Instant::now();
        let sigma = self.record_and_sign(x.eta, digest)?;
        timings.sign_ms = millis(sign_started);
        Ok((sigma, timings))
    }

    /// Returns sigma_S for the request, with the time of each step, or the reason for refusing it.
    pub fn sign_settle_timed(
        &mut self,
        request: SettleRequest,
    ) -> Result<([u8; 65], RegisterTimings)> {
        let started = Instant::now();
        let mut timings = RegisterTimings::default();
        let x = &request.statement;
        let policy = self.settle_policies.get(&x.policyId).with_context(|| {
            format!(
                "0x{} is not a Settle policy of this notary",
                hex::encode(x.policyId)
            )
        })?;
        let tau_lock = self
            .tau_lock
            .context("the notary has no tau_lock for Settle")?;
        self.ensure_unsigned(x.eta)?;
        check_subject(&request.notation_id)?;
        let expires_at: u64 = x
            .expiresAt
            .try_into()
            .context("expiresAt exceeds 64 bits")?;
        let day = engagement_day(expires_at, tau_lock, policy.utc_offset_secs)?;
        let presentation_started = Instant::now();
        let shape = policy.layout.shape(&request.notation_id)?;
        let attested = check_shape(
            request.presentation,
            &ShapeExpectation {
                shape: &shape,
                attestation_key: &self.attestation_key,
                root_certs: &self.root_certs,
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
        // The account of the owner's session is committed but phi_S does not read it.
        let [_account, property_hash, tenant_hash, date_hash] = attested.hidden_hashes[..] else {
            anyhow::bail!("the tenancy layout has four hidden fields");
        };
        let digest = digest(x, &self.domain);
        let public = PhiSPublic::new(
            [property_hash, tenant_hash, date_hash],
            x.txData.propertyId.0,
            x.cB.0,
            day,
            digest.0,
        )?;
        let groth16_started = Instant::now();
        let valid = policy.verifier.verify(&request.proof, &public.inputs())?;
        timings.groth16_ms = millis(groth16_started);
        ensure!(
            valid,
            "the phi_S proof does not verify for this statement and attestation"
        );
        timings.verify_ms = millis(started);
        let sign_started = Instant::now();
        let sigma = self.record_and_sign(x.eta, digest)?;
        timings.sign_ms = millis(sign_started);
        Ok((sigma, timings))
    }

    /// Returns sigma_A, or the reason for refusing it.
    pub fn sign_apply(&mut self, request: ApplyRequest) -> Result<[u8; 65]> {
        Ok(self.sign_apply_timed(request)?.0)
    }

    /// Returns sigma_S, or the reason for refusing it.
    pub fn sign_settle(&mut self, request: SettleRequest) -> Result<[u8; 65]> {
        Ok(self.sign_settle_timed(request)?.0)
    }

    fn ensure_unsigned(&self, eta: B256) -> Result<()> {
        ensure!(
            !self.nonces.contains(&eta.0),
            "nonce 0x{} has already been signed",
            hex::encode(eta)
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_cannot_change_the_request_line() {
        assert!(check_subject("N-0001").is_ok());
        for bad in [
            "",
            "N 0001",
            "N-0001 HTTP/1.1",
            "../title",
            "N\r\n",
            &"N".repeat(65),
        ] {
            assert!(check_subject(bad).is_err(), "{bad:?}");
        }
    }
}
