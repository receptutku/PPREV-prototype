//! Apply and Settle end to end (Sections V-E and V-G), as `register` runs Register: registry login,
//! MPC-TLS session, presentation, x_psi, the predicate proof, sigma_psi from the policy verifier, and
//! the transaction. The counterparty runs Apply against its eligibility record; the owner runs
//! Settle against a tenancy notation, with the opening of c_B that the counterparty handed over.
//! Every run yields a [`PhaseRecord`] with the time of each step.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, B256, Bytes, U256};
use anyhow::{Context, Result, ensure};
use pprev_notary::mock::counterparty_commitment;
use pprev_notary::presentation::t_att_of;
use pprev_notary::wire::{
    ApplySubmission, RegisterReply, SettleSubmission, Submission, submit as submit_to_verifier,
};
use pprev_types::calendar::engagement_day;
use pprev_types::circuit::{PhiAPublic, PhiSPublic};
use pprev_types::statement::{Apply, Settle, TxData, commitment, digest, domain};
use pprev_types::{PolicyBundle, RecordLayout, ResponseShape};
use serde::Serialize;
use tlsn::attestation::CryptoProvider;
use tlsn::attestation::presentation::Presentation;
use tlsn::verifier::ServerCertVerifier;
use tlsn::webpki::{CertificateDer, RootCertStore};

use crate::chain::{self, AppliedEvent, ApplyPayload, PhaseOutcome, SettlePayload, SettledEvent};
use crate::circuit::{
    self, CircuitFiles, PhiAInput, PhiSInput, Unsatisfied, commitment as field_commitment,
};
use crate::counting::{ByteCounts, CountingStream};
use crate::register::{Notarization, Resources, Timings, VerifierDetail, Witness};
use crate::session::{NotarizedShape, ShapeSetup, notarize_shape_with_retries, present_shape};

/// Registry, notary, and policy verifier of one attested phase.
#[derive(Clone)]
pub struct SessionConfig {
    pub notary: SocketAddr,
    pub verifier: SocketAddr,
    pub registry: SocketAddr,
    /// Registry CA certificate (DER).
    pub ca_der: Vec<u8>,
    pub account: String,
    pub password: String,
    pub max_sent: usize,
    pub max_recv: usize,
    pub max_retries: u32,
    pub preprocess_timeout: Duration,
}

/// The listing as Register published it: txID, txData, and the opening r of C_tx.
#[derive(Clone, Debug)]
pub struct Listing {
    pub tx_id: U256,
    pub tx_data: TxData,
    pub r: B256,
}

pub struct ApplyConfig {
    pub session: SessionConfig,
    pub layout: RecordLayout,
    pub policy: PolicyBundle,
    pub rpc_url: String,
    pub contract: Address,
    pub key: PrivateKeySigner,
    pub listing: Listing,
    pub deposit: U256,
    pub circuits: CircuitFiles,
    /// Directory for the witness input, the proof, and the payload.
    pub out: PathBuf,
    /// Nonce to use instead of a fresh one (negative test).
    pub eta: Option<B256>,
    /// Identifier for c_B instead of the session's account (negative test: c_B naming another
    /// account than the one whose income the session shows).
    pub identifier: Option<String>,
    /// A `proof.json` to submit instead of the counterparty's own proof (negative test).
    pub proof_from: Option<PathBuf>,
    /// Send the transaction; otherwise stop after sigma_A.
    pub submit: bool,
}

/// The engagement as Engage recorded it.
#[derive(Clone, Debug)]
pub struct Engagement {
    pub eng_id: U256,
    pub expires_at: U256,
}

pub struct SettleConfig {
    pub session: SessionConfig,
    pub layout: RecordLayout,
    pub policy: PolicyBundle,
    pub rpc_url: String,
    pub contract: Address,
    pub key: PrivateKeySigner,
    pub listing: Listing,
    pub engagement: Engagement,
    /// c_B as Apply recorded it, and its opening from the counterparty.
    pub c_b: B256,
    pub identifier: String,
    pub salt: B256,
    /// The tenancy notation to retrieve: the request target.
    pub notation_id: String,
    pub circuits: CircuitFiles,
    pub out: PathBuf,
    pub eta: Option<B256>,
    pub proof_from: Option<PathBuf>,
    pub submit: bool,
}

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    /// Included on-chain with the phase's event.
    Included,
    /// sigma_psi obtained; the transaction was not sent.
    Signed,
    /// The predicate has no witness for the session, and no other proof was given.
    NoWitness,
    /// The policy verifier refused to sign.
    Refused,
    /// The node rejected the transaction.
    Reverted,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseRecord<P, E> {
    /// `apply` or `settle`.
    pub phase: &'static str,
    pub outcome: Outcome,
    pub reason: Option<String>,
    pub account: String,
    pub submitter: Address,
    pub policy_id: B256,
    pub eta: B256,
    pub t_att: u64,
    /// The predicate's public inputs as the submitter computed them.
    pub public_inputs: Vec<String>,
    pub notarization: Notarization,
    pub witness: Witness,
    /// `own`, or `borrowed:sha256:<digest>` of the borrowed proof file.
    pub proof_source: String,
    pub timings: Timings,
    pub resources: Resources,
    pub payload: Option<P>,
    pub submission: Option<PhaseOutcome<E>>,
}

pub type ApplyRecord = PhaseRecord<ApplyPayload, AppliedEvent>;
pub type SettleRecord = PhaseRecord<SettlePayload, SettledEvent>;

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn unix_ms() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_millis() as i128
}

/// A notarised session with its presentation and the attested t_att.
struct Attested {
    notarized: NotarizedShape,
    presentation: Presentation,
    t_att: u64,
    notarization: Notarization,
    timings: Timings,
    resources: Resources,
    attestation_received: Instant,
}

/// Steps (b) of Section V-B for any phase: login, MPC-TLS session for `shape`, presentation, and
/// t_att read back from it.
async fn attest(session: &SessionConfig, shape: ResponseShape) -> Result<Attested> {
    let mut timings = Timings::default();
    let started = Instant::now();
    let token = crate::login(
        session.registry,
        &shape.server_name,
        &session.ca_der,
        &session.account,
        &session.password,
    )
    .await?;
    timings.outside_delta.login_ms = millis(started);

    let setup = ShapeSetup {
        shape,
        registry_addr: session.registry,
        root_certs: vec![session.ca_der.clone()],
        token,
        max_sent: session.max_sent,
        max_recv: session.max_recv,
        preprocess_timeout: session.preprocess_timeout,
    };
    let notary_addr = session.notary;
    let mut attempt_started = Vec::new();
    let mut attempt_counts = Vec::new();
    let (notarized, stats) = notarize_shape_with_retries(
        |_attempt| {
            attempt_started.push(Instant::now());
            let counts = ByteCounts::default();
            attempt_counts.push(counts.clone());
            async move {
                let stream = tokio::net::TcpStream::connect(notary_addr).await?;
                anyhow::Ok(CountingStream::with_counts(stream, counts))
            }
        },
        &setup,
        session.max_retries,
    )
    .await?;
    let attestation_received = Instant::now();
    let arrival_unix_ms = unix_ms();
    timings.outside_delta.mpc_tls_ms =
        (attestation_received - *attempt_started.last().expect("one attempt")).as_secs_f64()
            * 1000.0;
    let resources = Resources {
        mpc_traffic: attempt_counts.last().expect("one attempt").traffic(),
        ..Resources::default()
    };

    let started = Instant::now();
    let presentation = present_shape(&notarized, false)?;
    timings.inside_delta.presentation_ms = millis(started);

    let started = Instant::now();
    let provider = CryptoProvider {
        cert: ServerCertVerifier::new(&RootCertStore {
            roots: vec![CertificateDer(session.ca_der.clone())],
        })?,
        ..Default::default()
    };
    let output = presentation
        .clone()
        .verify(&provider)
        .context("verifying the submitter's own presentation")?;
    let t_att = t_att_of(&output)?;
    timings.inside_delta.read_t_att_ms = millis(started);
    timings.attestation_arrival_minus_t_att_ms = arrival_unix_ms - i128::from(t_att) * 1000;

    Ok(Attested {
        notarized,
        presentation,
        t_att,
        notarization: Notarization {
            attempts: stats.attempts,
            stalls: stats.stalls,
        },
        timings,
        resources,
        attestation_received,
    })
}

/// Step (c): the predicate proof, or the borrowed one. `Ok(None)` when the predicate has no witness
/// and no proof was borrowed; the record then says why.
fn prove_or_borrow<P, E>(
    circuits: &CircuitFiles,
    input: &impl Serialize,
    out: &std::path::Path,
    proof_from: Option<&PathBuf>,
    predicate: &str,
    record: &mut PhaseRecord<P, E>,
) -> Result<Option<String>> {
    let own = match circuit::prove(circuits, input, out) {
        Ok(proof) => {
            let inside = &mut record.timings.inside_delta;
            inside.witness_ms = Some(proof.timings.witness_ms);
            inside.snarkjs_prove_ms = Some(proof.timings.prove_ms);
            inside.t_prove_ms = Some(proof.timings.witness_ms + proof.timings.prove_ms);
            record.resources.witness_peak_rss_bytes = proof.timings.witness_peak_rss_bytes;
            record.resources.snarkjs_peak_rss_bytes = proof.timings.prove_peak_rss_bytes;
            Some(proof.proof_json)
        }
        Err(e) => {
            let Some(unsatisfied) = e.downcast_ref::<Unsatisfied>() else {
                return Err(e);
            };
            record.witness = Witness {
                satisfied: false,
                failed_assertion: Some(format!(
                    "template {} line {}",
                    unsatisfied.template, unsatisfied.line
                )),
            };
            record.reason = Some(format!(
                "{predicate} has no witness for this input: assertion failed in template {} at line {}",
                unsatisfied.template, unsatisfied.line
            ));
            None
        }
    };
    match proof_from {
        Some(path) => {
            let (json, source) = circuit::read_borrowed_proof(path)?;
            record.proof_source = source;
            Ok(Some(json))
        }
        None => Ok(own),
    }
}

/// Step (d): sigma_psi from the policy verifier, or the refusal.
async fn sign<P, E>(
    verifier: SocketAddr,
    submission: Submission,
    record: &mut PhaseRecord<P, E>,
) -> Result<Option<Bytes>> {
    let started = Instant::now();
    let reply = submit_to_verifier(verifier, &submission).await?;
    record.timings.verifier_round_trip_ms = Some(millis(started));
    match reply {
        RegisterReply::Refused { reason } => {
            record.outcome = Outcome::Refused;
            record.reason = Some(reason);
            Ok(None)
        }
        RegisterReply::Signed {
            sigma,
            decode_ms,
            timings,
        } => {
            record.timings.inside_delta.t_verify_ms = Some(decode_ms + timings.verify_ms);
            record.timings.inside_delta.t_sign_ms = Some(timings.sign_ms);
            record.timings.verifier = Some(VerifierDetail {
                decode_ms,
                presentation_ms: timings.presentation_ms,
                groth16_ms: timings.groth16_ms,
                verify_ms: timings.verify_ms,
                sign_ms: timings.sign_ms,
            });
            Ok(Some(Bytes::from(sigma)))
        }
    }
}

fn finish<P, E>(
    mut record: PhaseRecord<P, E>,
    outcome: Outcome,
    attestation_received: Instant,
) -> PhaseRecord<P, E> {
    record.outcome = outcome;
    record.timings.after_attestation_ms = millis(attestation_received);
    record
}

/// A fresh salt for c_B: 32 random bytes below the field order (the top three bits cleared).
fn fresh_salt() -> B256 {
    let mut salt: [u8; 32] = rand::random();
    salt[0] &= 0x1f;
    B256::from(salt)
}

/// Runs Apply for `config`. Expected refusals end the run with the matching [`Outcome`]; anything
/// else is an error.
pub async fn run_apply(config: &ApplyConfig) -> Result<ApplyRecord> {
    std::fs::create_dir_all(&config.out)
        .with_context(|| format!("creating {}", config.out.display()))?;
    let submitter = config.key.address();
    let chain_id = chain::chain_id(&config.rpc_url).await?;
    let eta = config
        .eta
        .unwrap_or_else(|| B256::from(rand::random::<[u8; 32]>()));
    let salt = fresh_salt();

    let attested = attest(&config.session, config.layout.shape("")?).await?;

    // c_B = H_c(identifier, salt), the identifier padded to the account width (Section V-E).
    let identifier = config.layout.pad(
        config
            .identifier
            .as_deref()
            .unwrap_or(&config.session.account),
        config.layout.account_width,
    )?;
    let c_b = counterparty_commitment(identifier.as_bytes(), &salt.0)?;

    // x_A (Table III) with a_B = the counterparty's account.
    let listing = &config.listing;
    let policy_id_a = config.policy.policy_id_a();
    let x = Apply {
        txId: listing.tx_id,
        cTx: commitment(&listing.tx_data, config.policy.policy_id_r(), listing.r),
        txData: listing.tx_data.clone(),
        cB: c_b,
        policyId: policy_id_a,
        submitter,
        eta,
        tAtt: attested.t_att,
    };
    let d = digest(&x, &domain(chain_id, config.contract));
    let openings = &attested.notarized.openings;
    ensure!(
        openings.len() == 2,
        "the eligibility layout has two hidden fields"
    );
    let public = PhiAPublic::new(
        field_commitment(&openings[0]),
        field_commitment(&openings[1]),
        c_b.0,
        listing.tx_data.amount,
        d.0,
    )?;

    let mut record = ApplyRecord {
        phase: "apply",
        outcome: Outcome::NoWitness,
        reason: None,
        account: config.session.account.clone(),
        submitter,
        policy_id: policy_id_a,
        eta,
        t_att: attested.t_att,
        public_inputs: public.inputs(),
        notarization: attested.notarization,
        witness: Witness {
            satisfied: true,
            failed_assertion: None,
        },
        proof_source: "own".into(),
        timings: attested.timings,
        resources: attested.resources,
        payload: None,
        submission: None,
    };

    let input = PhiAInput::new(&public, openings, &salt.0)?;
    let Some(proof_json) = prove_or_borrow(
        &config.circuits,
        &input,
        &config.out,
        config.proof_from.as_ref(),
        "phi_A",
        &mut record,
    )?
    else {
        return Ok(finish(
            record,
            Outcome::NoWitness,
            attested.attestation_received,
        ));
    };

    let submission = Submission::Apply(ApplySubmission::new(attested.presentation, &x, proof_json));
    let Some(sigma) = sign(config.session.verifier, submission, &mut record).await? else {
        return Ok(finish(
            record,
            Outcome::Refused,
            attested.attestation_received,
        ));
    };

    let payload = ApplyPayload {
        chain_id,
        contract: config.contract,
        submitter,
        tx_id: listing.tx_id,
        property_id: listing.tx_data.propertyId,
        amount: listing.tx_data.amount,
        settlement_share: listing.tx_data.settlementShare,
        r: listing.r,
        c_b,
        sigma_a: sigma,
        eta_a: eta,
        t_att_a: attested.t_att,
        deposit: config.deposit,
        identifier,
        salt,
    };
    std::fs::write(
        config.out.join("payload.json"),
        serde_json::to_string_pretty(&payload)? + "\n",
    )?;
    record.payload = Some(payload.clone());
    if !config.submit {
        return Ok(finish(
            record,
            Outcome::Signed,
            attested.attestation_received,
        ));
    }
    let outcome = chain::submit_apply(&config.rpc_url, &config.key, &payload).await?;
    let result = match &outcome {
        PhaseOutcome::Included { t_incl_ms, .. } => {
            record.timings.inside_delta.t_incl_ms = Some(*t_incl_ms);
            Outcome::Included
        }
        PhaseOutcome::Reverted { error } => {
            record.reason = Some(error.clone());
            Outcome::Reverted
        }
    };
    record.submission = Some(outcome);
    Ok(finish(record, result, attested.attestation_received))
}

/// Runs Settle for `config`. Expected refusals end the run with the matching [`Outcome`]; anything
/// else is an error.
pub async fn run_settle(config: &SettleConfig) -> Result<SettleRecord> {
    std::fs::create_dir_all(&config.out)
        .with_context(|| format!("creating {}", config.out.display()))?;
    let submitter = config.key.address();
    let chain_id = chain::chain_id(&config.rpc_url).await?;
    let eta = config
        .eta
        .unwrap_or_else(|| B256::from(rand::random::<[u8; 32]>()));
    let settle = config
        .policy
        .settle
        .as_ref()
        .context("the policy has no settle source")?;
    // The engagement day as the policy verifier derives it: the deployment's tau_lock, read from
    // the contract, and the registry's time zone from the policy.
    let tau_lock = chain::tau_lock(&config.rpc_url, config.contract).await?;
    let expires_at: u64 = config
        .engagement
        .expires_at
        .try_into()
        .context("expiresAt exceeds 64 bits")?;
    let day = engagement_day(expires_at, tau_lock, settle.utc_offset_secs)?;

    let attested = attest(&config.session, config.layout.shape(&config.notation_id)?).await?;

    // x_S (Table III) with a_P = the owner's account.
    let listing = &config.listing;
    let policy_id_s = config.policy.policy_id_s();
    let x = Settle {
        engId: config.engagement.eng_id,
        txId: listing.tx_id,
        cTx: commitment(&listing.tx_data, config.policy.policy_id_r(), listing.r),
        txData: listing.tx_data.clone(),
        cB: config.c_b,
        expiresAt: config.engagement.expires_at,
        policyId: policy_id_s,
        submitter,
        eta,
        tAtt: attested.t_att,
    };
    let d = digest(&x, &domain(chain_id, config.contract));
    let openings = &attested.notarized.openings;
    ensure!(
        openings.len() == 4,
        "the tenancy layout has four hidden fields"
    );
    let public = PhiSPublic::new(
        [
            field_commitment(&openings[1]),
            field_commitment(&openings[2]),
            field_commitment(&openings[3]),
        ],
        listing.tx_data.propertyId.0,
        config.c_b.0,
        day,
        d.0,
    )?;

    let mut record = SettleRecord {
        phase: "settle",
        outcome: Outcome::NoWitness,
        reason: None,
        account: config.session.account.clone(),
        submitter,
        policy_id: policy_id_s,
        eta,
        t_att: attested.t_att,
        public_inputs: public.inputs(),
        notarization: attested.notarization,
        witness: Witness {
            satisfied: true,
            failed_assertion: None,
        },
        proof_source: "own".into(),
        timings: attested.timings,
        resources: attested.resources,
        payload: None,
        submission: None,
    };

    // The identifier of the opening is the one the counterparty committed to; phi_S compares it
    // with the notation's tenant through c_B.
    ensure!(
        counterparty_commitment(config.identifier.as_bytes(), &config.salt.0)? == config.c_b,
        "the opening does not open c_B"
    );
    let input = PhiSInput::new(&public, openings, &config.salt.0)?;
    let Some(proof_json) = prove_or_borrow(
        &config.circuits,
        &input,
        &config.out,
        config.proof_from.as_ref(),
        "phi_S",
        &mut record,
    )?
    else {
        return Ok(finish(
            record,
            Outcome::NoWitness,
            attested.attestation_received,
        ));
    };

    let submission = Submission::Settle(SettleSubmission::new(
        attested.presentation,
        config.notation_id.clone(),
        &x,
        proof_json,
    ));
    let Some(sigma) = sign(config.session.verifier, submission, &mut record).await? else {
        return Ok(finish(
            record,
            Outcome::Refused,
            attested.attestation_received,
        ));
    };

    let payload = SettlePayload {
        chain_id,
        contract: config.contract,
        submitter,
        eng_id: config.engagement.eng_id,
        property_id: listing.tx_data.propertyId,
        amount: listing.tx_data.amount,
        settlement_share: listing.tx_data.settlementShare,
        r: listing.r,
        sigma_s: sigma,
        eta_s: eta,
        t_att_s: attested.t_att,
    };
    std::fs::write(
        config.out.join("payload.json"),
        serde_json::to_string_pretty(&payload)? + "\n",
    )?;
    record.payload = Some(payload.clone());
    if !config.submit {
        return Ok(finish(
            record,
            Outcome::Signed,
            attested.attestation_received,
        ));
    }
    let outcome = chain::submit_settle(&config.rpc_url, &config.key, &payload).await?;
    let result = match &outcome {
        PhaseOutcome::Included { t_incl_ms, .. } => {
            record.timings.inside_delta.t_incl_ms = Some(*t_incl_ms);
            Outcome::Included
        }
        PhaseOutcome::Reverted { error } => {
            record.reason = Some(error.clone());
            Outcome::Reverted
        }
    };
    record.submission = Some(outcome);
    Ok(finish(record, result, attested.attestation_received))
}
