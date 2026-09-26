//! The owner's side of Register end to end (Section V-B steps (a)-(d), Section V-D): registry login,
//! MPC-TLS session, presentation, x_R, phi_R proof, sigma_R from the policy verifier, and the
//! `register` transaction. Every run yields a [`RegisterRecord`] with the time of each step.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{B256, Bytes, U256};
use anyhow::{Context, Result};
use pprev_notary::presentation::t_att_of;
use pprev_notary::wire::{
    RegisterReply, RegisterSubmission, submit_register as submit_to_verifier,
};
use pprev_types::statement::{Register, TxData, commitment, digest, domain};
use pprev_types::{Layout, PolicyBundle};
use serde::Serialize;
use tlsn::attestation::CryptoProvider;
use tlsn::verifier::ServerCertVerifier;
use tlsn::webpki::{CertificateDer, RootCertStore};

use crate::chain::{self, RegisterPayload, SubmitOutcome};
use crate::circuit::{CircuitFiles, PhiRInput, Unsatisfied, prove, public_of};
use crate::session::{ProverSetup, notarize_with_retries, present};

pub struct RegisterConfig {
    pub notary: SocketAddr,
    pub verifier: SocketAddr,
    pub registry: SocketAddr,
    /// Registry CA certificate (DER).
    pub ca_der: Vec<u8>,
    pub layout: Layout,
    pub policy: PolicyBundle,
    pub account: String,
    pub password: String,
    pub property: String,
    pub rpc_url: String,
    pub contract: alloy_primitives::Address,
    pub key: PrivateKeySigner,
    pub amount: U256,
    pub settlement_share: U256,
    pub collateral: U256,
    pub circuits: CircuitFiles,
    /// Directory for the witness input, the proof, and the payload.
    pub out: PathBuf,
    pub max_sent: usize,
    pub max_recv: usize,
    pub max_retries: u32,
    pub preprocess_timeout: Duration,
    /// Nonce to use instead of a fresh one (negative test: a nonce the notary has signed).
    pub eta: Option<B256>,
    /// A `proof.json` to submit instead of the owner's own proof (negative test: a proof made for
    /// another session and statement).
    pub proof_from: Option<PathBuf>,
    /// Send the transaction; otherwise stop after sigma_R and leave the payload in `out`.
    pub submit: bool,
}

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    /// Included on-chain with a `Registered` event.
    Registered,
    /// sigma_R obtained; the transaction was not sent.
    Signed,
    /// phi_R has no witness for the owner's session, and no other proof was given.
    NoWitness,
    /// The policy verifier refused to sign.
    Refused,
    /// The node rejected the transaction.
    Reverted,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Notarization {
    /// Sessions started, the successful one included (D33).
    pub attempts: u32,
    /// Why each abandoned session was abandoned.
    pub stalls: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Witness {
    pub satisfied: bool,
    /// The assertion at which witness generation stopped, when it did.
    pub failed_assertion: Option<String>,
}

/// Steps before the notary fixes t_att.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutsideDelta {
    pub login_ms: f64,
    /// The successful MPC-TLS session up to the attestation; abandoned sessions are excluded (D33).
    pub mpc_tls_ms: f64,
}

/// Steps after t_att, which the freshness window must cover (Section VII-F).
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InsideDelta {
    /// Building the presentation from the attestation.
    pub presentation_ms: f64,
    /// Reading t_att back from the owner's own presentation.
    pub read_t_att_ms: f64,
    /// circom witness generation.
    pub witness_ms: Option<f64>,
    /// `snarkjs groth16 prove`.
    pub snarkjs_prove_ms: Option<f64>,
    /// t_prove: witness generation and `snarkjs groth16 prove`.
    pub t_prove_ms: Option<f64>,
    /// The policy verifier: decoding the submission and every check before signing.
    pub t_verify_ms: Option<f64>,
    /// The policy verifier: nonce record and signature.
    pub t_sign_ms: Option<f64>,
    /// From sending the transaction to its receipt.
    pub t_incl_ms: Option<f64>,
}

/// The policy verifier's own breakdown, as it reported it.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierDetail {
    pub decode_ms: f64,
    pub presentation_ms: f64,
    pub groth16_ms: f64,
    pub verify_ms: f64,
    pub sign_ms: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timings {
    pub outside_delta: OutsideDelta,
    pub inside_delta: InsideDelta,
    pub verifier: Option<VerifierDetail>,
    /// Round trip of the submission to the policy verifier, as the owner measured it.
    pub verifier_round_trip_ms: Option<f64>,
    /// From receiving the attestation to the end of the run (receipt, sigma_R, or refusal).
    pub after_attestation_ms: f64,
    /// The owner's clock when the attestation arrived minus t_att (seconds, from the notary's clock).
    pub attestation_arrival_minus_t_att_ms: i128,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRecord {
    pub outcome: Outcome,
    pub reason: Option<String>,
    pub account: String,
    pub property: String,
    pub submitter: alloy_primitives::Address,
    pub policy_id_r: B256,
    pub c_tx: B256,
    pub eta: B256,
    pub t_att: u64,
    pub notarization: Notarization,
    pub witness: Witness,
    /// `own`, or the path of the borrowed proof.
    pub proof_source: String,
    pub timings: Timings,
    pub payload: Option<RegisterPayload>,
    pub submission: Option<SubmitOutcome>,
}

fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn unix_ms() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_millis() as i128
}

/// Runs Register for `config`. Expected refusals (no witness, policy verifier, contract) end the
/// run with the matching [`Outcome`]; anything else is an error.
pub async fn run(config: &RegisterConfig) -> Result<RegisterRecord> {
    std::fs::create_dir_all(&config.out)
        .with_context(|| format!("creating {}", config.out.display()))?;
    let mut timings = Timings::default();
    let submitter = config.key.address();
    let chain_id = chain::chain_id(&config.rpc_url).await?;

    // (a) Fresh nonce and salt.
    let eta = config
        .eta
        .unwrap_or_else(|| B256::from(rand::random::<[u8; 32]>()));
    let r = B256::from(rand::random::<[u8; 32]>());

    // (b) Login, notarised session, presentation.
    let started = Instant::now();
    let token = crate::login(
        config.registry,
        &config.layout.server_name,
        &config.ca_der,
        &config.account,
        &config.password,
    )
    .await?;
    timings.outside_delta.login_ms = millis(started);

    let setup = ProverSetup {
        layout: config.layout.clone(),
        registry_addr: config.registry,
        root_certs: vec![config.ca_der.clone()],
        token,
        property_id: config.property.clone(),
        max_sent: config.max_sent,
        max_recv: config.max_recv,
        preprocess_timeout: config.preprocess_timeout,
    };
    let notary_addr = config.notary;
    let mut attempt_started = Vec::new();
    let (notarized, stats) = notarize_with_retries(
        |_attempt| {
            attempt_started.push(Instant::now());
            async move { anyhow::Ok(tokio::net::TcpStream::connect(notary_addr).await?) }
        },
        &setup,
        config.max_retries,
    )
    .await?;
    let attestation_received = Instant::now();
    let arrival_unix_ms = unix_ms();
    timings.outside_delta.mpc_tls_ms =
        (attestation_received - *attempt_started.last().expect("one attempt")).as_secs_f64()
            * 1000.0;
    let notarization = Notarization {
        attempts: stats.attempts,
        stalls: stats.stalls,
    };

    let started = Instant::now();
    let presentation = present(&notarized, false)?;
    timings.inside_delta.presentation_ms = millis(started);

    let started = Instant::now();
    let provider = CryptoProvider {
        cert: ServerCertVerifier::new(&RootCertStore {
            roots: vec![CertificateDer(config.ca_der.clone())],
        })?,
        ..Default::default()
    };
    let output = presentation
        .clone()
        .verify(&provider)
        .context("verifying the owner's own presentation")?;
    let t_att = t_att_of(&output)?;
    timings.inside_delta.read_t_att_ms = millis(started);
    timings.attestation_arrival_minus_t_att_ms = arrival_unix_ms - i128::from(t_att) * 1000;

    // x_R (Table III) with a_P = the owner's account.
    let policy_id_r = config.policy.policy_id_r();
    let tx_data = TxData {
        propertyId: B256::from(config.layout.property_id_word(&config.property)?),
        amount: config.amount,
        settlementShare: config.settlement_share,
    };
    let c_tx = commitment(&tx_data, policy_id_r, r);
    let x = Register {
        cTx: c_tx,
        txData: tx_data.clone(),
        policyId: policy_id_r,
        submitter,
        eta,
        tAtt: t_att,
    };
    let eip712 = domain(chain_id, config.contract);
    let d = digest(&x, &eip712);

    let mut record = RegisterRecord {
        outcome: Outcome::NoWitness,
        reason: None,
        account: config.account.clone(),
        property: config.property.clone(),
        submitter,
        policy_id_r,
        c_tx,
        eta,
        t_att,
        notarization,
        witness: Witness {
            satisfied: true,
            failed_assertion: None,
        },
        proof_source: "own".into(),
        timings,
        payload: None,
        submission: None,
    };
    let finish = |mut record: RegisterRecord, outcome: Outcome, reason: Option<String>| {
        record.outcome = outcome;
        record.reason = reason;
        record.timings.after_attestation_ms = millis(attestation_received);
        record
    };

    // (c) phi_R proof.
    let public = public_of(&notarized.openings, x.txData.propertyId.0, d.0);
    let own = prove(
        &config.circuits,
        &PhiRInput::new(&public, &notarized.openings),
        &config.out,
    );
    let proof_json = match own {
        Ok(proof) => {
            let inside = &mut record.timings.inside_delta;
            inside.witness_ms = Some(proof.timings.witness_ms);
            inside.snarkjs_prove_ms = Some(proof.timings.prove_ms);
            inside.t_prove_ms = Some(proof.timings.witness_ms + proof.timings.prove_ms);
            proof.proof_json
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
            if config.proof_from.is_none() {
                return Ok(finish(
                    record,
                    Outcome::NoWitness,
                    Some(unsatisfied.to_string()),
                ));
            }
            String::new()
        }
    };
    let proof_json = match &config.proof_from {
        Some(path) => {
            record.proof_source = path.display().to_string();
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
        }
        None => proof_json,
    };

    // (d) sigma_R from the policy verifier.
    let started = Instant::now();
    let reply = submit_to_verifier(
        config.verifier,
        &RegisterSubmission::new(presentation, config.property.clone(), &x, proof_json),
    )
    .await?;
    record.timings.verifier_round_trip_ms = Some(millis(started));
    let sigma = match reply {
        RegisterReply::Refused { reason } => {
            return Ok(finish(record, Outcome::Refused, Some(reason)));
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
            sigma
        }
    };

    let payload = RegisterPayload {
        chain_id,
        contract: config.contract,
        submitter,
        c_tx,
        property_id: tx_data.propertyId,
        amount: tx_data.amount,
        settlement_share: tx_data.settlementShare,
        policy_id_r,
        r,
        sigma_r: Bytes::from(sigma),
        eta_r: eta,
        t_att_r: t_att,
        collateral: config.collateral,
    };
    std::fs::write(
        config.out.join("payload.json"),
        serde_json::to_string_pretty(&payload)? + "\n",
    )?;
    record.payload = Some(payload.clone());
    if !config.submit {
        return Ok(finish(record, Outcome::Signed, None));
    }

    // Register transaction.
    let outcome = chain::submit_register(&config.rpc_url, &config.key, &payload).await?;
    let (result, reason) = match &outcome {
        SubmitOutcome::Included { t_incl_ms, .. } => {
            record.timings.inside_delta.t_incl_ms = Some(*t_incl_ms);
            (Outcome::Registered, None)
        }
        SubmitOutcome::Reverted { error } => (Outcome::Reverted, Some(error.clone())),
    };
    record.submission = Some(outcome);
    Ok(finish(record, result, reason))
}
