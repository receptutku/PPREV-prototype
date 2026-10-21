//! The reference encoding of `pprev_prover::e1` against real attestations: notarised title, income,
//! and tenancy sessions with the Ethereum-compatible algorithms, whose Merkle root the encoding must
//! recompute and whose signature must recover to the notary's attestation key; the revealed
//! commitments must open to the request line and the response structure. Each test also proves its
//! phase predicate for a statement in the baseline's EIP-712 domain and, with `PPREV_E1_FIXTURES`
//! set to a directory, writes the Solidity fixture of the integrated on-chain verification baseline
//! (`contracts/test/baseline/`).

mod common;

use alloy::sol_types::SolValue;
use alloy_primitives::{Address, B256, U256, keccak256};
use common::{
    ATTESTATION_KEY, MAX_RECV, MAX_SENT, TEST_PREPROCESS_TIMEOUT, attestation_verifying_key,
    fixtures, layout, spawn_notary, workspace_path,
};
use mock_registry::{PhaseLayouts, RunningRegistry};
use pprev_notary::mock::counterparty_commitment;
use pprev_notary::{NotaryConfig, ShapeExpectation, check_shape};
use pprev_prover::circuit::{
    CircuitFiles, PhiAInput, PhiRInput, PhiSInput, commitment, prove, public_of,
};
use pprev_prover::e1::{EncodedAttestation, FieldKind, encode};
use pprev_prover::{
    DEFAULT_MAX_RETRIES, HiddenOpenings, NotarizedShape, ShapeSetup, present_shape,
};
use pprev_types::calendar::engagement_day;
use pprev_types::circuit::{PhiAPublic, PhiSPublic};
use pprev_types::statement::{Apply, Register, Settle, TxData, digest, domain};
use pprev_types::{RecordLayout, ResponseShape};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Chain and contract of the baseline's EIP-712 domain; the Solidity tests deploy each phase's
/// baseline at this address.
const CHAIN_ID: u64 = 31337;
const BASELINE: Address = Address::new([0xe1; 20]);
/// Test-only key of the off-chain server-identity attestor.
const IDENTITY_KEY: [u8; 32] = [9u8; 32];
/// Bound on t_att - ConnectionInfo.time, as in the baselines' configuration.
const MAX_SESSION_SECS: u64 = 120;
const OWNER: (&str, &str) = ("ACC-000000000001", "owner-one");
const TENANT: (&str, &str) = ("ACC-000000000003", "tenant");
const PROPERTY: &str = "TR-06-CANKAYA-000123";
const TAU_LOCK: u64 = 14 * 86_400;
const UTC_OFFSET: i64 = 3 * 3600;
/// Engaged at 2026-10-21T09:00:00Z, the day of the fixture notation N-0001.
const ENGAGED: u64 = 1_792_573_200;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// snarkjs' proof as the exported Solidity verifier takes it: G2 coordinates imaginary part first.
fn solidity_proof(proof_json: &str) -> Value {
    let p: Value = serde_json::from_str(proof_json).unwrap();
    json!({
        "a": [p["pi_a"][0], p["pi_a"][1]],
        "b": [[p["pi_b"][0][1], p["pi_b"][0][0]], [p["pi_b"][1][1], p["pi_b"][1][0]]],
        "c": [p["pi_c"][0], p["pi_c"][1]],
    })
}

fn notary_address() -> Address {
    let key = k256::ecdsa::SigningKey::from_slice(&ATTESTATION_KEY).unwrap();
    Address::from_public_key(key.verifying_key())
}

fn record_layout(name: &str) -> RecordLayout {
    RecordLayout::load(workspace_path(&format!("policies/layouts/{name}.json"))).unwrap()
}

fn salt() -> [u8; 32] {
    let mut salt = keccak256("pprev.e1.salt").0;
    salt[0] &= 0x1f;
    salt
}

/// One notarised session with the Ethereum-compatible algorithms, and its encoding.
struct Session {
    notarized: NotarizedShape,
    encoded: EncodedAttestation,
    /// The mock registry's CA, the root the identity attestor trusts.
    ca: Vec<u8>,
}

async fn notarize(account: (&str, &str), shape: ResponseShape) -> Session {
    common::init_test_log();
    let registry = RunningRegistry::start_with_phases(
        layout(),
        PhaseLayouts {
            income: Some(record_layout("income-v1")),
            tenancy: Some(record_layout("tenancy-v1")),
        },
        fixtures(),
        "127.0.0.1:0",
    )
    .await
    .unwrap();
    let ca = registry.certs.ca_der.clone();
    let token = pprev_prover::login(registry.addr, &shape.server_name, &ca, account.0, account.1)
        .await
        .unwrap();
    let setup = ShapeSetup {
        shape,
        registry_addr: registry.addr,
        root_certs: vec![ca.clone()],
        token,
        max_sent: MAX_SENT,
        max_recv: MAX_RECV,
        preprocess_timeout: TEST_PREPROCESS_TIMEOUT,
        eth_attestation: true,
    };
    let mut config = NotaryConfig::new(ATTESTATION_KEY, vec![ca.clone()]);
    config.preprocess_timeout = TEST_PREPROCESS_TIMEOUT;
    config.eth_attestation = true;
    let mut tasks = Vec::new();
    let (notarized, _) = pprev_prover::notarize_shape_with_retries(
        |_attempt| {
            let io = spawn_notary(&config, &mut tasks);
            async move { anyhow::Ok(io) }
        },
        &setup,
        DEFAULT_MAX_RETRIES,
    )
    .await
    .unwrap();
    tasks.pop().unwrap().await.unwrap().unwrap();
    let encoded = encode(&notarized.attestation).expect("encoding");
    Session {
        notarized,
        encoded,
        ca,
    }
}

/// Checks the attestation's schema and its revealed commitments, and returns the attestation part
/// of the fixture and the hash of each role: structure, request line, then the hidden fields in
/// the order of `hidden` (indices into the session's openings).
fn attestation_part(
    s: &Session,
    hidden: &[usize],
    role_names: &[&str],
    policy_id: B256,
) -> (Value, Vec<[u8; 32]>, u64) {
    let e = &s.encoded;
    let n = 2 + hidden.len();
    assert_eq!(e.signer, notary_address());
    // id (16) + version (4) + alg (1) + ULEB128 length (1) + Keccak-256 digest (32).
    assert_eq!(e.header.len(), 54);
    assert_eq!(&e.header[22..], e.root.as_slice());
    let kinds: Vec<FieldKind> = e.fields.iter().map(|f| f.kind).collect();
    let mut expected = vec![
        FieldKind::VerifyingKey,
        FieldKind::ConnectionInfo,
        FieldKind::ServerEphemeralKey,
        FieldKind::CertCommitment,
        FieldKind::Extension,
    ];
    expected.extend(std::iter::repeat_n(FieldKind::TranscriptCommitment, n));
    assert_eq!(kinds, expected);
    let ids: Vec<u32> = e.fields.iter().map(|f| f.id).collect();
    assert_eq!(ids, (0..ids.len() as u32).collect::<Vec<_>>());

    let shape = &s.notarized.shape;
    assert_eq!(s.notarized.request.plaintext, shape.request_line.as_bytes());
    let revealed: Vec<u8> = shape
        .revealed
        .iter()
        .flat_map(|r| shape.template[r.clone()].to_vec())
        .collect();
    assert_eq!(s.notarized.structure.plaintext, revealed);
    let mut role_hashes = vec![
        sha256(&[
            &s.notarized.structure.plaintext,
            &s.notarized.structure.blinder,
        ]),
        sha256(&[&s.notarized.request.plaintext, &s.notarized.request.blinder]),
    ];
    role_hashes.extend(hidden.iter().map(|&i| commitment(&s.notarized.openings[i])));
    assert_eq!(role_names.len(), n);

    // The field ids of the commitments are not stable across sessions: each must match one role.
    let hash_of = |i: usize| -> [u8; 32] {
        let d = &e.fields[i].data;
        d[d.len() - 32..].try_into().unwrap()
    };
    let role_of_field: Vec<usize> = (5..e.fields.len())
        .map(|i| {
            let roles: Vec<usize> = (0..n).filter(|&r| role_hashes[r] == hash_of(i)).collect();
            assert_eq!(roles.len(), 1, "field {i} matches roles {roles:?}");
            roles[0]
        })
        .collect();
    let mut sorted = role_of_field.clone();
    sorted.sort();
    assert_eq!(sorted, (0..n).collect::<Vec<_>>());
    let field_of_role = |r: usize| 5 + role_of_field.iter().position(|&x| x == r).unwrap();

    let ext = &e.fields[4].data;
    let t_att = u64::from_be_bytes(ext[ext.len() - 8..].try_into().unwrap());

    // The identity attestor signs only a presentation it has verified the way PPREV's policy
    // verifier does: the attestation key and signature, the certificate chain against the registry's
    // CA and the DNS name, t_att, the response length, and the revealed request line and structure.
    // The signature covers the signed header, the attestation key, the server, and the policy.
    let presentation = present_shape(&s.notarized, false).expect("presentation");
    let attested = check_shape(
        presentation,
        &ShapeExpectation {
            shape,
            attestation_key: &attestation_verifying_key(),
            root_certs: std::slice::from_ref(&s.ca),
            max_session_secs: MAX_SESSION_SECS,
        },
    )
    .expect("the presentation verifies");
    assert_eq!(attested.t_att, t_att);
    let identity_digest = keccak256(
        (
            keccak256("PPREV.identity.v1"),
            keccak256(&e.header),
            e.signer,
            keccak256(shape.server_name.as_bytes()),
            policy_id,
        )
            .abi_encode(),
    );
    let identity_key = k256::ecdsa::SigningKey::from_slice(&IDENTITY_KEY).unwrap();
    let (sig, recid) = identity_key
        .sign_prehash_recoverable(identity_digest.as_slice())
        .unwrap();
    let mut identity_signature = sig.to_vec();
    identity_signature.push(27 + recid.to_byte());

    let domains: Vec<String> = [
        FieldKind::VerifyingKey,
        FieldKind::ConnectionInfo,
        FieldKind::ServerEphemeralKey,
        FieldKind::CertCommitment,
        FieldKind::Extension,
        FieldKind::TranscriptCommitment,
    ]
    .iter()
    .map(|k| hex(&k.domain()))
    .collect();
    let part = json!({
        "chainId": CHAIN_ID,
        "baseline": BASELINE,
        "attestation": e,
        "domains": domains,
        "roles": role_names,
        "commitmentPrefixesByRole": (0..n)
            .map(|r| { let d = &e.fields[field_of_role(r)].data; hex(&d[..d.len() - 34]) })
            .collect::<Vec<_>>(),
        "commitmentHashesByRole": role_hashes.iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "roleOfField": role_of_field,
        "requestLine": shape.request_line,
        "requestBlinder": hex(&s.notarized.request.blinder),
        "structure": hex(&s.notarized.structure.plaintext),
        "structureBlinder": hex(&s.notarized.structure.blinder),
        "receivedLength": shape.len,
        "tAtt": t_att,
        "serverName": shape.server_name,
        "identitySigner": Address::from_public_key(identity_key.verifying_key()),
        "identitySignature": hex(&identity_signature),
    });
    (part, role_hashes, t_att)
}

fn prove_with(files: CircuitFiles, input: &impl serde::Serialize) -> String {
    let dir = std::env::temp_dir().join(format!("pprev-e1-{}-{}", std::process::id(), files.name));
    std::fs::create_dir_all(&dir).unwrap();
    let proof = prove(&files, input, &dir).expect("proof");
    let _ = std::fs::remove_dir_all(&dir);
    proof.proof_json
}

fn write_fixture(name: &str, mut part: Value, phase: Value) {
    if let Ok(dir) = std::env::var("PPREV_E1_FIXTURES") {
        for (k, v) in phase.as_object().unwrap() {
            part[k] = v.clone();
        }
        let path = std::path::Path::new(&dir).join(format!("{name}.json"));
        std::fs::write(path, serde_json::to_string_pretty(&part).unwrap() + "\n").unwrap();
    }
}

fn tx_data() -> TxData {
    TxData {
        propertyId: B256::from(layout().property_id_word(PROPERTY).unwrap()),
        amount: U256::from(10u64).pow(U256::from(18)),
        settlementShare: U256::ZERO,
    }
}

#[tokio::test]
async fn register_attestation_and_fixture() {
    let s = notarize(OWNER, layout().shape(PROPERTY).unwrap()).await;
    let policy_id = keccak256("pprev.rental.register");
    // Hidden openings of the title layout: account, owners, propertyId.
    let (part, _, t_att) = attestation_part(
        &s,
        &[0, 1, 2],
        &["structure", "request", "account", "owners", "propertyId"],
        policy_id,
    );
    let x = Register {
        cTx: keccak256("C_tx"),
        txData: tx_data(),
        policyId: policy_id,
        submitter: Address::repeat_byte(0x11),
        eta: B256::repeat_byte(0x42),
        tAtt: t_att,
    };
    let d = digest(&x, &domain(CHAIN_ID, BASELINE));
    let [account, owners, property_id]: [_; 3] =
        s.notarized.openings.clone().try_into().ok().unwrap();
    let openings = HiddenOpenings {
        account,
        owners,
        property_id,
    };
    let public = public_of(&openings, x.txData.propertyId.0, d.0);
    let proof = prove_with(
        CircuitFiles::new(workspace_path("circuits")),
        &PhiRInput::new(&public, &openings),
    );
    write_fixture(
        "register",
        part,
        json!({
            "statement": {
                "cTx": x.cTx, "propertyId": x.txData.propertyId, "amount": x.txData.amount.to_string(),
                "settlementShare": "0", "policyId": policy_id, "submitter": x.submitter, "eta": x.eta,
            },
            "digest": d,
            "publicInputs": public.inputs(),
            "proof": solidity_proof(&proof),
        }),
    );
}

#[tokio::test]
async fn apply_attestation_and_fixture() {
    let s = notarize(TENANT, record_layout("income-v1").shape("").unwrap()).await;
    let policy_id = keccak256("pprev.rental.apply");
    // Hidden openings of the income layout: account, monthlyIncome.
    let (part, roles, t_att) = attestation_part(
        &s,
        &[0, 1],
        &["structure", "request", "account", "monthlyIncome"],
        policy_id,
    );
    let identifier = record_layout("income-v1").pad(TENANT.0, 16).unwrap();
    let c_b = counterparty_commitment(identifier.as_bytes(), &salt()).unwrap();
    let x = Apply {
        txId: U256::from(1),
        cTx: keccak256("C_tx"),
        txData: tx_data(),
        cB: c_b,
        policyId: policy_id,
        submitter: Address::repeat_byte(0x22),
        eta: B256::repeat_byte(0x43),
        tAtt: t_att,
    };
    let d = digest(&x, &domain(CHAIN_ID, BASELINE));
    let public = PhiAPublic::new(roles[2], roles[3], c_b.0, x.txData.amount, d.0).unwrap();
    let proof = prove_with(
        CircuitFiles::phi_a(workspace_path("circuits")),
        &PhiAInput::new(&public, &s.notarized.openings, &salt()).unwrap(),
    );
    write_fixture(
        "apply",
        part,
        json!({
            "statement": {
                "txId": "1", "cTx": x.cTx, "propertyId": x.txData.propertyId,
                "amount": x.txData.amount.to_string(), "settlementShare": "0", "cB": c_b,
                "policyId": policy_id, "submitter": x.submitter, "eta": x.eta,
            },
            "digest": d,
            "publicInputs": public.inputs(),
            "proof": solidity_proof(&proof),
        }),
    );
}

#[tokio::test]
async fn settle_attestation_and_fixture() {
    let s = notarize(OWNER, record_layout("tenancy-v1").shape("N-0001").unwrap()).await;
    let policy_id = keccak256("pprev.rental.settle");
    // Hidden openings of the tenancy layout: account (not read by phi_S), propertyId, tenant,
    // recordDate.
    let (part, roles, t_att) = attestation_part(
        &s,
        &[0, 1, 2, 3],
        &[
            "structure",
            "request",
            "account",
            "propertyId",
            "tenant",
            "recordDate",
        ],
        policy_id,
    );
    let identifier = record_layout("tenancy-v1").pad(TENANT.0, 16).unwrap();
    let c_b = counterparty_commitment(identifier.as_bytes(), &salt()).unwrap();
    let expires_at = ENGAGED + TAU_LOCK;
    let x = Settle {
        engId: U256::from(1),
        txId: U256::from(1),
        cTx: keccak256("C_tx"),
        txData: tx_data(),
        cB: c_b,
        expiresAt: U256::from(expires_at),
        policyId: policy_id,
        submitter: Address::repeat_byte(0x11),
        eta: B256::repeat_byte(0x44),
        tAtt: t_att,
    };
    let d = digest(&x, &domain(CHAIN_ID, BASELINE));
    let day = engagement_day(expires_at, TAU_LOCK, UTC_OFFSET).unwrap();
    let public = PhiSPublic::new(
        [roles[3], roles[4], roles[5]],
        x.txData.propertyId.0,
        c_b.0,
        day,
        d.0,
    )
    .unwrap();
    let proof = prove_with(
        CircuitFiles::phi_s(workspace_path("circuits")),
        &PhiSInput::new(&public, &s.notarized.openings, &salt()).unwrap(),
    );
    write_fixture(
        "settle",
        part,
        json!({
            "notationId": "N-0001",
            "tauLock": TAU_LOCK,
            "utcOffsetSecs": UTC_OFFSET,
            "engagementDay": day,
            "statement": {
                "engId": "1", "txId": "1", "cTx": x.cTx, "propertyId": x.txData.propertyId,
                "amount": x.txData.amount.to_string(), "settlementShare": "0", "cB": c_b,
                "expiresAt": expires_at.to_string(), "policyId": policy_id,
                "submitter": x.submitter, "eta": x.eta,
            },
            "digest": d,
            "publicInputs": public.inputs(),
            "proof": solidity_proof(&proof),
        }),
    );
}
