//! The request side of the policy verifier's presentation check (`check_shape`): the sent transcript
//! must be exactly one request of the layout's request template, every byte revealed except the
//! credential, whose position and length the template fixes.
//!
//! Each session is a real MPC-TLS session with the mock registry. A malformed request comes from the
//! prover's ordinary path: the test changes the exchange's shape (the template the prover renders
//! and sends, and the ranges it hides) before the session, as other suites change a layout, and the
//! policy verifier checks the presentation against the policy's own layout. The registry answers
//! every one of these requests with the ordinary record, so only the request check can refuse it.

mod common;

use common::{
    ATTESTATION_KEY, MAX_RECV, MAX_SENT, OWNER, PROPERTY, TENANT, TEST_PREPROCESS_TIMEOUT,
    attestation_verifying_key, fixtures, layout, provider, spawn_notary, workspace_path,
};
use mock_registry::{PhaseLayouts, RunningRegistry};
use pprev_notary::{
    AttestedShape, DEFAULT_MAX_SESSION_SECS, NotaryConfig, ShapeExpectation, check_shape,
};
use pprev_prover::{DEFAULT_MAX_RETRIES, NotarizedShape, ShapeSetup, present_shape};
use pprev_types::{HeaderTemplate, RecordLayout, ResponseShape};
use tlsn::rangeset::set::RangeSet;

fn record_layout(name: &str) -> RecordLayout {
    RecordLayout::load(workspace_path(&format!("policies/layouts/{name}.json"))).unwrap()
}

/// One notarised session, with the registry's CA.
struct Session {
    notarized: NotarizedShape,
    ca_der: Vec<u8>,
    token: String,
}

/// Logs in as `account` and notarises the exchange `shape` after `change` has altered the setup.
async fn notarize(
    account: (&str, &str),
    shape: ResponseShape,
    change: impl FnOnce(&mut ShapeSetup),
) -> Session {
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
    let ca_der = registry.certs.ca_der.clone();
    let token = pprev_prover::login(
        registry.addr,
        &shape.server_name,
        &ca_der,
        account.0,
        account.1,
    )
    .await
    .unwrap();
    let mut setup = ShapeSetup {
        shape,
        registry_addr: registry.addr,
        root_certs: vec![ca_der.clone()],
        token: token.clone(),
        max_sent: MAX_SENT,
        max_recv: MAX_RECV,
        preprocess_timeout: TEST_PREPROCESS_TIMEOUT,
        eth_attestation: false,
    };
    change(&mut setup);
    let mut config = NotaryConfig::new(ATTESTATION_KEY, vec![ca_der.clone()]);
    config.preprocess_timeout = TEST_PREPROCESS_TIMEOUT;
    let mut tasks = Vec::new();
    let (notarized, _) = tokio::time::timeout(
        common::SESSION_TIMEOUT,
        pprev_prover::notarize_shape_with_retries(
            |_attempt| {
                let io = spawn_notary(&config, &mut tasks);
                async move { anyhow::Ok(io) }
            },
            &setup,
            DEFAULT_MAX_RETRIES,
        ),
    )
    .await
    .expect("session within its bound")
    .expect("notarisation");
    tasks.pop().unwrap().await.unwrap().unwrap();
    Session {
        notarized,
        ca_der,
        token,
    }
}

/// The policy verifier's check of the session's presentation against the policy's `shape`.
fn check(session: &Session, shape: &ResponseShape) -> anyhow::Result<AttestedShape> {
    check_shape(
        present_shape(&session.notarized, false).unwrap(),
        &ShapeExpectation {
            shape,
            attestation_key: &attestation_verifying_key(),
            root_certs: std::slice::from_ref(&session.ca_der),
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
        },
    )
}

/// The policy's exchange: the title request for PROPERTY.
fn title() -> ResponseShape {
    layout().shape(PROPERTY).unwrap()
}

/// A title session whose request is rendered from the title layout after `change`.
async fn with_layout(change: impl FnOnce(&mut pprev_types::Layout)) -> Session {
    let mut l = layout();
    change(&mut l);
    notarize(OWNER, l.shape(PROPERTY).unwrap(), |_| {}).await
}

/// Asserts that the policy verifier refuses the session's presentation, with every one of
/// `reasons` in its error.
fn refused(session: &Session, reasons: &[&str]) {
    let err = format!(
        "{:#}",
        check(session, &title()).expect_err("the policy verifier accepted the presentation")
    );
    for reason in reasons {
        assert!(err.contains(reason), "expected {reason:?}, got: {err}");
    }
}

/// The honest request in each phase: accepted, and its presentation reveals the whole request but
/// the bearer token, byte for byte the template's.
#[tokio::test]
async fn the_honest_request_is_accepted_in_every_phase() {
    for (account, shape) in [
        (OWNER, title()),
        (TENANT, record_layout("income-v1").shape("").unwrap()),
        (OWNER, record_layout("tenancy-v1").shape("N-0001").unwrap()),
    ] {
        let session = notarize(account, shape.clone(), |_| {}).await;
        check(&session, &shape).unwrap_or_else(|e| panic!("{}: {e:#}", shape.request_line));
        let output = present_shape(&session.notarized, false)
            .unwrap()
            .verify(&provider(&session.ca_der))
            .unwrap();
        let transcript = output.transcript.unwrap();
        assert_eq!(
            transcript.sent_authed(),
            &RangeSet::from(shape.request_revealed())
        );
        assert_eq!(shape.credentials.len(), 1);
        let credential = shape.credentials[0].clone();
        assert_eq!(credential.len(), session.token.len());
        let mut expected = shape.request.clone();
        expected[credential].fill(0);
        assert_eq!(transcript.sent_unsafe(), expected.as_slice());
    }
}

#[tokio::test]
async fn an_extra_header_is_refused() {
    let session = with_layout(|l| {
        l.request.headers.insert(
            1,
            HeaderTemplate {
                name: "range".into(),
                value: "bytes=0-15".into(),
                credential_width: None,
            },
        )
    })
    .await;
    refused(
        &session,
        &[
            "sent 197 bytes, the request template has 178",
            "extra header \"range: bytes=0-15\"",
        ],
    );
}

#[tokio::test]
async fn a_changed_header_value_is_refused() {
    let session = with_layout(|l| l.request.headers[2].value = "CLOSE".into()).await;
    refused(
        &session,
        &[
            "revealed request bytes differ from the template",
            "header \"connection: CLOSE\" differs from the template's \"connection: close\"",
        ],
    );
}

#[tokio::test]
async fn a_reordered_header_is_refused() {
    let session = with_layout(|l| l.request.headers.swap(1, 2)).await;
    refused(
        &session,
        &[
            "revealed request bytes differ from the template",
            "headers in the order [\"host\", \"connection\", \"authorization\"], the template has \
             [\"host\", \"authorization\", \"connection\"]",
        ],
    );
}

#[tokio::test]
async fn a_request_body_is_refused() {
    let mut l = layout();
    l.request.headers.push(HeaderTemplate {
        name: "content-length".into(),
        value: "2".into(),
        credential_width: None,
    });
    let session = notarize(OWNER, l.shape(PROPERTY).unwrap(), |setup| {
        setup.shape.request.extend_from_slice(b"{}");
    })
    .await;
    refused(
        &session,
        &[
            "sent 199 bytes, the request template has 178",
            "extra header \"content-length: 2\"",
            "2 bytes follow the request head, beginning \"{}\"",
        ],
    );
}

#[tokio::test]
async fn a_second_pipelined_request_is_refused() {
    let session = notarize(OWNER, title(), |setup| {
        let shape = &mut setup.shape;
        let len = shape.request.len();
        let first = shape.request.clone();
        shape.request.extend_from_slice(&first);
        let credential = shape.credentials[0].clone();
        shape
            .credentials
            .push(credential.start + len..credential.end + len);
        setup.token = setup.token.repeat(2);
    })
    .await;
    refused(
        &session,
        &[
            "sent 356 bytes, the request template has 178",
            &format!(
                "178 bytes follow the request head, beginning \"GET /title/{PROPERTY} HTTP/1.1\""
            ),
        ],
    );
}

#[tokio::test]
async fn trailing_bytes_are_refused() {
    let session = notarize(OWNER, title(), |setup| {
        setup.shape.request.extend_from_slice(b"xyz");
    })
    .await;
    refused(
        &session,
        &[
            "sent 181 bytes, the request template has 178",
            "3 bytes follow the request head, beginning \"xyz\"",
        ],
    );
}

/// The token's range in the title request.
fn credential() -> std::ops::Range<usize> {
    title().credentials[0].clone()
}

fn hidden_reason(hidden: &[std::ops::Range<usize>]) -> String {
    format!(
        "hidden request bytes {hidden:?} are not the template's credential ranges {:?}",
        [credential()]
    )
}

#[tokio::test]
async fn a_shorter_credential_range_is_refused() {
    // The same request on the wire; the presentation reveals the token's last byte.
    let c = credential();
    let session = notarize(OWNER, title(), |setup| {
        let last = setup.token.as_bytes()[c.len() - 1];
        setup.shape.request[c.end - 1] = last;
        setup.shape.credentials[0].end -= 1;
        setup.token.pop();
    })
    .await;
    refused(
        &session,
        &[&hidden_reason(std::slice::from_ref(&(c.start..c.end - 1)))],
    );
}

#[tokio::test]
async fn a_longer_credential_range_is_refused() {
    // The same request on the wire; the presentation also hides the space before the token.
    let c = credential();
    let session = notarize(OWNER, title(), |setup| {
        setup.shape.credentials[0].start -= 1;
        setup.token.insert(0, ' ');
    })
    .await;
    refused(
        &session,
        &[&hidden_reason(std::slice::from_ref(&(c.start - 1..c.end)))],
    );
}

#[tokio::test]
async fn a_shifted_credential_range_is_refused() {
    // The same request on the wire; the hidden range starts one byte early and reveals the token's
    // last byte.
    let c = credential();
    let session = notarize(OWNER, title(), |setup| {
        let last = setup.token.as_bytes()[c.len() - 1];
        setup.shape.request[c.end - 1] = last;
        setup.shape.credentials[0] = c.start - 1..c.end - 1;
        setup.token.pop();
        setup.token.insert(0, ' ');
    })
    .await;
    refused(
        &session,
        &[&hidden_reason(std::slice::from_ref(
            &(c.start - 1..c.end - 1),
        ))],
    );
}

#[tokio::test]
async fn a_sent_range_left_hidden_is_refused() {
    // The same request on the wire; the presentation also hides the Host value, which the template
    // reveals.
    let shape = title();
    let request = String::from_utf8(shape.request.clone()).unwrap();
    let host = request.find("registry.pprev.test").unwrap();
    let host = host..host + "registry.pprev.test".len();
    let c = credential();
    let session = notarize(OWNER, shape, |setup| {
        setup.shape.credentials.insert(0, host.clone());
        setup.token.insert_str(0, "registry.pprev.test");
    })
    .await;
    refused(&session, &[&hidden_reason(&[host.clone(), c])]);
}
