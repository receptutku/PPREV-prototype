//! D29: t_att is the notary's clock, carried in the signed `pprev.t_att` extension; the policy
//! verifier checks it against `ConnectionInfo.time`, the prover's handshake time that tlsn accepts
//! within 5 s of the notary's clock (`mpc-tls/src/follower.rs`, `MAX_TIME_DIFF`).
//!
//! The clock-shift tests run the prover as a child process under libfaketime and are ignored by
//! default: `cargo test --release -p pprev-prover --test time -- --include-ignored`.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{
    ATTESTATION_KEY, OWNER, PROPERTY, attestation_verifying_key, fixtures, layout,
    notarize_with_clock, provider,
};
use mock_registry::RunningRegistry;
use pprev_notary::{
    DEFAULT_MAX_SESSION_SECS, Expectation, NotaryConfig, TLSN_CLOCK_TOLERANCE, check_presentation,
    unix_now,
};
use tlsn::attestation::presentation::Presentation;

fn expectation<'a>(
    layout: &'a pprev_types::Layout,
    key: &'a tlsn::attestation::signing::VerifyingKey,
    roots: &'a [Vec<u8>],
    max_session_secs: u64,
) -> Expectation<'a> {
    Expectation {
        layout,
        attestation_key: key,
        root_certs: roots,
        property_id: PROPERTY,
        max_session_secs,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t_att_is_the_notary_clock() {
    let run = notarize_with_clock(OWNER, PROPERTY, unix_now)
        .await
        .unwrap();
    let key = attestation_verifying_key();
    let roots = vec![run.ca_der.clone()];
    let presentation = pprev_prover::present(&run.notarized, false).unwrap();
    let attested = check_presentation(
        presentation,
        &expectation(&run.layout, &key, &roots, DEFAULT_MAX_SESSION_SECS),
    )
    .unwrap();
    assert_eq!(attested.t_att, run.report.t_att);
    assert!(run.notary_clock.0 <= attested.t_att && attested.t_att <= run.notary_clock.1);
    assert_eq!(attested.connection_time, run.report.connection_time);
    assert!(attested.connection_time <= attested.t_att);
}

fn clock_60s_behind() -> u64 {
    unix_now() - 60
}

fn clock_200s_ahead() -> u64 {
    unix_now() + 200
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_t_att_before_the_connection_time() {
    let run = notarize_with_clock(OWNER, PROPERTY, clock_60s_behind)
        .await
        .unwrap();
    let key = attestation_verifying_key();
    let roots = vec![run.ca_der.clone()];
    let presentation = pprev_prover::present(&run.notarized, false).unwrap();
    let err = check_presentation(
        presentation,
        &expectation(&run.layout, &key, &roots, DEFAULT_MAX_SESSION_SECS),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("precedes the connection time"),
        "{err:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_a_gap_above_the_session_bound_and_the_bound_is_configurable() {
    let run = notarize_with_clock(OWNER, PROPERTY, clock_200s_ahead)
        .await
        .unwrap();
    let key = attestation_verifying_key();
    let roots = vec![run.ca_der.clone()];
    let presentation = || pprev_prover::present(&run.notarized, false).unwrap();
    let err = check_presentation(
        presentation(),
        &expectation(&run.layout, &key, &roots, DEFAULT_MAX_SESSION_SECS),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("above the bound"), "{err:#}");
    let attested =
        check_presentation(presentation(), &expectation(&run.layout, &key, &roots, 300)).unwrap();
    assert_eq!(attested.t_att, run.report.t_att);
}

// ------------------------------------------------------------------ libfaketime (D30)

fn faketime_library() -> PathBuf {
    let candidates = [
        "/opt/homebrew/lib/faketime/libfaketime.1.dylib",
        "/usr/local/lib/faketime/libfaketime.1.dylib",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("libfaketime not found; install it with `brew install libfaketime`")
}

struct ShiftedRun {
    notary: anyhow::Result<pprev_notary::NotarizationReport>,
    prover_ok: bool,
    /// The prover did not exit on its own within the time limit.
    prover_killed: bool,
    prover_stderr: String,
    prover_stdout: String,
    presentation: Option<Presentation>,
    ca_der: Vec<u8>,
    notary_clock: (u64, u64),
}

/// Runs the prover binary with its clock shifted by `offset` seconds (libfaketime syntax, e.g. "+3")
/// against an in-process notary and registry with the real clock.
async fn run_with_prover_clock(offset: &str) -> ShiftedRun {
    let layout = layout();
    let registry = RunningRegistry::start(layout.clone(), fixtures(), "127.0.0.1:0")
        .await
        .unwrap();
    let ca_der = registry.certs.ca_der.clone();
    let dir = tempdir(offset);
    let ca_path = dir.join("ca.der");
    std::fs::write(&ca_path, &ca_der).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let notary_addr = listener.local_addr().unwrap();
    let mut config = NotaryConfig::new(ATTESTATION_KEY, vec![ca_der.clone()]);
    config.preprocess_timeout = common::TEST_PREPROCESS_TIMEOUT;
    let before = unix_now();
    // One notary task per connection: the prover opens a new one for each retry (D33).
    let (results_tx, mut results_rx) = tokio::sync::mpsc::unbounded_channel();
    let acceptor = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (config, results_tx) = (config.clone(), results_tx.clone());
            tokio::spawn(async move {
                let _ = results_tx.send(pprev_notary::notarize(stream, &config).await);
            });
        }
    });

    let out = dir.join("out");
    let (output, prover_killed) = tokio::task::spawn_blocking({
        let (registry_addr, ca_path, out) = (registry.addr, ca_path.clone(), out.clone());
        let layout_path = common::workspace_path("policies/layouts/title-v1.json");
        let offset = offset.to_string();
        move || {
            let child = Command::new(env!("CARGO_BIN_EXE_pprev-prover"))
                .args([
                    "notarize",
                    "--notary",
                    &notary_addr.to_string(),
                    "--registry",
                    &registry_addr.to_string(),
                ])
                .arg("--ca")
                .arg(&ca_path)
                .arg("--layout")
                .arg(&layout_path)
                .args([
                    "--account",
                    OWNER.0,
                    "--password",
                    OWNER.1,
                    "--property",
                    PROPERTY,
                ])
                .arg("--out")
                .arg(&out)
                .args([
                    "--preprocess-timeout-secs",
                    &common::TEST_PREPROCESS_TIMEOUT.as_secs().to_string(),
                ])
                .env("DYLD_INSERT_LIBRARIES", faketime_library())
                .env("DYLD_FORCE_FLAT_NAMESPACE", "1")
                .env("FAKETIME", offset)
                .env("FAKETIME_DONT_FAKE_MONOTONIC", "1")
                // PPREV_PROVER_LOG=debug in the test environment turns on the prover's log.
                .env(
                    "RUST_LOG",
                    std::env::var("PPREV_PROVER_LOG").unwrap_or_default(),
                )
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("start prover");
            wait_with_timeout(child, std::time::Duration::from_secs(90))
        }
    })
    .await
    .unwrap();
    // Every accepted session ends within the notary's session bound; the channel closes once the
    // acceptor and all session tasks are gone.
    acceptor.abort();
    let mut report = None;
    let mut last_error = None;
    while let Ok(Some(result)) =
        tokio::time::timeout(std::time::Duration::from_secs(60), results_rx.recv()).await
    {
        match result {
            Ok(r) => report = Some(r),
            Err(e) => last_error = Some(e),
        }
    }
    let notary = match (report, last_error) {
        (Some(r), _) => Ok(r),
        (None, Some(e)) => Err(e),
        (None, None) => Err(anyhow::anyhow!("the notary received no session")),
    };
    let after = unix_now();
    let presentation = std::fs::read(out.join("presentation.bin"))
        .ok()
        .map(|b| bincode::deserialize(&b).unwrap());
    ShiftedRun {
        notary,
        prover_ok: output.status.success(),
        prover_killed,
        prover_stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        prover_stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        presentation,
        ca_der,
        notary_clock: (before, after),
    }
}

/// Waits for the prover process; kills it after `limit` so that a hung session fails the test.
/// Returns the output and whether the process had to be killed.
fn wait_with_timeout(
    mut child: std::process::Child,
    limit: std::time::Duration,
) -> (std::process::Output, bool) {
    let start = std::time::Instant::now();
    let mut killed = false;
    while child.try_wait().expect("poll prover").is_none() {
        if start.elapsed() > limit {
            child.kill().expect("kill prover");
            killed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    (
        child.wait_with_output().expect("collect prover output"),
        killed,
    )
}

/// A fresh directory per run, so that tests running in parallel never share files.
fn tempdir(offset: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tag = offset.replace('+', "plus").replace('-', "minus");
    let dir = std::env::temp_dir().join(format!("pprev-time-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Reads t_att and ConnectionInfo.time from a verified presentation without the policy checks.
fn times_of(presentation: Presentation, ca_der: &[u8]) -> (u64, u64) {
    let output = presentation
        .verify(&provider(ca_der))
        .expect("presentation verifies");
    (
        pprev_notary::presentation::t_att_of(&output).expect("t_att"),
        output.connection_info.time,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires libfaketime"]
async fn prover_clock_plus_10s_is_rejected_by_tlsn() {
    let run = run_with_prover_clock("+10").await;
    assert!(!run.prover_ok);
    assert!(
        !run.prover_killed,
        "the prover hung after the notary rejected the session\nnotary: {:?}\nstderr: {}\nstdout: {}",
        run.notary.as_ref().err().map(|e| format!("{e:#}")),
        run.prover_stderr,
        run.prover_stdout
    );
    let err = run.notary.expect_err("notary must reject the session");
    assert!(
        !run.prover_stderr.contains("libfaketime:"),
        "libfaketime error: {}",
        run.prover_stderr
    );
    assert!(
        format!("{err:#}").contains("time difference"),
        "notary error: {err:#}\nprover stderr: {}",
        run.prover_stderr
    );
    assert!(run.presentation.is_none());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires libfaketime"]
async fn prover_clock_minus_3s_is_accepted_and_t_att_is_the_notary_clock() {
    let run = run_with_prover_clock("-3").await;
    assert!(
        run.prover_ok,
        "prover failed (killed: {}): {}\n{}",
        run.prover_killed, run.prover_stderr, run.prover_stdout
    );
    let report = run.notary.expect("notary accepted");
    let presentation = run.presentation.expect("presentation");
    let (t_att, connection_time) = times_of(presentation.clone(), &run.ca_der);
    assert_eq!(t_att, report.t_att);
    assert!(
        run.notary_clock.0 <= t_att && t_att <= run.notary_clock.1,
        "t_att follows the notary clock"
    );
    // The connection time is the prover's shifted clock.
    assert!(
        connection_time + 2 <= t_att && t_att <= connection_time + 5,
        "connection {connection_time}, t_att {t_att}"
    );
    let layout = layout();
    let key = attestation_verifying_key();
    let roots = vec![run.ca_der.clone()];
    check_presentation(
        presentation,
        &expectation(&layout, &key, &roots, DEFAULT_MAX_SESSION_SECS),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires libfaketime"]
async fn prover_clock_plus_3s_is_accepted_and_t_att_is_the_notary_clock() {
    let run = run_with_prover_clock("+3").await;
    assert!(
        run.prover_ok,
        "prover failed (killed: {}): {}\n{}",
        run.prover_killed, run.prover_stderr, run.prover_stdout
    );
    let report = run.notary.expect("notary accepted");
    let presentation = run.presentation.expect("presentation");
    let (t_att, connection_time) = times_of(presentation.clone(), &run.ca_der);
    assert_eq!(t_att, report.t_att);
    assert!(
        run.notary_clock.0 <= t_att && t_att <= run.notary_clock.1,
        "t_att follows the notary clock"
    );
    assert!(
        connection_time >= run.notary_clock.0 + 2,
        "connection time follows the prover's shifted clock"
    );
    // The prover's clock is ahead of the notary's, within tlsn's tolerance: t_att may precede the
    // connection time, and the consistency check accepts it.
    assert!(t_att + TLSN_CLOCK_TOLERANCE >= connection_time);
    let layout = layout();
    let key = attestation_verifying_key();
    let roots = vec![run.ca_der.clone()];
    let attested = check_presentation(
        presentation,
        &expectation(&layout, &key, &roots, DEFAULT_MAX_SESSION_SECS),
    )
    .expect("accepted within the tlsn clock tolerance");
    assert_eq!(attested.t_att, report.t_att);
}
