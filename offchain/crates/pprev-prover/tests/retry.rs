//! D33: preprocessing timeouts and retries. tlsn 0.1.0-alpha.15 deadlocks in MPC-TLS preprocessing
//! intermittently (tlsnotary/tlsn#1173). These tests stall preprocessing on purpose, with a peer that
//! holds the connection open and never speaks, or with a notary that cuts the session at once.

mod common;

use std::time::{Duration, Instant};

use common::{OWNER, PROPERTY, env, spawn_notary};
use pprev_notary::SessionCut;
use pprev_prover::{PreprocessingStalled, notarize, notarize_with_retries};

const SHORT: Duration = Duration::from_secs(1);

/// The error of a result whose success value has no `Debug` (it carries secrets).
fn err_of<T>(result: anyhow::Result<T>) -> anyhow::Error {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// One end of a connection whose other end is held open but never speaks.
fn silent_peer(held: &mut Vec<tokio::io::DuplexStream>) -> tokio::io::DuplexStream {
    let (far, near) = tokio::io::duplex(1 << 16);
    held.push(far);
    near
}

#[tokio::test(flavor = "multi_thread")]
async fn prover_times_out_a_stalled_preprocessing() {
    let mut e = env(OWNER, PROPERTY).await.unwrap();
    e.setup.preprocess_timeout = SHORT;
    let mut held = Vec::new();
    let start = Instant::now();
    let err = err_of(notarize(silent_peer(&mut held), &e.setup).await);
    assert!(
        err.downcast_ref::<PreprocessingStalled>().is_some(),
        "{err:#}"
    );
    assert!(start.elapsed() < SHORT + Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn prover_retries_after_a_stalled_preprocessing() {
    let mut e = env(OWNER, PROPERTY).await.unwrap();
    e.setup.preprocess_timeout = SHORT;
    let (mut held, mut notaries) = (Vec::new(), Vec::new());
    let (_, stats) = notarize_with_retries(
        |attempt| {
            let io = if attempt == 1 {
                silent_peer(&mut held)
            } else {
                spawn_notary(&e.notary_config, &mut notaries)
            };
            async move { anyhow::Ok(io) }
        },
        &e.setup,
        3,
    )
    .await
    .unwrap();
    assert_eq!(stats.attempts, 2);
    assert_eq!(stats.stalls.len(), 1);
    assert!(
        stats.stalls[0].contains("did not finish within"),
        "{:?}",
        stats.stalls
    );
    notaries.pop().unwrap().await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn prover_retries_when_the_notary_cuts_preprocessing() {
    let e = env(OWNER, PROPERTY).await.unwrap();
    let mut cutting = e.notary_config.clone();
    cutting.preprocess_timeout = Duration::ZERO;
    let mut notaries = Vec::new();
    let (_, stats) = notarize_with_retries(
        |attempt| {
            let config = if attempt == 1 {
                &cutting
            } else {
                &e.notary_config
            };
            let io = spawn_notary(config, &mut notaries);
            async move { anyhow::Ok(io) }
        },
        &e.setup,
        3,
    )
    .await
    .unwrap();
    assert_eq!(stats.attempts, 2);
    assert!(
        stats.stalls[0].contains("the notary closed the session"),
        "{:?}",
        stats.stalls
    );
    let first = notaries.remove(0).await.unwrap().unwrap_err();
    assert!(first.downcast_ref::<SessionCut>().is_some(), "{first:#}");
}

#[tokio::test(flavor = "multi_thread")]
async fn prover_gives_up_after_three_retries() {
    let mut e = env(OWNER, PROPERTY).await.unwrap();
    e.setup.preprocess_timeout = SHORT;
    let mut held = Vec::new();
    let mut connections = 0;
    let err = err_of(
        notarize_with_retries(
            |_| {
                connections += 1;
                let io = silent_peer(&mut held);
                async move { anyhow::Ok(io) }
            },
            &e.setup,
            3,
        )
        .await,
    );
    assert_eq!(connections, 4);
    assert!(
        format!("{err:#}").contains("preprocessing stalled on all 4 attempts"),
        "{err:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_after_preprocessing_are_not_retried() {
    // The registry answers 404 for an unknown property: a failure after preprocessing, not a stall.
    let e = env(OWNER, "TR-00-NOWHERE-000000").await.unwrap();
    let mut notaries = Vec::new();
    let mut connections = 0;
    let err = err_of(
        notarize_with_retries(
            |_| {
                connections += 1;
                let io = spawn_notary(&e.notary_config, &mut notaries);
                async move { anyhow::Ok(io) }
            },
            &e.setup,
            3,
        )
        .await,
    );
    assert_eq!(connections, 1);
    let msg = format!("{err:#}");
    assert!(
        msg.contains("notarisation failed on attempt 1") && msg.contains("404"),
        "{msg}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn notary_cuts_a_stalled_preprocessing() {
    let e = env(OWNER, PROPERTY).await.unwrap();
    let mut config = e.notary_config.clone();
    config.preprocess_timeout = SHORT;
    let mut held = Vec::new();
    let start = Instant::now();
    let err = pprev_notary::notarize(silent_peer(&mut held), &config)
        .await
        .unwrap_err();
    assert!(err.downcast_ref::<SessionCut>().is_some(), "{err:#}");
    assert!(format!("{err:#}").contains("preprocessing did not finish"));
    assert!(start.elapsed() < SHORT + Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn notary_cuts_a_session_above_its_bound() {
    let e = env(OWNER, PROPERTY).await.unwrap();
    let mut config = e.notary_config.clone();
    config.session_timeout = SHORT;
    let mut held = Vec::new();
    let err = pprev_notary::notarize(silent_peer(&mut held), &config)
        .await
        .unwrap_err();
    assert!(err.downcast_ref::<SessionCut>().is_some(), "{err:#}");
    assert!(format!("{err:#}").contains("did not finish within 1s"));
}
