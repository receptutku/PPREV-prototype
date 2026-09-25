//! Submitter side of PPREV's attested submission (Section V-B, steps (b) and (d)): registry login,
//! MPC-TLS session with the notary, transcript commitments (D3, D26), attestation, presentation.

pub mod login;
pub mod session;

pub use login::login;
pub use session::{
    DEFAULT_MAX_RETRIES, DEFAULT_PREPROCESS_TIMEOUT, NotarizeStats, Notarized,
    PreprocessingStalled, ProverSetup, notarize, notarize_with_retries, present,
};
