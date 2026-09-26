//! Submitter side of PPREV's attested submission (Section V-B, steps (b) and (d)): registry login,
//! MPC-TLS session with the notary, transcript commitments (D3, D26), attestation, presentation,
//! and the phi_R witness.

pub mod chain;
pub mod circuit;
pub mod counting;
pub mod login;
pub mod register;
pub mod session;

pub use login::login;
pub use session::{
    DEFAULT_MAX_RETRIES, DEFAULT_PREPROCESS_TIMEOUT, FieldOpening, HiddenOpenings, NotarizeStats,
    Notarized, PreprocessingStalled, ProverSetup, notarize, notarize_with_retries, present,
};
