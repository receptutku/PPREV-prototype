//! Submitter side of PPREV's attested submission (Section V-B, steps (b) and (d)): registry login,
//! MPC-TLS session with the notary, transcript commitments (D3, D26), attestation, presentation,
//! and the witnesses of phi_R, phi_A, and phi_S.

pub mod chain;
pub mod circuit;
pub mod counting;
pub mod e1;
pub mod login;
pub mod phases;
pub mod probe;
pub mod register;
pub mod session;

pub use login::login;
pub use session::{
    CommittedOpening, DEFAULT_MAX_RETRIES, DEFAULT_PREPROCESS_TIMEOUT, FieldOpening,
    HiddenOpenings, NotarizeStats, Notarized, NotarizedShape, PreprocessingStalled, ProverSetup,
    ShapeSetup, notarize, notarize_shape, notarize_shape_with_retries, notarize_with_retries,
    present, present_shape,
};
