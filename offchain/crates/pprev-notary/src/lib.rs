//! Notary and policy-verifier side of PPREV's attested submission (Section V-B).
//!
//! [`notarize`] runs the notary's half of an MPC-TLS session and returns a signed attestation that
//! carries the notary's own clock as the `pprev.t_att` extension (D29). [`check_presentation`]
//! verifies a presentation against the policy's layout and extracts t_att and the hashes of the
//! committed fields (D3, D26). [`PolicyVerifier`] adds the phi_R proof for Register and signs x_R
//! with sk_notary (D19, D20); [`mock::MockNotary`] checks phi_A and phi_S natively for Apply and
//! Settle (D23).

pub mod groth16;
pub mod mock;
pub mod nonces;
pub mod presentation;
pub mod register;
pub mod session;
pub mod sigma;

pub use groth16::{Groth16Proof, Groth16Verifier};
pub use nonces::NonceStore;
pub use presentation::{
    Attested, CommittedHash, Expectation, TLSN_CLOCK_TOLERANCE, attested_commitments,
    check_presentation, check_times,
};
pub use register::{PolicyVerifier, RegisterPolicy, RegisterRequest};
pub use session::{
    DEFAULT_PREPROCESS_TIMEOUT, DEFAULT_SESSION_TIMEOUT, NotarizationReport, NotaryConfig,
    SessionCut, notarize,
};
pub use sigma::StatementKey;

/// Identifier of the attestation extension that carries t_att.
pub const T_ATT_EXTENSION_ID: &[u8] = b"pprev.t_att";

/// Default upper bound on `t_att - ConnectionInfo.time`, in seconds (D29).
pub const DEFAULT_MAX_SESSION_SECS: u64 = 120;

/// Current Unix time in seconds from the local clock.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs()
}
