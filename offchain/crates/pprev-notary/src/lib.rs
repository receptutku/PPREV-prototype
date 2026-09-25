//! Notary and policy-verifier side of PPREV's attested submission (Section V-B).
//!
//! [`notarize`] runs the notary's half of an MPC-TLS session and returns a signed attestation that
//! carries the notary's own clock as the `pprev.t_att` extension (D29). [`check_presentation`]
//! verifies a presentation against the policy's layout and extracts t_att and the hashes of the
//! committed fields (D3, D26).

pub mod presentation;
pub mod session;

pub use presentation::{
    Attested, CommittedHash, Expectation, TLSN_CLOCK_TOLERANCE, attested_commitments,
    check_presentation, check_times,
};
pub use session::{
    DEFAULT_PREPROCESS_TIMEOUT, DEFAULT_SESSION_TIMEOUT, NotarizationReport, NotaryConfig,
    SessionCut, notarize,
};

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
