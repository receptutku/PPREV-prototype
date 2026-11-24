//! Types shared by the mock registry, the prover, and the notary.

pub mod calendar;
pub mod circuit;
pub mod field;
pub mod layout;
pub mod policy;
pub mod record;
pub mod statement;

pub use layout::{
    CREDENTIAL_PLACEHOLDER, HeaderTemplate, Layout, Rendered, RequestTemplate, ResponseRanges,
    ResponseShape, TitleRecord,
};
pub use policy::PolicyBundle;
pub use record::{RecordLayout, RecordRanges, RenderedRecord};
