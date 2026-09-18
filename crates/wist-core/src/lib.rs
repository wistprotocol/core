//! Rust implementation of the WIST-1..4 primitives: JCS canonicalization,
//! Conformance is defined by the sibling spec repo's schemas and vectors,
//! not by this crate — every normative behavior is verified against those
//! vectors in `tests/conformance.rs`.
#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The wire version this revision of the suite emits and validates.
pub const WIST_VERSION: &str = "1.0.0";

pub mod aggregator_keys;
pub mod chain;
pub mod checkpoint;
pub mod crypto;
pub mod declaration;
pub mod declarations;
pub mod delta;
pub mod delta_fields;
pub mod envelope;
pub mod epoch;
pub mod error;
pub mod extract;
pub mod host;
pub mod jcs;
pub mod json;
pub mod keyset;
pub mod label;
pub mod materialization;
pub mod merkle;
pub mod objects;
pub mod parameters;
pub mod publisher_time;
pub mod recovery;
pub mod snapshot;
pub mod suffix_list;
pub mod tiles;
pub mod timestamp;
pub mod withdrawal;
pub use error::Error;
