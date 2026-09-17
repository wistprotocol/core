//! Rust implementation of the WIST-1..4 primitives: JCS canonicalization,
//! Ed25519 envelopes, delta identity, Key Set resolution, chain tips,
//! Merkle trees/proofs, block/checkpoint verification, snapshot digests,
//! WIST-2 link/text extraction, the Declaration and recovery-window
//! replay, the WIST-4 Parameter Registry with its schedule replay, the
//! payload_withdrawal replay and the Public Suffix List snapshots with
//! the Registrable Domain.
//! Conformance is defined by the sibling spec repo's schemas and vectors,
//! not by this crate — every normative behavior is verified against those
//! vectors in `tests/conformance.rs`.
#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The wire version this revision of the suite emits and validates.
pub const WIST_VERSION: &str = "1.0.0";

pub mod block;
pub mod block_frames;
pub mod chain;
pub mod crypto;
pub mod declaration;
pub mod declarations;
pub mod delta;
pub mod delta_fields;
pub mod envelope;
pub mod error;
pub mod extract;
pub mod host;
pub mod jcs;
pub mod json;
pub mod keyset;
pub mod merkle;
pub mod objects;
pub mod parameters;
pub mod publisher_time;
pub mod recovery;
pub mod snapshot;
pub mod suffix_list;
pub mod timestamp;
pub mod withdrawal;
pub use error::Error;
