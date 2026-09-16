//! Rust implementation of the WIST-1..3 primitives: JCS canonicalization,
//! Ed25519 envelopes, delta identity, Key Set resolution, chain tips,
//! Merkle trees/proofs, block/checkpoint verification, snapshot digests,
//! WIST-2 link/text extraction, and WIST-4 audit math (ECVRF sampling and
//! the selection domain, Record standing, the Auditor roster, reputation,
//! decay, link agreement, the audit reference Delta, parameters in force,
//! the unauditable predicate).
//! Conformance is defined by the sibling spec repo's schemas and vectors,
//! not by this crate — every normative behavior is verified against those
//! vectors in `tests/conformance.rs`.
#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The wire version this revision of the suite emits and validates.
pub const WIST_VERSION: &str = "1.0.0";

pub mod agreement;
pub mod block;
pub mod block_frames;
pub mod canary;
pub mod chain;
pub mod confirmation;
pub mod coverage;
pub mod crypto;
pub mod declaration;
pub mod declarations;
pub mod delta;
pub mod delta_fields;
pub mod derivation;
pub mod envelope;
pub mod error;
pub mod extension;
pub mod extract;
pub mod host;
pub mod jcs;
pub mod json;
pub mod keyset;
pub mod merkle;
pub mod objects;
pub mod observer;
pub mod parameters;
pub mod publisher_time;
pub mod recovery;
pub mod reference;
pub mod reputation;
pub mod roster;
pub mod roster_replay;
pub mod sampling;
pub mod sanctions;
pub mod snapshot;
pub mod timestamp;
pub mod unauditable;
pub mod verdict;
pub mod vrf;
pub use error::Error;
