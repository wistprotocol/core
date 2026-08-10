//! Rust implementation of the WIST-1..3 primitives: JCS canonicalization,
//! Ed25519 envelopes, delta identity, Merkle trees/proofs, block/checkpoint
//! verification, snapshot digests, and WIST-2 link/text extraction.
//! Conformance is defined by the sibling spec repo's schemas and vectors,
//! not by this crate — every normative behavior is verified against those
//! vectors in `tests/conformance.rs`.
#![forbid(unsafe_code)]

pub mod agreement;
pub mod block;
pub mod crypto;
pub mod delta;
pub mod envelope;
pub mod error;
pub mod extract;
pub mod jcs;
pub mod merkle;
pub mod objects;
pub mod reputation;
pub mod snapshot;
pub mod vrf;
pub use error::Error;
