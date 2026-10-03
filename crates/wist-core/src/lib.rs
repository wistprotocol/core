#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const WIST_VERSION: &str = "1.0.0";

pub mod aggregator_keys;
pub mod catalog;
pub mod checkpoint;
pub mod collection;
pub mod constants;
pub mod crypto;
pub mod declaration;
pub mod declarations;
pub mod envelope;
pub mod epoch;
pub mod error;
pub mod extract;
pub mod host;
pub mod item;
pub mod jcs;
pub mod json;
pub mod keyset;
pub mod label;
pub mod materialization;
pub mod merkle;
pub mod narrowing;
pub mod objects;
pub mod parameters;
pub mod proof;
pub mod publisher_item;
pub mod publisher_time;
pub mod snapshot;
pub mod suffix_list;
pub mod tiles;
pub mod timestamp;
pub mod tree;
pub mod unsealed;
pub mod withdrawal;
pub use error::Error;
