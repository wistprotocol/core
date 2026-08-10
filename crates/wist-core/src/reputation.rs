use crate::crypto::hex_encode;
use crate::error::Error;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const DECAY_TABLE_BYTES: &[u8] = include_bytes!("decay-table.json");
pub const DECAY_TABLE_SHA256: &str =
    "f0cd1eb48cbfb1647a083b4ba06e7f69e6c42d5b5f4bf8e4f42b97c6bfdf7dc1";
pub const DECAY_MAX_DAYS: u64 = 1825;

pub struct DecayTable(Vec<u32>);

impl DecayTable {
    pub fn from_bytes(bytes: &[u8]) -> Result<DecayTable, Error> {
        let digest = Sha256::digest(bytes);
        if hex_encode(&digest) != DECAY_TABLE_SHA256 {
            return Err(Error::DecayTable("SHA-256 mismatch".into()));
        }
        #[derive(serde::Deserialize)]
        struct File {
            values: Vec<u32>,
        }
        let f: File = serde_json::from_slice(bytes)
            .map_err(|e| Error::DecayTable(e.to_string()))?;
        if f.values.len() != (DECAY_MAX_DAYS + 1) as usize {
            return Err(Error::DecayTable(format!("expected 1826 values, got {}", f.values.len())));
        }
        Ok(DecayTable(f.values))
    }

    pub fn builtin() -> &'static DecayTable {
        static TABLE: OnceLock<DecayTable> = OnceLock::new();
        TABLE.get_or_init(|| {
            DecayTable::from_bytes(DECAY_TABLE_BYTES).expect("vendored decay table corrupt")
        })
    }

    pub fn decay(&self, t_days: u64) -> u64 {
        if t_days > DECAY_MAX_DAYS {
            0
        } else {
            self.0[t_days as usize] as u64
        }
    }
}
