/// WIST-2 §3.1, in octets.
pub const CHANGE_LIST_CAP_BYTES: u64 = 1_048_576;
/// WIST-2 §3.1, in change lists.
pub const CHANGE_CHAIN_MAX: u64 = 16;
/// WIST-2 §3.1.
pub const REPLACED_FILE_SECONDS: u64 = 86_400;
/// WIST-1 §3.3 and WIST-3 §7, in days of 86 400 seconds.
pub const REMOVAL_RETENTION_DAYS: u64 = 180;
/// WIST-2 §8, in octets.
pub const CATALOG_FILE_READ_MAX_BYTES: u64 = 16_384;
/// WIST-3 §3.3, in octets of an Entry's JCS serialization.
pub const ENTRY_MAX_BYTES: u64 = 65_535;
