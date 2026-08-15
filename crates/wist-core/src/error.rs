#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("jcs: {0}")]
    Jcs(String),
    #[error("encoding: {0}")]
    Encoding(String),
    #[error("signature verification failed")]
    Signature,
    #[error("envelope: {0}")]
    Envelope(String),
    #[error("commitment: {0}")]
    Commitment(String),
    #[error("merkle: {0}")]
    Merkle(String),
    #[error("block: {0}")]
    Block(String),
    #[error("snapshot: {0}")]
    Snapshot(String),
    #[error("decay table: {0}")]
    DecayTable(String),
    #[error("reputation: {0}")]
    Reputation(String),
    #[error("confirmation: {0}")]
    Confirmation(String),
    #[error("vrf: {0}")]
    Vrf(String),
}
