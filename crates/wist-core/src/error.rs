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
    #[error("host: {0}")]
    Host(String),
    #[error("parameter: {0}")]
    Parameter(String),
    #[error("timestamp: {0}")]
    Timestamp(String),
    #[error("history: {0}")]
    History(String),
}
