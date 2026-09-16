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
    #[error("host: {0}")]
    Host(String),
    #[error("parameter: {0}")]
    Parameter(String),
    #[error("roster: {0}")]
    Roster(String),
    #[error("sanction: {0}")]
    Sanction(String),
    #[error("timestamp: {0}")]
    Timestamp(String),
    #[error("history: {0}")]
    History(String),
}
