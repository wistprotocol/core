#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("jcs: {0}")]
    Jcs(String),
    #[error("encoding: {0}")]
    Encoding(String),
    #[error("signature verification failed")]
    Signature,
}
