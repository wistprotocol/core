#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("jcs: {0}")]
    Jcs(String),
}
