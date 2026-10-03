pub const SNAPSHOT_MISMATCH_CODE: &str = "WIST3-E04";

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
    #[error("epoch: {0}")]
    Epoch(String),
    #[error("checkpoint: {0}")]
    Checkpoint(String),
    #[error("tile: {0}")]
    Tile(String),
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
    #[error("change list: {0}")]
    ChangeList(String),
    #[error(
        "WIST3-E04 the state file's aggregator_key tuples do not authenticate from the Anchor: {0}"
    )]
    KeyTuples(crate::aggregator_keys::KeyTupleRule),
    #[error(
        "WIST3-E04 the state file's aggregator_key tuples disagree with the Consumer's registry about key {key_id:?}"
    )]
    KeyTupleCatchUp { key_id: String },
    #[error(
        "WIST3-E04 {document}'s signature does not verify under key {key_id:?} at height {height}"
    )]
    UnsealedSignature {
        document: crate::unsealed::Document,
        key_id: String,
        height: u64,
    },
}

impl Error {
    pub fn code(&self) -> Option<&str> {
        let message = match self {
            Error::Jcs(m)
            | Error::Encoding(m)
            | Error::Envelope(m)
            | Error::Commitment(m)
            | Error::Merkle(m)
            | Error::Epoch(m)
            | Error::Checkpoint(m)
            | Error::Tile(m)
            | Error::Snapshot(m)
            | Error::Host(m)
            | Error::Parameter(m)
            | Error::Timestamp(m)
            | Error::History(m)
            | Error::ChangeList(m) => m.as_str(),
            Error::KeyTuples(_)
            | Error::KeyTupleCatchUp { .. }
            | Error::UnsealedSignature { .. } => return Some(SNAPSHOT_MISMATCH_CODE),
            Error::Signature => return None,
        };
        let token = message.split(' ').next()?;
        let bytes = token.as_bytes();
        let shaped = bytes.len() == 9
            && bytes.starts_with(b"WIST")
            && bytes[4].is_ascii_digit()
            && bytes[5] == b'-'
            && bytes[6] == b'E'
            && bytes[7].is_ascii_digit()
            && bytes[8].is_ascii_digit();
        shaped.then_some(token)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn a_leading_code_token_is_reported_and_other_messages_carry_none() {
        assert_eq!(
            Error::Checkpoint("WIST3-E03 malformed note".into()).code(),
            Some("WIST3-E03")
        );
        assert_eq!(Error::Epoch("Entries out of order".into()).code(), None);
        assert_eq!(Error::Signature.code(), None);
    }
}
