use crate::error::Error;
use crate::verdict::ChangeType;

#[derive(Debug, Clone, Copy)]
pub struct ChainDelta<'a> {
    pub id: &'a str,
    pub height: u64,
    pub sealed_at_s: i64,
    pub change: ChangeType,
    pub payload: Option<&'a str>,
}

fn index_of(chain: &[ChainDelta], id: &str) -> Option<usize> {
    chain.iter().position(|d| d.id == id)
}

fn content_bearing(change: ChangeType) -> bool {
    matches!(change, ChangeType::New | ChangeType::Update)
}

pub fn newest_at_or_before<'a>(chain: &[ChainDelta<'a>], fetched_at_s: i64) -> Option<&'a str> {
    chain
        .iter()
        .filter(|d| d.sealed_at_s <= fetched_at_s)
        .max_by_key(|d| d.height)
        .map(|d| d.id)
}

pub fn resolve_anchor<'a>(
    chain: &[ChainDelta<'a>],
    reference: &str,
) -> Result<Option<&'a str>, Error> {
    let ri = index_of(chain, reference)
        .ok_or_else(|| Error::Confirmation(format!("reference {reference} not in chain")))?;
    Ok(chain[..=ri]
        .iter()
        .rev()
        .find(|d| content_bearing(d.change))
        .and_then(|d| d.payload))
}

pub fn reference_valid(
    chain: &[ChainDelta],
    audited: &str,
    reference: &str,
    fetched_at_s: i64,
) -> Result<(), Error> {
    let ai = index_of(chain, audited)
        .ok_or_else(|| Error::Confirmation(format!("audited {audited} not in chain")))?;
    let ri = index_of(chain, reference).ok_or_else(|| {
        Error::Confirmation(format!(
            "WIST4-E02: reference {reference} outside the audited chain"
        ))
    })?;
    if ri < ai {
        return Err(Error::Confirmation(format!(
            "WIST4-E02: reference {reference} precedes audited {audited}"
        )));
    }
    if chain[ri].sealed_at_s > fetched_at_s {
        return Err(Error::Confirmation(format!(
            "WIST4-E02: reference {reference} sealed after fetched_at"
        )));
    }
    Ok(())
}
