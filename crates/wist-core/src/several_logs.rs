//! WIST-3 §7, Several Logs, over the Catalog order of WIST-1 §3.5.
use crate::catalog::catalog_id;
use crate::error::Error;
use crate::sealing::UrlState;
use crate::timestamp::log_seconds;
use serde_json::Value;
use std::cmp::Ordering;

pub fn catalog_order(
    (generated_at, catalog): (&str, &str),
    (other_generated_at, other_catalog): (&str, &str),
) -> Result<Ordering, Error> {
    Ok(log_seconds(generated_at)?
        .cmp(&log_seconds(other_generated_at)?)
        .then_with(|| catalog.as_bytes().cmp(other_catalog.as_bytes())))
}

pub fn in_catalog_order(catalogs: &[Value]) -> Result<Vec<String>, Error> {
    let mut keyed = catalogs
        .iter()
        .map(|catalog| {
            let generated_at = catalog["generated_at"]
                .as_str()
                .ok_or_else(|| Error::Envelope("a Catalog's generated_at is a string".into()))?;
            Ok((log_seconds(generated_at)?, catalog_id(catalog)?))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    keyed.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
    });
    Ok(keyed.into_iter().map(|(_, id)| id).collect())
}

fn state_order(state: &UrlState<'_>, other: &UrlState<'_>) -> Result<Ordering, Error> {
    Ok(catalog_order(
        (state.generated_at(), state.catalog()),
        (other.generated_at(), other.catalog()),
    )?
    .then_with(|| state.item_id().as_bytes().cmp(other.item_id().as_bytes())))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Combined<'a, L> {
    pub state: UrlState<'a>,
    pub logs: Vec<L>,
}

pub fn combine<'a, L, I>(states: I) -> Result<Option<Combined<'a, L>>, Error>
where
    L: Ord,
    I: IntoIterator<Item = (L, Option<UrlState<'a>>)>,
{
    let held: Vec<(L, UrlState<'a>)> = states
        .into_iter()
        .filter_map(|(log, state)| Some((log, state?)))
        .collect();
    let mut latest: Option<UrlState<'a>> = None;
    for (_, state) in &held {
        latest = match latest {
            Some(best) if state_order(state, &best)? != Ordering::Greater => Some(best),
            _ => Some(*state),
        };
    }
    let Some(latest) = latest else {
        return Ok(None);
    };
    let mut logs = Vec::new();
    for (log, state) in held {
        if state_order(&state, &latest)? == Ordering::Equal {
            logs.push(log);
        }
    }
    logs.sort();
    Ok(Some(Combined {
        state: latest,
        logs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealing::Removal;

    fn removal(item_id: &str, catalog: &str, generated_at: &str) -> Removal {
        Removal {
            item_id: item_id.into(),
            catalog: catalog.into(),
            generated_at: generated_at.into(),
        }
    }

    #[test]
    fn no_log_holding_a_state_combines_into_none() {
        assert_eq!(
            combine::<&str, _>([("a", None), ("b", None)]).unwrap(),
            None
        );
    }

    #[test]
    fn equal_instants_order_by_catalog_id_then_item_id() {
        let early = removal("sha256:b", "sha256:1", "2026-10-01T00:00:00Z");
        let later_catalog = removal("sha256:a", "sha256:2", "2026-10-01T00:00:00Z");
        let greater_item = removal("sha256:c", "sha256:2", "2026-10-01T00:00:00Z");
        let combined = combine([
            ("a", Some(UrlState::Removed(&early))),
            ("b", Some(UrlState::Removed(&later_catalog))),
            ("c", Some(UrlState::Removed(&greater_item))),
            ("d", Some(UrlState::Removed(&greater_item))),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(combined.state, UrlState::Removed(&greater_item));
        assert_eq!(combined.logs, ["c", "d"]);
    }

    #[test]
    fn an_instant_outside_the_log_profile_is_refused() {
        let off = removal("sha256:a", "sha256:1", "2026-10-01T00:00:00.5Z");
        assert!(combine([("a", Some(UrlState::Removed(&off)))]).is_err());
    }
}
