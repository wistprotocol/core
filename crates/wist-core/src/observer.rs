use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

pub fn suffix(name: &str) -> &str {
    name.rmatch_indices('.')
        .nth(1)
        .map_or(name, |(i, _)| &name[i + 1..])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget<'a> {
    pub suffix_order: Vec<&'a str>,
    pub positions: Vec<usize>,
    pub budgeted: Vec<&'a str>,
}

pub fn epoch_budget<'a>(registered: &[&'a str], epoch: u64, budget: NonZeroU64) -> Budget<'a> {
    budget_with_sort_keys(
        registered,
        epoch,
        budget,
        |name| Sha256::digest(name.as_bytes()).into(),
        |name| {
            let mut hash = Sha256::new();
            hash.update(epoch.to_be_bytes());
            hash.update(name.as_bytes());
            hash.finalize().into()
        },
    )
}

pub fn budget_with_sort_keys<'a>(
    registered: &[&'a str],
    epoch: u64,
    budget: NonZeroU64,
    suffix_key: impl Fn(&str) -> [u8; 32],
    observer_key: impl Fn(&str) -> [u8; 32],
) -> Budget<'a> {
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for &name in registered {
        groups.entry(suffix(name)).or_default().push(name);
    }
    let mut suffix_order: Vec<_> = groups.keys().copied().collect();
    suffix_order.sort_by_cached_key(|&name| (suffix_key(name), name));
    let size = suffix_order.len();
    let positions: Vec<_> = if size == 0 {
        Vec::new()
    } else {
        let start = (u128::from(epoch) * u128::from(budget.get())) % size as u128;
        (0..u128::from(budget.get()).min(size as u128))
            .map(|k| ((start + k) % size as u128) as usize)
            .collect()
    };
    let budgeted = positions
        .iter()
        .map(|&p| {
            groups[suffix_order[p]]
                .iter()
                .copied()
                .min_by_key(|&name| (observer_key(name), name))
                .unwrap()
        })
        .collect();
    Budget {
        suffix_order,
        positions,
        budgeted,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch {
    pub number: u64,
    pub first: u64,
    pub length: NonZeroU64,
}

impl Epoch {
    pub fn last(self) -> u128 {
        u128::from(self.first) + u128::from(self.length.get()) - 1
    }
}

pub fn epoch_of_block(
    block: u64,
    mut length_at_first_block: impl FnMut(u64) -> Option<NonZeroU64>,
) -> Option<Epoch> {
    let mut epoch = Epoch {
        number: 0,
        first: 0,
        length: length_at_first_block(0)?,
    };
    loop {
        if u128::from(block) <= epoch.last() {
            return Some(epoch);
        }
        epoch.first = u64::try_from(epoch.last() + 1).ok()?;
        epoch.number = epoch.number.checked_add(1)?;
        epoch.length = length_at_first_block(epoch.first)?;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Checkpoint<'a> {
    pub head: &'a str,
    pub height: u64,
}

pub fn covered_before(
    record: &str,
    reveal_height: u64,
    checkpoints: &[Checkpoint<'_>],
    prev_record: &BTreeMap<&str, Option<&str>>,
) -> bool {
    checkpoints
        .iter()
        .filter(|cp| cp.height < reveal_height)
        .any(|cp| {
            let mut cursor = Some(cp.head);
            let mut seen = BTreeSet::new();
            while let Some(id) = cursor {
                if id == record {
                    return true;
                }
                if !seen.insert(id) {
                    return false;
                }
                cursor = prev_record.get(id).copied().flatten();
            }
            false
        })
}
