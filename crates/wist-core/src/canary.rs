use crate::delta::make_credit_commitment;
use crate::extract::{extract_text, similarity};
use crate::observer::{suffix, Epoch};
use crate::verdict::{effective_similarity, ChangeType, Verdict};
use crate::{merkle, Error};
use std::collections::BTreeSet;
use std::num::NonZeroU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoringProfile {
    pub shingle_size: usize,
    pub min_observed_words: u64,
    pub similarity_consistent: u64,
    pub similarity_variance_floor: u64,
}

impl ScoringProfile {
    pub fn at_audited_delta(audited_sealed_at_s: i64, lookup: impl Fn(&str, i64) -> u64) -> Self {
        Self {
            shingle_size: usize::try_from(lookup("shingle_size", audited_sealed_at_s))
                .unwrap_or(usize::MAX),
            min_observed_words: lookup("min_observed_words", audited_sealed_at_s),
            similarity_consistent: lookup("similarity_consistent", audited_sealed_at_s),
            similarity_variance_floor: lookup("similarity_variance_floor", audited_sealed_at_s),
        }
    }

    pub fn derived_similarity(
        self,
        body: &[u8],
        reference_extract: &str,
        change: ChangeType,
    ) -> Option<u64> {
        similarity(
            reference_extract,
            &extract_text(body),
            self.min_observed_words,
            self.shingle_size,
        )
        .map(|value| effective_similarity(value, change))
    }

    pub fn band(self, derived_similarity: Option<u64>) -> Verdict {
        match derived_similarity {
            None => Verdict::NotAuditable,
            Some(value) if value >= self.similarity_consistent => Verdict::Consistent,
            Some(value) if value >= self.similarity_variance_floor => Verdict::DynamicVariance,
            Some(_) => Verdict::Inconsistent,
        }
    }

    pub fn hard_hit(
        self,
        reproduces: bool,
        verdict: Verdict,
        derived_similarity: Option<u64>,
    ) -> bool {
        reproduces
            && matches!(
                (verdict, self.band(derived_similarity)),
                (Verdict::Consistent, Verdict::Inconsistent)
                    | (Verdict::Inconsistent, Verdict::Consistent)
            )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Provisional,
    Standing,
    Mature,
}

pub fn tier(provisional: bool, reputation_u: u64, latency_threshold_u: u64) -> Tier {
    if provisional {
        Tier::Provisional
    } else if reputation_u >= latency_threshold_u {
        Tier::Mature
    } else {
        Tier::Standing
    }
}

pub fn scoring_window_open(
    reveal_sealed_at_s: i64,
    query_sealed_at_s: i64,
    payload_window_days: u64,
) -> bool {
    let elapsed = i128::from(query_sealed_at_s) - i128::from(reveal_sealed_at_s);
    elapsed >= 0 && elapsed / 86400 < i128::from(payload_window_days)
}

#[derive(Debug, Clone, Copy)]
pub struct NumericTiming {
    pub earliest: u128,
    pub latest: u128,
    pub lead_respected: bool,
}

impl NumericTiming {
    pub fn allows(self, reveal_height: u64) -> bool {
        self.lead_respected && (self.earliest..=self.latest).contains(&u128::from(reveal_height))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommitmentTiming {
    pub height: u64,
    pub lead_blocks: u64,
    pub lifetime_blocks: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RevealDelay {
    pub minimum_blocks: u64,
    pub suffixes_registered: u64,
    pub checkpoint_budget: NonZeroU64,
    pub epoch_blocks: NonZeroU64,
}

pub fn numeric_timing(
    commitment: CommitmentTiming,
    delta_heights: &[u64],
    delay: RevealDelay,
) -> Option<NumericTiming> {
    let newest = *delta_heights.iter().max()?;
    let turns = delay
        .suffixes_registered
        .div_ceil(delay.checkpoint_budget.get())
        .max(1);
    Some(NumericTiming {
        earliest: u128::from(newest)
            + u128::from(delay.minimum_blocks)
            + u128::from(turns - 1) * u128::from(delay.epoch_blocks.get()),
        latest: u128::from(commitment.height) + u128::from(commitment.lifetime_blocks),
        lead_respected: delta_heights.iter().all(|&height| {
            u128::from(height) >= u128::from(commitment.height) + u128::from(commitment.lead_blocks)
        }),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct CoverageDeadline {
    pub deadline_s: i128,
    pub record_seal_blocks: NonZeroU64,
}

#[derive(Debug, Clone)]
pub struct BudgetingEpoch<'a> {
    pub epoch: Epoch,
    pub budgeted_suffixes: Vec<&'a str>,
    pub record_seal_blocks: NonZeroU64,
}

pub fn sealing_opportunities(
    reveal_height: u64,
    block_times_s: &[i64],
    deadlines: &[CoverageDeadline],
    registered_at_newest_delta: &[&str],
    registered_at_reveal: &[&str],
    epochs: &[BudgetingEpoch<'_>],
) -> bool {
    let Some(latest_deadline) = deadlines.iter().map(|d| d.deadline_s).max() else {
        return false;
    };
    if usize::try_from(reveal_height)
        .ok()
        .is_none_or(|h| h >= block_times_s.len())
    {
        return false;
    }
    for deadline in deadlines {
        let available = block_times_s
            .iter()
            .enumerate()
            .take_while(|(height, _)| (*height as u128) < u128::from(reveal_height))
            .filter(|(_, time)| i128::from(**time) > deadline.deadline_s)
            .count() as u128;
        if available < u128::from(deadline.record_seal_blocks.get()) {
            return false;
        }
    }
    let original: BTreeSet<_> = registered_at_newest_delta
        .iter()
        .map(|name| suffix(name))
        .collect();
    let current: BTreeSet<_> = registered_at_reveal
        .iter()
        .map(|name| suffix(name))
        .collect();
    original.intersection(&current).all(|name| {
        epochs.windows(2).any(|pair| {
            let [epoch, following] = pair else {
                unreachable!()
            };
            let last_time = usize::try_from(epoch.epoch.last())
                .ok()
                .and_then(|h| block_times_s.get(h));
            epoch.epoch.last() + 1 == u128::from(following.epoch.first)
                && last_time.is_some_and(|&time| i128::from(time) >= latest_deadline)
                && epoch.budgeted_suffixes.contains(name)
                && u128::from(reveal_height)
                    >= following.epoch.last() + u128::from(epoch.record_seal_blocks.get())
        })
    })
}

#[derive(Debug, Clone)]
pub struct RevealedLeaf<'a> {
    pub delta_id: &'a str,
    pub body: &'a [u8],
    pub leaf_hash: [u8; 32],
    pub reference_extract: &'a str,
    pub salt_b64u: &'a str,
    pub tier: Tier,
    pub reveal_height: u64,
    pub reveal_sealed_at_s: i64,
    pub payload_window_days: u64,
}

#[derive(Debug, Clone)]
pub struct ScoringRecord<'a> {
    pub id: &'a str,
    pub auditor_id: &'a str,
    pub reference_delta: &'a str,
    pub fixed_height: Option<u64>,
    pub audited_sealed_at_s: i64,
    pub change: ChangeType,
    pub verdict: Verdict,
    pub credit_commitment: Option<&'a str>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub encountered: u64,
    pub credited: u64,
    pub hard_hits: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Scoreboard {
    pub provisional: Counts,
    pub standing: Counts,
    pub mature: Counts,
}

pub fn scoreboard(
    auditor_id: &str,
    query_height: u64,
    query_sealed_at_s: i64,
    leaves: &[RevealedLeaf<'_>],
    records: &[ScoringRecord<'_>],
    lookup: impl Fn(&str, i64) -> u64,
) -> Result<Scoreboard, Error> {
    let mut board = Scoreboard::default();
    let mut seen = BTreeSet::new();
    for record in records
        .iter()
        .filter(|record| record.auditor_id == auditor_id)
    {
        let Some(leaf) = leaves.iter().find(|leaf| {
            leaf.delta_id == record.reference_delta
                && leaf.reveal_height <= query_height
                && record
                    .fixed_height
                    .is_some_and(|height| height < leaf.reveal_height)
                && scoring_window_open(
                    leaf.reveal_sealed_at_s,
                    query_sealed_at_s,
                    leaf.payload_window_days,
                )
        }) else {
            continue;
        };
        if !seen.insert(record.id) {
            continue;
        }
        if merkle::leaf_hash(leaf.body) != leaf.leaf_hash {
            return Err(Error::Commitment(
                "served canary bytes do not match the revealed leaf".into(),
            ));
        }
        let reproduces = record.credit_commitment
            == Some(make_credit_commitment(leaf.salt_b64u, leaf.body, auditor_id)?.as_str());
        let profile = ScoringProfile::at_audited_delta(record.audited_sealed_at_s, &lookup);
        let derived = profile.derived_similarity(leaf.body, leaf.reference_extract, record.change);
        let row = match leaf.tier {
            Tier::Provisional => &mut board.provisional,
            Tier::Standing => &mut board.standing,
            Tier::Mature => &mut board.mature,
        };
        row.encountered += 1;
        row.credited += u64::from(reproduces);
        row.hard_hits += u64::from(profile.hard_hit(reproduces, record.verdict, derived));
    }
    Ok(board)
}
