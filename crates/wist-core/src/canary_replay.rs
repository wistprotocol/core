//! WIST-4 §§5.1/9.1 canary replay: `canary_commitment` and `canary_reveal`
//! acts over sealed Blocks — field diagnostics, authentication under the
//! planter's Key Set, the epoch ration per planter suffix, reveal
//! validation (commitment, leaves, inclusion proofs, Log-wide Delta
//! reservation, numeric timing and the actual-sealing-opportunity test),
//! per-Block batch settlement and the commitments live at a height.
use crate::crypto::PublicKey;
use crate::declarations::Position;
use crate::delta_fields::canonical_b64u;
use crate::envelope::verify_envelope;
use crate::objects::audit::{RegistryAction, RegistryUpdateEnvelope};
use crate::objects::PublisherKey;
use crate::roster_replay::hostname_subject;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The canary parameters in force at a Block (WIST-4 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryProfile {
    pub lead_blocks: u64,
    pub leaves_max: u64,
    pub commitments_max: u64,
    pub reveal_min_blocks: u64,
    pub lifetime_blocks: u64,
    pub epoch_blocks: u64,
    pub checkpoint_budget: u64,
}

/// The coverage parameters in force at a Block that the reveal test reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageProfile {
    pub deadline_hours: u64,
    pub seal_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryCommitment {
    pub id: String,
    pub planter: String,
    pub root: String,
    pub leaves: u64,
    pub height: u64,
    pub revealed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryReveal {
    pub position: Position,
    pub id: String,
    pub subject: String,
    pub commitment: String,
    pub deltas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedAct {
    pub position: Position,
    pub action: String,
    pub subject: String,
    pub code: &'static str,
    pub reason: String,
}

struct RevealLeaf {
    index: u64,
    delta_id: String,
    leaf_hash: [u8; 32],
    path: Vec<[u8; 32]>,
}

struct RevealCandidate {
    position: Position,
    id: String,
    subject: String,
    commitment: String,
    leaves: Vec<RevealLeaf>,
}

struct BlockFacts {
    sealed_at_s: i64,
    canary: CanaryProfile,
    coverage: CoverageProfile,
}

#[derive(Default)]
pub struct CanaryReplay {
    blocks: Vec<BlockFacts>,
    deltas: BTreeMap<String, (u64, String)>,
    applied: BTreeSet<String>,
    commitments: BTreeMap<String, CanaryCommitment>,
    suffix_epoch_commitments: BTreeMap<(String, u64), u64>,
    reserved_deltas: BTreeMap<String, String>,
    block_reveals: Vec<RevealCandidate>,
    reveals: Vec<CanaryReveal>,
    rejected: Vec<RejectedAct>,
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn parse_digest(id: &str) -> Option<[u8; 32]> {
    id.strip_prefix("sha256:")
        .and_then(|hex| crate::crypto::hex_decode(hex).ok())
        .and_then(|bytes| bytes.try_into().ok())
}

impl CanaryReplay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the next sealed Block's instant and the profiles in force.
    pub fn push_block(
        &mut self,
        height: u64,
        sealed_at_s: i64,
        canary: CanaryProfile,
        coverage: CoverageProfile,
    ) -> Result<(), crate::Error> {
        if self.blocks.len() as u64 != height {
            return Err(crate::Error::History(
                "canary replay requires contiguous Blocks from genesis".into(),
            ));
        }
        self.blocks.push(BlockFacts {
            sealed_at_s,
            canary,
            coverage,
        });
        Ok(())
    }

    /// Records a sealed Delta a reveal may later bind.
    pub fn register_delta(&mut self, delta_id: &str, height: u64, publisher: &str) {
        self.deltas
            .insert(delta_id.to_owned(), (height, publisher.to_owned()));
    }

    /// Applies a canary act sealed at `position`, authenticated under the
    /// planter's signing keys at that Block; other acts are ignored.
    pub fn act(&mut self, position: Position, body: &Value, subject_keys: &[PublisherKey]) {
        let action = body["update"]["action"].as_str().unwrap_or("");
        if !matches!(action, "canary_commitment" | "canary_reveal") {
            return;
        }
        if let Err((code, reason)) = self.act_inner(position, body, subject_keys) {
            self.rejected.push(RejectedAct {
                position,
                action: action.to_owned(),
                subject: body["update"]["subject"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                code,
                reason: format!("{code}: {reason}"),
            });
        }
    }

    fn act_inner(
        &mut self,
        position: Position,
        body: &Value,
        subject_keys: &[PublisherKey],
    ) -> std::result::Result<(), (&'static str, String)> {
        let height = position.block_number;
        let id = crate::delta::delta_id(&body["update"])
            .map_err(|e| ("WIST4-E11", format!("act cannot be identified: {e}")))?;
        if self.applied.contains(&id) {
            return Ok(());
        }
        let envelope: RegistryUpdateEnvelope =
            serde_json::from_value(body.clone()).map_err(|e| {
                (
                    "WIST4-E11",
                    format!("malformed Registry Update envelope: {e}"),
                )
            })?;
        let update = &envelope.update;
        if !crate::delta_fields::version_spelled(&update.wist_version)
            || update.wist_version.split('.').next() != Some("1")
        {
            return Err(("WIST4-E11", "unsupported Registry Update version".into()));
        }
        if crate::timestamp::log_seconds(&update.effective_at).is_err() {
            return Err((
                "WIST4-E11",
                "effective_at is not a whole-second UTC instant".into(),
            ));
        }
        if envelope.sig.alg != "Ed25519"
            || envelope.sig.key_id.chars().count() > 64
            || !canonical_b64u(&envelope.sig.value, 64)
        {
            return Err(("WIST4-E11", "malformed signature fields".into()));
        }
        if !hostname_subject(&update.subject) {
            return Err((
                "WIST4-E04",
                "subject is not a hostname of at least two labels".into(),
            ));
        }
        let details = update
            .details
            .as_ref()
            .filter(|details| details.is_object())
            .ok_or(("WIST4-E04", "details are missing".to_owned()))?;
        subject_keys
            .iter()
            .find(|key| key.key_id == envelope.sig.key_id)
            .and_then(|key| PublicKey::from_b64u(&key.public_key).ok())
            .filter(|key| verify_envelope(body, "update", key).is_ok())
            .ok_or((
                "WIST4-E11",
                "act is not authenticated under its subject's Key Set at the Block".to_owned(),
            ))?;
        let profile = &self.blocks[height as usize].canary;
        match update.action {
            RegistryAction::CanaryCommitment => {
                let root = details["root"]
                    .as_str()
                    .filter(|root| digest(root))
                    .ok_or(("WIST4-E04", "details.root is not a digest".to_owned()))?
                    .to_owned();
                let leaves = details["leaves"]
                    .as_u64()
                    .filter(|leaves| *leaves >= 1)
                    .ok_or((
                        "WIST4-E04",
                        "details.leaves is not a count from 1".to_owned(),
                    ))?;
                if leaves > profile.leaves_max {
                    return Err(("WIST4-E08", "leaves exceed canary_leaves_max".into()));
                }
                let epoch = self.epoch_of(height).ok_or((
                    "WIST4-E08",
                    "no budgeting epoch covers the Block".to_owned(),
                ))?;
                let suffix = crate::observer::suffix(&update.subject).to_owned();
                let sealed = self
                    .suffix_epoch_commitments
                    .entry((suffix, epoch.number))
                    .or_insert(0);
                if *sealed >= profile.commitments_max {
                    return Err((
                        "WIST4-E08",
                        "the planter suffix's epoch ration is exhausted".into(),
                    ));
                }
                *sealed += 1;
                self.commitments.insert(
                    id.clone(),
                    CanaryCommitment {
                        id: id.clone(),
                        planter: update.subject.clone(),
                        root,
                        leaves,
                        height,
                        revealed_at: None,
                    },
                );
                self.applied.insert(id);
                Ok(())
            }
            RegistryAction::CanaryReveal => {
                let commitment = details["commitment"]
                    .as_str()
                    .filter(|id| digest(id))
                    .ok_or(("WIST4-E04", "details.commitment is not an ID".to_owned()))?
                    .to_owned();
                let leaves = details["leaves"]
                    .as_array()
                    .filter(|leaves| !leaves.is_empty())
                    .ok_or((
                        "WIST4-E04",
                        "details.leaves is not a non-empty array".to_owned(),
                    ))?
                    .iter()
                    .map(|leaf| {
                        let index = leaf["index"]
                            .as_u64()
                            .ok_or(("WIST4-E04", "leaf index is not an integer".to_owned()))?;
                        let delta_id = leaf["delta_id"]
                            .as_str()
                            .filter(|id| digest(id))
                            .ok_or(("WIST4-E04", "leaf delta_id is not a Delta ID".to_owned()))?
                            .to_owned();
                        let leaf_hash = leaf["leaf_hash"]
                            .as_str()
                            .and_then(parse_digest)
                            .ok_or(("WIST4-E04", "leaf_hash is not a digest".to_owned()))?;
                        let path = leaf["path"]
                            .as_array()
                            .ok_or(("WIST4-E04", "leaf path is not an array".to_owned()))?
                            .iter()
                            .map(|node| {
                                node.as_str()
                                    .and_then(parse_digest)
                                    .ok_or(("WIST4-E04", "path node is not a digest".to_owned()))
                            })
                            .collect::<std::result::Result<Vec<_>, _>>()?;
                        Ok(RevealLeaf {
                            index,
                            delta_id,
                            leaf_hash,
                            path,
                        })
                    })
                    .collect::<std::result::Result<Vec<_>, (&'static str, String)>>()?;
                self.block_reveals.push(RevealCandidate {
                    position,
                    id,
                    subject: update.subject.clone(),
                    commitment,
                    leaves,
                });
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// WIST-4 §3.1: the Observers an epoch budgets, read from the
    /// registrations at the epoch's first Block and that Block's budget.
    pub fn budgeted_observers(
        &self,
        epoch: &crate::observer::Epoch,
        registered_at: &dyn Fn(i64) -> Vec<String>,
    ) -> Vec<String> {
        let Some(first) = self.blocks.get(epoch.first as usize) else {
            return Vec::new();
        };
        let Some(budget) = std::num::NonZeroU64::new(first.canary.checkpoint_budget) else {
            return Vec::new();
        };
        let registered_owned = registered_at(first.sealed_at_s);
        let registered: Vec<&str> = registered_owned.iter().map(String::as_str).collect();
        crate::observer::epoch_budget(&registered, epoch.number, budget)
            .budgeted
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    pub fn epoch_of(&self, height: u64) -> Option<crate::observer::Epoch> {
        crate::observer::epoch_of_block(height, |first| {
            self.blocks
                .get(first as usize)
                .and_then(|block| std::num::NonZeroU64::new(block.canary.epoch_blocks))
        })
    }

    fn validate_reveal(
        &self,
        candidate: &RevealCandidate,
        height: u64,
        registered_at: &dyn Fn(i64) -> Vec<String>,
    ) -> std::result::Result<Vec<u64>, String> {
        let commitment = self
            .commitments
            .get(&candidate.commitment)
            .filter(|commitment| commitment.height < height)
            .ok_or_else(|| "reveal names no sealed commitment".to_owned())?;
        if commitment.revealed_at.is_some() {
            return Err("commitment is already revealed".into());
        }
        let root = parse_digest(&commitment.root)
            .ok_or_else(|| "commitment root is unusable".to_owned())?;
        let profile_at_commitment = &self.blocks[commitment.height as usize].canary;
        let mut indexes = BTreeSet::new();
        let mut deltas = BTreeSet::new();
        let mut delta_heights = Vec::new();
        for leaf in &candidate.leaves {
            if leaf.index >= commitment.leaves || !indexes.insert(leaf.index) {
                return Err("leaf index is out of range or repeated".into());
            }
            let (fact_height, fact_publisher) = self
                .deltas
                .get(&leaf.delta_id)
                .filter(|(fact_height, _)| *fact_height < height)
                .ok_or_else(|| "leaf names no Delta sealed below the reveal".to_owned())?;
            if *fact_publisher != candidate.subject {
                return Err("leaf names another domain's Delta".into());
            }
            if *fact_height < commitment.height + profile_at_commitment.lead_blocks {
                return Err("leaf names a Delta sealed inside the lead".into());
            }
            if !deltas.insert(leaf.delta_id.clone()) {
                return Err("a Delta is bound to two leaves".into());
            }
            if self.reserved_deltas.contains_key(&leaf.delta_id) {
                return Err("a Delta is reserved by an earlier reveal".into());
            }
            crate::merkle::verify_inclusion(
                &leaf.leaf_hash,
                leaf.index as usize,
                commitment.leaves as usize,
                &leaf.path,
                &root,
            )
            .map_err(|_| "inclusion proof fails".to_owned())?;
            delta_heights.push(*fact_height);
        }
        let newest = *delta_heights
            .iter()
            .max()
            .ok_or_else(|| "no leaves".to_owned())?;
        let newest_block = &self.blocks[newest as usize];
        let registered_at_newest_owned = registered_at(newest_block.sealed_at_s);
        let registered_at_newest: Vec<&str> = registered_at_newest_owned
            .iter()
            .map(String::as_str)
            .collect();
        let suffixes: BTreeSet<&str> = registered_at_newest
            .iter()
            .map(|id| crate::observer::suffix(id))
            .collect();
        let delay = crate::canary::RevealDelay {
            minimum_blocks: newest_block.canary.reveal_min_blocks,
            suffixes_registered: suffixes.len() as u64,
            checkpoint_budget: std::num::NonZeroU64::new(newest_block.canary.checkpoint_budget)
                .ok_or_else(|| "checkpoint budget is zero".to_owned())?,
            epoch_blocks: std::num::NonZeroU64::new(newest_block.canary.epoch_blocks)
                .ok_or_else(|| "epoch length is zero".to_owned())?,
        };
        let timing = crate::canary::numeric_timing(
            crate::canary::CommitmentTiming {
                height: commitment.height,
                lead_blocks: profile_at_commitment.lead_blocks,
                lifetime_blocks: profile_at_commitment.lifetime_blocks,
            },
            &delta_heights,
            delay,
        )
        .ok_or_else(|| "no leaves".to_owned())?;
        if !timing.allows(height) {
            return Err("reveal is sealed before the reveal minimum or after the lifetime".into());
        }
        let block_times: Vec<i64> = self.blocks.iter().map(|b| b.sealed_at_s).collect();
        let deadlines: Vec<crate::canary::CoverageDeadline> = delta_heights
            .iter()
            .map(|&h| {
                let block = &self.blocks[h as usize];
                Ok(crate::canary::CoverageDeadline {
                    deadline_s: i128::from(block.sealed_at_s)
                        + i128::from(block.coverage.deadline_hours) * 3_600,
                    record_seal_blocks: std::num::NonZeroU64::new(block.coverage.seal_blocks)
                        .ok_or_else(|| "record_seal_blocks is zero".to_owned())?,
                })
            })
            .collect::<std::result::Result<_, String>>()?;
        let registered_at_reveal_owned = registered_at(self.blocks[height as usize].sealed_at_s);
        let registered_at_reveal: Vec<&str> = registered_at_reveal_owned
            .iter()
            .map(String::as_str)
            .collect();
        let mut epoch_inputs: Vec<(crate::observer::Epoch, Vec<String>, u64, u64)> = Vec::new();
        let mut first = 0u64;
        while (first as usize) < self.blocks.len() {
            let Some(epoch) = self.epoch_of(first) else {
                break;
            };
            let first_block = &self.blocks[epoch.first as usize];
            let last = epoch.last();
            epoch_inputs.push((
                epoch,
                registered_at(first_block.sealed_at_s),
                first_block.canary.checkpoint_budget,
                first_block.coverage.seal_blocks,
            ));
            first = u64::try_from(last + 1).map_err(|_| "epoch overflow".to_owned())?;
        }
        let mut epochs = Vec::new();
        for (epoch, registered_owned, checkpoint_budget, seal_blocks) in &epoch_inputs {
            let registered: Vec<&str> = registered_owned.iter().map(String::as_str).collect();
            let budgeted = match std::num::NonZeroU64::new(*checkpoint_budget) {
                Some(budget) => crate::observer::epoch_budget(&registered, epoch.number, budget)
                    .budgeted
                    .into_iter()
                    .map(crate::observer::suffix)
                    .collect(),
                None => Vec::new(),
            };
            epochs.push(crate::canary::BudgetingEpoch {
                epoch: *epoch,
                budgeted_suffixes: budgeted,
                record_seal_blocks: std::num::NonZeroU64::new(*seal_blocks)
                    .ok_or_else(|| "record_seal_blocks is zero".to_owned())?,
            });
        }
        if !crate::canary::sealing_opportunities(
            height,
            &block_times,
            &deadlines,
            &registered_at_newest,
            &registered_at_reveal,
            &epochs,
        ) {
            return Err("reveal leaves no actual sealing opportunity".into());
        }
        Ok(delta_heights)
    }

    /// Settles the reveals sealed in the Block at `height` as a batch, given
    /// the Observers registered at any instant.
    pub fn settle(&mut self, height: u64, registered_at: &dyn Fn(i64) -> Vec<String>) {
        let candidates = std::mem::take(&mut self.block_reveals);
        let mut seen_ids = BTreeSet::new();
        let mut valid: Vec<(usize, &RevealCandidate)> = Vec::new();
        let mut rejected: Vec<(Position, String, String)> = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            if !seen_ids.insert(candidate.id.clone()) {
                continue;
            }
            match self.validate_reveal(candidate, height, registered_at) {
                Ok(_) => valid.push((index, candidate)),
                Err(reason) => {
                    rejected.push((candidate.position, candidate.subject.clone(), reason))
                }
            }
        }
        let mut survivors = Vec::new();
        for (index, candidate) in &valid {
            let conflicting = valid.iter().any(|(other, competitor)| {
                other != index
                    && (competitor.commitment == candidate.commitment
                        || competitor.leaves.iter().any(|leaf| {
                            candidate
                                .leaves
                                .iter()
                                .any(|mine| mine.delta_id == leaf.delta_id)
                        }))
            });
            if conflicting {
                rejected.push((
                    candidate.position,
                    candidate.subject.clone(),
                    "reveal shares a commitment or Delta with another reveal in the Block".into(),
                ));
            } else {
                survivors.push(*candidate);
            }
        }
        let survivors: Vec<(Position, String, String, String, Vec<String>)> = survivors
            .iter()
            .map(|candidate| {
                (
                    candidate.position,
                    candidate.id.clone(),
                    candidate.subject.clone(),
                    candidate.commitment.clone(),
                    candidate
                        .leaves
                        .iter()
                        .map(|leaf| leaf.delta_id.clone())
                        .collect(),
                )
            })
            .collect();
        for (position, subject, reason) in rejected {
            self.rejected.push(RejectedAct {
                position,
                action: "canary_reveal".into(),
                subject,
                code: "WIST4-E08",
                reason: format!("WIST4-E08: {reason}"),
            });
        }
        for (position, id, subject, commitment, deltas) in survivors {
            if let Some(record) = self.commitments.get_mut(&commitment) {
                record.revealed_at = Some(height);
            }
            for delta in &deltas {
                self.reserved_deltas.insert(delta.clone(), id.clone());
            }
            self.applied.insert(id.clone());
            self.reveals.push(CanaryReveal {
                position,
                id,
                subject,
                commitment,
                deltas,
            });
        }
    }

    pub fn commitments(&self) -> impl Iterator<Item = &CanaryCommitment> {
        self.commitments.values()
    }

    pub fn live_commitments(&self, height: u64) -> Vec<&CanaryCommitment> {
        self.commitments
            .values()
            .filter(|commitment| {
                commitment.height <= height
                    && commitment.revealed_at.is_none_or(|at| at > height)
                    && height
                        <= commitment.height
                            + self.blocks[commitment.height as usize]
                                .canary
                                .lifetime_blocks
            })
            .collect()
    }

    pub fn reveals(&self) -> &[CanaryReveal] {
        &self.reveals
    }

    pub fn reserved_delta(&self, delta_id: &str) -> Option<&str> {
        self.reserved_deltas.get(delta_id).map(String::as_str)
    }

    /// The rejections recorded since the last call.
    pub fn take_rejected(&mut self) -> Vec<RejectedAct> {
        std::mem::take(&mut self.rejected)
    }

    pub fn epoch_of_block(&self, height: u64) -> Option<crate::observer::Epoch> {
        self.epoch_of(height)
    }
}
