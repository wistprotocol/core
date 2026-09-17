//! WIST-1 §5.2 Declaration replay: the accepted Declaration per domain,
//! the sequence floor, recovery windows with their owner, chain head,
//! pre-recovery source and competitors, settlement at the window's end,
//! and identity resets — computed identically by every party replaying a
//! Log.
use crate::declaration::{evaluate, evaluate_initial, inner_hash, validate_fields, Decision};
use crate::error::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Position {
    pub block_number: u64,
    pub entry_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Declaration {
    envelope: Value,
    hash: String,
    position: Position,
    sealed_at_s: i64,
}

impl Declaration {
    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn position(&self) -> Position {
        self.position
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryWindow {
    owner: Arc<Declaration>,
    head: Arc<Declaration>,
    before: Arc<Declaration>,
    end_s: i128,
    competitors: Vec<Arc<Declaration>>,
}

impl RecoveryWindow {
    pub fn owner(&self) -> &Declaration {
        &self.owner
    }

    pub fn head(&self) -> &Declaration {
        &self.head
    }

    pub fn before(&self) -> &Declaration {
        &self.before
    }

    pub fn end_s(&self) -> i128 {
        self.end_s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    current: Arc<Declaration>,
    highest_accepted_seq: u64,
    first: Position,
    reset: Option<Position>,
    window: Option<RecoveryWindow>,
}

impl Domain {
    pub fn current(&self) -> &Declaration {
        &self.current
    }

    pub fn highest_accepted_seq(&self) -> u64 {
        self.highest_accepted_seq
    }

    pub fn first(&self) -> Position {
        self.first
    }

    pub fn reset(&self) -> Option<Position> {
        self.reset
    }

    pub fn window(&self) -> Option<&RecoveryWindow> {
        self.window.as_ref()
    }

    pub fn delta_admission_sources(&self) -> Vec<&Declaration> {
        self.window.as_ref().map_or_else(
            || vec![self.current()],
            |window| vec![window.before(), window.owner()],
        )
    }

    pub fn delta_sealing_source(&self) -> Option<&Declaration> {
        self.window.is_none().then(|| self.current())
    }
}

#[derive(Debug, Clone)]
pub struct Installation {
    pub declaration: Arc<Declaration>,
    pub decision: Option<Decision>,
    pub opens_window: bool,
    pub resets_identity: bool,
}

#[derive(Debug, Clone)]
pub struct Settlement {
    pub domain: String,
    pub restored: Arc<Declaration>,
    pub superseded: Vec<Arc<Declaration>>,
}

#[derive(Debug, Clone, Default)]
pub struct Effects {
    pub settlements: Vec<Settlement>,
    pub installations: Vec<Installation>,
}

#[derive(Debug, Clone)]
pub struct Projection {
    domains: BTreeMap<String, Domain>,
    effects: Effects,
    block_number: u64,
    sealed_at_s: i64,
}

impl Projection {
    pub fn domains(&self) -> &BTreeMap<String, Domain> {
        &self.domains
    }

    pub fn effects(&self) -> &Effects {
        &self.effects
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn sealed_at_s(&self) -> i64 {
        self.sealed_at_s
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Declarations {
    domains: BTreeMap<String, Domain>,
    head: Option<(u64, String)>,
    sealed_at_s: Option<i64>,
}

impl Declarations {
    pub fn domains(&self) -> &BTreeMap<String, Domain> {
        &self.domains
    }

    pub fn head(&self) -> Option<(u64, &str)> {
        self.head
            .as_ref()
            .map(|(height, hash)| (*height, hash.as_str()))
    }

    /// Applies the next Block of the accepted prefix.
    pub fn apply_block(
        &mut self,
        block_number: u64,
        prev_block_hash: &str,
        block_hash: &str,
        sealed_at: &str,
        recovery_window_days: i64,
        entries: &[Value],
    ) -> Result<Effects> {
        let continues = match &self.head {
            None => block_number == 0,
            Some((height, hash)) => {
                height.checked_add(1) == Some(block_number) && hash == prev_block_hash
            }
        };
        if !continues {
            return Err(Error::History(
                "Declaration replay requires the next Block of its accepted prefix".into(),
            ));
        }
        let projection = self.project(sealed_at, recovery_window_days, entries)?;
        self.domains = projection.domains;
        self.head = Some((block_number, block_hash.to_owned()));
        self.sealed_at_s = Some(projection.sealed_at_s);
        Ok(projection.effects)
    }

    /// Seeds the accepted prefix's head for a party that starts at a
    /// Snapshot's `log_position` rather than at Block 0; the next applied
    /// Block must be the following height.
    pub fn seed_head(&mut self, block_number: u64, block_hash: &str, sealed_at_s: Option<i64>) {
        self.head = Some((block_number, block_hash.to_owned()));
        self.sealed_at_s = sealed_at_s;
    }

    /// Seeds a domain's accepted state from a Snapshot: the current
    /// Declaration at its sealing position, the accepted sequence floor
    /// and, when a window is open, its chain head and frozen end.
    pub fn adopt(
        &mut self,
        domain: &str,
        current: Value,
        position: Position,
        sealed_at_s: i64,
        highest_accepted_seq: u64,
        window: Option<(Value, Position, i64, i128)>,
    ) -> Result<()> {
        let hash = inner_hash(&current).map_err(failure)?;
        let current = Arc::new(Declaration {
            envelope: current,
            hash,
            position,
            sealed_at_s,
        });
        let window = match window {
            Some((head, head_position, head_sealed_at_s, end_s)) => {
                let hash = inner_hash(&head).map_err(failure)?;
                let head = Arc::new(Declaration {
                    envelope: head,
                    hash,
                    position: head_position,
                    sealed_at_s: head_sealed_at_s,
                });
                Some(RecoveryWindow {
                    owner: head.clone(),
                    head: head.clone(),
                    before: current.clone(),
                    end_s,
                    competitors: Vec::new(),
                })
            }
            None => None,
        };
        self.domains.insert(
            domain.to_owned(),
            Domain {
                current: current.clone(),
                highest_accepted_seq,
                first: position,
                reset: None,
                window,
            },
        );
        Ok(())
    }

    pub fn project(
        &self,
        sealed_at: &str,
        recovery_window_days: i64,
        entries: &[Value],
    ) -> Result<Projection> {
        let sealed_at_s = crate::timestamp::log_seconds(sealed_at)?;
        if self
            .sealed_at_s
            .is_some_and(|previous| sealed_at_s <= previous)
        {
            return Err(failure(
                "candidate timestamp must follow the accepted prefix",
            ));
        }
        crate::parameters::validate_value("recovery_window_days", recovery_window_days)?;
        crate::block::validate_entry_order(entries)?;
        let block_number = self.head.as_ref().map_or(Ok(0), |(height, _)| {
            height
                .checked_add(1)
                .ok_or_else(|| failure("Block height overflow"))
        })?;
        let mut staged = self.domains.clone();
        let mut effects = Effects::default();
        for (domain, state) in &mut staged {
            if state
                .window
                .as_ref()
                .is_some_and(|window| i128::from(sealed_at_s) >= window.end_s)
            {
                let window = state.window.take().unwrap();
                state.current = window.head.clone();
                effects.settlements.push(Settlement {
                    domain: domain.clone(),
                    restored: window.head,
                    superseded: window.competitors,
                });
            }
        }
        let mut groups = BTreeMap::<(String, u64), Vec<(usize, &Value)>>::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry["type"] != "publisher_declaration" {
                continue;
            }
            let envelope = validate_fields(&entry["body"]).map_err(rejection)?;
            if envelope.publisher.wist_version != crate::WIST_VERSION {
                return Err(Error::History("unsupported Declaration version".into()));
            }
            groups
                .entry((envelope.publisher.domain, envelope.publisher.seq))
                .or_default()
                .push((index, &entry["body"]));
        }
        for ((domain, seq), group) in groups {
            let (index, incoming) = group[0];
            if let Some(state) = staged.get(&domain) {
                let mut unchanged = true;
                for (_, envelope) in &group {
                    unchanged &= inner_hash(envelope).map_err(failure)? == state.current.hash;
                }
                if unchanged {
                    continue;
                }
            }
            let canonical = crate::jcs::canonicalize(incoming)?;
            for (_, envelope) in &group[1..] {
                if crate::jcs::canonicalize(envelope)? != canonical {
                    return Err(failure("WIST1-E08 conflicting Declaration group"));
                }
            }
            let declaration = Arc::new(Declaration {
                envelope: incoming.clone(),
                hash: inner_hash(incoming).map_err(failure)?,
                position: Position {
                    block_number,
                    entry_index: index,
                },
                sealed_at_s,
            });
            let mut installation = Installation {
                declaration: declaration.clone(),
                decision: None,
                opens_window: false,
                resets_identity: false,
            };
            if let Some(state) = staged.get_mut(&domain) {
                if seq <= state.highest_accepted_seq {
                    return Err(failure(
                        "WIST1-E08 Declaration sequence does not exceed accepted floor",
                    ));
                }
                let previous = std::iter::once(&state.current)
                    .chain(state.window.iter().map(|window| &window.head))
                    .find(|head| incoming["publisher"]["prev_declaration"] == head.hash)
                    .ok_or_else(|| failure("WIST1-E08 ineligible Declaration predecessor"))?
                    .clone();
                let decision = evaluate(previous.envelope(), incoming).map_err(rejection)?;
                if let Some(window) = &mut state.window {
                    if previous.hash == window.head.hash
                        && matches!(decision, Decision::Ordinary | Decision::Recovery)
                    {
                        window.head = declaration.clone();
                    } else {
                        window.competitors.push(declaration.clone());
                    }
                } else if decision == Decision::Recovery {
                    let end_s = i128::from(sealed_at_s) + i128::from(recovery_window_days) * 86_400;
                    if end_s > i128::from(crate::parameters::LOG_TIMESTAMP_MAX_S) {
                        return Err(failure(
                            "WIST1-E08 recovery window end exceeds the Log timestamp range",
                        ));
                    }
                    state.window = Some(RecoveryWindow {
                        owner: declaration.clone(),
                        head: declaration.clone(),
                        before: previous,
                        end_s,
                        competitors: Vec::new(),
                    });
                    installation.opens_window = true;
                } else if decision == Decision::FreshIdentity {
                    state.reset = Some(declaration.position);
                    installation.resets_identity = true;
                }
                state.current = declaration;
                state.highest_accepted_seq = seq;
                installation.decision = Some(decision);
            } else {
                evaluate_initial(incoming).map_err(rejection)?;
                staged.insert(
                    domain,
                    Domain {
                        current: declaration.clone(),
                        highest_accepted_seq: seq,
                        first: declaration.position,
                        reset: None,
                        window: None,
                    },
                );
            }
            effects.installations.push(installation);
        }
        Ok(Projection {
            domains: staged,
            effects,
            block_number,
            sealed_at_s,
        })
    }
}

fn failure(detail: impl Into<String>) -> Error {
    Error::History(detail.into())
}

fn rejection((code, detail): (&str, String)) -> Error {
    failure(format!("{code} {detail}"))
}
