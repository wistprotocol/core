use super::collections::limits;
use super::read_json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wist_core::collection::{names, Limits};
use wist_core::declaration::{inner_hash, publisher_of, validate_fields};
use wist_core::declarations::{Declarations, Domain, Projection, TransitionKind};

const DOMAIN: &str = "example.com";

fn unbounded() -> Limits {
    let largest = |name| {
        wist_core::parameters::spec(name)
            .and_then(|spec| spec.max)
            .unwrap_or(wist_core::parameters::WIRE_INTEGER_MAX)
    };
    Limits::new(
        largest("collections_max"),
        largest("scope_entries_max"),
        largest("url_cap_bytes"),
    )
    .unwrap()
}

fn entries(envelopes: &[&Value]) -> Vec<Value> {
    let mut entries: Vec<Value> = envelopes
        .iter()
        .map(|envelope| json!({"type": "publisher_declaration", "body": envelope}))
        .collect();
    wist_core::epoch::sort_entries(&mut entries).unwrap();
    entries
}

fn state_pull_case(name: &str) -> Value {
    read_json("vectors/wist2/declaration-pull.json")["state_pull_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no state_pull_case {name}"))
        .clone()
}

fn seal(
    state: &mut Declarations,
    height: u64,
    sealed_at: &str,
    declaration_activation_epochs: i64,
    envelopes: &[&Value],
) {
    state
        .apply_epoch(
            height,
            &format!("height {height}"),
            sealed_at,
            7,
            declaration_activation_epochs,
            &Limits::suite(),
            &entries(envelopes),
        )
        .unwrap();
}

fn pull(
    state: &Declarations,
    at: &str,
    declaration_activation_epochs: i64,
    envelopes: &[&Value],
) -> Result<Projection, wist_core::Error> {
    state.project_pull(
        at,
        7,
        declaration_activation_epochs,
        &Limits::suite(),
        &entries(envelopes),
    )
}

fn kind_of(projection: &Projection, envelope: &Value) -> Vec<TransitionKind> {
    let hash = inner_hash(envelope).unwrap();
    projection
        .effects()
        .transitions
        .iter()
        .filter(|transition| transition.declaration.hash() == hash)
        .map(|transition| transition.kind)
        .collect()
}

fn hash(envelope: &Value) -> String {
    inner_hash(envelope).unwrap()
}

#[test]
fn a_fetched_replacement_of_a_pending_head_due_at_the_pull_height_is_classified_against_the_pending_state(
) {
    let case = state_pull_case("replacement of the pending head signed by a recovery key is a pending replacement, pulled under the current Declaration alone");
    let [g, p, q] = ["G", "P", "Q"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 1, &[g]);
    seal(&mut state, 1, "2026-10-01T01:00:00Z", 1, &[p]);
    assert_eq!(
        state.domains()[DOMAIN]
            .pending()
            .unwrap()
            .activation_height(),
        2
    );

    let projection = pull(&state, "2026-10-01T02:00:00Z", 1, &[q]).unwrap();
    assert_eq!(
        kind_of(&projection, q),
        [TransitionKind::PendingReplacement]
    );
    assert!(projection.effects().activations.is_empty());
    let domain = &projection.domains()[DOMAIN];
    assert_eq!(domain.current().hash(), hash(g));
    assert_eq!(domain.pending().unwrap().head().hash(), hash(q));
    assert_eq!(domain.pending().unwrap().activation_height(), 2);
    assert!(domain.window().is_none());

    let epoch = state
        .project(
            "2026-10-01T02:00:00Z",
            7,
            1,
            &Limits::suite(),
            &entries(&[q]),
        )
        .unwrap();
    assert_eq!(
        kind_of(&epoch, p),
        [TransitionKind::Activation],
        "the Epoch at the activation height activates before applying the newcomer"
    );
    assert_ne!(kind_of(&epoch, q), [TransitionKind::PendingReplacement]);
}

#[test]
fn a_recovery_rotation_fetched_beside_a_pending_head_due_at_the_pull_height_reverses_it() {
    let case = state_pull_case(
        "recovery rotation discovered beside a pending head: pulled under the two frozen sources",
    );
    let [g, p, r] = ["G", "P", "R"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 1, &[g]);
    seal(&mut state, 1, "2026-10-01T01:00:00Z", 1, &[p]);

    let projection = pull(&state, "2026-10-01T02:00:00Z", 1, &[r]).unwrap();
    assert_eq!(
        kind_of(&projection, r),
        [TransitionKind::ReversalRecoveryRotation]
    );
    let domain = &projection.domains()[DOMAIN];
    assert!(domain.pending().is_none());
    let sources: Vec<&str> = domain
        .admission_sources()
        .into_iter()
        .map(|source| source.hash())
        .collect();
    assert_eq!(sources, [hash(g), hash(r)]);
}

#[test]
fn a_pending_head_due_at_the_pull_height_stays_pending_at_the_pull() {
    let case =
        state_pull_case("pending head served again: pulled under the current Declaration alone");
    let [g, p] = ["G", "P"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 1, &[g]);
    seal(&mut state, 1, "2026-10-01T01:00:00Z", 1, &[p]);

    let projection = pull(&state, "2026-10-01T02:00:00Z", 1, &[]).unwrap();
    assert!(projection.effects().transitions.is_empty());
    let domain = &projection.domains()[DOMAIN];
    assert_eq!(domain.current().hash(), hash(g));
    assert_eq!(domain.pending().unwrap().head().hash(), hash(p));
    assert!(domain.reset().is_none());

    let served = pull(&state, "2026-10-01T02:00:00Z", 1, &[p]).unwrap();
    assert_eq!(kind_of(&served, p), [TransitionKind::Idempotent]);
}

#[test]
fn a_fresh_identity_fetched_under_zero_activation_epochs_stays_pending_at_the_pull() {
    let case = state_pull_case("fresh identity fetched under declaration_activation_epochs 0 and not yet sealed stays pending: pulled under the current Declaration alone");
    let [g, p] = ["G", "P"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 0, &[g]);

    let projection = pull(&state, "2026-10-01T01:00:00Z", 0, &[p]).unwrap();
    assert_eq!(
        kind_of(&projection, p),
        [TransitionKind::FreshIdentityPending]
    );
    assert!(projection.effects().activations.is_empty());
    let domain = &projection.domains()[DOMAIN];
    assert_eq!(domain.current().hash(), hash(g));
    assert_eq!(domain.pending().unwrap().head().hash(), hash(p));
    assert!(domain.reset().is_none());

    let epoch = state
        .project(
            "2026-10-01T01:00:00Z",
            7,
            0,
            &Limits::suite(),
            &entries(&[p]),
        )
        .unwrap();
    assert_eq!(
        kind_of(&epoch, p),
        [
            TransitionKind::FreshIdentityPending,
            TransitionKind::Activation
        ]
    );
}

#[test]
fn a_fresh_identity_discovered_under_zero_activation_epochs_stays_pending_when_served_again_at_a_pull(
) {
    let case = state_pull_case("fresh identity discovered under declaration_activation_epochs 0 and not yet sealed, served again: pulled under the current Declaration alone");
    let [g, p] = ["G", "P"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 0, &[g]);

    let discovered = pull(&state, "2026-10-01T01:00:00Z", 0, &[p]).unwrap();
    let domain = &discovered.domains()[DOMAIN];
    assert_eq!(domain.current().hash(), hash(g));
    assert_eq!(domain.pending().unwrap().head().hash(), hash(p));

    let served = pull(&state, "2026-10-01T01:00:00Z", 0, &[p, p]).unwrap();
    assert_eq!(
        kind_of(&served, p),
        [TransitionKind::FreshIdentityPending],
        "an exact repeat applies once"
    );
}

#[test]
fn a_pull_at_the_recovery_window_end_settles_the_window_and_one_a_second_earlier_does_not() {
    let case = state_pull_case(
        "recovery rotation superseded unsealed at settlement: pulled under the settled Declaration",
    );
    let [g, r, c] = ["G", "R", "C"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 24, &[g]);
    seal(&mut state, 1, "2026-10-01T01:00:00Z", 24, &[]);
    seal(&mut state, 2, "2026-10-01T02:00:00Z", 24, &[r]);
    seal(&mut state, 3, "2026-10-01T03:00:00Z", 24, &[c]);
    seal(&mut state, 4, "2026-10-08T01:00:00Z", 24, &[]);
    let end = state.domains()[DOMAIN].window().unwrap().end_s();
    assert_eq!(
        end,
        i128::from(wist_core::timestamp::log_seconds("2026-10-08T02:00:00Z").unwrap())
    );

    let before = pull(&state, "2026-10-08T01:59:59Z", 24, &[]).unwrap();
    assert!(before.effects().settlements.is_empty());
    assert_eq!(before.domains()[DOMAIN].current().hash(), hash(c));
    assert!(before.domains()[DOMAIN].window().is_some());

    let at = pull(&state, "2026-10-08T02:00:00Z", 24, &[]).unwrap();
    assert_eq!(at.effects().settlements.len(), 1);
    assert_eq!(kind_of(&at, r), [TransitionKind::Settlement]);
    let domain = &at.domains()[DOMAIN];
    assert_eq!(domain.current().hash(), hash(r));
    assert!(domain.window().is_none());
}

#[test]
fn a_pull_reads_the_window_at_its_own_instant_even_before_the_last_sealed_at() {
    let case = state_pull_case(
        "recovery rotation superseded unsealed at settlement: pulled under the settled Declaration",
    );
    let [g, r] = ["G", "R"].map(|label| &case["declarations"][label]);
    let mut state = Declarations::default();
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 24, &[g]);
    seal(&mut state, 1, "2026-10-01T02:00:00Z", 24, &[r]);

    let projection = pull(&state, "2026-10-01T01:00:00Z", 24, &[]).unwrap();
    assert!(projection.effects().transitions.is_empty());
    assert!(projection.domains()[DOMAIN].window().is_some());
}

#[test]
fn the_sealed_at_of_the_accepted_prefix_is_readable() {
    let case = state_pull_case("first contact: pulled under the fetched Declaration");
    let g = &case["declarations"]["G"];
    let mut state = Declarations::default();
    assert_eq!(state.sealed_at_s(), None);
    seal(&mut state, 0, "2026-10-01T00:00:00Z", 24, &[g]);
    assert_eq!(
        state.sealed_at_s(),
        Some(wist_core::timestamp::log_seconds("2026-10-01T00:00:00Z").unwrap())
    );
}

struct Labels(BTreeMap<String, String>);

impl Labels {
    fn of(declarations: &Value) -> Self {
        Labels(
            declarations
                .as_object()
                .unwrap()
                .iter()
                .map(|(label, envelope)| (hash(envelope), label.clone()))
                .collect(),
        )
    }

    fn get(&self, hash: &str) -> &str {
        &self.0[hash]
    }
}

fn pulled_sources(labels: &Labels, domain: &Domain) -> (Vec<String>, Vec<String>) {
    let sources = domain.admission_sources();
    let mut collections: Vec<String> = Vec::new();
    for source in &sources {
        let publisher = publisher_of(source.envelope()).unwrap();
        for name in names(&publisher) {
            if !collections.iter().any(|seen| seen == name) {
                collections.push(name.to_owned());
            }
        }
    }
    (
        sources
            .iter()
            .map(|source| labels.get(source.hash()).to_owned())
            .collect(),
        collections,
    )
}

fn heads(domain: &Domain) -> (&str, Option<&str>, Option<&str>) {
    (
        domain.current().hash(),
        domain.window().map(|window| window.head().hash()),
        domain.pending().map(|pending| pending.head().hash()),
    )
}

#[test]
fn state_pull_cases_replay_through_the_pull_projection() {
    let vector = read_json("vectors/wist2/declaration-pull.json");
    let mut replayed = 0;
    for case in vector["state_pull_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = &case["expected"];
        let fetched_label = &case["pull"]["fetched"];
        if fetched_label.is_null() {
            assert_eq!(expected["acceptance"], "not_fetched", "{name}");
            continue;
        }
        let envelopes = &case["declarations"];
        let labels = Labels::of(envelopes);
        let history = &case["history_parameters"];
        let recovery_window_days = history["recovery_window_days"].as_i64().unwrap_or(7);
        let activation = history["declaration_activation_epochs"]
            .as_i64()
            .unwrap_or(24);
        let mut state = Declarations::default();
        for epoch in case["epochs"].as_array().unwrap() {
            let sealed: Vec<&Value> = epoch["declarations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|label| &envelopes[label.as_str().unwrap()])
                .collect();
            state
                .apply_epoch(
                    epoch["height"].as_u64().unwrap(),
                    "root",
                    epoch["sealed_at"].as_str().unwrap(),
                    recovery_window_days,
                    activation,
                    &limits(&epoch["parameters"]),
                    &entries(&sealed),
                )
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        let at = case["pull"]["sealed_at"].as_str().unwrap();
        assert_eq!(
            state.head().map_or(0, |(height, _)| height + 1),
            case["pull"]["height"].as_u64().unwrap(),
            "{name}"
        );
        let project = |admitted: &[&Value], limits: &Limits| {
            state.project_pull(
                at,
                recovery_window_days,
                activation,
                limits,
                &entries(admitted),
            )
        };
        let mut admitted: Vec<&Value> = Vec::new();
        for label in case["discovered"].as_array().unwrap() {
            let envelope = &envelopes[label.as_str().unwrap()];
            let trial: Vec<&Value> = admitted.iter().copied().chain([envelope]).collect();
            if project(&trial, &unbounded()).is_ok() {
                admitted.push(envelope);
            }
        }
        let view = project(&admitted, &unbounded()).unwrap();
        let fetched = &envelopes[fetched_label.as_str().unwrap()];
        let fetched_hash = hash(fetched);
        let outcome = match view.domains().get(DOMAIN).map(heads) {
            Some((current, _, pending))
                if current == fetched_hash || pending == Some(&fetched_hash) =>
            {
                Ok(("idempotent".to_owned(), view.domains()[DOMAIN].clone()))
            }
            Some((_, Some(window_head), _)) if window_head == fetched_hash => Ok((
                "recovery_chain_head".to_owned(),
                view.domains()[DOMAIN].clone(),
            )),
            _ => match validate_fields(fetched, Some(&limits(&case["pull"]["parameters"]))) {
                Err((code, _)) => Err(code.to_owned()),
                Ok(_) => {
                    let trial: Vec<&Value> = admitted.iter().copied().chain([fetched]).collect();
                    match project(&trial, &unbounded()) {
                        Err(error) => Err(error.code().unwrap().to_owned()),
                        Ok(projection) => {
                            let kind = kind_of(&projection, fetched).last().unwrap().as_str();
                            Ok((kind.to_owned(), projection.domains()[DOMAIN].clone()))
                        }
                    }
                }
            },
        };
        match outcome {
            Ok((acceptance, domain)) => {
                assert_eq!(expected["acceptance"], acceptance, "{name}");
                assert_eq!(expected["proceeds"], true, "{name}");
                let (sources, collections) = pulled_sources(&labels, &domain);
                assert_eq!(expected["sources"], json!(sources), "{name}");
                assert_eq!(expected["collections_pulled"], json!(collections), "{name}");
            }
            Err(code) => {
                assert_eq!(expected["acceptance"], code, "{name}");
                assert_eq!(expected["proceeds"], false, "{name}");
            }
        }
        replayed += 1;
    }
    assert!(replayed >= 20, "replayed {replayed}");
}

#[test]
fn declaration_refresh_acceptance_replays_through_the_pull_projection() {
    let vector = read_json("vectors/wist2/declaration-refresh.json");
    let clock = vector["clock"].as_str().unwrap();
    let domain = vector["domain"].as_str().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut state = Declarations::default();
        for (height, sealed) in case["sealed"].as_array().into_iter().flatten().enumerate() {
            seal(
                &mut state,
                height as u64,
                sealed["at"].as_str().unwrap(),
                24,
                &[&sealed["envelope"]],
            );
        }
        let mut accepted: Vec<Value> = Vec::new();
        for (index, (pull, expected)) in case["pulls"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["expected"].as_array().unwrap())
            .enumerate()
        {
            let fetched = &pull["declaration"];
            let project = |envelopes: &[&Value]| {
                state.project_pull(clock, 7, 24, &Limits::suite(), &entries(envelopes))
            };
            let outcome = if fetched.is_null() {
                "stopped"
            } else {
                let held: Vec<&Value> = accepted.iter().collect();
                let view = project(&held).unwrap();
                let fetched_hash = hash(fetched);
                let idempotent = view.domains().get(domain).is_some_and(|state| {
                    let (current, _, pending) = heads(state);
                    current == fetched_hash || pending == Some(&fetched_hash)
                });
                let trial: Vec<&Value> = held.iter().copied().chain([fetched]).collect();
                if idempotent {
                    "accepted"
                } else if project(&trial).is_ok() {
                    accepted.push(fetched.clone());
                    "accepted"
                } else {
                    "stopped"
                }
            };
            assert_eq!(expected["declaration"], outcome, "{name}: pull {index}");
        }
    }
}
