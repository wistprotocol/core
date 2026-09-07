# wist-core

Rust implementation of the WIST Protocol's WIST-1..3 primitives: JCS canonicalization, Ed25519
envelopes, delta identity, Merkle trees/proofs, block/checkpoint verification,
snapshot digests, and WIST-2 link/text extraction, and WIST-4 audit math
(ECVRF sampling, reputation, decay, link agreement). Conformance is defined by
the sibling spec repo's schemas and vectors, not by this crate — every
normative behavior is verified against those vectors in `tests/conformance.rs`.

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set:

```bash
WIST_SPEC_DIR=/path/to/spec cargo test
```

## Extension replay

`extension::evaluate` takes the valid Records for one Delta in Log order,
the complete sealed Block history through the height being read, and an
`ExtensionClaim` identifying the trigger, whether it summoned peers, and
the confirmation quorum and window in force at its Block. It derives the
first closing Block and, when contradicted, the establishing Block.
Records after the fixed window cannot change that outcome.

Associate each establishing Block with the signing Publisher's domain in
an `extension::Escalation`. `extension::escalated_sampling` evaluates the
domain's 30-day state at a supplied Block. Selection callers pass the
sanction and escalation states at height B − 1 to `sampling::p_1e7` or
`extension::StandingClaim`, with sampling constants in force at B. For
Block 0, both states come from the empty Log. Escalation changes sampling
only; it creates no sanction or removal state.

## Roster replay

`roster::Roster::apply_block` derives admitted and Observer key tenures from
roster acts whose signatures and details have already been validated.
Blocks arrive in increasing `sealed_at` order. Removals read the pre-Block
roster; admissions and registrations resolve as a simultaneous batch.
`apply_block_checked` also accepts an evidence validator: it checks removals
before they take effect and candidates after duplicate and incumbent checks,
so invalid evidence cannot retire a key or veto a competing claim.

Parse revised registry details with `RegistryUpdate::typed_details` and wire
removal evidence with `RosterAction::try_remove_with`. The older
`remove_with` constructor accepts already-validated, normalized evidence.
`validate_admission_evidence` takes only accepted Observer registrations and
otherwise-valid checkpoints for this Log, including the admission Block.
Callers validate checkpoint signatures under the registered key and resolve
the named chain head before supplying that history. The function enforces
track-record presence and the highest-height, greatest-ID citation; it does
not reject a claimed scoreboard merely for disagreeing with a recomputation
(WIST-4 §3.1). Canary membership, timing and scoring require separate replay
checks beyond the typed details contract.

Audit Record deserialization requires all five measured fields, including
`credit_commitment`, on measured verdicts and omits them on unmeasured
verdicts. `not_auditable` additionally requires `unmeasured`. Snapshot state
supports escalation, Observer tenure and live canary commitment tuples.

## Parameter validation

`parameters::PARAMS` lists the amendable identifiers, defaults and fixed
bounds. `validate_value` enforces those bounds and the signed wire-integer
range; failures are WIST4-E03. `validate` checks a candidate against the
combination rules involving its identifier, using an otherwise-valid map.
`validate_combinations` checks all arithmetic combinations in a supplied
map. Intermediate calculations use 128-bit integers.

`parameters::Schedule::replay` processes amendments in canonical Log order,
enforces the grace period in force when each candidate seals, and checks
every prospective effective-time map. `try_accept` provides incremental
admission in the same order and rejects repeated or out-of-order positions.
Rejected candidates leave accepted values unchanged and are never retried.
`ScheduleReplay::error_at` identifies rejected amendments as WIST4-E03.
`value_at` reads the schedule's accepted prefix at the supplied instant.

Cadence validation preserves extension windows from every historical
constant-map interval, including changes that are still pending. The
standalone `validate_cadence_transitions` helper takes chronologically
ordered, maximal intervals of the complete parameter map; equal cadence
fields alone do not establish equal maps.

Supply the Log's first Block timestamp and otherwise-validated amendments:
authenticated Registry Updates with parsed integer values and timestamps,
unique Entry positions, and verified Block chronology. `try_accept_with_block_size` additionally checks each prospective cap
against the supplied largest complete JCS Block through the candidate's
own height. Callers preserve that running maximum during replay and
restoration; a later maximum must not reconsider earlier acceptance.
`block_size_bounds` returns the minimum sealing cap and maximum transport
cap across the current and accepted future maps at the supplied instant.
After all candidates, callers reject a Block whose running size maximum
exceeds the minimum. The maximum bounds decompression from a verified
prefix; it does not authorize a Block before an increase takes effect.
These checks do not replace authentication or the evidence-serving duty
below.

## Sanction replay

`sanctions::Ladder::apply_block` consumes one domain's validated findings
in increasing Block order. It applies identity resets, lifts and
notice-scoped voids before findings, then orders findings by confirming
Record Entry index. Each rung retains the Record ID, height and Entry
index that armed it. Voiding an old activation leaves a later rearming
intact; lifts preserve findings, while identity resets clear them.
Callers supply findings applicable to the current identity under §6.3.

`sanctions::process_at` replays signed, otherwise-valid appeal and ruling
acts against a supplied notice through a specified Block. It resolves
appeals before rulings, deduplicates Update IDs, rejects competing acts,
and requires merits rulings to seal above the target activation Block.
`ProcessState::error_at` reports WIST4-E05 for rejected acts. Notice clocks
come from the notice Block; ruling clocks come from the accepted appeal
Block. The result supplies the void instant for the caller to apply to
the notice's activation at the first Block reaching it.

`sanctions::Replay::apply_block` integrates notice admission, accepted
processes and rung derivation for one domain. It applies existing processes'
reversals at the first supplied Block reaching their deadlines, before new
findings; then validates notices against the resulting activations and
resolves same-Block appeals. Only one eligible notice per activation opens
a process. Invalid candidates cannot veto eligible ones; distinct eligible
candidates in one Block all fail, and repeated Update IDs retain their
first sealing. Recovery notices open no sanction process.

`ConfirmedFinding::new` checks the first confirmation using each candidate
Record's anchored quorum and window, and derives severity from the full
closed set. Notice evidence must establish the activating finding and an
original arming branch with complete quorums. Count windows remain anchored
to the activation, including pre-lift findings of the same identity. The
level-4 further-finding branch additionally requires evidence for the actual
prior level-3 activation. Optional citations must resolve to available
Audit Records. `BlockAdmission` reports accepted notice indices and
WIST4-E04/E05 rejections; `notices()` exposes accepted processes and their
current retention endpoints.

Supply authenticated Blocks in increasing order, including every Block
through the queried height, schema-validated Registry Updates and their
actual IDs, and parameter values from the accepted schedule. Target and
evidence fields receive additional WIST4-E04 checks during notice admission.
Appeals must already verify under the notice-era Key Set. Findings must
supply the complete applicable verdict history through first confirmation,
with valid signatures, standing, Delta/kind grouping and current-identity
scope; `ConfirmedFinding` checks confirmation and severity, not those
prerequisites. `available_records` supplies additional authenticated Record
IDs available by this Block; finding Records are registered automatically.
Identity resets and lifts must already be validated. Timestamp-only helpers,
`Ladder`, and `process_at` remain available for callers with prevalidated
facts; `Replay` performs the notice and transition integration above.

## Canary scoring and Observer checkpoints

`delta::make_credit_commitment` binds the raw response body and Auditor ID
under the Reference Payload's salt. Canary leaves use `merkle::leaf_hash`
and `merkle::verify_inclusion`, including exact proof-path consumption.
`canary::scoreboard` verifies supplied bytes against each revealed leaf,
recomputes credit and hard hits, and counts each Record ID once per tier.
It pins all four extraction and similarity-band parameters to the audited
Delta's Block and applies the delete mirror. Reveals contribute only while
their reveal-anchored scoring windows remain open.

`canary::numeric_timing` calculates the commitment-anchored lead and
lifetime and the newest-Delta-anchored minimum and budget rotation.
Admission also requires `canary::sealing_opportunities`: actual Blocks
must leave the ordinary Record allowance and the required Observer
checkpoint opportunities before the reveal. Supply every bound Delta's
anchored coverage deadline and seal allowance, the registered identities
at the newest Delta and reveal, and consecutive budgeting epochs.
Block timestamp slices start at height zero and contain the reveal Block.

`observer::epoch_of_block` reads each epoch's length at its first Block.
`epoch_budget` groups canonical registered identities by two-label suffix,
walks the fixed suffix hash order and selects one identity per budgeted
suffix. Equal digests use UTF-8 name order; `budget_with_sort_keys` exposes
that ordering boundary for collision-domain conformance tests.
`covered_before` follows authenticated `prev_record` links from accepted
checkpoints sealed strictly below the reveal.

These functions consume validated protocol facts. For a complete scoreboard,
callers provide all accepted live reveals and eligible Records, with
Log-wide unique leaf bindings, authenticated Reference Payloads and Record
chains, and an accepted parameter schedule. Each Record's `fixed_height`
is its earliest valid sealing or covering checkpoint height. Leaf tiers
come from the domain state at the leaf Delta's Block minus one, using the
sampling threshold rules. Timing and epoch inputs retain their WIST-4 §9
anchors. Signature, standing, registration, commitment ration and reveal
batch validation remain admission responsibilities; successful scoring or
numeric timing alone does not establish a valid canary act.

## Evidence retention

`sanctions::process_at` also derives `retention_end_at_s` from the accepted
process at the supplied prefix. Without a timely accepted appeal it remains
the notice's appeal-seal deadline, even after an `unappealed` statement.
An accepted appeal supplies its anchored ruling deadline; an accepted merits
ruling closes the process at its Block. Future and rejected acts move no
deadline, and clearing a rung does not close its notice process.

`sanctions::must_retain_evidence` combines those process endpoints with a
Block's ordinary retention floor. Supply all accepted notice processes
citing that Block, recomputed at the queried prefix, and the
`mirror_retention_days` value at the Block's first service. The process
endpoint is inclusive; the ordinary floor expires at its endpoint.
Mirrors must acquire every cited Record Block before serving the notice
Block and persist these obligations across restarts. The helper determines
retention duration; callers perform and verify the required storage.

## Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## Spec

Protocol definitions and conformance vectors live in the sibling
[spec repo](../spec) (WIST-1 delta format, WIST-2 site publication, WIST-3
logbook & distribution, WIST-4 audit math).

## wist-bench

`crates/wist-bench` simulates WIST-4 §4 audit sampling with this crate's
normative arithmetic at three scenario tiers and derives fetch-volume,
bandwidth, storage, and compute figures for an Auditor.
