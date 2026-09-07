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

These functions provide map validation. Sealing and replay callers must
also enforce grace, validate every prospective effective-time map, check
cadence transitions, and preserve live evidence-retention obligations
(WIST-4 §9). Bounds and arithmetic alone do not establish compliance with
the section's broader guarantee-preservation requirements.

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

Callers verify signatures and evidence, establish the notice's activation,
and enforce the single-notice rule for each subject, level and activation
before supplying it. The timestamp-only helpers accept prevalidated facts;
use `Ladder` for same-Block transitions and `process_at` for process
eligibility and multiplicity.

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
