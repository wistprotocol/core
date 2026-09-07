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
