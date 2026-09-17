# wist-core

The signed Delta format targets [WIST specification revision `d75bd49abcfbbe6a672e4fb695e078b489f51ba7`](https://github.com/wistprotocol/spec/tree/d75bd49abcfbbe6a672e4fb695e078b489f51ba7). Object version `1.0.0` alone does not identify a compatible draft.

Delta Envelopes require a canonical `publisher` inside the signed and hashed object. The typed object and `delta::publisher` reject missing or noncanonical identities without rewriting signed bytes. Signature/key-history and `(publisher, url)` chain validation remain caller obligations.

Rust implementation of the WIST Protocol's primitives: JCS canonicalization,
Ed25519 envelopes, delta identity, Key Set resolution, chain tips, Merkle
trees/proofs, block/checkpoint verification, snapshot digests and state
tuples, WIST-2 link/text extraction, the WIST-1 §5.2 Declaration and
recovery-window replay, and the WIST-4 Parameter Registry with its schedule
replay. The [specification](../spec/README.md) defines conformance;
`crates/wist-core/tests/conformance.rs` exercises its vectors.

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

Canonical Host processing uses Unicode 16.0 UTS #46 data. Exact IDNA adapter
and ICU normalizer/property dependency constraints keep a dependency update
from admitting names assigned only in a later Unicode version. The `zerovec`
allocation feature supports these ICU data providers. Signed host vectors
exercise both Unicode 16 additions and Unicode 17 exclusions.

## Registry Updates

`objects::RegistryUpdate` carries the four WIST-4 §3 governance acts.
`typed_details` parses `details` under the act's §5.1 contract and checks
the `subject` shape, key fields, parameter identifier and bounds, and the
withdrawal's Delta ID and Canonical Host; a violation is WIST4-E04.
Authentication under a Log key valid at the act's Block, the grace period
and the Delta a withdrawal names remain caller checks.

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

Supply the Log's first Block timestamp and otherwise-validated amendments:
authenticated Registry Updates with parsed integer values and timestamps,
unique Entry positions, and verified Block chronology.
`try_accept_with_block_size` additionally checks each prospective cap
against the supplied largest complete JCS Block through the candidate's
own height. Callers preserve that running maximum during replay and
restoration; a later maximum must not reconsider earlier acceptance.
`block_size_bounds` returns the minimum sealing cap and maximum transport
cap across the current and accepted future maps at the supplied instant.
After all candidates, callers reject a Block whose running size maximum
exceeds the minimum. The maximum bounds decompression from a verified
prefix; it does not authorize a Block before an increase takes effect.

## Recovery settlement

`recovery::settle` consumes accepted Declarations in application order.
Each `WindowDeclaration.label` is its inner-object hash, `predecessor` is its
named predecessor hash, and `signer` is the authenticated public key, not its
identifier. Callers establish sequence, predecessor eligibility, signatures,
recovery-key protection and window ownership before constructing these inputs.
The helper follows only replacements naming the current recovery-chain head
and signed by a public key in that head's signing or recovery set.

Queue admission and settlement receive a verification callback over the full
signed Delta Envelope and complete `PublisherKey` entries. The callback must
check the named binding, canonical signature and parsed `observed_at` against
`valid_from`; key-identifier membership alone is insufficient. Admission tries
the frozen pre-recovery and opening sets independently. Settlement returns
signature-eligible survivors in acceptance order and rejected queued copies;
it establishes no Payload availability, quota eligibility or Block inclusion.
A rejected Delta ID is not permanently barred. History restoration, due-process
admission and durable queue/status effects remain service responsibilities.
The settlement conformance fixtures restrict timestamp comparisons to
whole-second literal-Z values; their callback is not a general RFC 3339 parser.

`declarations::Declarations` replays Declarations Block by Block: the
accepted Declaration and sequence floor per domain, recovery windows with
their owner, chain head, pre-recovery source and competitors, settlement at
the frozen window end, identity resets and per-Block installation effects.
An adoption entry seeds a domain and an open window from Snapshot state.

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
