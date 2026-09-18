# wist-core

The signed Delta format targets [WIST specification revision `1f37876a2792b042ddd2b782edebb56560f51c9d`](https://github.com/wistprotocol/spec/tree/1f37876a2792b042ddd2b782edebb56560f51c9d). Object version `1.0.0` alone does not identify a compatible draft.

Delta Envelopes require a canonical `publisher` inside the signed and hashed object. The typed object and `delta::publisher` reject missing or noncanonical identities without rewriting signed bytes. Signature/key-history and `(publisher, url)` chain validation remain caller obligations.

Rust implementation of the WIST Protocol's primitives: JCS canonicalization,
Ed25519 envelopes, delta identity, Key Set resolution, chain tips, the
Logbook's RFC 6962 Merkle tree with its Inclusion and Consistency Proofs,
C2SP Checkpoints with their Witness Cosignatures, the tiles and entry
bundles the tree is served as, Block verification against a Checkpoint,
snapshot digests and state tuples, WIST-2 link/text extraction, the WIST-1
§5.2 Declaration and recovery-window replay, and the WIST-4 Parameter
Registry with its schedule replay. The [specification](../spec/README.md)
defines conformance; `crates/wist-core/tests/conformance.rs` exercises its
vectors.

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

## The Logbook's tree, Checkpoints and tiles

`merkle` is RFC 6962 over SHA-256 (WIST-3 §4): `leaf_hash`, `node_hash`,
`merkle_root` over leaf hashes at any size with `EMPTY_ROOT` =
`SHA-256("")` for the empty tree, `inclusion_proof`/`verify_inclusion` with
every §4 rejection, and `consistency_proof`/`verify_consistency` under RFC
9162 §2.1.4.2, where a stated size of zero must carry `EMPTY_ROOT` on
either side of the proof. The same roots and proofs are computed from stored hashes
through the `HashReader` trait — `node(level, index)` is the root of the
complete subtree over `[index·2^level, (index+1)·2^level)` — by
`root_from`, `inclusion_proof_from` and `consistency_proof_from`, so a
party holding tiles rather than every leaf gets identical values;
`LeafHashes` reads a leaf-hash slice, `Extended` and `root_after_appending`
read a prior tree plus the leaves a Block appends.

`checkpoint::Checkpoint` is the five-line signed note of WIST-3 §5.
`parse` rejects every octet-level departure as `WIST3-E03`; `note_text`
and `encode` re-emit it byte for byte; `new`, `sign` and `add_signature`
build one and append further signature lines — a rotation's second key, or
a Cosignature a Witness returned — without changing the note text.
`aggregator_key_id`, `witness_key_id` and `verifier_key` derive the
[signed-note] key IDs of §3.4 and the verifier-key string a Witness is
configured with; `cosignature_line` and `verify_cosignature` are
[tlog-cosignature] v1. `verify` takes the Aggregator keys valid at the
Checkpoint's height and the Consumer's trusted Witness roster, ignores
every line naming neither, rejects the Checkpoint when a line naming a
known key fails, requires at least one Aggregator signature, and returns
the `key_id`s that signed with the distinct Witness names that cosigned;
`adoption` applies `checkpoint_witness_quorum` to those names and reports
an acceptance with no trusted Cosignature as unwitnessed. `progression`
is §5's rollback rule, `equivocation` and `prefix_equivocation` its three
equivocation forms, `check_sequence` §3.1's Block-to-Block rules
(sequential number, a tree that never shrinks, a strictly increasing
`sealed_at` on the cadence grid), `check_consistency` the Consistency
Proof between two Checkpoints, and `archive_path`/`check_archive_path`
§6's per-Block archive path. A tree below the previous Checkpoint's size
is the §5 divergence `WIST3-E02`, in `check_sequence` and in
`block::verify_block`; the other sequence failures carry no code.

`tiles` is the [tlog-tiles] surface (WIST-3 §6): `Tile` and `Bundle` with
their paths, including the `x`-prefixed three-digit groups above index
999 and the `.p/<W>` partial widths; `required_tiles`/`required_bundles`
for a tree size and `tiles_for_range`/`bundles_for_range` for a Block's
leaves; `encode_tile`/`decode_tile` and
`encode_entry_bundle`/`decode_entry_bundle`, which reject a truncated
Entry or octets left over; `TileSet`, which builds and serves a tree's
tiles and reads them back as a `HashReader`; `check_tree` and
`check_bundle`, which verify served octets by recomputation against a
verified Checkpoint's root; and the `TILE_MAX_BYTES`,
`ENTRY_BUNDLE_MAX_BYTES` and `ENTRY_MAX_BYTES` bounds a Consumer stops
reading at, equality permitted.

`block::verify_block` checks a Block's Entries against Checkpoint N: the
five Entry types, the canonical order, each Entry's JCS within 65 535
octets, the Block's entry-bundle octets against the cap in force, and that
the leaf hashes occupy `[size(N-1), size(N))` in the tree whose root the
Checkpoint states, recomputed from the prefix already verified.
`sort_entries` puts Entries in that canonical order, `block_octets` sizes a
Block and `parse_entries` reads an entry bundle's leaf data back into
Entries. `snapshot::check_manifest_anchor` is WIST-3 §8 step 5, where a
Snapshot manifest that names another tree than the Checkpoint at its
`block_number` is `WIST3-E02`.

## Registry Updates

`objects::RegistryUpdate` carries the five WIST-4 §3 governance acts.
`typed_details` parses `details` under the act's §5.1 contract and checks
the `subject` shape, key fields, parameter identifier and bounds, and the
withdrawal's Delta ID and Canonical Host, and the suffix-list snapshot's
identifier and byte count; a violation is WIST4-E04.
`aggregator_keys::authenticate` verifies one act's Envelope against an
explicit key set, naming its signer by `sig.key_id`; a failure is
WIST4-E11. The grace period and the Delta a withdrawal names remain
caller checks.

## The Aggregator key registry

`aggregator_keys::Registry` is WIST-3 §3.4's key validity by height,
shared by every party that verifies a Checkpoint or a governance act. It
holds every key the Log ever admitted — `key_id`, public key,
`added_height` and `removed_height` — built by `from_genesis` from the
Anchor's genesis key at height 0 or by `from_entries` from the WIST-3 §7
`aggregator_key` tuples, retired keys included, which `entries` writes
back. `valid_at` returns the keys a Checkpoint at a height may be signed
under: admitted at or below it and retired above it, removal being
permanent and the genesis key removable like any other;
`public_key_at` resolves one `key_id` at a height for the other acts of
that Block.

`apply_block` replays a Block's `aggregator_key_add` and
`aggregator_key_remove` acts in canonical Entry order and returns one
outcome per act. Every act is authenticated under the keys valid at the
Block before it — the genesis key alone for Block 0 — so a key admitted
in the same Block never authenticates one, and a key retired in the same
Block still does, which lets a key sign its own removal and makes the
result independent of Entry order. An act that survives authentication is
then read against every key ever admitted plus the acts already accepted
in the Block: an add naming an admitted `key_id`, an add whose note key
ID (`checkpoint::aggregator_key_id`) an admitted key already derives, and
a remove of a `key_id` not valid at the Block before are all conflicts.
An unauthenticated act is ignored as WIST4-E11 and a conflicting one
as WIST4-E04 (`KEY_ACT_CONFLICT_CODE`); either way the registry is unchanged and
the Block stays valid. Accepted acts take effect together at the Block's
own height.

## Withdrawal replay

`withdrawal::WithdrawalReplay::apply` replays one `payload_withdrawal`
act at a height under WIST-4 §5.1: raw JSON eligibility (WIST1-E05),
the field partition between WIST4-E11 and WIST4-E04, authentication
under the Log key the caller resolves for `sig.key_id` at that Block,
and the sealed-Delta contract the caller answers with `SealedDelta`
(`Known` with the signed publisher and height, `Absent`, or
`Unverifiable` for a Delta below what the party holds, which is read as
consistent). The earliest accepted withdrawal's height is kept for a
repeated act, `entries` yields the WIST-3 §7 withdrawal tuples and
`adopt` seeds the replay from tuples or a store. The conformance test
consumes `vectors/wist4/withdrawal.json`.

## Labels, disputes and definitions

`label::validate_label` checks one Label Envelope under the Labeler's
Declaration and the `url_cap_bytes` in force: fields, version, the
subject's normalization and cap, the WIST-4 §6 name form with the
`wist` terms, `expires_at` after `asserted_at`, `delta` only with a URL
subject, self-labeling against the declared scope, and the signature
under the named signing entry valid at `asserted_at`; the rejection
carries its `WIST2-E06`, `WIST1-E02` or `WIST1-E01` code.
`validate_dispute` adds the sealed-Label and subject-authority checks
and `validate_definition` the description and treatment. `label_id`,
`dispute_id` and `definition_path` derive identifiers; `current_label`
and `current_dispute` pick the current object of a triple or pair by
`asserted_at` and Log order; `label_tuple` and `dispute_tuple` yield
the WIST-3 §7 tuples, none for a retracted or expired Label;
`binding_applies` reads a Label's `delta` against a record's anchor;
`labeler_rows` computes `tier1/labelers.parquet`; `counted_at` and
`labeler_active` are WIST-4 §6's recommended default profile. The
conformance tests consume `vectors/wist2/labels.json`,
`disputes.json`, `label-definitions.json` and
`vectors/wist3/label-tables.json`.

## Suffix lists and the Registrable Domain

`suffix_list::SuffixList::parse` reads a Public Suffix List snapshot's
exact octets into rules in Canonical Host form, and `registrable_domain`
derives a Canonical Host's Registrable Domain under it by WIST-4 §3.1's
algorithm, the host itself where the list leaves none or while no
snapshot is in force. `SuffixListReplay::apply` replays a
`suffix_list_update` at a height: the field partition, the details
contract, authentication under the Log key the caller resolves, and the
named file's octet count the caller answers with; an accepted act is in
force from the Block after its sealing Block, a repeated pin of the
snapshot in force changes nothing, and `entry_at` yields the WIST-3 §7
`suffix_list` tuple. `check_block_capacity` counts a Block's
`publisher_delta`, `label` and `dispute` Entries per Registrable Domain
against `domain_block_entries_max` and its `label` and `dispute` Entries
against `labeler_block_entries_max` (WIST-3 §3.2). The conformance test
consumes `vectors/wist4/registrable-domain.json`, the Public Suffix List
project's own cases included.

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

`declarations::Declarations` replays Declarations Block by Block, each
Block named by its number and the root hash its Checkpoint states: the
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
