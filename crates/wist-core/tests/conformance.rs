use std::path::PathBuf;

#[path = "conformance/aggregator_keys.rs"]
mod aggregator_keys;
#[path = "conformance/catalogs.rs"]
mod catalogs;
#[path = "conformance/collections.rs"]
mod collections;
#[path = "conformance/declarations.rs"]
mod declarations;
#[path = "conformance/item_roots.rs"]
mod item_roots;
#[path = "conformance/items.rs"]
mod items;
#[path = "conformance/key_directory.rs"]
mod key_directory;
#[path = "conformance/logbook.rs"]
mod logbook;
#[path = "conformance/parameters.rs"]
mod parameters;
#[path = "conformance/recovery.rs"]
mod recovery;
#[path = "conformance/snapshot_keys.rs"]
mod snapshot_keys;
#[path = "conformance/trees.rs"]
mod trees;

pub fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

pub fn read_json(rel: &str) -> serde_json::Value {
    let path = spec_dir().join(rel);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("invalid JSON in spec repo")
}

pub fn read_text(rel: &str) -> String {
    let path = spec_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

pub fn example_log() -> (String, wist_core::checkpoint::AggregatorKey) {
    let anchor = read_json("examples/log-anchor.json");
    let anchor = &anchor["anchor"];
    let key = wist_core::checkpoint::AggregatorKey {
        key_id: anchor["genesis_key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string(),
        public_key: wist_core::crypto::PublicKey::from_b64u(
            anchor["genesis_key"]["public_key"].as_str().unwrap(),
        )
        .unwrap(),
    };
    (anchor["log_id"].as_str().unwrap().to_string(), key)
}

pub fn entry_leaf_hashes(entries: &serde_json::Value) -> Vec<[u8; 32]> {
    entries
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .map(|entry| wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap()))
        .collect()
}

pub fn hash_list(value: &serde_json::Value) -> Vec<[u8; 32]> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|hash| {
            wist_core::crypto::hex_decode(hash.as_str().unwrap().trim_start_matches("sha256:"))
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect()
}

#[test]
fn spec_checkout_present() {
    let keys = read_json("vectors/wist1/keypair.json");
    assert_eq!(
        keys["public_key"],
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
    );
}

#[test]
fn wist1_canonical_bytes() {
    let env = read_json("vectors/wist1/envelope.json");
    let expected = std::fs::read(spec_dir().join("vectors/wist1/catalog.canonical")).unwrap();
    assert_eq!(
        wist_core::jcs::canonicalize(&env["catalog"]).unwrap(),
        expected
    );
}

#[test]
fn wist1_signature_and_deterministic_resign() {
    let env = read_json("vectors/wist1/envelope.json");
    let keys = read_json("vectors/wist1/keypair.json");
    let canonical = wist_core::jcs::canonicalize(&env["catalog"]).unwrap();

    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    wist_core::crypto::verify(&pk, &canonical, env["sig"]["value"].as_str().unwrap()).unwrap();

    let seed: [u8; 32] = wist_core::crypto::hex_decode(keys["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sk = wist_core::crypto::SigningKey::from_seed(&seed);
    assert_eq!(sk.sign(&canonical), env["sig"]["value"].as_str().unwrap());
}

#[test]
fn wist1_catalog_id() {
    let env = read_json("vectors/wist1/envelope.json");
    let expected = std::fs::read_to_string(spec_dir().join("vectors/wist1/id.txt")).unwrap();
    assert_eq!(
        wist_core::catalog::catalog_id(&env["catalog"]).unwrap(),
        expected.trim()
    );
    assert_eq!(read_json("examples/catalog.json"), env);
}

#[test]
fn verify_envelope_rejects_missing_and_tampered() {
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    let doc = read_json("examples/catalog.json");
    wist_core::envelope::verify_envelope(&doc, "catalog", &pk).unwrap();

    assert!(wist_core::envelope::verify_envelope(&doc, "delta", &pk).is_err());

    let mut no_sig_value = doc.clone();
    no_sig_value["sig"].as_object_mut().unwrap().remove("value");
    assert!(wist_core::envelope::verify_envelope(&no_sig_value, "catalog", &pk).is_err());

    let mut bad_sig = doc.clone();
    let mut sig = bad_sig["sig"]["value"].as_str().unwrap().to_owned();
    let flipped = if sig.ends_with('A') { 'B' } else { 'A' };
    sig.replace_range(sig.len() - 1.., &flipped.to_string());
    bad_sig["sig"]["value"] = sig.into();
    assert!(wist_core::envelope::verify_envelope(&bad_sig, "catalog", &pk).is_err());

    let mut tampered_field = doc.clone();
    tampered_field["catalog"]["size"] = 2.into();
    assert!(wist_core::envelope::verify_envelope(&tampered_field, "catalog", &pk).is_err());

    let other = wist_core::crypto::SigningKey::from_seed(&[9u8; 32]).public();
    assert!(wist_core::envelope::verify_envelope(&doc, "catalog", &other).is_err());
}

#[test]
fn example_payload_reproduces_the_example_items_commitment() {
    let payload = read_json("examples/payload.json");
    let item = read_json("examples/item.json");
    let page: wist_core::objects::PageItem = serde_json::from_value(item.clone()).unwrap();
    let salt = payload["salt"].as_str().unwrap();
    assert_eq!(
        wist_core::item::commitment(salt, &payload["content"]).unwrap(),
        page.payload.commitment
    );
    wist_core::item::judge_payload(&page, &payload, &wist_core::item::SizeCaps::suite()).unwrap();

    let mut tampered = payload.clone();
    let extract = tampered["content"]["extract"].as_str().unwrap().to_owned() + "x";
    tampered["content"]["extract"] = extract.into();
    assert_ne!(
        wist_core::item::commitment(salt, &tampered["content"]).unwrap(),
        page.payload.commitment
    );
    assert_eq!(
        wist_core::item::judge_payload(&page, &tampered, &wist_core::item::SizeCaps::suite()),
        Err("WIST1-E10")
    );
    assert!(wist_core::item::commitment("AAAA", &payload["content"]).is_err());
}

#[test]
fn catalog_and_item_examples_parse_typed() {
    use wist_core::objects as o;
    let envelope: o::CatalogEnvelope =
        serde_json::from_value(read_json("examples/catalog.json")).unwrap();
    assert_eq!(envelope.catalog.size, 1);
    let item: o::Item = serde_json::from_value(read_json("examples/item.json")).unwrap();
    assert!(matches!(item, o::Item::Page(_)));
    let _: o::Payload = serde_json::from_value(read_json("examples/payload.json")).unwrap();
}

#[test]
fn typed_catalogs_and_items_deny_unknown_members() {
    use wist_core::objects as o;
    let mut catalog = read_json("examples/catalog.json");
    catalog["catalog"]["items"] = serde_json::json!([]);
    assert!(serde_json::from_value::<o::CatalogEnvelope>(catalog).is_err());

    let mut envelope = read_json("examples/catalog.json");
    envelope["surprise"] = 1.into();
    assert!(serde_json::from_value::<o::CatalogEnvelope>(envelope).is_err());

    for (path, member) in [
        ("", "change_type"),
        ("/payload", "salt"),
        ("/meta", "title"),
    ] {
        let mut item = read_json("examples/item.json");
        item.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(member.into(), 1.into());
        assert!(serde_json::from_value::<o::Item>(item).is_err(), "{member}");
    }

    let mut removed = serde_json::json!({
        "publisher": "example.com",
        "url": "https://example.com/blog/post-1",
        "observed_at": "2026-08-02T12:00:00Z",
        "removed": true
    });
    assert!(matches!(
        serde_json::from_value::<o::Item>(removed.clone()).unwrap(),
        o::Item::Removed(_)
    ));
    removed["meta"] = serde_json::json!({"lang": "en"});
    assert!(serde_json::from_value::<o::Item>(removed).is_err());
}

#[test]
fn typed_catalogs_and_items_require_members_and_refuse_null_optionals() {
    use wist_core::objects as o;
    for member in ["size", "root", "tree", "generated_at"] {
        let mut catalog = read_json("examples/catalog.json");
        catalog["catalog"].as_object_mut().unwrap().remove(member);
        assert!(
            serde_json::from_value::<o::CatalogEnvelope>(catalog).is_err(),
            "{member}"
        );
    }
    for member in ["payload", "meta", "observed_at"] {
        let mut item = read_json("examples/item.json");
        item.as_object_mut().unwrap().remove(member);
        assert!(serde_json::from_value::<o::Item>(item).is_err(), "{member}");
    }
    for member in ["topics", "license"] {
        let mut item = read_json("examples/item.json");
        item["meta"][member] = serde_json::Value::Null;
        assert!(serde_json::from_value::<o::Item>(item).is_err(), "{member}");
        let mut item = read_json("examples/item.json");
        item["meta"].as_object_mut().unwrap().remove(member);
        assert!(serde_json::from_value::<o::Item>(item).is_ok(), "{member}");
    }
    let mut payload = read_json("examples/payload.json");
    payload["content"]["summary"]["abstract"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<o::Payload>(payload).is_err());
    for (removed, accepted) in [
        (serde_json::json!(true), true),
        (serde_json::json!(false), false),
        (serde_json::Value::Null, false),
    ] {
        let item = serde_json::json!({
            "publisher": "example.com",
            "url": "https://example.com/blog/post-1",
            "observed_at": "2026-08-02T12:00:00Z",
            "removed": removed
        });
        assert_eq!(serde_json::from_value::<o::Item>(item).is_ok(), accepted);
    }
}

#[test]
fn typed_integers_are_read_by_their_numeric_value() {
    use wist_core::objects as o;
    for spelling in ["263", "263.0", "2.63e2"] {
        let commitment: o::PayloadCommitment = serde_json::from_str(&format!(
            "{{\"commitment\":\"hmac-sha256:{}\",\"alg\":\"HMAC-SHA256\",\"bytes\":{spelling}}}",
            "0".repeat(64)
        ))
        .unwrap();
        assert_eq!(commitment.bytes, 263);
    }
    for spelling in ["-1", "1.5", "9007199254740992", "1e400", "\"1\""] {
        assert!(serde_json::from_str::<o::PayloadCommitment>(&format!(
            "{{\"commitment\":\"hmac-sha256:{}\",\"alg\":\"HMAC-SHA256\",\"bytes\":{spelling}}}",
            "0".repeat(64)
        ))
        .is_err());
    }
    let mut catalog = read_json("examples/catalog.json");
    catalog["catalog"]["size"] = serde_json::json!(1.0);
    let envelope: o::CatalogEnvelope = serde_json::from_value(catalog).unwrap();
    assert_eq!(envelope.catalog.size, 1);
}

#[test]
fn example_envelopes_verify() {
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    for (file, inner) in [
        ("catalog.json", "catalog"),
        ("publisher.json", "publisher"),
        ("snapshot-manifest.json", "manifest"),
        ("snapshot-index.json", "index"),
        ("snapshot-state.json", "state"),
        ("registry-update.json", "update"),
        ("log-anchor.json", "anchor"),
        ("label.json", "label"),
        ("label-feed.json", "feed"),
        ("label-definition.json", "definition"),
    ] {
        let doc = read_json(&format!("examples/{file}"));
        wist_core::envelope::verify_envelope(&doc, inner, &pk)
            .unwrap_or_else(|e| panic!("{file}: {e}"));
    }
}

#[test]
fn wist3_merkle_vectors() {
    let epoch = read_json("vectors/wist3/epoch.json");
    let leaves = entry_leaf_hashes(&epoch["entries"]);
    let root = wist_core::merkle::merkle_root(&leaves);
    assert_eq!(
        format!("sha256:{}", wist_core::crypto::hex_encode(&root)),
        epoch["root"].as_str().unwrap()
    );
    assert_eq!(leaves, hash_list(&epoch["leaf_hashes"]));

    let checkpoint =
        wist_core::checkpoint::Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
    assert_eq!(checkpoint.tree_size(), epoch["tree_size"].as_u64().unwrap());
    assert_eq!(*checkpoint.root(), root);

    let proof = read_json("vectors/wist3/inclusion-proof.json");
    let index = proof["index"].as_u64().unwrap();
    let tree_size = proof["tree_size"].as_u64().unwrap();
    assert_eq!(tree_size, epoch["tree_size"].as_u64().unwrap());
    let path = hash_list(&proof["path"]);
    checkpoint
        .verify_inclusion(&leaves[index as usize], index, tree_size, &path)
        .unwrap();
    assert_eq!(
        wist_core::merkle::inclusion_proof(index, &leaves).unwrap(),
        path
    );
    assert!(checkpoint
        .verify_inclusion(&leaves[index as usize], index, tree_size + 1, &path)
        .is_err());
}

#[test]
fn the_example_checkpoint_states_the_example_epochs_tree() {
    let (log_id, key) = example_log();
    let note = read_text("examples/checkpoint.txt");
    let epoch = read_json("vectors/wist3/epoch.json");
    assert_eq!(note, epoch["checkpoint"].as_str().unwrap());

    let checkpoint = wist_core::checkpoint::Checkpoint::parse(&note).unwrap();
    assert_eq!(checkpoint.encode(), note);
    let verification =
        wist_core::checkpoint::verify(&checkpoint, &log_id, std::slice::from_ref(&key), &[])
            .unwrap();
    assert_eq!(verification.signers, [key.key_id.clone()].into());
    assert!(verification.cosigners.is_empty());
    assert_eq!(checkpoint.epoch_number(), 0);

    let entries: Vec<serde_json::Value> = epoch["entries"].as_array().unwrap().clone();
    let summary = wist_core::epoch::verify_epoch(
        0,
        &checkpoint,
        &entries,
        &wist_core::merkle::LeafHashes(&[]),
        268_435_456,
    )
    .unwrap();
    assert_eq!(summary.leaf_hashes, entry_leaf_hashes(&epoch["entries"]));
}

#[test]
fn an_epochs_entries_must_fill_the_leaf_range_its_checkpoint_states() {
    let (_, _) = example_log();
    let epoch = read_json("vectors/wist3/epoch.json");
    let checkpoint =
        wist_core::checkpoint::Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
    let mut entries: Vec<serde_json::Value> = epoch["entries"].as_array().unwrap().clone();
    entries.pop();
    let err = wist_core::epoch::verify_epoch(
        0,
        &checkpoint,
        &entries,
        &wist_core::merkle::LeafHashes(&[]),
        268_435_456,
    )
    .unwrap_err();
    assert_eq!(err.code(), Some("WIST3-E03"));

    let mut swapped: Vec<serde_json::Value> = epoch["entries"].as_array().unwrap().clone();
    swapped.swap(0, 1);
    let err = wist_core::epoch::verify_epoch(
        0,
        &checkpoint,
        &swapped,
        &wist_core::merkle::LeafHashes(&[]),
        268_435_456,
    )
    .unwrap_err();
    assert_eq!(err.code(), Some("WIST3-E03"));
}

#[test]
#[ignore = "vectors/wist3/snapshot-records.json"]
fn wist3_snapshot_records_digest() {
    let v = read_json("vectors/wist3/snapshot-records.json");
    let records: Vec<_> = v["records"].as_array().unwrap().clone();
    for r in &records {
        wist_core::snapshot::check_record_shape(r).unwrap();
    }
    let digest = wist_core::snapshot::content_digest(&records).unwrap();
    assert_eq!(digest, v["content_digest"].as_str().unwrap());

    let mut reversed = records.clone();
    reversed.reverse();
    assert_eq!(
        wist_core::snapshot::content_digest(&reversed).unwrap(),
        digest
    );

    let manifest = read_json("examples/snapshot-manifest.json");
    assert_eq!(
        manifest["manifest"]["content_digest"].as_str().unwrap(),
        digest
    );
}

#[test]
fn state_digest_matches_manifest() {
    let state = read_json("examples/snapshot-state.json");
    let manifest = read_json("examples/snapshot-manifest.json");
    let entries: Vec<_> = state["state"]["entries"].as_array().unwrap().clone();
    assert_eq!(
        wist_core::snapshot::state_digest(&entries).unwrap(),
        manifest["manifest"]["state"]["state_digest"]
            .as_str()
            .unwrap()
    );
}

#[test]
#[ignore = "examples/snapshot-state.json"]
fn every_example_parses_typed() {
    use wist_core::objects as o;
    fn p<T: serde::de::DeserializeOwned>(file: &str) -> T {
        let bytes = std::fs::read(spec_dir().join("examples").join(file)).unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"))
    }
    let _: o::PublisherEnvelope = p("publisher.json");
    let _: o::LogAnchorEnvelope = p("log-anchor.json");
    let _: o::SnapshotIndexEnvelope = p("snapshot-index.json");
    let _: o::SnapshotManifestEnvelope = p("snapshot-manifest.json");
    let _: o::SnapshotStateEnvelope = p("snapshot-state.json");
    let _: o::Status = p("status.json");
    let _: o::Payload = p("payload.json");
    let _: o::RegistryUpdateEnvelope = p("registry-update.json");
    let _: o::LabelEnvelope = p("label.json");
    let _: o::FeedEnvelope = p("label-feed.json");
    let _: o::DisputeEnvelope = p("dispute.json");
    let _: o::LabelDefinitionEnvelope = p("label-definition.json");
}

#[test]
fn state_tuple_over_arity_rejected() {
    let mut doc = read_json("examples/snapshot-state.json");
    doc["state"]["entries"][1]
        .as_array_mut()
        .unwrap()
        .push("extra".into());
    let res: Result<wist_core::objects::SnapshotStateEnvelope, _> = serde_json::from_value(doc);
    assert!(res.is_err());
}

#[test]
#[ignore = "vectors/wist2/link-extraction.json"]
fn wist2_link_extraction_vector() {
    let vec = read_json("vectors/wist2/link-extraction.json");
    let cap = vec["links_cap_bytes"].as_u64().unwrap() as usize;
    for case in vec["cases"].as_array().unwrap() {
        let html = wist_core::crypto::hex_decode(case["html_hex"].as_str().unwrap()).unwrap();
        let (urls, total) = wist_core::extract::extract_links(
            &html,
            case["base_url"].as_str().unwrap(),
            case["publisher_domain"].as_str().unwrap(),
        );
        let member = wist_core::extract::links_member(&urls, total, cap);
        assert_eq!(member, case["expected"], "{}", case["label"]);
    }
}

#[test]
#[ignore = "vectors/wist2/text-extraction.json"]
fn wist2_text_extraction_vector() {
    let vec = read_json("vectors/wist2/text-extraction.json");
    for case in vec["extraction"].as_array().unwrap() {
        let html = wist_core::crypto::hex_decode(case["html_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            wist_core::extract::extract_text(&html),
            case["expected"].as_str().unwrap(),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn manifest_anchored_to_the_checkpoint_at_its_epoch() {
    let manifest: wist_core::objects::SnapshotManifestEnvelope =
        serde_json::from_value(read_json("examples/snapshot-manifest.json")).unwrap();
    let checkpoint =
        wist_core::checkpoint::Checkpoint::parse(&read_text("examples/checkpoint.txt")).unwrap();
    wist_core::snapshot::check_manifest_anchor(&manifest.manifest, &checkpoint).unwrap();

    let mut moved = manifest.manifest.clone();
    moved.tree_size += 1;
    assert_eq!(
        wist_core::snapshot::check_manifest_anchor(&moved, &checkpoint)
            .unwrap_err()
            .code(),
        Some("WIST3-E02")
    );
}

#[test]
fn wist1_host_canonicalization() {
    let v = read_json("vectors/wist1/host-canonicalization.json");
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let got = wist_core::host::canonical_host(input);
        match case["expected"].as_str() {
            Some(expected) => assert_eq!(got.as_deref().ok(), Some(expected), "{name}"),
            None => assert!(
                got.is_err(),
                "{name}: expected no canonicalization, got {got:?}"
            ),
        }
    }
}

#[test]
fn wist1_declaration_host_spelling() {
    let vector = read_json("vectors/wist1/declaration-hosts.json");
    for case in vector["hosts"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let canonical = wist_core::host::canonical_host(input);
        assert_eq!(
            canonical.as_deref().ok(),
            case["canonical"].as_str(),
            "{}",
            case["name"]
        );
        assert_eq!(
            canonical.as_deref().ok() == Some(input),
            case["expected"] == "well_formed",
            "{}",
            case["name"]
        );
    }
    let author =
        wist_core::crypto::PublicKey::from_b64u(vector["author_key"].as_str().unwrap()).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let envelope = &case["envelope"];
        let publisher = &envelope["publisher"];
        let bytes = wist_core::jcs::canonicalize(publisher).unwrap();
        wist_core::crypto::verify(&author, &bytes, envelope["sig"]["value"].as_str().unwrap())
            .unwrap();
        let valid = std::iter::once(publisher["domain"].as_str().unwrap())
            .chain(
                publisher["subdomain_scope"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap()),
            )
            .all(|host| wist_core::host::canonical_host(host).as_deref().ok() == Some(host));
        assert_eq!(valid, case["expected"] == "initial", "{}", case["name"]);
    }
}

#[test]
fn wist1_ed25519_verification_profile() {
    let v = read_json("vectors/wist1/ed25519-strictness.json");
    let msg = wist_core::crypto::hex_decode(v["message_hex"].as_str().unwrap()).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let key_raw =
            wist_core::crypto::hex_decode(case["public_key_hex"].as_str().unwrap()).unwrap();
        let sig_raw =
            wist_core::crypto::hex_decode(case["signature_hex"].as_str().unwrap()).unwrap();
        let sig_b64u = wist_core::crypto::b64u_encode(&sig_raw);
        let accepted = match wist_core::crypto::PublicKey::from_b64u(
            &wist_core::crypto::b64u_encode(&key_raw),
        ) {
            Ok(pk) => wist_core::crypto::verify(&pk, &msg, &sig_b64u).is_ok(),
            Err(_) => false,
        };
        let expected = case["expected"].as_str().unwrap() == "accept";
        assert_eq!(accepted, expected, "{name}");
    }
}

#[test]
fn wist3_empty_epoch_restates_the_tree_before_it() {
    use wist_core::checkpoint::Checkpoint;
    let v = read_json("vectors/wist3/empty-epoch.json");
    let (log_id, key) = example_log();

    assert_eq!(v["empty_tree_size"].as_u64().unwrap(), 0);
    assert_eq!(
        hash_list(&serde_json::json!([v["empty_tree_root"]]))[0],
        wist_core::merkle::EMPTY_ROOT,
        "the empty tree's root is RFC 6962's MTH of the empty sequence"
    );
    assert_eq!(
        wist_core::merkle::merkle_root(&[]),
        wist_core::merkle::EMPTY_ROOT
    );

    let epoch0 = read_json("vectors/wist3/epoch.json");
    let previous = Checkpoint::parse(epoch0["checkpoint"].as_str().unwrap()).unwrap();
    let empty = Checkpoint::parse(v["epoch_1"]["checkpoint"].as_str().unwrap()).unwrap();
    for checkpoint in [&previous, &empty] {
        wist_core::checkpoint::verify(checkpoint, &log_id, std::slice::from_ref(&key), &[])
            .unwrap();
    }
    assert!(v["epoch_1"]["entries"].as_array().unwrap().is_empty());
    assert_eq!(empty.tree_size(), previous.tree_size());
    assert_eq!(empty.root(), previous.root());
    assert_eq!(empty.root_token(), v["epoch_0_root"].as_str().unwrap());
    wist_core::checkpoint::check_sequence(Some(&previous), &empty, 3600).unwrap();

    let leaves = entry_leaf_hashes(&epoch0["entries"]);
    wist_core::epoch::verify_epoch(
        previous.tree_size(),
        &empty,
        &[],
        &wist_core::merkle::LeafHashes(&leaves),
        268_435_456,
    )
    .unwrap();
    assert!(v["consistency_proof_4_to_4"].as_array().unwrap().is_empty());
    wist_core::checkpoint::check_consistency(&previous, &empty, &[]).unwrap();
}

fn string_list(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn wist1_keyset_at_height_vectors() {
    use wist_core::keyset::{key_set_at, verifies_at, SealedDeclaration};

    let vector = read_json("vectors/wist1/keyset-at-height.json");
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let declarations: Vec<SealedDeclaration> = case["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| SealedDeclaration {
                seq: d["seq"].as_u64().unwrap(),
                height: d["height"].as_u64().unwrap(),
                keys: string_list(&d["keys"]),
            })
            .collect();
        let expected = &case["expected"];

        for row in expected["key_set_at"].as_array().unwrap() {
            let height = row["height"].as_u64().unwrap();
            assert_eq!(
                key_set_at(&declarations, height),
                string_list(&row["keys"]),
                "{name}: key set at height {height}"
            );
        }

        let mut verifies = Vec::new();
        let mut rejected = Vec::new();
        for catalog in case["catalogs"].as_array().unwrap() {
            let catalog_id = catalog["catalog_id"].as_str().unwrap().to_string();
            let height = catalog["height"].as_u64().unwrap();
            let signer = catalog["signer"].as_str().unwrap();
            if verifies_at(&declarations, height, signer) {
                verifies.push(catalog_id);
            } else {
                rejected.push(catalog_id);
            }
        }
        assert_eq!(
            verifies,
            string_list(&expected["verifies"]),
            "{name}: verifies"
        );
        assert_eq!(
            rejected,
            string_list(&expected["rejected"]),
            "{name}: rejected"
        );
    }
}

#[test]
fn wist2_page_keyset_vectors() {
    use wist_core::keyset::{
        page_key_set_current, page_key_set_next, page_resolution, DeclarationAtInstant,
        PageResolution,
    };

    let vector = read_json("vectors/wist2/page-keyset.json");
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let declarations: Vec<DeclarationAtInstant> = case["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| DeclarationAtInstant {
                seq: d["seq"].as_u64().unwrap(),
                sealed_at_s: d["sealed_at_s"].as_i64().unwrap(),
                keys: string_list(&d["keys"]),
            })
            .collect();
        let pages = case["pages"].as_array().unwrap();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(pages.len(), expected.len(), "{name}: one row per page");

        for (page, row) in pages.iter().zip(expected) {
            let number = page["page"].as_u64().unwrap();
            assert_eq!(row["page"].as_u64().unwrap(), number, "{name}: row order");
            let generated_at_s = page["generated_at_s"].as_i64().unwrap();
            let signer = page["signer"].as_str().unwrap();

            assert_eq!(
                page_key_set_current(&declarations, generated_at_s),
                string_list(&row["current_keys"]),
                "{name}: page {number} current key set"
            );
            assert_eq!(
                page_key_set_next(&declarations, generated_at_s),
                string_list(&row["next_keys"]),
                "{name}: page {number} next key set"
            );

            let resolution = page_resolution(&declarations, generated_at_s, signer);
            let expected_under = match row["verifies_under"].as_str() {
                Some("current") => Some(PageResolution::Current),
                Some("next") => Some(PageResolution::Next),
                Some(other) => panic!("{name}: unknown resolution {other}"),
                None => None,
            };
            assert_eq!(
                resolution, expected_under,
                "{name}: page {number} verifies under"
            );
            assert_eq!(
                resolution.is_some(),
                row["verifies"].as_bool().unwrap(),
                "{name}: page {number} verifies"
            );
        }
    }
}

#[test]
#[ignore = "vectors/wist4/withdrawal.json"]
fn wist4_withdrawal_vectors() {
    use wist_core::withdrawal::{Disposition, SealedDelta, WithdrawalReplay};
    let vector = read_json("vectors/wist4/withdrawal.json");
    let log_key =
        wist_core::crypto::PublicKey::from_b64u(vector["log_key"]["public_key"].as_str().unwrap())
            .unwrap();
    let log_key_id = vector["log_key"]["key_id"].as_str().unwrap();
    let sealed: Vec<(String, String, u64)> = vector["sealed_deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["delta_id"].as_str().unwrap().into(),
                d["publisher"].as_str().unwrap().into(),
                d["height"].as_u64().unwrap(),
            )
        })
        .collect();
    let mut replay = WithdrawalReplay::new();
    let mut codes = std::collections::BTreeSet::new();
    for case in vector["act_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let disposition = replay.apply_raw(
            case["height"].as_u64().unwrap(),
            case["envelope_json"].as_str().unwrap().as_bytes(),
            |key_id| (key_id == log_key_id).then(|| log_key.clone()),
            |delta_id| {
                sealed.iter().find(|(id, _, _)| id == delta_id).map_or(
                    SealedDelta::Absent,
                    |(_, publisher, height)| SealedDelta::Known {
                        publisher: publisher.clone(),
                        height: *height,
                    },
                )
            },
        );
        match disposition {
            Disposition::Accepted {
                withdrawn_height, ..
            } => {
                assert!(case["code"].is_null(), "{label}");
                assert_eq!(
                    Some(withdrawn_height),
                    case["withdrawn_height"].as_u64(),
                    "{label}"
                );
                codes.insert(None);
            }
            Disposition::Rejected(code) => {
                assert_eq!(Some(code), case["code"].as_str(), "{label}");
                assert!(case["withdrawn_height"].is_null(), "{label}");
                codes.insert(Some(code));
            }
            Disposition::NotWithdrawal => panic!("{label}: not a withdrawal"),
        }
    }
    assert_eq!(
        codes,
        [None, Some("WIST4-E11"), Some("WIST4-E04")]
            .into_iter()
            .collect()
    );
    let tuples: Vec<serde_json::Value> = replay
        .entries()
        .into_iter()
        .map(|entry| {
            serde_json::to_value(wist_core::objects::StateEntry::Withdrawal(entry)).unwrap()
        })
        .collect();
    let mut expected = vector["state_tuples"].as_array().unwrap().clone();
    expected.sort_by_key(|t| t.to_string());
    let mut got = tuples;
    got.sort_by_key(|t| t.to_string());
    assert_eq!(got, expected);
    let mut resumed = WithdrawalReplay::new();
    for entry in replay.entries() {
        resumed.adopt(&entry.delta_id, &entry.publisher, entry.sealing_height);
    }
    assert_eq!(resumed.entries().len(), replay.entries().len());
    let mut records: Vec<serde_json::Value> = vector["sealed_deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            serde_json::to_value(wist_core::objects::StateEntry::Record(
                wist_core::objects::RecordEntry {
                    publisher: d["publisher"].as_str().unwrap().into(),
                    url: d["url"].as_str().unwrap().into(),
                    delta_id: d["delta_id"].as_str().unwrap().into(),
                },
            ))
            .unwrap()
        })
        .collect();
    records.sort_by_key(|t| t.to_string());
    let mut expected_records = vector["record_tuples"].as_array().unwrap().clone();
    expected_records.sort_by_key(|t| t.to_string());
    assert_eq!(records, expected_records);
    let materialized: Vec<&str> = vector["sealed_deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["delta_id"].as_str().unwrap())
        .filter(|id| !replay.is_withdrawn(id))
        .collect();
    let expected_materialized: Vec<&str> = vector["materialized"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(materialized, expected_materialized);
    let resume = &vector["resume"];
    let mut resumed = WithdrawalReplay::new();
    for tuple in resume["adopted"].as_array().unwrap() {
        resumed.adopt(
            tuple[1].as_str().unwrap(),
            tuple[2].as_str().unwrap(),
            tuple[3].as_u64().unwrap(),
        );
    }
    let walked: Vec<(String, String, u64)> = resume["walked_deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["delta_id"].as_str().unwrap().into(),
                d["publisher"].as_str().unwrap().into(),
                d["height"].as_u64().unwrap(),
            )
        })
        .collect();
    for case in resume["act_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let disposition = resumed.apply_raw(
            case["height"].as_u64().unwrap(),
            case["envelope_json"].as_str().unwrap().as_bytes(),
            |key_id| (key_id == log_key_id).then(|| log_key.clone()),
            |delta_id| {
                walked.iter().find(|(id, _, _)| id == delta_id).map_or(
                    SealedDelta::Unverifiable,
                    |(_, publisher, height)| SealedDelta::Known {
                        publisher: publisher.clone(),
                        height: *height,
                    },
                )
            },
        );
        match disposition {
            Disposition::Accepted {
                withdrawn_height, ..
            } => {
                assert!(case["code"].is_null(), "{label}");
                assert_eq!(
                    Some(withdrawn_height),
                    case["withdrawn_height"].as_u64(),
                    "{label}"
                );
            }
            Disposition::Rejected(code) => assert_eq!(Some(code), case["code"].as_str(), "{label}"),
            Disposition::NotWithdrawal => panic!("{label}: not a withdrawal"),
        }
    }
    let mut resumed_tuples: Vec<serde_json::Value> = resumed
        .entries()
        .into_iter()
        .map(|entry| {
            serde_json::to_value(wist_core::objects::StateEntry::Withdrawal(entry)).unwrap()
        })
        .collect();
    resumed_tuples.sort_by_key(|t| t.to_string());
    let mut expected_resumed = resume["state_tuples"].as_array().unwrap().clone();
    expected_resumed.sort_by_key(|t| t.to_string());
    assert_eq!(resumed_tuples, expected_resumed);
    assert_eq!(
        replay.apply_raw(
            9,
            br#"{"update": {"wist_version": "1.0.0", "action": "parameter_change", "subject": "quota_base", "effective_at": "2026-08-05T12:00:00Z", "details": {"parameter": "quota_base", "value": 2}}, "sig": {"key_id": "x", "alg": "Ed25519", "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
            |_| None,
            |_| SealedDelta::Absent
        ),
        Disposition::NotWithdrawal
    );
    let duplicate = br#"{"update": {"a": 1, "a": 2}, "sig": {}}"#;
    assert_eq!(
        replay.apply_raw(9, duplicate, |_| None, |_| SealedDelta::Absent),
        Disposition::Rejected("WIST1-E05")
    );
}

#[test]
fn wist4_parameter_in_force_vectors() {
    use wist_core::parameters::{value_in_force, ParameterChange};

    let vector = read_json("vectors/wist4/parameter-in-force.json");
    for case in vector["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let default = case["default"].as_i64().unwrap();
        let changes: Vec<ParameterChange> = case["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| ParameterChange {
                epoch_number: c["epoch_number"].as_u64().unwrap(),
                entry_index: c["entry_index"].as_u64().unwrap(),
                effective_at_s: c["effective_at_s"].as_i64().unwrap(),
                value: c["value"].as_i64().unwrap(),
            })
            .collect();

        for query in case["queries"].as_array().unwrap() {
            let t_s = query["t_s"].as_i64().unwrap();
            let expected_value = query["value"].as_i64().unwrap();
            let expected_from = query["from_index"].as_u64().map(|i| i as usize);
            assert_eq!(
                value_in_force(default, &changes, t_s),
                (expected_value, expected_from),
                "{label}: value in force at {t_s}"
            );
        }
    }
}

fn parameter_default(name: &str) -> i64 {
    wist_core::parameters::spec(name).unwrap().default.unwrap()
}

#[test]
fn wist4_parameter_catalog() {
    use wist_core::parameters::{spec, validate_value, PARAMS, WIRE_INTEGER_MAX};
    let schema = read_json("schemas/registry-update.schema.json");
    let clause = schema["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["if"]["properties"]["update"]["properties"]["action"]["const"] == "parameter_change"
        })
        .unwrap();
    let details = &clause["then"]["properties"]["update"]["properties"]["details"];
    let identifiers = details["properties"]["parameter"]["enum"]
        .as_array()
        .unwrap();
    assert_eq!(PARAMS.len(), identifiers.len());
    for ident in identifiers {
        assert!(spec(ident.as_str().unwrap()).is_some(), "{ident}");
    }
    for clause in details["allOf"].as_array().unwrap() {
        let name = clause["if"]["properties"]["parameter"]["const"]
            .as_str()
            .unwrap();
        let bounds = &clause["then"]["properties"]["value"];
        let p = spec(name).unwrap();
        assert_eq!(p.min, bounds["minimum"].as_i64(), "{name}");
        assert_eq!(p.max, bounds["maximum"].as_i64(), "{name}");
    }
    for p in PARAMS {
        validate_value(p.name, p.default.unwrap()).unwrap();
        validate_value(p.name, p.min.unwrap_or(-WIRE_INTEGER_MAX)).unwrap();
        validate_value(p.name, p.max.unwrap_or(WIRE_INTEGER_MAX)).unwrap();
        assert!(validate_value(p.name, p.min.unwrap_or(-WIRE_INTEGER_MAX) - 1).is_err());
        assert!(validate_value(p.name, p.max.unwrap_or(WIRE_INTEGER_MAX) + 1).is_err());
    }
    for name in [
        "sampling_floor",
        "similarity_consistent",
        "shingle_size",
        "c_cap",
        "unknown",
    ] {
        assert!(validate_value(name, 1).is_err());
    }
    wist_core::parameters::validate_combinations(parameter_default).unwrap();
}

#[test]
#[ignore = "vectors/wist4/registrable-domain.json"]
fn wist4_registrable_domain_vectors() {
    use std::collections::BTreeMap;
    use wist_core::suffix_list::{
        check_epoch_capacity, registrable_domain, Disposition, EpochCaps, HeldFile, SuffixList,
        SuffixListReplay,
    };
    let vector = read_json("vectors/wist4/registrable-domain.json");
    let mut lists: BTreeMap<String, SuffixList> = BTreeMap::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for list in vector["lists"].as_array().unwrap() {
        let parsed = SuffixList::parse(list["text"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(parsed.identifier(), list["sha256"].as_str().unwrap());
        assert_eq!(parsed.bytes(), list["bytes"].as_u64().unwrap());
        let name = list["name"].as_str().unwrap().to_string();
        names.insert(parsed.identifier().to_string(), name.clone());
        lists.insert(name, parsed);
    }
    let name_of = |in_force: Option<(&str, u64)>| in_force.map(|(id, _)| names[id].clone());
    let list_named = |name: Option<&str>| name.map(|name| &lists[name]);
    let mut exercised = 0;
    for case in vector["official_cases"].as_array().unwrap() {
        let Some(host) = case["host"].as_str() else {
            continue;
        };
        let derived = lists["first"].registrable_domain(host);
        assert_eq!(derived.domain, case["registrable"], "{}", case["input"]);
        assert_eq!(
            derived.public_suffix, case["public_suffix"],
            "{}",
            case["input"]
        );
        exercised += 1;
    }
    assert!(exercised >= 60);
    for case in vector["domain_cases"].as_array().unwrap() {
        let derived = registrable_domain(
            case["host"].as_str().unwrap(),
            list_named(case["list"].as_str()),
        );
        assert_eq!(derived.domain, case["registrable"], "{}", case["label"]);
        assert_eq!(
            derived.public_suffix, case["public_suffix"],
            "{}",
            case["label"]
        );
    }
    let log_key =
        wist_core::crypto::PublicKey::from_b64u(vector["log_key"]["public_key"].as_str().unwrap())
            .unwrap();
    let log_key_id = vector["log_key"]["key_id"].as_str().unwrap();
    let mut replay = SuffixListReplay::new();
    let mut codes = std::collections::BTreeSet::new();
    for case in vector["act_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let height = case["height"].as_u64().unwrap();
        let doc =
            wist_core::json::parse(case["envelope_json"].as_str().unwrap().as_bytes()).unwrap();
        if let Some(consumer) = case["consumer"].as_str() {
            let mut stopped = replay.clone();
            let disposition = stopped.apply(
                height,
                &doc,
                |key_id| (key_id == log_key_id).then(|| log_key.clone()),
                |_| HeldFile::Unobtainable,
            );
            assert!(
                matches!(disposition, Disposition::Rejected(code) if code == consumer),
                "{label}: {disposition:?}"
            );
        }
        let disposition = replay.apply(
            height,
            &doc,
            |key_id| (key_id == log_key_id).then(|| log_key.clone()),
            |id| {
                names.get(id).map_or(HeldFile::Absent, |name| {
                    HeldFile::Bytes(lists[name].bytes())
                })
            },
        );
        match disposition {
            Disposition::Accepted { .. } => assert!(case["code"].is_null(), "{label}"),
            Disposition::Rejected(code) => {
                assert_eq!(Some(code), case["code"].as_str(), "{label}");
                codes.insert(code);
            }
            Disposition::NotSuffixList => panic!("{label}: not a suffix_list_update"),
        }
        assert_eq!(
            name_of(replay.in_force_after(height)).as_deref(),
            case["in_force_after"].as_str(),
            "{label}"
        );
    }
    assert_eq!(codes, ["WIST4-E11", "WIST4-E04"].into_iter().collect());
    for row in vector["in_force"].as_array().unwrap() {
        let height = row["height"].as_u64().unwrap();
        assert_eq!(
            name_of(replay.in_force_at_epoch(height)).as_deref(),
            row["list"].as_str(),
            "height {height}"
        );
    }
    let list_at_epoch =
        |height: u64| list_named(name_of(replay.in_force_at_epoch(height)).as_deref());
    for case in vector["capacity_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let cap = case["domain_epoch_entries_max"].as_u64().unwrap();
        let entries: Vec<(&str, &str)> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["type"].as_str().unwrap(), e["domain"].as_str().unwrap()))
            .collect();
        let outcome = check_epoch_capacity(
            entries,
            list_at_epoch(case["height"].as_u64().unwrap()),
            EpochCaps {
                domain_epoch_entries_max: cap,
                labeler_epoch_entries_max: cap,
            },
        );
        match case["expected"].as_str() {
            Some(code) => assert!(
                outcome
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains(code)),
                "{label}: {outcome:?}"
            ),
            None => assert!(outcome.is_ok(), "{label}: {outcome:?}"),
        }
    }
    for case in vector["quota_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let base = case["quota_base"].as_u64().unwrap();
        let mut noise: BTreeMap<String, u64> = BTreeMap::new();
        for ping in case["pings"].as_array().unwrap() {
            let at = ping["height"]
                .as_u64()
                .unwrap_or_else(|| case["height"].as_u64().unwrap());
            let unit = registrable_domain(ping["host"].as_str().unwrap(), list_at_epoch(at)).domain;
            let count = noise.entry(unit).or_default();
            let status = if *count >= base {
                429
            } else {
                if ping["noise"].as_bool().unwrap() {
                    *count += 1;
                }
                202
            };
            assert_eq!(Some(status), ping["expected"].as_u64(), "{label}: {ping}");
        }
    }
    for row in vector["state_tuples"].as_array().unwrap() {
        let tree_size = row["tree_size"].as_u64().unwrap();
        let entry = replay.entry_at(tree_size).unwrap();
        let tuple =
            serde_json::to_value(wist_core::objects::StateEntry::SuffixList(entry)).unwrap();
        assert_eq!(
            vec![tuple],
            *row["entries"].as_array().unwrap(),
            "{tree_size}"
        );
    }
}

fn vector_clock(vector: &serde_json::Value) -> (i64, i64) {
    (
        wist_core::timestamp::log_seconds(vector["clock"].as_str().unwrap()).unwrap(),
        vector["clock_skew_seconds"].as_i64().unwrap(),
    )
}

fn label_outcome(result: &Result<(), wist_core::label::Rejection>) -> &'static str {
    use wist_core::label::Rejection;
    match result {
        Ok(()) => "accepted",
        Err(Rejection::Fields) => "fields",
        Err(Rejection::Clock) => "clock",
        Err(Rejection::SelfLabel) => "self",
        Err(Rejection::Unsealed) => "unsealed",
        Err(Rejection::Authority) => "authority",
        Err(Rejection::Binding) => "binding",
        Err(Rejection::Signature) => "signature",
    }
}

#[test]
#[ignore = "vectors/wist2/labels.json"]
fn wist2_label_vectors() {
    use wist_core::label::{self, SealedLabel};
    let vector = read_json("vectors/wist2/labels.json");
    let declaration: wist_core::objects::PublisherEnvelope =
        serde_json::from_value(vector["declaration"].clone()).unwrap();
    let url_cap = vector["url_cap_bytes"].as_i64().unwrap();
    let clock = vector_clock(&vector);
    let spec = std::fs::read_to_string(spec_dir().join("specs/WIST-4-governance.md")).unwrap();
    let registry = spec
        .split("## 6. Label Registry")
        .nth(1)
        .unwrap()
        .split("## 7.")
        .next()
        .unwrap();
    let terms: Vec<&str> = registry
        .lines()
        .filter(|line| line.starts_with("| `wist:"))
        .map(|line| line[3..].split('`').next().unwrap())
        .collect();
    assert_eq!(terms, label::WIST_TERMS);
    let mut outcomes = std::collections::BTreeSet::new();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let result =
            label::validate_label(&case["envelope"], &declaration, url_cap, clock.0, clock.1)
                .map(|_| ());
        let got = label_outcome(&result);
        assert_eq!(got, case["expected"].as_str().unwrap(), "{name}");
        match result {
            Ok(()) => {
                assert!(case["code"].is_null(), "{name}");
                assert_eq!(
                    label::label_id(&case["envelope"]["label"]).unwrap(),
                    case["label_id"],
                    "{name}"
                );
            }
            Err(rejection) => {
                assert_eq!(Some(rejection.code()), case["code"].as_str(), "{name}");
                assert!(case["label_id"].is_null(), "{name}");
            }
        }
        outcomes.insert(got);
    }
    assert_eq!(outcomes.len(), 6);
    let bound = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "asserted_at at the allowance bound")
        .unwrap();
    assert_eq!(
        label_outcome(
            &label::validate_label(
                &bound["envelope"],
                &declaration,
                url_cap,
                clock.0,
                clock.1 - 1
            )
            .map(|_| ())
        ),
        "clock"
    );
    let example = read_json("examples/label.json");
    assert!(label::validate_label(&example, &declaration, url_cap, clock.0, clock.1).is_ok());
    let feed = read_json("examples/label-feed.json");
    assert_eq!(
        feed["feed"]["deltas"],
        serde_json::json!([label::label_id(&example["label"]).unwrap()])
    );
    let mut dropped = 0;
    for case in vector["current_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sealed: Vec<SealedLabel> = case["sealed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| SealedLabel {
                label: serde_json::from_value(s["label"].clone()).unwrap(),
                label_id: s["label_id"].as_str().unwrap().into(),
                height: s["height"].as_u64().unwrap(),
                entry_index: s["entry_index"].as_u64().unwrap(),
            })
            .collect();
        let current = label::current_label(&sealed).unwrap();
        assert_eq!(current.label_id, case["current"], "{name}");
        let tuple = label::label_tuple(current, case["sealed_at"].as_str().unwrap())
            .map(|t| serde_json::to_value(wist_core::objects::StateEntry::Label(t)).unwrap());
        assert_eq!(
            tuple.unwrap_or(serde_json::Value::Null),
            case["state_tuple"],
            "{name}"
        );
        dropped += usize::from(case["state_tuple"].is_null());
    }
    assert!(dropped >= 2);
    for case in vector["binding_cases"].as_array().unwrap() {
        assert_eq!(
            label::binding_applies(case["delta"].as_str(), case["record_anchor"].as_str()),
            case["applies"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn wist2_dispute_vectors() {
    use wist_core::label::{self, LabelLookup, SealedDispute};
    let vector = read_json("vectors/wist2/disputes.json");
    let clock = vector_clock(&vector);
    let sealed: Vec<(String, String)> = vector["sealed_labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["label_id"].as_str().unwrap().into(),
                l["subject"].as_str().unwrap().into(),
            )
        })
        .collect();
    let lookup = |id: &str| {
        sealed.iter().find(|(label_id, _)| label_id == id).map_or(
            LabelLookup::Absent,
            |(_, subject)| LabelLookup::Known {
                subject: subject.clone(),
            },
        )
    };
    let mut outcomes = std::collections::BTreeSet::new();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let declaration: wist_core::objects::PublisherEnvelope =
            serde_json::from_value(case["declaration"].clone()).unwrap();
        let result =
            label::validate_dispute(&case["envelope"], &declaration, lookup, clock.0, clock.1)
                .map(|_| ());
        let got = label_outcome(&result);
        assert_eq!(got, case["expected"].as_str().unwrap(), "{name}");
        match result {
            Ok(()) => assert_eq!(
                label::dispute_id(&case["envelope"]["dispute"]).unwrap(),
                case["dispute_id"],
                "{name}"
            ),
            Err(rejection) => assert_eq!(Some(rejection.code()), case["code"].as_str(), "{name}"),
        }
        outcomes.insert(got);
    }
    assert_eq!(outcomes.len(), 7);
    let example = read_json("examples/dispute.json");
    let publisher: wist_core::objects::PublisherEnvelope =
        serde_json::from_value(read_json("examples/publisher.json")).unwrap();
    assert!(label::validate_dispute(
        &example,
        &publisher,
        |_| LabelLookup::Known {
            subject: "https://example.com/blog/post-1".into()
        },
        clock.0,
        clock.1
    )
    .is_ok());
    let unsealed = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["expected"] == "unsealed")
        .unwrap();
    let authority = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["expected"] == "authority")
        .unwrap();
    for case in [unsealed, authority] {
        let declaration: wist_core::objects::PublisherEnvelope =
            serde_json::from_value(case["declaration"].clone()).unwrap();
        assert!(
            label::validate_dispute(
                &case["envelope"],
                &declaration,
                |_| LabelLookup::Unverifiable,
                clock.0,
                clock.1
            )
            .is_ok(),
            "{}",
            case["name"]
        );
    }
    for case in vector["current_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sealed: Vec<SealedDispute> = case["sealed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| SealedDispute {
                dispute: serde_json::from_value(s["dispute"].clone()).unwrap(),
                dispute_id: s["dispute_id"].as_str().unwrap().into(),
                height: s["height"].as_u64().unwrap(),
                entry_index: s["entry_index"].as_u64().unwrap(),
            })
            .collect();
        let current = label::current_dispute(&sealed).unwrap();
        assert_eq!(current.dispute_id, case["current"], "{name}");
        let tuple = serde_json::to_value(wist_core::objects::StateEntry::Dispute(
            label::dispute_tuple(current),
        ))
        .unwrap();
        assert_eq!(tuple, case["state_tuple"], "{name}");
    }
}

#[test]
fn wist2_label_definition_vectors() {
    use wist_core::label;
    let vector = read_json("vectors/wist2/label-definitions.json");
    let declaration: wist_core::objects::PublisherEnvelope =
        serde_json::from_value(vector["declaration"].clone()).unwrap();
    let mut treatments = std::collections::BTreeSet::new();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let result = label::validate_definition(&case["envelope"], &declaration);
        assert_eq!(
            result.is_ok(),
            case["expected"] == "accepted",
            "{name}: {result:?}"
        );
        match result {
            Ok(definition) => {
                treatments.insert(definition.definition.treatment);
                assert_eq!(
                    label::definition_path(&definition.definition.name),
                    case["path"],
                    "{name}"
                );
            }
            Err(_) => assert!(case["path"].is_null(), "{name}"),
        }
    }
    assert_eq!(treatments.len(), 3);
    let example = read_json("examples/label-definition.json");
    assert!(label::validate_definition(&example, &declaration).is_ok());
}

#[test]
#[ignore = "vectors/wist3/label-tables.json"]
fn wist3_label_table_vectors() {
    use wist_core::label::{self, LabelEvent, SealedLabelCount};
    use wist_core::suffix_list::{check_epoch_capacity, EpochCaps};
    let vector = read_json("vectors/wist3/label-tables.json");
    for case in vector["statistics_cases"].as_array().unwrap() {
        let rows = label::labeler_rows(case["sealed"].as_array().unwrap().iter().map(|e| {
            SealedLabelCount {
                height: e["height"].as_u64().unwrap(),
                labeler: e["labeler"].as_str().unwrap(),
                subject: e["subject"].as_str().unwrap(),
                retracted: e["retracted"].as_bool().unwrap(),
            }
        }));
        let expected: Vec<label::LabelerRow> = case["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| label::LabelerRow {
                labeler: r["labeler"].as_str().unwrap().into(),
                label_count: r["label_count"].as_u64().unwrap(),
                retraction_count: r["retraction_count"].as_u64().unwrap(),
                distinct_subjects: r["distinct_subjects"].as_u64().unwrap(),
                first_seen_height: r["first_seen_height"].as_u64().unwrap(),
            })
            .collect();
        assert_eq!(rows, expected, "{}", case["label"]);
    }
    for case in vector["cap_cases"].as_array().unwrap() {
        let entries: Vec<(&str, &str)> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["type"].as_str().unwrap(), e["domain"].as_str().unwrap()))
            .collect();
        let outcome = check_epoch_capacity(
            entries,
            None,
            EpochCaps {
                domain_epoch_entries_max: case["domain_epoch_entries_max"].as_u64().unwrap(),
                labeler_epoch_entries_max: case["labeler_epoch_entries_max"].as_u64().unwrap(),
            },
        );
        match case["expected"].as_str() {
            Some(code) => assert!(
                outcome
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains(code)),
                "{}: {outcome:?}",
                case["label"]
            ),
            None => assert!(outcome.is_ok(), "{}: {outcome:?}", case["label"]),
        }
    }
    for case in vector["persistence_cases"].as_array().unwrap() {
        let events: Vec<LabelEvent> = case["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| LabelEvent {
                height: e["height"].as_u64().unwrap(),
                asserted_at: e["asserted_at"].as_str().unwrap(),
                retracted: e["retracted"].as_bool().unwrap(),
            })
            .collect();
        let expiry = case["expires_at_height"].as_u64();
        for probe in case["probes"].as_array().unwrap() {
            assert_eq!(
                label::counted_at(&events, expiry, probe["height"].as_u64().unwrap()),
                probe["counted"].as_bool().unwrap(),
                "{}: {probe}",
                case["label"]
            );
        }
    }
    for case in vector["inactivity_cases"].as_array().unwrap() {
        assert_eq!(
            label::labeler_active(
                case["last_sealed_height"].as_u64().unwrap(),
                case["inactivity_epochs"].as_u64().unwrap(),
                case["height"].as_u64().unwrap()
            ),
            case["applies"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
    }
}

#[test]
#[ignore = "vectors/wist3/materialization-preference.json"]
fn wist3_materialization_preference_vectors() {
    let vector = read_json("vectors/wist3/materialization-preference.json");
    for case in vector["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let candidates: Vec<&str> = case["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        let materialized = wist_core::materialization::preferred(
            case["host"].as_str().unwrap(),
            case["self_declared"].as_bool().unwrap(),
            candidates,
        );
        assert_eq!(
            materialized,
            case["materialized"].as_str(),
            "{label}: materialized Publisher"
        );
    }
}

fn spec_prose(file: &str) -> String {
    read_text(&format!("specs/{file}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn spelled(octets: u64) -> String {
    let digits = octets.to_string();
    let mut groups: Vec<&str> = Vec::new();
    let mut end = digits.len();
    while end > 3 {
        groups.push(&digits[end - 3..end]);
        end -= 3;
    }
    groups.push(&digits[..end]);
    groups.reverse();
    groups.join(" ")
}

#[test]
fn suite_constants_are_the_values_the_spec_states() {
    use wist_core::constants::*;
    let publication = spec_prose("WIST-2-site-publication.md");
    for stated in [
        format!(
            "`change_list_cap_bytes` is {} octets, `change_chain_max` {} change lists and `replaced_file_seconds` {} seconds.",
            spelled(CHANGE_LIST_CAP_BYTES),
            CHANGE_CHAIN_MAX,
            spelled(REPLACED_FILE_SECONDS)
        ),
        format!(
            "{} octets of `catalog.json`;",
            spelled(CATALOG_FILE_READ_MAX_BYTES)
        ),
    ] {
        assert!(publication.contains(&stated), "{stated}");
    }
    let item_format = spec_prose("WIST-1-item-format.md");
    let stated = format!(
        "`removal_retention_days` (WIST-3 §7), {} days,",
        REMOVAL_RETENTION_DAYS
    );
    assert!(item_format.contains(&stated), "{stated}");
    let logbook = spec_prose("WIST-3-logbook-distribution.md");
    for stated in [
        format!("`removal_retention_days` is {REMOVAL_RETENTION_DAYS} in every Log"),
        format!("MUST NOT exceed {} octets", spelled(ENTRY_MAX_BYTES)),
    ] {
        assert!(logbook.contains(&stated), "{stated}");
    }
}
