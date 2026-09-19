use crate::aggregator_keys::Registry;
use crate::error::Error;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Document {
    Index,
    Manifest,
    StateFile,
    MirrorList,
}

impl Document {
    pub fn inner_key(self) -> &'static str {
        match self {
            Document::Index => "index",
            Document::Manifest => "manifest",
            Document::StateFile => "state",
            Document::MirrorList => "mirrors",
        }
    }
}

impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Document::Index => "the Snapshot index",
            Document::Manifest => "the Snapshot manifest",
            Document::StateFile => "the Snapshot state file",
            Document::MirrorList => "the Mirror list",
        };
        f.write_str(name)
    }
}

pub fn verify(
    document: Document,
    envelope: &Value,
    registry: &Registry,
    height: u64,
) -> Result<(), Error> {
    let signer = envelope
        .pointer("/sig/key_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let rejected = || {
        Err(Error::UnsealedSignature {
            document,
            key_id: signer.to_owned(),
            height,
        })
    };
    let Some(public_key) = registry.public_key_at(signer, height) else {
        return rejected();
    };
    match crate::envelope::verify_envelope(envelope, document.inner_key(), &public_key) {
        Ok(()) => Ok(()),
        Err(_) => rejected(),
    }
}

pub fn verifies_at_no_height(document: Document, envelope: &Value, registry: &Registry) -> bool {
    let Some(signer) = envelope.pointer("/sig/key_id").and_then(Value::as_str) else {
        return false;
    };
    registry.record(signer).is_some_and(|record| {
        crate::envelope::verify_envelope(envelope, document.inner_key(), &record.public_key)
            .is_err()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::objects::GenesisKey;
    use serde_json::json;

    const LOG_ID: &str = "log.example.org";
    const SEALED_AT: &str = "2026-08-02T13:00:00Z";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }

    fn key_act(action: &str, signer_id: &str, signer: &SigningKey, key: &SigningKey) -> Value {
        let details = match action {
            "aggregator_key_add" => {
                json!({"key_id": "k2", "alg": "Ed25519", "public_key": key.public().to_b64u()})
            }
            _ => json!({"key_id": "k2"}),
        };
        let update = json!({
            "wist_version": "1.0.0",
            "action": action,
            "subject": "k2",
            "details": details,
            "effective_at": SEALED_AT,
        });
        crate::envelope::sign_envelope(&update, "update", signer_id, signer).unwrap()
    }

    fn registry() -> (Registry, SigningKey) {
        let genesis = signing_key(1);
        let second = signing_key(2);
        let mut registry = Registry::from_genesis(
            LOG_ID,
            &GenesisKey {
                key_id: "genesis".into(),
                alg: "Ed25519".into(),
                public_key: genesis.public().to_b64u(),
            },
        )
        .unwrap();
        registry.apply_epoch(
            1,
            &[key_act("aggregator_key_add", "genesis", &genesis, &second)],
        );
        registry.apply_epoch(
            3,
            &[key_act(
                "aggregator_key_remove",
                "genesis",
                &genesis,
                &second,
            )],
        );
        (registry, second)
    }

    fn document(kind: Document, signer_id: &str, signer: &SigningKey) -> Value {
        let inner = json!({"wist_version": "1.0.0", "updated_at": SEALED_AT});
        crate::envelope::sign_envelope(&inner, kind.inner_key(), signer_id, signer).unwrap()
    }

    #[test]
    fn a_document_verifies_under_the_keys_valid_at_the_adopted_height_alone() {
        let (registry, second) = registry();
        let index = document(Document::Index, "k2", &second);
        for height in [1, 2] {
            verify(Document::Index, &index, &registry, height).unwrap();
        }
        for height in [0, 3, 4] {
            assert!(verify(Document::Index, &index, &registry, height).is_err());
        }
    }

    #[test]
    fn a_failing_document_names_itself_its_key_and_its_height_under_one_code() {
        let (registry, second) = registry();
        for (kind, name) in [
            (Document::Index, "the Snapshot index"),
            (Document::Manifest, "the Snapshot manifest"),
            (Document::StateFile, "the Snapshot state file"),
            (Document::MirrorList, "the Mirror list"),
        ] {
            let error = verify(kind, &document(kind, "k2", &second), &registry, 3).unwrap_err();
            let message = error.to_string();
            assert!(message.contains(name), "{message}");
            assert!(message.contains("k2") && message.contains('3'), "{message}");
            assert_eq!(error.code(), Some("WIST3-E04"));
        }
    }

    #[test]
    fn a_signature_verifies_at_no_height_only_when_the_key_its_tuple_names_rejects_it() {
        let (registry, second) = registry();
        let index = document(Document::Index, "k2", &second);
        assert!(!verifies_at_no_height(Document::Index, &index, &registry));

        let mut damaged = index.clone();
        damaged["index"]["updated_at"] = json!("2026-08-02T14:00:00Z");
        assert!(verifies_at_no_height(Document::Index, &damaged, &registry));
        assert!(verify(Document::Index, &damaged, &registry, 1).is_err());

        let mut unknown_signer = index;
        unknown_signer["sig"]["key_id"] = json!("k9");
        assert!(!verifies_at_no_height(
            Document::Index,
            &unknown_signer,
            &registry
        ));
        assert!(verify(Document::Index, &unknown_signer, &registry, 1).is_err());
    }
}
