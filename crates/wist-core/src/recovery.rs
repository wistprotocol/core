use crate::objects::PublisherKey;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct WindowDeclaration {
    pub label: String,
    pub predecessor: Option<String>,
    pub signer: String,
    pub keys: Vec<PublisherKey>,
    pub recovery_keys: Vec<PublisherKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub effective_declaration: String,
    pub effective_keys: Vec<String>,
    pub superseded: Vec<String>,
    pub eligible: Vec<String>,
    pub rejected: Vec<String>,
}

pub fn admits_to_queue(
    pre_recovery_keys: &[PublisherKey],
    recovery_keys: &[PublisherKey],
    delta: &Value,
    verifies: impl Fn(&Value, &[PublisherKey]) -> bool,
) -> bool {
    verifies(delta, pre_recovery_keys) || verifies(delta, recovery_keys)
}

pub fn settle(
    recovery: &WindowDeclaration,
    window: &[WindowDeclaration],
    queued: &[(String, Value)],
    verifies: impl Fn(&Value, &[PublisherKey]) -> bool,
) -> Settlement {
    let mut head = recovery;
    let mut superseded = Vec::new();
    for declaration in window {
        if declaration.predecessor.as_ref() == Some(&head.label)
            && head
                .keys
                .iter()
                .chain(&head.recovery_keys)
                .any(|key| key.x == declaration.signer)
        {
            head = declaration;
        } else {
            superseded.push(declaration.label.clone());
        }
    }
    let mut eligible = Vec::new();
    let mut rejected = Vec::new();
    for (delta_id, delta) in queued {
        if verifies(delta, &head.keys) {
            eligible.push(delta_id.clone());
        } else {
            rejected.push(delta_id.clone());
        }
    }
    Settlement {
        effective_declaration: head.label.clone(),
        effective_keys: head.keys.iter().map(|key| key.kid.clone()).collect(),
        superseded,
        eligible,
        rejected,
    }
}
