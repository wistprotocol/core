use crate::objects::PublisherKey;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct WindowDeclaration {
    pub label: String,
    pub predecessor: Option<String>,
    pub signer: String,
    pub domain: String,
    pub subdomain_scope: Vec<String>,
    pub keys: Vec<PublisherKey>,
    pub recovery_keys: Vec<PublisherKey>,
}

impl WindowDeclaration {
    /// WIST-1 §3.2: the source covers the Delta's URL host and one of its own bindings verifies it.
    fn authorizes(
        &self,
        delta: &Value,
        verifies: &impl Fn(&Value, &[PublisherKey]) -> bool,
    ) -> bool {
        delta["delta"]["url"].as_str().is_some_and(|url| {
            crate::declaration::url_in_scope(url, &self.domain, &self.subdomain_scope)
        }) && verifies(delta, &self.keys)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub effective_declaration: String,
    pub effective_keys: Vec<String>,
    pub superseded: Vec<String>,
    pub eligible: Vec<String>,
    pub rejected: Vec<String>,
}

/// WIST-1 §5.2: either frozen admission source authorizes, each under its own bindings and scope.
pub fn admits_to_queue(
    pre_recovery: &WindowDeclaration,
    recovery: &WindowDeclaration,
    delta: &Value,
    verifies: impl Fn(&Value, &[PublisherKey]) -> bool,
) -> bool {
    pre_recovery.authorizes(delta, &verifies) || recovery.authorizes(delta, &verifies)
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
        if head.authorizes(delta, &verifies) {
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
