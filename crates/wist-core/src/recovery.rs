/// WIST-1 §5.2 recovery-window derivations: which served Deltas the window
/// queues, and what its end does with them. Both read key membership and Log
/// order only, so both are facts a replaying party derives identically.

#[derive(Debug, Clone)]
pub struct WindowDeclaration {
    pub label: String,
    pub signer: String,
    pub keys: Vec<String>,
    pub recovery_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub effective_keys: Vec<String>,
    pub superseded: Vec<String>,
    pub sealed: Vec<String>,
    pub rejected: Vec<String>,
}

/// A Delta is queued when it verifies under either the Key Set in effect
/// before the recovery or the recovery Declaration's own.
pub fn admits_to_queue(
    pre_recovery_keys: &[String],
    recovery_keys: &[String],
    signer: &str,
) -> bool {
    pre_recovery_keys.iter().any(|k| k == signer) || recovery_keys.iter().any(|k| k == signer)
}

/// The window's end: the recovery Declaration and the chain legitimately
/// following it take effect, everything else sealed inside the window is
/// superseded, and each queued Delta is revalidated against the chain's
/// newest Key Set.
pub fn settle(
    recovery: &WindowDeclaration,
    window: &[WindowDeclaration],
    queued: &[(String, String)],
) -> Settlement {
    let mut head = recovery.clone();
    let mut superseded = Vec::new();
    for decl in window {
        if head.keys.contains(&decl.signer) || head.recovery_keys.contains(&decl.signer) {
            head = decl.clone();
        } else {
            superseded.push(decl.label.clone());
        }
    }
    let mut sealed = Vec::new();
    let mut rejected = Vec::new();
    for (delta_id, signer) in queued {
        if head.keys.contains(signer) {
            sealed.push(delta_id.clone());
        } else {
            rejected.push(delta_id.clone());
        }
    }
    Settlement {
        effective_keys: head.keys.clone(),
        superseded,
        sealed,
        rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(label: &str, signer: &str, keys: &[&str], recovery_keys: &[&str]) -> WindowDeclaration {
        WindowDeclaration {
            label: label.into(),
            signer: signer.into(),
            keys: keys.iter().map(|s| (*s).into()).collect(),
            recovery_keys: recovery_keys.iter().map(|s| (*s).into()).collect(),
        }
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).into()).collect()
    }

    #[test]
    fn queue_admits_the_union_and_nothing_else() {
        let pre = ids(&["k1"]);
        let rec = ids(&["k2"]);
        assert!(admits_to_queue(&pre, &rec, "k1"));
        assert!(admits_to_queue(&pre, &rec, "k2"));
        assert!(!admits_to_queue(&pre, &rec, "kX"));
    }

    #[test]
    fn a_rotation_by_the_compromised_key_is_superseded() {
        let recovery = decl("recovery", "r1", &["k2"], &["r2"]);
        let window = [decl("thief", "k1", &["kT"], &["r1"])];
        let queued = vec![
            ("d-thief".to_string(), "k1".to_string()),
            ("d-owner".to_string(), "k2".to_string()),
        ];
        let out = settle(&recovery, &window, &queued);
        assert_eq!(out.effective_keys, ids(&["k2"]));
        assert_eq!(out.superseded, ids(&["thief"]));
        assert_eq!(out.sealed, ids(&["d-owner"]));
        assert_eq!(out.rejected, ids(&["d-thief"]));
    }

    #[test]
    fn the_chain_extends_through_either_key_set() {
        let recovery = decl("recovery", "r1", &["k2"], &["r2"]);
        let window = [
            decl("post-recovery", "k2", &["k3"], &["r2"]),
            decl("second recovery", "r2", &["k4"], &["r3"]),
        ];
        let out = settle(&recovery, &window, &[]);
        assert_eq!(out.effective_keys, ids(&["k4"]));
        assert!(out.superseded.is_empty());
    }
}
