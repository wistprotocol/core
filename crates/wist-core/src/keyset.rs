#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDeclaration {
    pub seq: u64,
    pub height: u64,
    pub keys: Vec<String>,
}

pub fn key_set_at(declarations: &[SealedDeclaration], height: u64) -> &[String] {
    declarations
        .iter()
        .filter(|d| d.height <= height)
        .max_by_key(|d| d.seq)
        .map(|d| d.keys.as_slice())
        .unwrap_or(&[])
}

pub fn verifies_at(declarations: &[SealedDeclaration], height: u64, signer: &str) -> bool {
    key_set_at(declarations, height).iter().any(|k| k == signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(seq: u64, height: u64, keys: &[&str]) -> SealedDeclaration {
        SealedDeclaration {
            seq,
            height,
            keys: keys.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn no_declarations_means_no_key_set() {
        assert!(key_set_at(&[], 10).is_empty());
        assert!(!verifies_at(&[], 10, "k1"));
    }

    #[test]
    fn a_declaration_above_the_height_is_invisible() {
        let decls = [sealed(0, 5, &["k1"])];
        assert!(key_set_at(&decls, 4).is_empty());
        assert_eq!(key_set_at(&decls, 5), ["k1"]);
    }

    #[test]
    fn resolution_reads_seq_not_slice_position() {
        let decls = [sealed(1, 5, &["k2"]), sealed(0, 1, &["k1"])];
        assert_eq!(key_set_at(&decls, 9), ["k2"]);
        assert_eq!(key_set_at(&decls, 4), ["k1"]);
    }

    #[test]
    fn a_later_declarations_key_does_not_verify_below_it() {
        let decls = [sealed(0, 1, &["k1"]), sealed(1, 5, &["k2"])];
        assert!(!verifies_at(&decls, 4, "k2"));
        assert!(verifies_at(&decls, 5, "k2"));
    }
}
