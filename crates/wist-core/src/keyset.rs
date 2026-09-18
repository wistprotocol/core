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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationAtInstant {
    pub seq: u64,
    pub sealed_at_s: i64,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageResolution {
    Current,
    Next,
}

pub fn page_key_set_current(
    declarations: &[DeclarationAtInstant],
    generated_at_s: i64,
) -> &[String] {
    declarations
        .iter()
        .filter(|d| d.sealed_at_s <= generated_at_s)
        .max_by_key(|d| (d.sealed_at_s, d.seq))
        .map(|d| d.keys.as_slice())
        .unwrap_or(&[])
}

pub fn page_key_set_next(declarations: &[DeclarationAtInstant], generated_at_s: i64) -> &[String] {
    declarations
        .iter()
        .filter(|d| d.sealed_at_s > generated_at_s)
        .min_by_key(|d| (d.sealed_at_s, std::cmp::Reverse(d.seq)))
        .map(|d| d.keys.as_slice())
        .unwrap_or(&[])
}

pub fn page_resolution(
    declarations: &[DeclarationAtInstant],
    generated_at_s: i64,
    signer: &str,
) -> Option<PageResolution> {
    if page_key_set_current(declarations, generated_at_s)
        .iter()
        .any(|k| k == signer)
    {
        Some(PageResolution::Current)
    } else if page_key_set_next(declarations, generated_at_s)
        .iter()
        .any(|k| k == signer)
    {
        Some(PageResolution::Next)
    } else {
        None
    }
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

    fn at(seq: u64, sealed_at_s: i64, keys: &[&str]) -> DeclarationAtInstant {
        DeclarationAtInstant {
            seq,
            sealed_at_s,
            keys: keys.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn a_page_with_nothing_sealed_after_it_has_no_next_key_set() {
        let decls = [at(0, 100, &["k1"])];
        assert_eq!(page_key_set_current(&decls, 150), ["k1"]);
        assert!(page_key_set_next(&decls, 150).is_empty());
        assert_eq!(
            page_resolution(&decls, 150, "k1"),
            Some(PageResolution::Current)
        );
        assert_eq!(page_resolution(&decls, 150, "k2"), None);
    }

    #[test]
    fn an_epoch_sealing_two_declarations_resolves_to_its_key_set_either_way() {
        let decls = [
            at(0, 100, &["k1"]),
            at(1, 200, &["k2"]),
            at(2, 200, &["k3"]),
        ];
        assert_eq!(page_key_set_current(&decls, 200), ["k3"]);
        assert_eq!(page_key_set_next(&decls, 150), ["k3"]);
        assert_eq!(page_resolution(&decls, 150, "k2"), None);
        assert_eq!(page_resolution(&decls, 200, "k2"), None);
    }

    #[test]
    fn page_resolution_reads_instants_not_slice_position() {
        let decls = [at(1, 200, &["k2"]), at(0, 100, &["k1"])];
        assert_eq!(page_key_set_current(&decls, 199), ["k1"]);
        assert_eq!(page_key_set_next(&decls, 50), ["k1"]);
        assert_eq!(
            page_resolution(&decls, 199, "k2"),
            Some(PageResolution::Next)
        );
    }
}
