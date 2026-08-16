use crate::error::Error;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

/// WIST-1 §2 Canonical Host: UTS #46 processing with
/// `UseSTD3ASCIIRules=true`, `CheckHyphens=false`, `CheckBidi=true`,
/// `CheckJoiners=true`, `Transitional_Processing=false` and
/// `VerifyDnsLength=true` to IDNA2008 A-labels, trailing dot removed,
/// no port. Case is folded by the mapping step and by nothing before it.
pub fn canonical_host(host: &str) -> Result<String, Error> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    Uts46::new()
        .to_ascii(
            trimmed.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Allow,
            DnsLength::Verify,
        )
        .map(|c| c.into_owned())
        .map_err(|e| Error::Host(format!("host {host:?} has no canonicalization: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_case_and_strips_trailing_dot() {
        assert_eq!(canonical_host("EXAMPLE.org.").unwrap(), "example.org");
        assert_eq!(canonical_host("example.org").unwrap(), "example.org");
    }

    #[test]
    fn encodes_idn_to_a_labels() {
        assert_eq!(
            canonical_host("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn uses_nontransitional_processing_for_sharp_s() {
        assert_eq!(canonical_host("faß.de").unwrap(), "xn--fa-hia.de");
    }

    #[test]
    fn maps_final_sigma_context_free() {
        assert_eq!(canonical_host("example.ΑΣ").unwrap(), "example.xn--mxa0b");
    }

    #[test]
    fn allows_positional_hyphens() {
        assert_eq!(
            canonical_host("r2---sn-x.example").unwrap(),
            "r2---sn-x.example"
        );
        assert_eq!(canonical_host("-foo.example").unwrap(), "-foo.example");
    }

    #[test]
    fn already_canonical_a_labels_pass_through() {
        assert_eq!(
            canonical_host("xn--bcher-kva.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn rejects_std3_violations_and_bad_lengths() {
        assert!(canonical_host("under_score.example").is_err());
        assert!(canonical_host("").is_err());
        let long_label = format!("{}.example", "a".repeat(64));
        assert!(canonical_host(&long_label).is_err());
    }

    #[test]
    fn rejects_joiner_and_bidi_violations() {
        assert!(canonical_host("a\u{200c}b.example").is_err());
        assert!(canonical_host("\u{05d0}a.example").is_err());
    }

    #[test]
    fn ascii_ip_literal_passes_std3() {
        assert_eq!(canonical_host("127.0.0.1").unwrap(), "127.0.0.1");
    }
}
