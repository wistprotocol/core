use crate::error::Error;

/// WIST-1 §2 Canonical Host: lowercase, then UTS #46 processing with
/// `UseSTD3ASCIIRules=true`, `Transitional_Processing=false` and
/// `VerifyDnsLength=true` to IDNA2008 A-labels, trailing dot removed,
/// no port.
pub fn canonical_host(host: &str) -> Result<String, Error> {
    let lowered = host.to_lowercase();
    let trimmed = lowered.strip_suffix('.').unwrap_or(&lowered);
    idna::domain_to_ascii_strict(trimmed)
        .map_err(|e| Error::Host(format!("host {host:?} has no canonicalization: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_strips_trailing_dot() {
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
    fn ascii_ip_literal_passes_std3() {
        assert_eq!(canonical_host("127.0.0.1").unwrap(), "127.0.0.1");
    }
}
