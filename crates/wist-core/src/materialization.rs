//! WIST-3 §7, one URL, one Publisher: which Publisher's record a URL's
//! host materializes when several Publishers hold a live record for it.

/// The Publisher whose record materializes for a URL of `host`, out of
/// the Publishers holding a live record for it. `self_declared` is true
/// once the host's own `seq`-0 Declaration Entry is sealed at or below
/// the height: from there only the host's own Publisher materializes.
/// Otherwise the nearest ancestor does — the longest domain the host
/// descends from — and where no candidate is an ancestor, the least
/// domain in ascending octet order.
pub fn preferred<'a, I>(host: &str, self_declared: bool, candidates: I) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let candidates: Vec<&str> = candidates.into_iter().collect();
    if self_declared {
        return candidates.into_iter().find(|domain| *domain == host);
    }
    candidates
        .iter()
        .filter(|domain| is_ancestor(domain, host))
        .max_by_key(|domain| domain.len())
        .or_else(|| candidates.iter().min())
        .copied()
}

/// Whether `host` is `<label>.domain` or a deeper descendant, the label
/// boundary being the dot a suffix match alone would miss.
pub fn is_ancestor(domain: &str, host: &str) -> bool {
    host.len() > domain.len() + 1
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_candidate_materializes_nothing() {
        assert_eq!(preferred("a.example.com", false, []), None);
        assert_eq!(preferred("a.example.com", true, []), None);
    }

    #[test]
    fn a_host_is_no_ancestor_of_itself() {
        assert!(!is_ancestor("example.com", "example.com"));
        assert!(is_ancestor("example.com", "a.example.com"));
        assert!(!is_ancestor("example.com", "notexample.com"));
    }
}
