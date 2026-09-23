//! WIST-3 §7, one URL, one Publisher.

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
