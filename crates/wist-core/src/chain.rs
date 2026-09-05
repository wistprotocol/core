use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainTips {
    tips: BTreeMap<String, BTreeMap<String, String>>,
}

impl ChainTips {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tip(&self, publisher: &str, url: &str) -> Option<&str> {
        self.tips.get(publisher)?.get(url).map(String::as_str)
    }

    pub fn apply(&mut self, publisher: &str, url: &str, id: &str, prev: Option<&str>) -> bool {
        if self.tip(publisher, url) != prev {
            return false;
        }
        self.tips
            .entry(publisher.to_string())
            .or_default()
            .insert(url.to_string(), id.to_string());
        true
    }

    /// Sets a tip without the `prev` check — for restoring state a
    /// Snapshot or a local store already carries.
    pub fn adopt(&mut self, publisher: &str, url: &str, id: &str) {
        self.tips
            .entry(publisher.to_string())
            .or_default()
            .insert(url.to_string(), id.to_string());
    }

    pub fn tips(&self) -> impl Iterator<Item = (&str, &str, &str)> + '_ {
        self.tips.iter().flat_map(|(publisher, urls)| {
            urls.iter()
                .map(move |(url, tip)| (publisher.as_str(), url.as_str(), tip.as_str()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "example.com";
    const A: &str = "https://example.com/a";
    const B: &str = "https://example.com/b";

    #[test]
    fn an_unknown_key_carries_no_tip() {
        let tips = ChainTips::new();
        assert_eq!(tips.tip(P, A), None);
        assert_eq!(tips.tips().count(), 0);
    }

    #[test]
    fn an_ignored_delta_leaves_the_tip_where_it_was() {
        let mut tips = ChainTips::new();
        assert!(tips.apply(P, A, "d1", None));
        assert!(tips.apply(P, A, "d2", Some("d1")));
        assert!(!tips.apply(P, A, "d3", Some("d1")));
        assert!(!tips.apply(P, A, "d4", None));
        assert!(!tips.apply(P, A, "d5", Some("d3")));
        assert_eq!(tips.tip(P, A), Some("d2"));
    }

    #[test]
    fn urls_chain_separately_under_one_publisher() {
        let mut tips = ChainTips::new();
        assert!(tips.apply(P, A, "d1", None));
        assert!(tips.apply(P, B, "e1", None));
        assert!(!tips.apply(P, B, "e2", Some("d1")));
        assert!(tips.apply(P, B, "e2", Some("e1")));
        assert_eq!(tips.tip(P, A), Some("d1"));
        assert_eq!(tips.tip(P, B), Some("e2"));
    }

    #[test]
    fn tips_iterate_in_key_order() {
        let mut tips = ChainTips::new();
        assert!(tips.apply("www.example.com", A, "w1", None));
        assert!(tips.apply(P, B, "e1", None));
        assert!(tips.apply(P, A, "d1", None));
        let got: Vec<_> = tips.tips().collect();
        assert_eq!(
            got,
            [(P, A, "d1"), (P, B, "e1"), ("www.example.com", A, "w1")]
        );
    }
}
