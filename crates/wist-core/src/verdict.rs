const MICRO: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    New,
    Update,
    Attest,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Consistent,
    DynamicVariance,
    Inconsistent,
    Unreachable,
    NotAuditable,
    LinkVariance,
    LinkInconsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reference {
    Available,
    EmptyExtract,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Unobtained,
    BoundsStopped,
    DeleteGone,
    NonHtml,
    Html {
        observed_words: u64,
        similarity: u64,
        link_agreement: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub similarity_consistent: u64,
    pub similarity_variance_floor: u64,
    pub link_agreement_consistent: u64,
    pub link_variance_floor: u64,
    pub min_observed_words: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            similarity_consistent: 600_000,
            similarity_variance_floor: 300_000,
            link_agreement_consistent: 600_000,
            link_variance_floor: 300_000,
            min_observed_words: 40,
        }
    }
}

pub fn effective_similarity(similarity: u64, change: ChangeType) -> u64 {
    match change {
        ChangeType::New | ChangeType::Update | ChangeType::Attest => similarity,
        ChangeType::Delete => MICRO - similarity,
    }
}

pub fn resolve(
    change: ChangeType,
    reference: Reference,
    observation: Observation,
    thresholds: &Thresholds,
) -> Verdict {
    match reference {
        Reference::Missing | Reference::EmptyExtract => return Verdict::NotAuditable,
        Reference::Available => {}
    }
    let (similarity, link_agreement) = match observation {
        Observation::Unobtained => return Verdict::Unreachable,
        Observation::BoundsStopped | Observation::NonHtml => return Verdict::NotAuditable,
        Observation::DeleteGone => (0, None),
        Observation::Html {
            observed_words,
            similarity,
            link_agreement,
        } => {
            if observed_words < thresholds.min_observed_words {
                return Verdict::NotAuditable;
            }
            (similarity, link_agreement)
        }
    };
    let effective = effective_similarity(similarity, change);
    if effective < thresholds.similarity_variance_floor {
        return Verdict::Inconsistent;
    }
    if effective < thresholds.similarity_consistent {
        return Verdict::DynamicVariance;
    }
    let link_applies =
        change != ChangeType::Delete && matches!(observation, Observation::Html { .. });
    match link_agreement {
        Some(link) if link_applies => {
            if link >= thresholds.link_agreement_consistent {
                Verdict::Consistent
            } else if link >= thresholds.link_variance_floor {
                Verdict::LinkVariance
            } else {
                Verdict::LinkInconsistent
            }
        }
        _ => Verdict::Consistent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html(similarity: u64, link_agreement: Option<u64>) -> Observation {
        Observation::Html {
            observed_words: 100,
            similarity,
            link_agreement,
        }
    }

    fn resolve_default(change: ChangeType, reference: Reference, obs: Observation) -> Verdict {
        resolve(change, reference, obs, &Thresholds::default())
    }

    #[test]
    fn mirror_is_identity_except_delete() {
        assert_eq!(effective_similarity(700_000, ChangeType::New), 700_000);
        assert_eq!(effective_similarity(700_000, ChangeType::Update), 700_000);
        assert_eq!(effective_similarity(700_000, ChangeType::Attest), 700_000);
        assert_eq!(effective_similarity(700_000, ChangeType::Delete), 300_000);
        assert_eq!(effective_similarity(0, ChangeType::Delete), 1_000_000);
    }

    #[test]
    fn missing_reference_is_not_auditable_even_when_fetch_also_failed() {
        assert_eq!(
            resolve_default(ChangeType::New, Reference::Missing, Observation::Unobtained),
            Verdict::NotAuditable
        );
        assert_eq!(
            resolve_default(ChangeType::New, Reference::Missing, html(1_000_000, None)),
            Verdict::NotAuditable
        );
    }

    #[test]
    fn empty_reference_extract_is_not_auditable() {
        assert_eq!(
            resolve_default(ChangeType::Update, Reference::EmptyExtract, html(0, None)),
            Verdict::NotAuditable
        );
    }

    #[test]
    fn unobtained_representation_is_unreachable() {
        assert_eq!(
            resolve_default(
                ChangeType::New,
                Reference::Available,
                Observation::Unobtained
            ),
            Verdict::Unreachable
        );
        assert_eq!(
            resolve_default(
                ChangeType::Delete,
                Reference::Available,
                Observation::Unobtained
            ),
            Verdict::Unreachable
        );
    }

    #[test]
    fn bounds_stopped_fetch_is_not_auditable() {
        assert_eq!(
            resolve_default(
                ChangeType::New,
                Reference::Available,
                Observation::BoundsStopped
            ),
            Verdict::NotAuditable
        );
    }

    #[test]
    fn non_html_representation_is_not_auditable() {
        assert_eq!(
            resolve_default(
                ChangeType::Attest,
                Reference::Available,
                Observation::NonHtml
            ),
            Verdict::NotAuditable
        );
    }

    #[test]
    fn mass_guard_boundary() {
        let below = Observation::Html {
            observed_words: 39,
            similarity: 0,
            link_agreement: None,
        };
        let at = Observation::Html {
            observed_words: 40,
            similarity: 0,
            link_agreement: None,
        };
        assert_eq!(
            resolve_default(ChangeType::New, Reference::Available, below),
            Verdict::NotAuditable
        );
        assert_eq!(
            resolve_default(ChangeType::New, Reference::Available, at),
            Verdict::Inconsistent
        );
    }

    #[test]
    fn delete_gone_is_ruled_on_consistent() {
        assert_eq!(
            resolve_default(
                ChangeType::Delete,
                Reference::Available,
                Observation::DeleteGone
            ),
            Verdict::Consistent
        );
    }

    #[test]
    fn extract_bands_partition_at_the_edges() {
        for (similarity, verdict) in [
            (600_000, Verdict::Consistent),
            (599_999, Verdict::DynamicVariance),
            (300_000, Verdict::DynamicVariance),
            (299_999, Verdict::Inconsistent),
            (0, Verdict::Inconsistent),
            (1_000_000, Verdict::Consistent),
        ] {
            assert_eq!(
                resolve_default(
                    ChangeType::New,
                    Reference::Available,
                    html(similarity, None)
                ),
                verdict,
                "similarity {similarity}"
            );
        }
    }

    #[test]
    fn delete_bands_read_over_the_mirror() {
        assert_eq!(
            resolve_default(
                ChangeType::Delete,
                Reference::Available,
                html(400_000, None)
            ),
            Verdict::Consistent
        );
        assert_eq!(
            resolve_default(
                ChangeType::Delete,
                Reference::Available,
                html(400_001, None)
            ),
            Verdict::DynamicVariance
        );
        assert_eq!(
            resolve_default(
                ChangeType::Delete,
                Reference::Available,
                html(700_001, None)
            ),
            Verdict::Inconsistent
        );
    }

    #[test]
    fn link_bands_partition_inside_the_consistent_band() {
        for (link, verdict) in [
            (1_000_000, Verdict::Consistent),
            (600_000, Verdict::Consistent),
            (599_999, Verdict::LinkVariance),
            (300_000, Verdict::LinkVariance),
            (299_999, Verdict::LinkInconsistent),
            (0, Verdict::LinkInconsistent),
        ] {
            assert_eq!(
                resolve_default(
                    ChangeType::New,
                    Reference::Available,
                    html(800_000, Some(link))
                ),
                verdict,
                "link_agreement {link}"
            );
        }
    }

    #[test]
    fn link_reading_never_reached_outside_the_consistent_band() {
        assert_eq!(
            resolve_default(
                ChangeType::New,
                Reference::Available,
                html(400_000, Some(0))
            ),
            Verdict::DynamicVariance
        );
        assert_eq!(
            resolve_default(
                ChangeType::New,
                Reference::Available,
                html(100_000, Some(0))
            ),
            Verdict::Inconsistent
        );
    }

    #[test]
    fn link_dimension_is_neutral_for_delete() {
        assert_eq!(
            resolve_default(ChangeType::Delete, Reference::Available, html(0, Some(0))),
            Verdict::Consistent
        );
    }

    #[test]
    fn omitted_link_agreement_resolves_from_the_extract_alone() {
        assert_eq!(
            resolve_default(
                ChangeType::Update,
                Reference::Available,
                html(800_000, None)
            ),
            Verdict::Consistent
        );
    }

    #[test]
    fn custom_thresholds_are_read_not_hardcoded() {
        let t = Thresholds {
            similarity_consistent: 500_000,
            similarity_variance_floor: 200_000,
            link_agreement_consistent: 700_000,
            link_variance_floor: 100_000,
            min_observed_words: 10,
        };
        let obs = Observation::Html {
            observed_words: 10,
            similarity: 500_000,
            link_agreement: Some(650_000),
        };
        assert_eq!(
            resolve(ChangeType::New, Reference::Available, obs, &t),
            Verdict::LinkVariance
        );
        let low_mass = Observation::Html {
            observed_words: 9,
            similarity: 500_000,
            link_agreement: None,
        };
        assert_eq!(
            resolve(ChangeType::New, Reference::Available, low_mass, &t),
            Verdict::NotAuditable
        );
    }
}
