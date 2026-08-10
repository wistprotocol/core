use serde::Serialize;
use wist_core::reputation::PROVISIONAL_CAP_U;
use wist_core::sampling;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum Band {
    Mature,
    Mid,
    Provisional,
    Sanctioned,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub struct MixEntry {
    pub band: Band,
    pub share_bp: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Scenario {
    pub name: String,
    pub pages: u64,
    pub churn_bp: u32,
    pub blocks_per_day: u32,
    pub days: u32,
    pub auditors: u32,
    pub seed: String,
    pub mix: Vec<MixEntry>,
}

pub fn band_rep_u(b: Band) -> u64 {
    match b {
        Band::Mature => 1_000_000,
        Band::Mid => 600_000,
        Band::Provisional => PROVISIONAL_CAP_U,
        Band::Sanctioned => 0,
    }
}

pub fn band_p_1e7(b: Band) -> u64 {
    sampling::p_1e7(band_rep_u(b), b == Band::Sanctioned)
}

impl Scenario {
    pub fn tier(name: &str) -> Option<Scenario> {
        let (pages, churn_bp, mix): (u64, u32, Vec<MixEntry>) = match name {
            "small" => (
                1_000_000,
                200,
                vec![
                    MixEntry {
                        band: Band::Mature,
                        share_bp: 9_000,
                    },
                    MixEntry {
                        band: Band::Provisional,
                        share_bp: 1_000,
                    },
                ],
            ),
            "medium" => (
                100_000_000,
                100,
                vec![
                    MixEntry {
                        band: Band::Mature,
                        share_bp: 7_000,
                    },
                    MixEntry {
                        band: Band::Mid,
                        share_bp: 2_000,
                    },
                    MixEntry {
                        band: Band::Provisional,
                        share_bp: 1_000,
                    },
                ],
            ),
            "large" => (
                1_000_000_000,
                50,
                vec![
                    MixEntry {
                        band: Band::Mature,
                        share_bp: 6_000,
                    },
                    MixEntry {
                        band: Band::Mid,
                        share_bp: 2_500,
                    },
                    MixEntry {
                        band: Band::Provisional,
                        share_bp: 1_400,
                    },
                    MixEntry {
                        band: Band::Sanctioned,
                        share_bp: 100,
                    },
                ],
            ),
            _ => return None,
        };
        Some(Scenario {
            name: name.to_string(),
            pages,
            churn_bp,
            blocks_per_day: 24,
            days: 7,
            auditors: 5,
            seed: "wist-bench-v1".to_string(),
            mix,
        })
    }

    pub fn deltas_per_day(&self) -> u64 {
        self.pages * self.churn_bp as u64 / 10_000
    }

    pub fn validate(&self) -> Result<(), String> {
        let sum: u32 = self.mix.iter().map(|m| m.share_bp).sum();
        if sum != 10_000 {
            return Err(format!("mix shares sum to {sum} bp, expected 10000"));
        }
        if self.blocks_per_day == 0 || self.days == 0 || self.auditors == 0 {
            return Err("blocks_per_day, days, auditors must be nonzero".into());
        }
        if self.deltas_per_day() == 0 {
            return Err("scenario produces zero deltas per day".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_exist_and_validate() {
        for name in ["small", "medium", "large"] {
            let sc = Scenario::tier(name).unwrap();
            assert_eq!(sc.name, name);
            sc.validate().unwrap();
            assert_eq!(sc.mix.iter().map(|m| m.share_bp).sum::<u32>(), 10_000);
        }
        assert!(Scenario::tier("huge").is_none());
    }

    #[test]
    fn deltas_per_day_matches_churn() {
        assert_eq!(Scenario::tier("small").unwrap().deltas_per_day(), 20_000);
        assert_eq!(
            Scenario::tier("medium").unwrap().deltas_per_day(),
            1_000_000
        );
        assert_eq!(Scenario::tier("large").unwrap().deltas_per_day(), 5_000_000);
    }

    #[test]
    fn band_rates_are_the_normative_ones() {
        assert_eq!(band_p_1e7(Band::Mature), 200_000);
        assert_eq!(band_p_1e7(Band::Mid), 1_400_000);
        assert_eq!(band_p_1e7(Band::Provisional), 2_900_000);
        assert_eq!(band_p_1e7(Band::Sanctioned), 5_000_000);
    }

    #[test]
    fn validate_rejects_bad_mix() {
        let mut sc = Scenario::tier("small").unwrap();
        sc.mix[0].share_bp -= 1;
        assert!(sc.validate().is_err());
    }
}
