use clap::Args;
use serde_json::json;

use crate::scenario::{Band, MixEntry, Scenario};
use crate::sim;

#[derive(Args, Clone, Debug, Default)]
pub struct ScenarioFlags {
    #[arg(long)]
    pub tier: Option<String>,
    #[arg(long)]
    pub pages: Option<u64>,
    #[arg(long)]
    pub churn_bp: Option<u32>,
    #[arg(long)]
    pub blocks_per_day: Option<u32>,
    #[arg(long)]
    pub days: Option<u32>,
    #[arg(long)]
    pub auditors: Option<u32>,
    #[arg(long)]
    pub seed: Option<String>,
    #[arg(long)]
    pub mix: Option<String>,
}

pub fn parse_mix(s: &str) -> Result<Vec<MixEntry>, String> {
    let mut mix = Vec::new();
    for part in s.split(',') {
        let (name, bp) = part
            .split_once(':')
            .ok_or_else(|| format!("bad mix entry {part}, want band:bp"))?;
        let band = Band::parse(name).ok_or_else(|| format!("unknown band {name}"))?;
        let share_bp: u32 = bp.parse().map_err(|_| format!("bad share {bp}"))?;
        mix.push(MixEntry { band, share_bp });
    }
    let sum: u32 = mix.iter().map(|m| m.share_bp).sum();
    if sum != 10_000 {
        return Err(format!("mix shares sum to {sum} bp, expected 10000"));
    }
    Ok(mix)
}

impl ScenarioFlags {
    pub fn to_scenario(&self) -> Result<Scenario, String> {
        let tier = self.tier.as_deref().unwrap_or("small");
        let mut sc = Scenario::tier(tier).ok_or_else(|| format!("unknown tier {tier}"))?;
        if let Some(v) = self.pages {
            sc.pages = v;
        }
        if let Some(v) = self.churn_bp {
            sc.churn_bp = v;
        }
        if let Some(v) = self.blocks_per_day {
            sc.blocks_per_day = v;
        }
        if let Some(v) = self.days {
            sc.days = v;
        }
        if let Some(v) = self.auditors {
            sc.auditors = v;
        }
        if let Some(v) = &self.seed {
            sc.seed = v.clone();
        }
        if let Some(v) = &self.mix {
            sc.mix = parse_mix(v)?;
        }
        sc.validate()?;
        Ok(sc)
    }
}

pub fn simulate_json(sc: &Scenario) -> String {
    let result = sim::run(sc);
    serde_json::to_string_pretty(&json!({"scenario": sc, "result": result})).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Band;

    #[test]
    fn parse_mix_roundtrip() {
        let mix = parse_mix("mature:7000,mid:2000,provisional:900,sanctioned:100").unwrap();
        assert_eq!(mix.len(), 4);
        assert_eq!(mix[1].band, Band::Mid);
        assert_eq!(mix[3].share_bp, 100);
        assert!(parse_mix("mature:5000").is_err());
        assert!(parse_mix("weird:10000").is_err());
    }

    #[test]
    fn simulate_json_contains_scenario_and_result() {
        let sc = crate::scenario::Scenario {
            days: 1,
            auditors: 1,
            blocks_per_day: 1,
            pages: 10_000,
            churn_bp: 100,
            ..crate::scenario::Scenario::tier("small").unwrap()
        };
        let v: serde_json::Value = serde_json::from_str(&simulate_json(&sc)).unwrap();
        assert_eq!(v["scenario"]["pages"], 10_000);
        assert!(v["result"]["expected_per_day"].as_f64().unwrap() > 0.0);
    }
}
