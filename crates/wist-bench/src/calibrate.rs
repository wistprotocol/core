use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calibration {
    pub count: u64,
    pub payload_p50: u64,
    pub payload_max: u64,
}

pub fn measure(dir: &Path) -> Result<Calibration, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut sizes: Vec<u64> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            sizes.push(entry.metadata().map_err(|e| e.to_string())?.len());
        }
    }
    if sizes.is_empty() {
        return Err(format!("no .json payloads in {}", dir.display()));
    }
    sizes.sort_unstable();
    Ok(Calibration {
        count: sizes.len() as u64,
        payload_p50: sizes[sizes.len() / 2],
        payload_max: *sizes.last().unwrap(),
    })
}

pub fn load(path: &Path) -> Result<Calibration, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/payloads")
    }

    #[test]
    fn measures_p50_and_max() {
        let c = measure(&fixtures()).unwrap();
        assert_eq!(c.count, 3);
        assert_eq!(c.payload_p50, 900);
        assert_eq!(c.payload_max, 1200);
    }

    #[test]
    fn empty_dir_is_an_error() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        assert!(measure(&dir.join("no-such")).is_err());
    }

    #[test]
    fn json_roundtrip() {
        let c = measure(&fixtures()).unwrap();
        let s = serde_json::to_string(&c).unwrap();
        let back: Calibration = serde_json::from_str(&s).unwrap();
        assert_eq!(back.payload_max, c.payload_max);
    }
}
