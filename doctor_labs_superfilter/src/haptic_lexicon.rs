// doctor_labs_superfilter/src/haptic_lexicon.rs
use serde_yaml::Value;
use std::collections::HashMap;
use crate::{BlacklistFamily, SpanScore, RogueScore, RogueConfig, CapabilityMode};

#[derive(Debug, Clone)]
pub struct HapticLexiconTerm {
    pub id: String,
    pub family: BlacklistFamily,
    pub risk_kernel: HashMap<BlacklistFamily, f64>,
    pub pattern: Value, // YAML sub-object
}

pub struct HapticLexicon {
    terms: Vec<HapticLexiconTerm>,
}

impl HapticLexicon {
    pub fn load_from_yaml(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let docs: Vec<Value> = serde_yaml::from_str(&content)?;
        let mut terms = vec![];
        for doc in docs {
            let id = doc["id"].as_str().unwrap_or("").to_string();
            let fam_str = doc["family"].as_str().unwrap_or("NHSP");
            let family = match fam_str {
                "NHSP" => BlacklistFamily::NHSP,
                "HTA" => BlacklistFamily::HTA,
                "PSA" => BlacklistFamily::PSA,
                "NIH" => BlacklistFamily::NIH,
                _ => BlacklistFamily::NHSP,
            };
            // … parse risk_kernel, pattern (sanitized)
            terms.push(HapticLexiconTerm { id, family, risk_kernel: HashMap::new(), pattern: doc });
        }
        Ok(HapticLexicon { terms })
    }

    pub fn score_message(&self, spans: &[SpanScore], cfg: &RogueConfig) -> (RogueScore, CapabilityMode) {
        let r = RogueScore::from_spans(spans, cfg);
        let mode = CapabilityMode::from_rogue_score(&r, cfg);
        (r, mode)
    }
}
