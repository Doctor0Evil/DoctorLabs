use serde::Deserialize;
use std::collections::HashMap;
use crate::{BlacklistFamily, RogueConfig};

#[derive(Debug, Deserialize)]
pub struct LexiconEntry {
    pub id: String,
    pub family: String,
    pub risk_kernel: RiskKernelCfg,
    pub governance: GovernanceCfg,
}

#[derive(Debug, Deserialize)]
pub struct RiskKernelCfg {
    pub family_weights: HashMap<String, f64>,
    pub gaussian_sigma: f64,
}

#[derive(Debug, Deserialize)]
pub struct GovernanceCfg {
    pub capability_mode_mapping: CapabilityTauCfg,
}

#[derive(Debug, Deserialize)]
pub struct CapabilityTauCfg {
    pub tau1: f64,
    pub tau2: f64,
}

fn parse_family(name: &str) -> Option<BlacklistFamily> {
    match name {
        "NHSP" => Some(BlacklistFamily::NHSP),
        "HTA"  => Some(BlacklistFamily::HTA),
        "PSA"  => Some(BlacklistFamily::PSA),
        "NIH"  => Some(BlacklistFamily::NIH),
        "CRS"  => Some(BlacklistFamily::CONTROL_REVERSAL_SEMANTICS),
        _      => None,
    }
}

/// Load lexicon YAML and fold into RogueConfig.
/// This only tunes alpha/beta/tau*, it never changes code paths.
pub fn apply_lexicon_to_config(
    entries: &[LexiconEntry],
    cfg: &mut RogueConfig,
) {
    use BlacklistFamily::*;

    // Start from whatever defaults you already have.
    for entry in entries {
        // Risk kernel weights.
        for (fam_str, w) in &entry.risk_kernel.family_weights {
            if let Some(fam) = parse_family(fam_str) {
                cfg.beta.insert(fam, *w);
            }
        }

        // Optionally, CRS-tagged entries can “pull up” CONTROL_REVERSAL_SEMANTICS.
        if entry.family == "HTA" || entry.family == "PSA"
           || entry.family == "NHSP" || entry.family == "NIH"
        {
            if entry.id.contains("CRS") || entry.id.contains("CONTROL") {
                cfg.beta
                    .entry(CONTROL_REVERSAL_SEMANTICS)
                    .and_modify(|b| *b = (*b).max(1.0))
                    .or_insert(1.0);
            }
        }

        // Governance thresholds tau1/tau2:
        cfg.tau1 = cfg.tau1.min(entry.governance.capability_mode_mapping.tau1);
        cfg.tau2 = cfg.tau2.min(entry.governance.capability_mode_mapping.tau2);
    }
}
