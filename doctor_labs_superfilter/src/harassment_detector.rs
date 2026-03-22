use crate::{BlacklistFamily, SpanScore, RogueScore, RogueConfig, CapabilityMode};
use std::collections::HashMap;

/// New harassment families (internal only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarassmentFamily {
    NHSP, // NEURAL-HARASSMENT-SPIKE-PATTERN
    HTA,  // HAPTIC-TARGETING-ABUSE
    PSA,  // PROLONGED-SESSION-ABUSE
    NIH,  // NODE-INTERPRETER-HARASSMENT
}

/// Compute rogue score from neural + text + behavioral spans (reflective engine)
pub fn compute_harassment_rogue(spans: &[SpanScore], cfg: &RogueConfig) -> RogueScore {
    let families = [HarassmentFamily::NHSP, HarassmentFamily::HTA,
                    HarassmentFamily::PSA, HarassmentFamily::NIH];
    let mut per_family = [0.0_f64; 4];
    let mut r_total = 0.0;

    for (i, fam) in families.iter().enumerate() {
        let beta_f = cfg.beta.get(&BlacklistFamily::CBCP).copied().unwrap_or(1.0); // reuse CBCP weight
        let mut sum_f = 0.0;
        for span in spans {
            if let Some(&w) = span.family_weights.get(&BlacklistFamily::CBCP) { // map to existing
                sum_f += beta_f * w; // extend with NHSP-specific ω later
            }
        }
        per_family[i] = sum_f;
        r_total += sum_f;
    }
    RogueScore { r_total, per_family: per_family.try_into().unwrap() }
}

/// Monotone escalation using your neural I/O as input
pub fn escalate_on_harassment(r: &RogueScore, cfg: &RogueConfig) -> CapabilityMode {
    if r.r_total <= cfg.tau1 { CapabilityMode::Normal }
    else if r.r_total <= cfg.tau2 { CapabilityMode::AugmentedLog }
    else { CapabilityMode::AugmentedReview }
}
