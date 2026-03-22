// doctor_labs_superfilter/src/harassment_detector.rs

use crate::{
    BlacklistFamily,
    CapabilityMode,
    RogueConfig,
    RogueScore,
    SpanScore,
    NUM_BLACKLIST_FAMILIES,
};

/// Compute rogue score from neural + text + behavioral spans (reflective engine).
/// This just delegates to the generic RogueScore aggregator, which already
/// applies per-family α/β weighting (including NHSP/HTA/PSA/NIH if configured).
pub fn compute_harassment_rogue(spans: &[SpanScore], cfg: &RogueConfig) -> RogueScore {
    RogueScore::from_spans(spans, cfg)
}

/// Convenience: extract the full per-family vector from a RogueScore,
/// with explicit indices for the harassment-related families.
pub fn harassment_family_vector(r: &RogueScore) -> [f64; NUM_BLACKLIST_FAMILIES] {
    let mut v = [0.0; NUM_BLACKLIST_FAMILIES];

    v[BlacklistFamily::NHSP.index()] = r.family_score(BlacklistFamily::NHSP);
    v[BlacklistFamily::HTA.index()]  = r.family_score(BlacklistFamily::HTA);
    v[BlacklistFamily::PSA.index()]  = r.family_score(BlacklistFamily::PSA);
    v[BlacklistFamily::NIH.index()]  = r.family_score(BlacklistFamily::NIH);

    v
}

/// Monotone escalation using your neural I/O as input.
/// This preserves capabilities by only switching between Normal,
/// AugmentedLog, and AugmentedReview based on the total rogue score.
pub fn escalate_on_harassment(r: &RogueScore, cfg: &RogueConfig) -> CapabilityMode {
    if r.r_total <= cfg.tau1 {
        CapabilityMode::Normal
    } else if r.r_total <= cfg.tau2 {
        CapabilityMode::AugmentedLog
    } else {
        CapabilityMode::AugmentedReview
    }
}
