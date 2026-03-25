// doctor_labs_superfilter/src/quiet_violence_detector.rs
#![forbid(unsafe_code)]
use std::collections::HashMap;
use crate::{BlacklistFamily, SpanScore, RogueScore, RogueConfig, CapabilityMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuietViolenceFamily {
    QVP, HTA, PSA, NHSP, NIH,
}

#[derive(Debug, Clone)]
pub struct QuietViolenceIndex {
    pub scores: HashMap<QuietViolenceFamily, f64>,
    pub qv_total: f64,
}

impl QuietViolenceDetector {
    pub fn new() -> Self { Self {} }

    /// Compute QV_t from fused BCI/XR spans (EEG + haptic + session + XR pose)
    pub fn compute_index(spans: &[SpanScore], cfg: &RogueConfig) -> QuietViolenceIndex {
        let families = [QuietViolenceFamily::QVP, QuietViolenceFamily::HTA, QuietViolenceFamily::PSA,
                        QuietViolenceFamily::NHSP, QuietViolenceFamily::NIH];
        let mut scores = HashMap::new();
        let mut qv = 0.0;

        for fam in families {
            let beta_f = cfg.beta.get(&BlacklistFamily::CBCP).copied().unwrap_or(1.0); // reuse CBCP weight
            let mut sum_f = 0.0;
            for span in spans {
                // family_weights already populated by semantic layer (embedding similarity)
                if let Some(&w) = span.family_weights.get(&BlacklistFamily::CBCP) { // map QVP→CBCP for now
                    sum_f += beta_f * w;
                }
            }
            scores.insert(fam, sum_f);
            qv += sum_f;
        }

        QuietViolenceIndex { scores, qv_total: qv }
    }

    /// Monotone escalation using existing CapabilityMode
    pub fn escalate(cap_mode: CapabilityMode, qv_index: &QuietViolenceIndex, cfg: &RogueConfig) -> CapabilityMode {
        if qv_index.qv_total > cfg.tau2 {
            CapabilityMode::AugmentedReview
        } else if qv_index.qv_total > cfg.tau1 {
            CapabilityMode::AugmentedLog
        } else {
            cap_mode
        }
    }
}
