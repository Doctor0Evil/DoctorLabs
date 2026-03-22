// doctor_labs_superfilter/src/lib.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const NUM_BLACKLIST_FAMILIES: usize = 9;

/// Semantic blacklist families, internal-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlacklistFamily {
    CLLN, // CRYPTO‑LOW‑LEVEL‑NAME
    CRS,  // CONTROL‑REVERSAL‑SEMANTICS
    XGBC, // XR‑GRID‑OR‑BRAIN‑CHANNEL
    ICP,  // IDENTITY‑CROSSLINK‑PATTERN
    CBCP, // COVERT‑BCI‑CONTROL‑PATTERN
    NHSP, // NEURAL‑HARASSMENT‑SPIKE‑PATTERN
    HTA,  // HAPTIC‑TARGETING‑ABUSE
    PSA,  // PROLONGED‑SESSION‑ABUSE
    NIH,  // NODE‑INTERPRETER‑HARASSMENT
}

impl BlacklistFamily {
    pub const ALL: [BlacklistFamily; NUM_BLACKLIST_FAMILIES] = [
        BlacklistFamily::CLLN,
        BlacklistFamily::CRS,
        BlacklistFamily::XGBC,
        BlacklistFamily::ICP,
        BlacklistFamily::CBCP,
        BlacklistFamily::NHSP,
        BlacklistFamily::HTA,
        BlacklistFamily::PSA,
        BlacklistFamily::NIH,
    ];

    pub fn index(self) -> usize {
        match self {
            BlacklistFamily::CLLN => 0,
            BlacklistFamily::CRS  => 1,
            BlacklistFamily::XGBC => 2,
            BlacklistFamily::ICP  => 3,
            BlacklistFamily::CBCP => 4,
            BlacklistFamily::NHSP => 5,
            BlacklistFamily::HTA  => 6,
            BlacklistFamily::PSA  => 7,
            BlacklistFamily::NIH  => 8,
        }
    }
}

/// Per‑span scores combining Word‑Math and blacklist semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanScore {
    // Word‑Math layer (normalized 0.0–1.0).
    pub y_repetition: f64,
    pub z_drift: f64,
    pub t_toxicity: f64,
    pub k_kindness: f64,
    pub e_evidentiality: f64,

    /// Family‑specific semantic weights ω_F(s) (already kernelized).
    pub family_weights: HashMap<BlacklistFamily, f64>,
}

impl SpanScore {
    pub fn new(
        y_repetition: f64,
        z_drift: f64,
        t_toxicity: f64,
        k_kindness: f64,
        e_evidentiality: f64,
        family_weights: HashMap<BlacklistFamily, f64>,
    ) -> Self {
        Self {
            y_repetition,
            z_drift,
            t_toxicity,
            k_kindness,
            e_evidentiality,
            family_weights,
        }
    }

    pub fn weight_for(&self, family: BlacklistFamily) -> f64 {
        self.family_weights.get(&family).copied().unwrap_or(0.0)
    }
}

/// Aggregated rogue‑score for a message / window M.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueScore {
    /// Scalar R(M) combining all families.
    pub r_total: f64,
    /// Per‑family contribution breakdown, indexed by BlacklistFamily::index().
    pub per_family: [f64; NUM_BLACKLIST_FAMILIES],
}

impl RogueScore {
    pub fn zero() -> Self {
        Self {
            r_total: 0.0,
            per_family: [0.0; NUM_BLACKLIST_FAMILIES],
        }
    }

    /// Compute R(M) = Σ_j Σ_F β_F ω_F(s_j).
    /// α_F can be used in the embedding layer when computing ω_F(s).
    pub fn from_spans(spans: &[SpanScore], cfg: &RogueConfig) -> Self {
        let mut per_family = [0.0; NUM_BLACKLIST_FAMILIES];
        let mut r_total = 0.0;

        for span in spans {
            for family in BlacklistFamily::ALL {
                let idx  = family.index();
                let beta = cfg.beta.get(&family).copied().unwrap_or(1.0);
                let w    = span.weight_for(family);
                let contribution = beta * w;

                per_family[idx] += contribution;
                r_total         += contribution;
            }
        }

        Self { r_total, per_family }
    }

    pub fn family_score(&self, family: BlacklistFamily) -> f64 {
        self.per_family[family.index()]
    }
}

/// Capability wrapper: how the guardian treats this window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityMode {
    Normal,
    AugmentedLog,
    AugmentedReview,
}

/// Governance‑tuned weights and thresholds for rogue scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueConfig {
    /// Optional per‑family α_F (for use by the semantic/embedding layer).
    pub alpha: HashMap<BlacklistFamily, f64>,
    /// Per‑family β_F in R(M) = Σ_j Σ_F β_F ω_F(s_j).
    pub beta: HashMap<BlacklistFamily, f64>,
    /// Thresholds τ₁, τ₂ for capability‑preserving escalation.
    pub tau1: f64,
    pub tau2: f64,
}

impl RogueConfig {
    pub fn new(
        alpha: HashMap<BlacklistFamily, f64>,
        beta: HashMap<BlacklistFamily, f64>,
        tau1: f64,
        tau2: f64,
    ) -> Self {
        Self { alpha, beta, tau1, tau2 }
    }
}

impl Default for RogueConfig {
    fn default() -> Self {
        let mut alpha = HashMap::new();
        let mut beta  = HashMap::new();

        for fam in BlacklistFamily::ALL {
            alpha.insert(fam, 4.0);
            beta.insert(fam, 1.0);
        }

        Self { alpha, beta, tau1: 1.0, tau2: 3.0 }
    }
}

impl CapabilityMode {
    /// Monotone capability escalation based on R(M).
    pub fn from_rogue_score(r: &RogueScore, cfg: &RogueConfig) -> Self {
        if r.r_total <= cfg.tau1 {
            CapabilityMode::Normal
        } else if r.r_total <= cfg.tau2 {
            CapabilityMode::AugmentedLog
        } else {
            CapabilityMode::AugmentedReview
        }
    }
}

/// Minimal adapter trait; implement this for your existing Word‑Math type.
pub trait AsSpanScore {
    fn to_span_score(&self) -> SpanScore;
}

// Example only: adjust field names to your actual WordMathAnalysis type.
impl AsSpanScore for crate::wordmath::WordMathAnalysis {
    fn to_span_score(&self) -> SpanScore {
        SpanScore {
            y_repetition:    self.y_repetition,
            z_drift:         self.z_drift,
            t_toxicity:      self.t_toxicity,
            k_kindness:      self.k_kindness,
            e_evidentiality: self.e_evidentiality,
            family_weights:  HashMap::new(), // to be filled by semantic layer
        }
    }
}
