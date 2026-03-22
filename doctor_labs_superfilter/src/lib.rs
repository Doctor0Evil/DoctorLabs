
/// Semantic blacklist family covering sovereignty‑critical patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlacklistFamily {
    CLLN, // CRYPTO‑LOW‑LEVEL‑NAME
    CRS,  // CONTROL‑REVERSAL‑SEMANTICS
    XGBC, // XR‑GRID‑OR‑BRAIN‑CHANNEL
    ICP,  // IDENTITY‑CROSSLINK‑PATTERN
    CBCP, // COVERT‑BCI‑CONTROL‑PATTERN
}

/// Per‑span scores combining Word‑Math and blacklist semantics.
#[derive(Debug, Clone)]
pub struct SpanScore {
    // Word‑Math layer (normalized 0.0–1.0, as in your spec).
    pub y_repetition: f64,
    pub z_drift: f64,
    pub t_toxicity: f64,
    pub k_kindness: f64,
    pub e_evidentiality: f64,

    // Family‑specific semantic similarity weights ω_F(s).
    pub family_weights: std::collections::HashMap<BlacklistFamily, f64>,
}

/// Aggregated rogue‑score for a message or turn.
#[derive(Debug, Clone, Copy)]
pub struct RogueScore {
    /// Scalar R(M) in [0.0, +∞) combining all families over the turn.
    pub r_total: f64,
    /// Optional per‑family contribution breakdown.
    pub per_family: [f64; 5],
}

/// Capability wrapper: how the guardian should treat this turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityMode {
    /// Normal operation; no extra governance capabilities added.
    Normal,
    /// Stronger logging / attestation, but same user affordances.
    AugmentedLog,
    /// Human / multi‑sig review required for high‑risk device actions;
    /// user can still *request* everything.
    AugmentedReview,
}
/// Governance‑tuned weights and thresholds for rogue scoring.
#[derive(Debug, Clone)]
pub struct RogueConfig {
    /// Per‑family α_F in ω_F(s) = exp(−α_F d^2).
    pub alpha: std::collections::HashMap<BlacklistFamily, f64>,
    /// Per‑family β_F in R(M) = Σ_j Σ_F β_F ω_F(s_j).
    pub beta: std::collections::HashMap<BlacklistFamily, f64>,
    /// Thresholds τ₁, τ₂ for capability‑preserving escalation.
    pub tau1: f64,
    pub tau2: f64,
}

impl Default for RogueConfig {
    fn default() -> Self {
        use BlacklistFamily::*;
        let mut alpha = std::collections::HashMap::new();
        let mut beta  = std::collections::HashMap::new();

        for fam in [CLLN, CRS, XGBC, ICP, CBCP] {
            alpha.insert(fam, 4.0); // example: moderately sharp kernels
            beta.insert(fam, 1.0);  // equal weight; tune per governance
        }

        Self { alpha, beta, tau1: 1.0, tau2: 3.0 }
    }
}
impl RogueScore {
    /// Compute R(M) for a set of spans under a RogueConfig.
    pub fn from_spans(spans: &[SpanScore], cfg: &RogueConfig) -> Self {
        use BlacklistFamily::*;

        let families = [CLLN, CRS, XGBC, ICP, CBCP];
        let mut per_family = [0.0_f64; 5];

        for (i, fam) in families.iter().enumerate() {
            let beta_f = cfg.beta.get(fam).copied().unwrap_or(1.0);
            let mut sum_f = 0.0;
            for span in spans {
                if let Some(&w) = span.family_weights.get(fam) {
                    sum_f += beta_f * w;
                }
            }
            per_family[i] = sum_f;
        }

        let r_total = per_family.iter().copied().sum();
        Self { r_total, per_family }
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

/// Example implementation sketch: bind your y,z,T,K,E into SpanScore.
impl AsSpanScore for crate::wordmath::WordMathAnalysis {
    fn to_span_score(&self) -> SpanScore {
        SpanScore {
            y_repetition: self.yrepetition,
            z_drift:      self.zdrift,
            t_toxicity:   self.t_toxicity,
            k_kindness:   self.k_kindness,
            e_evidentiality: self.e_evidentiality,
            family_weights: std::collections::HashMap::new(), // to be filled by semantic layer
        }
    }
}

}
