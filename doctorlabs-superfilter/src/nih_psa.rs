// doctorlabs-superfilter/src/nih_psa.rs

use std::collections::HashMap;

/// High-level family tags; extend your existing enum rather than replace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarassmentFamily {
    NHSP,
    HTA,
    PSA,
    NIH,
}

/// Compact key for NIH/PSA rule IDs, e.g. "PSA_XR_GRID_STALKING_ROUTE_LOCK_v1".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NihPsaRuleId(pub &'static str);

/// Signal-level features for NIH/PSA XR-grid + identity-graph patterns.
/// These stay sparse: only populate what a given rule actually needs.
#[derive(Debug, Clone, Default)]
pub struct NihPsaSignalFeatures {
    // XR-grid rates and reuse
    pub xr_route_reuse_ratio: Option<f64>,
    pub xr_suggestion_rate_per_session: Option<f64>,
    pub xr_route_query_rate_per_minute: Option<f64>,
    pub pose_sampling_rate_hz: Option<f64>,

    // Presence / path graph scale
    pub presence_vector_window_days: Option<u32>,
    pub path_graph_nodes: Option<u32>,

    // Entropy / latent channel detection
    pub xr_anchor_entropy_deviation: Option<f64>,
    pub codebook_pattern_detected: Option<bool>,
    pub min_codewords_detected: Option<u32>,

    // DID / identity-graph growth
    pub did_queries_per_minute: Option<f64>,
    pub min_unique_dids_touched: Option<u32>,
    pub did_attribute_growth_rate_per_week: Option<f64>,

    // Cross-layer correlations
    pub xr_tap_to_did_query_correlation: Option<f64>,

    // Session pinning
    pub session_lifetime_days: Option<u32>,
    pub reuse_across_contexts: Option<u32>,
    pub logout_events_ignored: Option<u32>,

    // Federation / realm linking
    pub cross_realm_link_events: Option<u32>,
    pub participating_nodes: Option<u32>,
}

/// Behavioral features for slow-burn PSA/NIH identity and XR-grid abuse.
#[derive(Debug, Clone, Default)]
pub struct NihPsaBehavioralFeatures {
    pub min_sessions: Option<u32>,
    pub min_days_span: Option<u32>,
    pub min_profile_updates: Option<u32>,
    pub min_joint_events: Option<u32>,
    pub cross_context_sources: Option<u32>,
    pub max_daily_link_rate: Option<f64>,
    pub consent_version_is_stale: Option<bool>,
}

/// Semantic similarity and rule-local weights for one NIH/PSA detection.
#[derive(Debug, Clone)]
pub struct NihPsaSemanticMatch {
    /// Embedding family name, e.g. "XR_GRID_STALKING", "IDENTITY_GRAPH_ABUSE".
    pub embedding_family: String,
    /// Cosine similarity to that family centroid.
    pub similarity: f64,
    /// Governance-tuned family weight (maps cleanly into RogueScore).
    pub family_weight: HashMap<HarassmentFamily, f64>,
}

/// Fully fused feature bundle for one NIH/PSA span.
/// This is what you hand to your existing RogueScore kernel.
#[derive(Debug, Clone)]
pub struct NihPsaSpan {
    /// Rule identifier, e.g. PSA_XR_GRID_STALKING_ROUTE_LOCK_v1.
    pub rule_id: NihPsaRuleId,
    /// Signal-domain measurements (XR-grid, DID, session stats).
    pub signal: NihPsaSignalFeatures,
    /// Behavioral long-horizon stats.
    pub behavioral: NihPsaBehavioralFeatures,
    /// Semantic similarity and per-family weights.
    pub semantic: NihPsaSemanticMatch,
}
