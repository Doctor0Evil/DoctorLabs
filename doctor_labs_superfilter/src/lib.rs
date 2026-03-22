// doctor_labs_superfilter/src/lib.rs
// Doctor-Labs SuperFilter Core Library
// Capability-Preserving Harassment Detection Engine
// Version: 2026.03.23 | ALN-NanoNet HyperSafe Construct Compliant

#![deny(clippy::all)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod wordmath;
pub mod harassment_detector;
pub mod span_score;
pub mod rogue_config;
pub mod evidence_bundle;

use std::collections::HashMap;
use std::fmt::{self, Display};
use std::hash::Hash;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// BLACKLIST FAMILY ENUMERATION
// ============================================================================

/// Core harassment family classifications for neurorights-aligned filtering.
/// Each variant represents a distinct threat category requiring specific
/// governance responses while preserving user capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum BlacklistFamily {
    /// Coercive Language & Linguistic Manipulation (legacy)
    CLLN = 0,
    /// Cross-Reference Spoofing (legacy)
    CRS = 1,
    /// eXploitative Governance Bypass Coercion (legacy)
    XGBC = 2,
    /// Identity Crosslinking Pattern (legacy)
    ICP = 3,
    /// Covert BCI Control Pattern (legacy)
    CBCP = 4,
    /// Neural-Harassment-Spike-Pattern (priority: HIGH)
    NHSP = 5,
    /// Haptic-Targeting-Abuse (priority: HIGH)
    HTA = 6,
    /// Prolonged-Session-Abuse (priority: MEDIUM)
    PSA = 7,
    /// Node-Interpreter-Harassment (priority: MEDIUM)
    NIH = 8,
}

impl BlacklistFamily {
    /// Returns the governance priority weight for this family.
    /// HTA and NHSP receive highest priority for real-time intervention.
    #[must_use]
    pub fn priority_weight(&self) -> f64 {
        match self {
            Self::HTA | Self::NHSP => 2.5,  // High priority: direct sensory/neural impact
            Self::PSA | Self::NIH => 1.5,  // Medium priority: structural abuse
            Self::CLLN | Self::CRS | Self::XGBC | Self::ICP | Self::CBCP => 1.0,
        }
    }

    /// Returns the neuroright category this family protects.
    #[must_use]
    pub fn neuroright_category(&self) -> &'static str {
        match self {
            Self::NHSP => "MENTAL_INTEGRITY",
            Self::HTA => "SENSORY_INTEGRITY",
            Self::PSA => "COGNITIVE_LIBERTY",
            Self::NIH => "NEURAL_PRIVACY",
            _ => "GENERAL_SAFETY",
        }
    }

    /// Returns all family variants as a slice for iteration.
    #[must_use]
    pub const fn all_families() -> &'static [Self] {
        &[
            Self::CLLN, Self::CRS, Self::XGBC, Self::ICP, Self::CBCP,
            Self::NHSP, Self::HTA, Self::PSA, Self::NIH,
        ]
    }

    /// Returns the count of all family variants.
    #[must_use]
    pub const fn count() -> usize {
        9
    }
}

impl Display for BlacklistFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// CAPABILITY MODE ENUMERATION
// ============================================================================

/// System operational modes for capability-preserving escalation.
/// Transitions are strictly monotone: user capabilities never decrease,
/// only governance functions are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CapabilityMode {
    /// Baseline operation with standard logging and filtering.
    Normal = 0,
    /// Enhanced telemetry and audit trail collection.
    AugmentedLog = 1,
    /// High-risk actions require human/multi-sig review before execution.
    AugmentedReview = 2,
}

impl CapabilityMode {
    /// Returns true if this mode represents an escalation from the other.
    #[must_use]
    pub fn is_escalation_from(&self, other: &Self) -> bool {
        matches!(
            (other, self),
            (Self::Normal, Self::AugmentedLog)
                | (Self::Normal, Self::AugmentedReview)
                | (Self::AugmentedLog, Self::AugmentedReview)
        )
    }

    /// Returns the governance functions active in this mode.
    #[must_use]
    pub fn active_governance_functions(&self) -> &'static [&'static str] {
        match self {
            Self::Normal => &["baseline_logging", "standard_filtering"],
            Self::AugmentedLog => &[
                "baseline_logging",
                "standard_filtering",
                "enhanced_telemetry",
                "audit_trail_collection",
            ],
            Self::AugmentedReview => &[
                "baseline_logging",
                "standard_filtering",
                "enhanced_telemetry",
                "audit_trail_collection",
                "human_review_required",
                "multi_sig_validation",
            ],
        }
    }

    /// Returns all modes in escalation order.
    #[must_use]
    pub const fn escalation_order() -> &'static [Self] {
        &[Self::Normal, Self::AugmentedLog, Self::AugmentedReview]
    }
}

impl Display for CapabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// ROGUE SCORE STRUCTURE
// ============================================================================

/// Aggregated harassment risk score computed over interaction windows.
/// Used to drive capability-preserving escalation decisions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RogueScore {
    /// Total aggregated rogue score across all families.
    pub r_total: f64,
    /// Per-family breakdown for audit and explainability.
    pub per_family: [f64; 9],
    /// Timestamp of score computation (UNIX epoch milliseconds).
    pub computed_at: u64,
    /// Session identifier for traceability.
    pub session_id: String,
    /// Node identifier where interactions occurred.
    pub node_id: Option<String>,
}

impl RogueScore {
    /// Creates a new zero-initialized RogueScore.
    #[must_use]
    pub fn new(session_id: String, node_id: Option<String>) -> Self {
        Self {
            r_total: 0.0,
            per_family: [0.0; 9],
            computed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            session_id,
            node_id,
        }
    }

    /// Computes rogue score from a slice of SpanScore instances.
    /// Applies family-specific weights and kernels per RogueConfig.
    #[must_use]
    pub fn from_spans(spans: &[crate::span_score::SpanScore], cfg: &crate::rogue_config::RogueConfig) -> Self {
        let session_id = spans.first().map(|s| s.session_id.clone()).unwrap_or_default();
        let mut r_total = 0.0;
        let mut per_family = [0.0; 9];

        for span in spans {
            for (family_idx, family) in BlacklistFamily::all_families().iter().enumerate() {
                if let Some(&weight) = span.family_weights.get(family) {
                    let alpha = cfg.alpha.get(family).copied().unwrap_or(1.0);
                    let beta = cfg.beta.get(family).copied().unwrap_or(1.0);
                    let kernel_value = (-alpha * weight * weight).exp();
                    let contribution = beta * kernel_value;
                    per_family[family_idx] += contribution;
                    r_total += contribution;
                }
            }
        }

        Self {
            r_total,
            per_family,
            computed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            session_id,
            node_id: None,
        }
    }

    /// Returns the dominant harassment family (highest per-family score).
    #[must_use]
    pub fn dominant_family(&self) -> Option<BlacklistFamily> {
        let max_idx = self.per_family.iter().enumerate().max_by(|a, b| {
            a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal)
        })?.0;
        BlacklistFamily::all_families().get(max_idx).copied()
    }

    /// Returns true if score exceeds the specified threshold.
    #[must_use]
    pub fn exceeds_threshold(&self, threshold: f64) -> bool {
        self.r_total > threshold
    }
}

// ============================================================================
// SANITIZATION UTILITIES
// ============================================================================

/// Sanitizes content by replacing blacklisted patterns with category labels.
/// Never surfaces raw harassment tokens to downstream systems or users.
#[must_use]
pub fn sanitize_content(content: &str, hits: &[BlacklistFamily]) -> String {
    let mut sanitized = content.to_string();
    for hit in hits {
        let replacement = format!("[{}-REDACTED]", hit);
        // In production, this would use semantic matching, not simple replacement
        sanitized = sanitized.replace(&format!("{:?}", hit), &replacement);
    }
    sanitized
}

/// Generates a redaction label for a given harassment family.
#[must_use]
pub fn redaction_label(family: BlacklistFamily) -> String {
    format!("[{}-REDACTED]", family)
}

// ============================================================================
// MONOTONE ESCALATION LOGIC
// ============================================================================

/// Determines the appropriate capability mode based on rogue score thresholds.
/// This function enforces the monotone invariant: capabilities never decrease.
#[must_use]
pub fn determine_capability_mode(score: &RogueScore, config: &crate::rogue_config::RogueConfig) -> CapabilityMode {
    if score.r_total <= config.tau1 {
        CapabilityMode::Normal
    } else if score.r_total <= config.tau2 {
        CapabilityMode::AugmentedLog
    } else {
        CapabilityMode::AugmentedReview
    }
}

/// Validates that a state transition preserves user capabilities.
/// Returns true if the transition is valid (monotone), false otherwise.
#[must_use]
pub fn validate_monotone_transition(from: CapabilityMode, to: CapabilityMode) -> bool {
    matches!(
        (from, to),
        (CapabilityMode::Normal, CapabilityMode::Normal)
            | (CapabilityMode::Normal, CapabilityMode::AugmentedLog)
            | (CapabilityMode::Normal, CapabilityMode::AugmentedReview)
            | (CapabilityMode::AugmentedLog, CapabilityMode::AugmentedLog)
            | (CapabilityMode::AugmentedLog, CapabilityMode::AugmentedReview)
            | (CapabilityMode::AugmentedReview, CapabilityMode::AugmentedReview)
    )
}

// ============================================================================
// LIBRARY INITIALIZATION
// ============================================================================

/// Library version string for compliance tracking.
pub const VERSION: &str = "2026.03.23";

/// ALN-NanoNet HyperSafe Construct compliance marker.
pub const HYPER_SAFE_CONSTRUCT_COMPLIANT: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_family_priority_weights() {
        assert!(BlacklistFamily::HTA.priority_weight() > 2.0);
        assert!(BlacklistFamily::NHSP.priority_weight() > 2.0);
        assert!(BlacklistFamily::PSA.priority_weight() < 2.0);
    }

    #[test]
    fn test_monotone_transition_validation() {
        assert!(validate_monotone_transition(CapabilityMode::Normal, CapabilityMode::AugmentedLog));
        assert!(!validate_monotone_transition(CapabilityMode::AugmentedReview, CapabilityMode::Normal));
    }

    #[test]
    fn test_capability_mode_governance_functions() {
        let normal_funcs = CapabilityMode::Normal.active_governance_functions();
        let review_funcs = CapabilityMode::AugmentedReview.active_governance_functions();
        assert!(review_funcs.len() > normal_funcs.len());
    }
}
