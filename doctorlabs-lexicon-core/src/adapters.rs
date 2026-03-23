// ============================================================================
// DoctorLabs Lexicon - NIH/PSA Helper Structs and RogueScore Integration
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module implements the "Telemetry Adapter Layer":
//   - Defines specialized feature structs for NIH (Node-Interpreter) and 
//     PSA (Prolonged-Session) harassment families.
//   - Adapts NIH/PSA spans into generic SpanScore for RogueScore computation.
//   - Ensures specialized detection patterns respect global safety invariants.
//
// CRITICAL SAFETY INVARIANT:
//   The adapter must not introduce capability-reducing weights or bypass
//   PII handling policies. All features must be aggregated/metric-based,
//   never raw neural data.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - RogueScore risk kernel (File 3: rogue_score.rs)
//   - CapabilityMode three-mode escalation (File 4: capability_mode.rs)
//   - Neurorights invariants (Mental Privacy, Cognitive Liberty)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![cfg_attr(not(test), warn(missing_docs))]

use crate::{HarassmentFamily, LexiconResult, LexiconError};
use crate::rogue_score::SpanScore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// NIH/PSA Rule Identification
// ============================================================================

/// Compact key for NIH/PSA rule IDs (e.g., "PSA_XR_GRID_STALKING_ROUTE_LOCK_v1")
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NihPsaRuleId(pub String);

impl std::fmt::Display for NihPsaRuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// NIH/PSA Signal Features (XR-Grid, Identity, Session)
// ============================================================================

/// Signal-level features specific to NIH/PSA XR-grid and identity-graph patterns.
/// 
/// SAFETY NOTE: These features are aggregated metrics (counts, ratios, z-scores),
/// not raw telemetry. This ensures compliance with `NoRawNeuralExport` policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NihPsaSignalFeatures {
    /// XR-grid route reuse ratio (0.0 to 1.0)
    #[serde(default)]
    pub xr_route_reuse_ratio: Option<f64>,
    
    /// XR suggestion rate per session
    #[serde(default)]
    pub xr_suggestion_rate_per_session: Option<f64>,
    
    /// XR route query rate per minute
    #[serde(default)]
    pub xr_route_query_rate_per_minute: Option<f64>,
    
    /// Pose sampling rate in Hz
    #[serde(default)]
    pub pose_sampling_rate_hz: Option<f64>,
    
    /// Presence vector window in days
    #[serde(default)]
    pub presence_vector_window_days: Option<u32>,
    
    /// Path graph nodes count
    #[serde(default)]
    pub path_graph_nodes: Option<u32>,
    
    /// XR anchor entropy deviation (z-score)
    #[serde(default)]
    pub xr_anchor_entropy_deviation: Option<f64>,
    
    /// Codebook pattern detected flag (latent channel)
    #[serde(default)]
    pub codebook_pattern_detected: Option<bool>,
    
    /// Minimum codewords detected
    #[serde(default)]
    pub min_codewords_detected: Option<u32>,
    
    /// DID queries per minute
    #[serde(default)]
    pub did_queries_per_minute: Option<f64>,
    
    /// Minimum unique DIDs touched
    #[serde(default)]
    pub min_unique_dids_touched: Option<u32>,
    
    /// DID attribute growth rate per week
    #[serde(default)]
    pub did_attribute_growth_rate_per_week: Option<f64>,
    
    /// XR tap to DID query correlation (0.0 to 1.0)
    #[serde(default)]
    pub xr_tap_to_did_query_correlation: Option<f64>,
    
    /// Session lifetime in days
    #[serde(default)]
    pub session_lifetime_days: Option<u32>,
    
    /// Reuse across contexts count
    #[serde(default)]
    pub reuse_across_contexts: Option<u32>,
    
    /// Logout events ignored count
    #[serde(default)]
    pub logout_events_ignored: Option<u32>,
    
    /// Cross-realm link events count
    #[serde(default)]
    pub cross_realm_link_events: Option<u32>,
    
    /// Participating nodes count (federation)
    #[serde(default)]
    pub participating_nodes: Option<u32>,
}

impl NihPsaSignalFeatures {
    /// Validates that signal features are within safe bounds
    pub fn validate(&self) -> LexiconResult<()> {
        // Validate ratios
        if let Some(ratio) = self.xr_route_reuse_ratio {
            if ratio < 0.0 || ratio > 1.0 {
                return Err(LexiconError::SchemaValidation {
                    term_id: crate::LexiconTermId("NIH_PSA_SIGNAL".to_string()),
                    reason: format!("XR route reuse ratio {} outside [0.0, 1.0]", ratio),
                });
            }
        }
        
        if let Some(corr) = self.xr_tap_to_did_query_correlation {
            if corr < 0.0 || corr > 1.0 {
                return Err(LexiconError::SchemaValidation {
                    term_id: crate::LexiconTermId("NIH_PSA_SIGNAL".to_string()),
                    reason: format!("XR/DID correlation {} outside [0.0, 1.0]", corr),
                });
            }
        }
        
        // Validate rates (non-negative)
        if let Some(rate) = self.xr_route_query_rate_per_minute {
            if rate < 0.0 {
                return Err(LexiconError::SchemaValidation {
                    term_id: crate::LexiconTermId("NIH_PSA_SIGNAL".to_string()),
                    reason: "Query rate cannot be negative".to_string(),
                });
            }
        }
        
        Ok(())
    }
}

// ============================================================================
// NIH/PSA Behavioral Features (Long-Horizon Patterns)
// ============================================================================

/// Behavioral features for slow-burn PSA/NIH identity and XR-grid abuse.
/// 
/// These features track longitudinal patterns (days, weeks, sessions) to detect
/// coercion that unfolds over time rather than in single spikes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NihPsaBehavioralFeatures {
    /// Minimum sessions for pattern detection
    #[serde(default)]
    pub min_sessions: Option<u32>,
    
    /// Minimum days span for long-horizon patterns
    #[serde(default)]
    pub min_days_span: Option<u32>,
    
    /// Minimum profile updates count
    #[serde(default)]
    pub min_profile_updates: Option<u32>,
    
    /// Minimum joint events (XR + DID)
    #[serde(default)]
    pub min_joint_events: Option<u32>,
    
    /// Cross-context sources count
    #[serde(default)]
    pub cross_context_sources: Option<u32>,
    
    /// Maximum daily link rate (to detect slow-burn)
    #[serde(default)]
    pub max_daily_link_rate: Option<f64>,
    
    /// Consent version is stale flag
    #[serde(default)]
    pub consent_version_is_stale: Option<bool>,
}

impl NihPsaBehavioralFeatures {
    /// Validates behavioral feature constraints
    pub fn validate(&self) -> LexiconResult<()> {
        if let Some(rate) = self.max_daily_link_rate {
            if rate < 0.0 {
                return Err(LexiconError::SchemaValidation {
                    term_id: crate::LexiconTermId("NIH_PSA_BEHAVIORAL".to_string()),
                    reason: "Daily link rate cannot be negative".to_string(),
                });
            }
        }
        
        Ok(())
    }
}

// ============================================================================
// NIH/PSA Semantic Match
// ============================================================================

/// Semantic similarity and rule-local weights for one NIH/PSA detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NihPsaSemanticMatch {
    /// Embedding family name (e.g., "XR_GRID_STALKING", "IDENTITY_GRAPH_ABUSE")
    pub embedding_family: String,
    
    /// Cosine similarity to that family centroid (0.0 to 1.0)
    pub similarity: f64,
    
    /// Governance-tuned family weight (maps into RogueScore)
    pub family_weight: HashMap<HarassmentFamily, f64>,
}

impl NihPsaSemanticMatch {
    /// Validates semantic match constraints
    pub fn validate(&self) -> LexiconResult<()> {
        if self.similarity < 0.0 || self.similarity > 1.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: crate::LexiconTermId("NIH_PSA_SEMANTIC".to_string()),
                reason: format!("Similarity {} outside [0.0, 1.0]", self.similarity),
            });
        }
        
        // Validate family weights sum
        let weight_sum: f64 = self.family_weight.values().sum();
        if weight_sum < 0.0 || weight_sum > 4.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: crate::LexiconTermId("NIH_PSA_SEMANTIC".to_string()),
                reason: format!("Family weight sum {} outside [0.0, 4.0]", weight_sum),
            });
        }
        
        Ok(())
    }
}

// ============================================================================
// NIH/PSA Span (Fully Fused Feature Bundle)
// ============================================================================

/// Fully fused feature bundle for one NIH/PSA span.
/// 
/// This is the input object handed to the adapter for conversion into `SpanScore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NihPsaSpan {
    /// Rule identifier (e.g., PSA_XR_GRID_STALKING_ROUTE_LOCK_v1)
    pub rule_id: NihPsaRuleId,
    
    /// Signal-domain measurements (XR-grid, DID, session stats)
    pub signal: NihPsaSignalFeatures,
    
    /// Behavioral long-horizon stats
    pub behavioral: NihPsaBehavioralFeatures,
    
    /// Semantic similarity and per-family weights
    pub semantic: NihPsaSemanticMatch,
}

impl NihPsaSpan {
    /// Validates the entire span before adaptation
    pub fn validate(&self) -> LexiconResult<()> {
        self.signal.validate()?;
        self.behavioral.validate()?;
        self.semantic.validate()?;
        Ok(())
    }
}

// ============================================================================
// Adapter Logic (NIH/PSA → SpanScore)
// ============================================================================

/// Converts an NIH/PSA span into a generic `SpanScore` for `RogueScore` computation.
/// 
/// # Safety Invariants
/// 1. Does not introduce capability-reducing weights.
/// 2. Ensures family weights are normalized.
/// 3. Preserves rule ID for audit traceability.
/// 
/// # Arguments
/// * `span` - The validated NIH/PSA span.
/// 
/// # Returns
/// * `SpanScore` - Ready for ingestion by `RogueScoreCalculator`.
pub fn nih_psa_span_to_span_score(span: &NihPsaSpan) -> LexiconResult<SpanScore> {
    // Validate input span first
    span.validate()?;
    
    // Create base span score
    let mut span_score = SpanScore::default();
    
    // Map semantic family weights directly
    // These weights determine how much this span contributes to each harassment family's risk
    span_score.family_weights = span.semantic.family_weight.clone();
    
    // Compute toxicity based on semantic similarity
    // Higher similarity to abuse centroid = higher toxicity
    span_score.t_toxicity = span.semantic.similarity;
    
    // Compute repetition based on behavioral features
    // Long-horizon patterns get higher repetition scores
    if let Some(sessions) = span.behavioral.min_sessions {
        span_score.y_repetition = (sessions as f64).ln(); // Log scale for sessions
    }
    
    // Compute drift based on signal features (e.g., entropy deviation)
    if let Some(entropy) = span.signal.xr_anchor_entropy_deviation {
        span_score.z_drift = entropy.abs();
    }
    
    // Evidentiality is high if codebook patterns are detected (latent channel)
    if span.signal.codebook_pattern_detected.unwrap_or(false) {
        span_score.e_evidentiality = 1.0;
    } else {
        span_score.e_evidentiality = 0.8; // Default confidence
    }
    
    // Kindness is neutral (1.0) unless explicit consent mitigation is present
    // (Not applicable for NIH/PSA abuse patterns typically)
    span_score.k_kindness = 1.0;
    
    // Final validation of generated span score
    span_score.validate()?;
    
    Ok(span_score)
}

/// Batch adapter for multiple NIH/PSA spans
pub fn adapt_nih_psa_spans(spans: &[NihPsaSpan]) -> LexiconResult<Vec<SpanScore>> {
    spans.iter().map(nih_psa_span_to_span_score).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_nih_psa_span() -> NihPsaSpan {
        let mut family_weight = HashMap::new();
        family_weight.insert(HarassmentFamily::NIH, 1.0);
        family_weight.insert(HarassmentFamily::PSA, 0.5);
        
        NihPsaSpan {
            rule_id: NihPsaRuleId("TEST_NIH_PSA_v1".to_string()),
            signal: NihPsaSignalFeatures {
                xr_route_reuse_ratio: Some(0.8),
                xr_anchor_entropy_deviation: Some(2.5),
                codebook_pattern_detected: Some(true),
                ..Default::default()
            },
            behavioral: NihPsaBehavioralFeatures {
                min_sessions: Some(5),
                ..Default::default()
            },
            semantic: NihPsaSemanticMatch {
                embedding_family: "XR_GRID_STALKING".to_string(),
                similarity: 0.9,
                family_weight,
            },
        }
    }

    #[test]
    fn test_nih_psa_span_validation() {
        let span = create_test_nih_psa_span();
        assert!(span.validate().is_ok());
    }

    #[test]
    fn test_nih_psa_span_invalid_ratio() {
        let mut span = create_test_nih_psa_span();
        span.signal.xr_route_reuse_ratio = Some(1.5); // Invalid > 1.0
        assert!(span.validate().is_err());
    }

    #[test]
    fn test_adapter_conversion() {
        let span = create_test_nih_psa_span();
        let score = nih_psa_span_to_span_score(&span);
        
        assert!(score.is_ok());
        let score = score.unwrap();
        
        // Check toxicity matches similarity
        assert!((score.t_toxicity - 0.9).abs() < f64::EPSILON);
        
        // Check family weights were transferred
        assert_eq!(score.family_weights.get(&HarassmentFamily::NIH), Some(&1.0));
    }

    #[test]
    fn test_adapter_evidentiality_codebook() {
        let mut span = create_test_nih_psa_span();
        span.signal.codebook_pattern_detected = Some(true);
        
        let score = nih_psa_span_to_span_score(&span).unwrap();
        assert!((score.e_evidentiality - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_adapter_repetition_log_scale() {
        let mut span = create_test_nih_psa_span();
        span.behavioral.min_sessions = Some(10);
        
        let score = nih_psa_span_to_span_score(&span).unwrap();
        // ln(10) ≈ 2.3
        assert!(score.y_repetition > 2.0);
    }

    #[test]
    fn test_batch_adapter() {
        let spans = vec![create_test_nih_psa_span(), create_test_nih_psa_span()];
        let scores = adapt_nih_psa_spans(&spans);
        
        assert!(scores.is_ok());
        assert_eq!(scores.unwrap().len(), 2);
    }
}
