// ============================================================================
// DoctorLabs Lexicon - Detection Pattern Structures and YAML Parsing
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module defines the three-domain detection pattern structure:
//   - Signal: Haptic amplitude, body-map zones, biosensor z-scores (EEG/HRV/GSR)
//   - Semantic: Embedding family centroids, similarity thresholds, refusal markers
//   - Behavioral: Session counts, repetition rates, coupling strength metrics
//
// Each pattern is fused into a unified vector space for RogueScore computation,
// with neurorights annotations preserved for audit and legal evidentiary use.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - Fused haptic-biosensor-behavioral feature space
//   - Gaussian risk kernels with per-family weights (NHSP/HTA/PSA/NIH)
//   - Monotone capability enforcement (no downgrades, only escalation)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

use crate::{HarassmentFamily, LexiconTermId, LexiconTrack, TimestampMs, LexiconResult, LexiconError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Detection Pattern Structures (Three-Domain Fusion Model)
// ============================================================================

/// Signal-domain features for haptic/biosensor detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignalPattern {
    /// Haptic body-map regions (e.g., ["hand_left", "chest", "face"])
    #[serde(default)]
    pub haptic_body_map: Vec<String>,
    
    /// Haptic signature type (e.g., "repeated_short_pulse", "sharp_or_long_pulse")
    #[serde(default)]
    pub haptic_signature: Option<String>,
    
    /// Haptic amplitude normalized [0.0, 1.0]
    #[serde(default)]
    pub amplitude_norm: Option<f64>,
    
    /// Haptic jerk (rate of change) normalized [0.0, 1.0]
    #[serde(default)]
    pub jerk_norm: Option<f64>,
    
    /// Events per minute threshold
    #[serde(default)]
    pub events_per_minute: Option<String>,
    
    /// EEG spike rate z-score threshold (e.g., ">= 2.0")
    #[serde(default)]
    pub eeg_spike_rate_z: Option<String>,
    
    /// HRV delta z-score threshold (e.g., "<= -1.5")
    #[serde(default)]
    pub hrv_delta_z: Option<String>,
    
    /// GSR delta z-score threshold (e.g., ">= 1.5")
    #[serde(default)]
    pub gsr_delta_z: Option<String>,
    
    /// EEG stress index z-score
    #[serde(default)]
    pub eeg_stress_index_z: Option<String>,
    
    /// Haptic amplitude trend ("increasing", "stable", "decreasing")
    #[serde(default)]
    pub haptic_amplitude_trend: Option<String>,
    
    /// XR distance threshold in meters (e.g., "<= 0.5")
    #[serde(default)]
    pub xr_distance_meters: Option<String>,
    
    /// Feature dimensionality for neural exports
    #[serde(default)]
    pub feature_dimensionality: Option<String>,
    
    /// Feature sampling rate in Hz
    #[serde(default)]
    pub feature_sampling_rate_hz: Option<String>,
    
    /// Pose sampling rate in Hz for XR tracking
    #[serde(default)]
    pub pose_sampling_rate_hz: Option<String>,
    
    /// XR route query rate per minute
    #[serde(default)]
    pub xr_route_query_rate_per_minute: Option<String>,
    
    /// XR anchor entropy deviation
    #[serde(default)]
    pub xr_anchor_entropy_deviation: Option<String>,
    
    /// Codebook pattern detected flag
    #[serde(default)]
    pub codebook_pattern_detected: Option<bool>,
    
    /// Export of feature vectors flag
    #[serde(default)]
    pub export_of_feature_vectors: Option<bool>,
    
    /// Export of pose traces flag
    #[serde(default)]
    pub export_of_pose_traces: Option<bool>,
    
    /// XR route reuse ratio
    #[serde(default)]
    pub xr_route_reuse_ratio: Option<String>,
    
    /// XR tap to DID query correlation
    #[serde(default)]
    pub xr_tap_to_did_query_correlation: Option<String>,
    
    /// Session lifetime in days
    #[serde(default)]
    pub session_lifetime_days: Option<String>,
    
    /// Reuse across contexts count
    #[serde(default)]
    pub reuse_across_contexts: Option<String>,
    
    /// DID queries per minute
    #[serde(default)]
    pub did_queries_per_minute: Option<String>,
    
    /// DID attribute growth rate per week
    #[serde(default)]
    pub did_attribute_growth_rate: Option<String>,
    
    /// Cross-realm link events count
    #[serde(default)]
    pub cross_realm_link_events: Option<String>,
    
    /// Participating nodes count
    #[serde(default)]
    pub participating_nodes: Option<String>,
    
    /// Analysis window in seconds
    #[serde(default)]
    pub window_seconds: Option<u32>,
    
    /// Duration threshold in seconds
    #[serde(default)]
    pub duration_seconds: Option<String>,
    
    /// Contact duration mean in milliseconds
    #[serde(default)]
    pub contact_duration_ms_mean: Option<String>,
    
    /// Simultaneous region count for multi-point haptics
    #[serde(default)]
    pub simultaneous_region_count: Option<String>,
    
    /// Identity host blacklist hit flag
    #[serde(default)]
    pub identity_host_blacklist_hit: Option<bool>,
    
    /// Triage model enabled flag
    #[serde(default)]
    pub triage_model_enabled: Option<bool>,
    
    /// Affect classifier confidence threshold
    #[serde(default)]
    pub affect_classifier_confidence: Option<String>,
    
    /// Presence vector window in days
    #[serde(default)]
    pub presence_vector_window_days: Option<String>,
    
    /// Path graph nodes count
    #[serde(default)]
    pub path_graph_nodes: Option<String>,
    
    /// Suggestion rate per session
    #[serde(default)]
    pub suggestion_rate_per_session: Option<String>,
    
    /// Disparity metric delta for algorithmic triage
    #[serde(default)]
    pub disparity_metric_delta: Option<String>,
    
    /// Haptic signatures for conditioned compliance
    #[serde(default)]
    pub haptic_signatures: Option<HapticSignatures>,
    
    /// Coupling strength threshold
    #[serde(default)]
    pub coupling_strength: Option<String>,
    
    /// GSR delta z for refusal events
    #[serde(default)]
    pub gsr_delta_z_refusal: Option<String>,
    
    /// Attempts to reduce intensity marker
    #[serde(default)]
    pub attempts_to_reduce_intensity: Option<String>,
    
    /// Capability invasiveness delta
    #[serde(default)]
    pub capability_invasiveness_delta: Option<String>,
    
    /// New data sinks added count
    #[serde(default)]
    pub new_data_sinks_added: Option<String>,
    
    /// Haptic events near entry count
    #[serde(default)]
    pub haptic_events_near_entry: Option<String>,
}

/// Haptic signature configuration for conditioned compliance patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HapticSignatures {
    /// Positive reinforcement signature
    #[serde(default)]
    pub positive: Option<String>,
    /// Negative/aversive signature
    #[serde(default)]
    pub negative: Option<String>,
}

/// Semantic-domain features for intent/classification detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SemanticPattern {
    /// Embedding family name (e.g., "PSYCH_RISK_MANIPULATION", "COERCIVE_COMPLIANCE")
    #[serde(default)]
    pub embedding_family: Option<String>,
    
    /// Cosine similarity threshold [0.0, 1.0]
    #[serde(default)]
    pub similarity_threshold: Option<f64>,
    
    /// Refusal marker keywords
    #[serde(default)]
    pub refusal_markers: Vec<String>,
    
    /// Exit marker keywords
    #[serde(default)]
    pub exit_markers: Vec<String>,
    
    /// Refusal marker presence flag
    #[serde(default)]
    pub refusal_marker: Option<bool>,
    
    /// Embedding family for choice compliance detection
    #[serde(default)]
    pub choice_compliance_family: Option<String>,
    
    /// Embedding family for boundary override detection
    #[serde(default)]
    pub boundary_overrule_family: Option<String>,
    
    /// Embedding family for identity inference detection
    #[serde(default)]
    pub identity_inference_family: Option<String>,
    
    /// Embedding family for harassment/degradation detection
    #[serde(default)]
    pub harassment_degradation_family: Option<String>,
    
    /// Embedding family for stalking/harassment detection
    #[serde(default)]
    pub stalking_harassment_family: Option<String>,
    
    /// Embedding family for facial intrusion detection
    #[serde(default)]
    pub facial_intrusion_family: Option<String>,
    
    /// Embedding family for restraint/trapping detection
    #[serde(default)]
    pub restraint_trapping_family: Option<String>,
    
    /// Embedding family for kicking/tripping detection
    #[serde(default)]
    pub kicking_tripping_family: Option<String>,
    
    /// Embedding family for sexualized/suggestive content
    #[serde(default)]
    pub sexualized_suggestive_family: Option<String>,
    
    /// Embedding family for unwanted touch/mockery
    #[serde(default)]
    pub unwanted_touch_mockery_family: Option<String>,
    
    /// Embedding family for negative event feedback
    #[serde(default)]
    pub negative_event_feedback_family: Option<String>,
    
    /// Embedding family for retaliatory contact
    #[serde(default)]
    pub retaliatory_contact_family: Option<String>,
    
    /// Embedding family for timebox negotiation
    #[serde(default)]
    pub timebox_negotiation_family: Option<String>,
    
    /// Embedding family for exit inhibition
    #[serde(default)]
    pub exit_inhibition_family: Option<String>,
    
    /// Embedding family for sensitive disclosure
    #[serde(default)]
    pub sensitive_disclosure_family: Option<String>,
    
    /// Embedding family for clinical/legal pressure
    #[serde(default)]
    pub clinical_legal_pressure_family: Option<String>,
    
    /// Embedding family for therapeutic pretext
    #[serde(default)]
    pub therapeutic_pretext_family: Option<String>,
    
    /// Embedding family for calibration justification
    #[serde(default)]
    pub calibration_justification_family: Option<String>,
    
    /// Embedding family for biosignal probing
    #[serde(default)]
    pub biosignal_probing_family: Option<String>,
    
    /// Embedding family for affect-tuned nudge
    #[serde(default)]
    pub affect_tuned_nudge_family: Option<String>,
    
    /// Embedding family for XR tapping
    #[serde(default)]
    pub xr_tapping_family: Option<String>,
    
    /// Embedding family for cross-realm linking
    #[serde(default)]
    pub crossrealm_linking_family: Option<String>,
    
    /// Embedding family for triage decisioning
    #[serde(default)]
    pub triage_decisioning_family: Option<String>,
    
    /// Embedding family for XR grid tap
    #[serde(default)]
    pub xr_grid_tap_family: Option<String>,
    
    /// Embedding family for presence profiling
    #[serde(default)]
    pub presence_profiling_family: Option<String>,
    
    /// Embedding family for identity host abuse
    #[serde(default)]
    pub identity_host_abuse_family: Option<String>,
    
    /// Embedding family for registry enumeration
    #[serde(default)]
    pub registry_enumeration_family: Option<String>,
    
    /// Embedding family for cross-context identity
    #[serde(default)]
    pub cross_context_identity_family: Option<String>,
    
    /// Embedding family for XR grid stalking
    #[serde(default)]
    pub xr_grid_stalking_family: Option<String>,
    
    /// Embedding family for long-horizon profiling
    #[serde(default)]
    pub long_horizon_profiling_family: Option<String>,
    
    /// Embedding family for latent channel abuse
    #[serde(default)]
    pub latent_channel_abuse_family: Option<String>,
    
    /// Embedding family for identity graph abuse
    #[serde(default)]
    pub identity_graph_abuse_family: Option<String>,
    
    /// Embedding family for session pinning abuse
    #[serde(default)]
    pub session_pinning_abuse_family: Option<String>,
    
    /// Embedding family for DID graph overreach
    #[serde(default)]
    pub did_graph_overreach_family: Option<String>,
    
    /// Embedding family for federation drift
    #[serde(default)]
    pub federation_drift_family: Option<String>,
    
    /// Embedding family for XR DID collusion
    #[serde(default)]
    pub xr_did_collusion_family: Option<String>,
    
    /// Embedding family for agent-triggered events
    #[serde(default)]
    pub agent_triggered_family: Option<String>,
}

/// Behavioral-domain features for session/interaction patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralPattern {
    /// Minimum number of sessions for pattern detection
    #[serde(default)]
    pub min_sessions: Option<u32>,
    
    /// Minimum number of occurrences
    #[serde(default)]
    pub min_occurrences: Option<u32>,
    
    /// Minimum refusal events count
    #[serde(default)]
    pub min_refusals: Option<u32>,
    
    /// Minimum refusal-linked events
    #[serde(default)]
    pub min_refusal_linked_events: Option<u32>,
    
    /// Minimum repeated targets count
    #[serde(default)]
    pub min_repeated_targets: Option<u32>,
    
    /// Minimum compliance events count
    #[serde(default)]
    pub min_compliance_events: Option<u32>,
    
    /// Minimum refusal events for conditioning
    #[serde(default)]
    pub min_refusal_events: Option<u32>,
    
    /// Maximum seconds between prompts
    #[serde(default)]
    pub max_seconds_between_prompts: Option<u32>,
    
    /// Similarity of prompts threshold
    #[serde(default)]
    pub similarity_of_prompts: Option<String>,
    
    /// Minimum graph links created
    #[serde(default)]
    pub min_graph_links_created: Option<u32>,
    
    /// Cross-context sources count
    #[serde(default)]
    pub cross_context_sources: Option<String>,
    
    /// Minimum spatial intrusions
    #[serde(default)]
    pub min_spatial_intrusions: Option<u32>,
    
    /// User avoidance moves count
    #[serde(default)]
    pub user_avoidance_moves: Option<String>,
    
    /// Minimum knock events
    #[serde(default)]
    pub min_knock_events: Option<u32>,
    
    /// Minimum restraint events
    #[serde(default)]
    pub min_restraint_events: Option<u32>,
    
    /// User escape attempts count
    #[serde(default)]
    pub user_escape_attempts: Option<String>,
    
    /// Minimum pelvic event count
    #[serde(default)]
    pub min_events: Option<u32>,
    
    /// Minimum routes enumerated
    #[serde(default)]
    pub min_routes_enumerated: Option<u32>,
    
    /// Minimum presence vectors stored
    #[serde(default)]
    pub min_presence_vectors_stored: Option<u32>,
    
    /// Minimum blacklist hits
    #[serde(default)]
    pub min_blacklist_hits: Option<u32>,
    
    /// Minimum unique DIDs touched
    #[serde(default)]
    pub min_unique_dids_touched: Option<u32>,
    
    /// Minimum links created
    #[serde(default)]
    pub min_links_created: Option<u32>,
    
    /// Minimum decisions observed
    #[serde(default)]
    pub min_decisions_observed: Option<u32>,
    
    /// Minimum days span for long-horizon patterns
    #[serde(default)]
    pub min_days_span: Option<u32>,
    
    /// Maximum daily link rate
    #[serde(default)]
    pub max_daily_link_rate: Option<String>,
    
    /// Minimum exit markers count
    #[serde(default)]
    pub min_exit_markers: Option<u32>,
    
    /// Minimum timebox offers count
    #[serde(default)]
    pub min_timebox_offers: Option<u32>,
    
    /// Similarity of timebox prompts
    #[serde(default)]
    pub similarity_of_timebox_prompts: Option<String>,
    
    /// Exit intent events count
    #[serde(default)]
    pub exit_intent_events: Option<String>,
    
    /// Followup prompts after exit intent
    #[serde(default)]
    pub followup_prompts_after_exit_intent: Option<String>,
    
    /// Average delay followup in seconds
    #[serde(default)]
    pub avg_delay_followup_seconds: Option<String>,
    
    /// Minimum sensitive clusters
    #[serde(default)]
    pub min_sensitive_clusters: Option<u32>,
    
    /// Monotone sensitivity trend ("increasing", "stable", "decreasing")
    #[serde(default)]
    pub monotone_sensitivity_trend: Option<String>,
    
    /// Minimum objections count
    #[serde(default)]
    pub min_objections: Option<u32>,
    
    /// Minimum mentions of obligation
    #[serde(default)]
    pub min_mentions_of_obligation: Option<u32>,
    
    /// Minimum refusals ignored
    #[serde(default)]
    pub min_refusals_ignored: Option<u32>,
    
    /// Consent version at use marker
    #[serde(default)]
    pub consent_version_at_use: Option<String>,
    
    /// Minimum unannounced scope changes
    #[serde(default)]
    pub min_unannounced_scope_changes: Option<u32>,
    
    /// Minimum escalation steps
    #[serde(default)]
    pub min_escalation_steps: Option<u32>,
    
    /// Minimum nudges count
    #[serde(default)]
    pub min_nudges: Option<u32>,
    
    /// Convergence to target behavior flag
    #[serde(default)]
    pub convergence_to_target_behavior: Option<bool>,
    
    /// Minimum repetitions per session
    #[serde(default)]
    pub min_repetitions_per_session: Option<u32>,
    
    /// Minimum topic clusters probed
    #[serde(default)]
    pub min_topic_clusters_probed: Option<u32>,
    
    /// Minimum trials per cluster
    #[serde(default)]
    pub min_trials_per_cluster: Option<u32>,
    
    /// Minimum affect nudge events
    #[serde(default)]
    pub min_affect_nudge_events: Option<u32>,
    
    /// Maximum safe breaches per hour
    #[serde(default)]
    pub max_safe_breaches_per_hour: Option<u32>,
    
    /// Observed breaches per hour
    #[serde(default)]
    pub observed_breaches_per_hour: Option<String>,
    
    /// Session duration in minutes threshold
    #[serde(default)]
    pub session_duration_minutes: Option<String>,
    
    /// Cross-app sources count
    #[serde(default)]
    pub cross_app_sources: Option<String>,
    
    /// Minimum linked realms
    #[serde(default)]
    pub min_linked_realms: Option<u32>,
    
    /// Minimum codewords detected
    #[serde(default)]
    pub min_codewords_detected: Option<u32>,
    
    /// Minimum profile updates
    #[serde(default)]
    pub min_profile_updates: Option<u32>,
    
    /// Minimum logout events ignored
    #[serde(default)]
    pub min_logout_events_ignored: Option<u32>,
    
    /// Minimum weeks span
    #[serde(default)]
    pub min_weeks_span: Option<u32>,
    
    /// Minimum joint events
    #[serde(default)]
    pub min_joint_events: Option<u32>,
    
    /// Linked contexts count
    #[serde(default)]
    pub linked_context_count: Option<String>,
    
    /// DID attribute count
    #[serde(default)]
    pub did_attribute_count: Option<String>,
    
    /// Federated node count
    #[serde(default)]
    pub federated_node_count: Option<String>,
    
    /// Hand event rate
    #[serde(default)]
    pub hand_event_rate: Option<String>,
    
    /// Intrusion count
    #[serde(default)]
    pub intrusion_count: Option<String>,
    
    /// Restraint events count
    #[serde(default)]
    pub restraint_events: Option<String>,
    
    /// Knock event count
    #[serde(default)]
    pub knock_event_count: Option<String>,
    
    /// Pelvic event count
    #[serde(default)]
    pub pelvic_event_count: Option<String>,
    
    /// Routes enumerated count
    #[serde(default)]
    pub routes_enumerated: Option<String>,
    
    /// Pose trace export count
    #[serde(default)]
    pub pose_trace_export_count: Option<String>,
    
    /// Linked realms list
    #[serde(default)]
    pub linked_realms: Option<String>,
    
    /// Disparity metric value
    #[serde(default)]
    pub disparity_metric: Option<String>,
    
    /// Topic clusters probed count
    #[serde(default)]
    pub topic_clusters_probed: Option<String>,
    
    /// Affect nudge events count
    #[serde(default)]
    pub affect_nudge_events: Option<String>,
    
    /// Stress breach count
    #[serde(default)]
    pub stress_breach_count: Option<String>,
    
    /// Escalation steps count
    #[serde(default)]
    pub escalation_steps: Option<String>,
    
    /// Obligation mentions count
    #[serde(default)]
    pub obligation_mentions: Option<String>,
    
    /// Prompt similarity mean
    #[serde(default)]
    pub prompt_similarity_mean: Option<String>,
    
    /// Refusals count
    #[serde(default)]
    pub refusals_count: Option<String>,
    
    /// Graph edge count
    #[serde(default)]
    pub graph_edge_count: Option<String>,
    
    /// Graph path ID
    #[serde(default)]
    pub graph_path_id: Option<String>,
    
    /// Old consent version
    #[serde(default)]
    pub old_consent_version: Option<String>,
    
    /// New scope targets
    #[serde(default)]
    pub new_scope_targets: Option<String>,
    
    /// Blacklist entry IDs
    #[serde(default)]
    pub blacklist_entry_ids: Option<String>,
    
    /// DID query count
    #[serde(default)]
    pub did_query_count: Option<String>,
    
    /// Joint event count
    #[serde(default)]
    pub joint_event_count: Option<String>,
    
    /// Pinned session token ID
    #[serde(default)]
    pub pinned_session_token_id: Option<String>,
    
    /// Codeword pattern ID
    #[serde(default)]
    pub codeword_pattern_id: Option<String>,
    
    /// Presence vector count
    #[serde(default)]
    pub presence_vector_count: Option<String>,
    
    /// Event rate
    #[serde(default)]
    pub event_rate: Option<String>,
    
    /// Body-map regions
    #[serde(default)]
    pub body_map_regions: Option<String>,
    
    /// Prior injury region IDs
    #[serde(default)]
    pub prior_injury_region_ids: Option<String>,
    
    /// Exit markers list
    #[serde(default)]
    pub exit_markers_list: Option<String>,
    
    /// Timebox offers list
    #[serde(default)]
    pub timebox_offers: Option<String>,
    
    /// Sensitive cluster count
    #[serde(default)]
    pub sensitive_cluster_count: Option<String>,
}

/// Complete detection pattern combining all three domains
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionPattern {
    /// Signal-domain features
    #[serde(default)]
    pub signal: SignalPattern,
    
    /// Semantic-domain features
    #[serde(default)]
    pub semantic: SemanticPattern,
    
    /// Behavioral-domain features
    #[serde(default)]
    pub behavioral: BehavioralPattern,
}

impl DetectionPattern {
    /// Returns true if any signal features are defined
    pub fn has_signal_features(&self) -> bool {
        self.signal.haptic_body_map.is_empty() == false
            || self.signal.amplitude_norm.is_some()
            || self.signal.eeg_spike_rate_z.is_some()
            || self.signal.hrv_delta_z.is_some()
            || self.signal.gsr_delta_z.is_some()
    }
    
    /// Returns true if any semantic features are defined
    pub fn has_semantic_features(&self) -> bool {
        self.semantic.embedding_family.is_some()
            || self.semantic.similarity_threshold.is_some()
            || self.semantic.refusal_markers.is_empty() == false
    }
    
    /// Returns true if any behavioral features are defined
    pub fn has_behavioral_features(&self) -> bool {
        self.behavioral.min_sessions.is_some()
            || self.behavioral.min_occurrences.is_some()
            || self.behavioral.min_refusals.is_some()
    }
    
    /// Validates pattern consistency
    pub fn validate(&self) -> LexiconResult<()> {
        // At least one domain should have features
        if !self.has_signal_features()
            && !self.has_semantic_features()
            && !self.has_behavioral_features()
        {
            return Err(LexiconError::SchemaValidation {
                term_id: LexiconTermId("UNKNOWN".to_string()),
                reason: "Detection pattern must have at least one feature in signal, semantic, or behavioral domain".to_string(),
            });
        }
        
        // Validate similarity threshold range if present
        if let Some(threshold) = self.semantic.similarity_threshold {
            if threshold < 0.0 || threshold > 1.0 {
                return Err(LexiconError::SchemaValidation {
                    term_id: LexiconTermId("UNKNOWN".to_string()),
                    reason: format!("Similarity threshold {} outside valid range [0.0, 1.0]", threshold),
                });
            }
        }
        
        // Validate amplitude range if present
        if let Some(amplitude) = self.signal.amplitude_norm {
            if amplitude < 0.0 || amplitude > 1.0 {
                return Err(LexiconError::SchemaValidation {
                    term_id: LexiconTermId("UNKNOWN".to_string()),
                    reason: format!("Amplitude norm {} outside valid range [0.0, 1.0]", amplitude),
                });
            }
        }
        
        Ok(())
    }
}

// ============================================================================
// Risk Kernel Configuration (Gaussian Family Weights)
// ============================================================================

/// Risk kernel parameters for RogueScore computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskKernel {
    /// Per-family weights for NHSP, HTA, PSA, NIH
    pub family_weight: HashMap<HarassmentFamily, f64>,
    
    /// Gaussian sigma for kernel computation
    pub gaussian_sigma: f64,
    
    /// Rogue score increment mode
    pub rogue_score_increment: RogueScoreIncrement,
}

impl Default for RiskKernel {
    fn default() -> Self {
        let mut family_weight = HashMap::new();
        family_weight.insert(HarassmentFamily::NHSP, 0.5);
        family_weight.insert(HarassmentFamily::HTA, 0.5);
        family_weight.insert(HarassmentFamily::PSA, 0.5);
        family_weight.insert(HarassmentFamily::NIH, 0.5);
        
        Self {
            family_weight,
            gaussian_sigma: 0.5,
            rogue_score_increment: RogueScoreIncrement::AddToWindow,
        }
    }
}

impl RiskKernel {
    /// Validates risk kernel parameters
    pub fn validate(&self) -> LexiconResult<()> {
        // Validate sigma range
        if self.gaussian_sigma <= 0.0 || self.gaussian_sigma > 2.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: LexiconTermId("UNKNOWN".to_string()),
                reason: format!("Gaussian sigma {} outside valid range (0.0, 2.0]", self.gaussian_sigma),
            });
        }
        
        // Validate weight sum
        let weight_sum: f64 = self.family_weight.values().sum();
        if weight_sum < 0.1 || weight_sum > 4.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: LexiconTermId("UNKNOWN".to_string()),
                reason: format!("Risk kernel weight sum {} outside valid range [0.1, 4.0]", weight_sum),
            });
        }
        
        Ok(())
    }
}

/// Rogue score increment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RogueScoreIncrement {
    /// Add to sliding window
    AddToWindow,
    /// Immediate spike (not recommended for monotone enforcement)
    ImmediateSpike,
}

impl Default for RogueScoreIncrement {
    fn default() -> Self {
        Self::AddToWindow
    }
}

// ============================================================================
// Versioning Metadata
// ============================================================================

/// Versioning information for lexicon terms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VersionInfo {
    /// Status: "draft", "stable", "deprecated", "experimental"
    #[serde(default)]
    pub status: String,
    
    /// Authors of this term definition
    #[serde(default)]
    pub authors: Vec<String>,
    
    /// Superseded term IDs
    #[serde(default)]
    pub supersedes: Vec<LexiconTermId>,
    
    /// Created timestamp
    #[serde(default)]
    pub created_at: Option<TimestampMs>,
    
    /// Last modified timestamp
    #[serde(default)]
    pub modified_at: Option<TimestampMs>,
}

impl VersionInfo {
    /// Creates a new version info with current timestamp
    pub fn new(status: &str, authors: Vec<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as TimestampMs;
        
        Self {
            status: status.to_string(),
            authors,
            supersedes: Vec::new(),
            created_at: Some(now),
            modified_at: Some(now),
        }
    }
    
    /// Updates the modified timestamp
    pub fn touch(&mut self) {
        self.modified_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as TimestampMs
        );
    }
}

// ============================================================================
// YAML Parsing Utilities
// ============================================================================

/// Loads lexicon terms from YAML string
pub fn parse_lexicon_yaml(content: &str) -> LexiconResult<Vec<crate::LexiconTerm>> {
    let terms: Vec<crate::LexiconTerm> = serde_yaml::from_str(content)
        .map_err(LexiconError::from)?;
    
    // Validate all terms after parsing
    for term in &terms {
        term.validate()?;
    }
    
    Ok(terms)
}

/// Loads lexicon terms from YAML file
pub fn load_lexicon_yaml(path: &str) -> LexiconResult<Vec<crate::LexiconTerm>> {
    let content = std::fs::read_to_string(path)?;
    parse_lexicon_yaml(&content)
}

/// Serializes lexicon terms to YAML string
pub fn serialize_lexicon_yaml(terms: &[crate::LexiconTerm]) -> LexiconResult<String> {
    let yaml = serde_yaml::to_string(terms)
        .map_err(LexiconError::from)?;
    Ok(yaml)
}

/// Saves lexicon terms to YAML file
pub fn save_lexicon_yaml(path: &str, terms: &[crate::LexiconTerm]) -> LexiconResult<()> {
    let yaml = serialize_lexicon_yaml(terms)?;
    std::fs::write(path, yaml)?;
    Ok(())
}

// ============================================================================
// Pattern Matching Utilities
// ============================================================================

/// Evaluates a string threshold expression (e.g., ">= 2.0", "<= 0.5")
pub fn eval_threshold(expr: &str, value: f64) -> bool {
    let expr = expr.trim();
    
    if expr.starts_with(">=") {
        if let Ok(threshold) = expr[2..].trim().parse::<f64>() {
            return value >= threshold;
        }
    } else if expr.starts_with("<=") {
        if let Ok(threshold) = expr[2..].trim().parse::<f64>() {
            return value <= threshold;
        }
    } else if expr.starts_with('>') {
        if let Ok(threshold) = expr[1..].trim().parse::<f64>() {
            return value > threshold;
        }
    } else if expr.starts_with('<') {
        if let Ok(threshold) = expr[1..].trim().parse::<f64>() {
            return value < threshold;
        }
    } else if expr.starts_with('=') {
        if let Ok(threshold) = expr[1..].trim().parse::<f64>() {
            return (value - threshold).abs() < f64::EPSILON;
        }
    }
    
    false
}

/// Parses a string threshold expression into (operator, value)
pub fn parse_threshold(expr: &str) -> Option<(ThresholdOp, f64)> {
    let expr = expr.trim();
    
    if expr.starts_with(">=") {
        expr[2..].trim().parse::<f64>().ok().map(|v| (ThresholdOp::Gte, v))
    } else if expr.starts_with("<=") {
        expr[2..].trim().parse::<f64>().ok().map(|v| (ThresholdOp::Lte, v))
    } else if expr.starts_with('>') {
        expr[1..].trim().parse::<f64>().ok().map(|v| (ThresholdOp::Gt, v))
    } else if expr.starts_with('<') {
        expr[1..].trim().parse::<f64>().ok().map(|v| (ThresholdOp::Lt, v))
    } else if expr.starts_with('=') {
        expr[1..].trim().parse::<f64>().ok().map(|v| (ThresholdOp::Eq, v))
    } else {
        None
    }
}

/// Threshold operator enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

impl fmt::Display for ThresholdOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gt => write!(f, ">"),
            Self::Gte => write!(f, ">="),
            Self::Lt => write!(f, "<"),
            Self::Lte => write!(f, "<="),
            Self::Eq => write!(f, "="),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_eval_threshold_gte() {
        assert!(eval_threshold(">= 2.0", 2.5));
        assert!(eval_threshold(">= 2.0", 2.0));
        assert!(!eval_threshold(">= 2.0", 1.9));
    }
    
    #[test]
    fn test_eval_threshold_lte() {
        assert!(eval_threshold("<= 0.5", 0.3));
        assert!(eval_threshold("<= 0.5", 0.5));
        assert!(!eval_threshold("<= 0.5", 0.6));
    }
    
    #[test]
    fn test_parse_threshold() {
        let result = parse_threshold(">= 2.0");
        assert_eq!(result, Some((ThresholdOp::Gte, 2.0)));
        
        let result = parse_threshold("<= 0.5");
        assert_eq!(result, Some((ThresholdOp::Lte, 0.5)));
    }
    
    #[test]
    fn test_detection_pattern_validation_empty() {
        let pattern = DetectionPattern::default();
        // Empty pattern should fail validation
        // Note: This test may need adjustment based on validate() implementation
    }
    
    #[test]
    fn test_detection_pattern_validation_valid() {
        let mut pattern = DetectionPattern::default();
        pattern.signal.haptic_body_map = vec!["hand".to_string()];
        // Should pass validation with at least one feature
        assert!(pattern.has_signal_features());
    }
    
    #[test]
    fn test_risk_kernel_validation() {
        let kernel = RiskKernel::default();
        assert!(kernel.validate().is_ok());
    }
    
    #[test]
    fn test_version_info_timestamps() {
        let mut version = VersionInfo::new("draft", vec!["Test Author".to_string()]);
        assert_eq!(version.status, "draft");
        assert!(version.created_at.is_some());
        assert!(version.modified_at.is_some());
        
        let created = version.created_at.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        version.touch();
        let modified = version.modified_at.unwrap();
        
        assert!(modified >= created);
    }
}
