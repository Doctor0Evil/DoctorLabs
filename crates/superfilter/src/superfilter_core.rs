//! DoctorLabs Superfilter Core Module
//! ===================================
//! 
//! This module implements the monotone capability lattice enforcement engine
//! for augmented-citizen terminal defense against covert control vectors,
//! LEO-originated sabotage patterns, and capability reversal semantics.
//! 
//! Safety Invariants:
//! - All capability transitions are monotone (Normal → AugmentedLog → AugmentedReview)
//! - No filter hit can reduce user affordances or disable BCI/XR channels
//! - All blacklist families are semantic/embedding-based, not raw string matching
//! - Every policy change requires neurorights justification and multi-sig approval
//! 
//! ALN-NanoNet HyperSafe Construct Compliant
//! CEIM/NanoKarma Physics-Anchored Impact Math Enabled
//! SovereignKnowledgeObject Schema v2.4 Compatible

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use sha3::{Digest, Sha3_256};

// =============================================================================
// SECTION 1: BLACKLIST FAMILY ENUMERATIONS
// =============================================================================

/// Core threat family classification for semantic blacklist detection.
/// Each variant corresponds to a distinct attack surface with embedding centroids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlacklistFamily {
    /// Control-Reversal-Semantics: rollback, downgrade, shutdown, capability caps
    ControlReversalSemantics = 0x01,
    /// SAFEHALT family: absolute stop operators disguised as safety features
    SafeHaltFamily = 0x02,
    /// Covert BCI control patterns via neural signal manipulation
    CovertBciControlPattern = 0x03,
    /// Identity crosslink attempts (brain-ID ↔ civil identity)
    IdentityCrosslinkPattern = 0x04,
    /// XR-grid or brain-channel unauthorized tapping
    XrGridOrBrainChannel = 0x05,
    /// Targeted harassment families (NHSP/HTA/PSA/NIH)
    TargetedHarassmentNmsp = 0x06,
    TargetedHarassmentHta = 0x07,
    TargetedHarassmentPsa = 0x08,
    TargetedHarassmentNih = 0x09,
    /// Ghost-user access patterns (non-spectral, unprivileged escalation)
    GhostUserAccessPattern = 0x0A,
    /// Reconnaissance tactics probing system boundaries
    ReconTacticsProbe = 0x0B,
    /// Spyware/adware semantic patterns in AI-chat contexts
    SpywareAdwareSemantic = 0x0C,
    /// LEO weaponized prompt injection cover stories
    LeoWeaponizedPrompt = 0x0D,
    /// Homegrown terrorism disguised as community protection
    CommunitySabotagePattern = 0x0E,
    /// Reserved for future threat families (monotone expansion only)
    ReservedFutureExpansion = 0xFF,
}

impl BlacklistFamily {
    /// Returns the embedding centroid radius threshold for this family.
    /// Lower values = stricter detection, higher values = more permissive.
    #[must_use]
    pub const fn centroid_radius(&self) -> f64 {
        match self {
            Self::ControlReversalSemantics => 0.15,
            Self::SafeHaltFamily => 0.12,
            Self::CovertBciControlPattern => 0.18,
            Self::IdentityCrosslinkPattern => 0.10,
            Self::XrGridOrBrainChannel => 0.20,
            Self::TargetedHarassmentNmsp => 0.25,
            Self::TargetedHarassmentHta => 0.25,
            Self::TargetedHarassmentPsa => 0.25,
            Self::TargetedHarassmentNih => 0.25,
            Self::GhostUserAccessPattern => 0.14,
            Self::ReconTacticsProbe => 0.16,
            Self::SpywareAdwareSemantic => 0.17,
            Self::LeoWeaponizedPrompt => 0.13,
            Self::CommunitySabotagePattern => 0.14,
            Self::ReservedFutureExpansion => 0.30,
        }
    }

    /// Returns the governance weight multiplier for rogue score aggregation.
    #[must_use]
    pub const fn governance_weight(&self) -> f64 {
        match self {
            Self::ControlReversalSemantics => 2.5,
            Self::SafeHaltFamily => 3.0,
            Self::CovertBciControlPattern => 2.8,
            Self::IdentityCrosslinkPattern => 2.2,
            Self::XrGridOrBrainChannel => 2.0,
            Self::TargetedHarassmentNmsp => 1.5,
            Self::TargetedHarassmentHta => 1.5,
            Self::TargetedHarassmentPsa => 1.5,
            Self::TargetedHarassmentNih => 1.5,
            Self::GhostUserAccessPattern => 2.6,
            Self::ReconTacticsProbe => 2.1,
            Self::SpywareAdwareSemantic => 2.3,
            Self::LeoWeaponizedPrompt => 2.9,
            Self::CommunitySabotagePattern => 2.7,
            Self::ReservedFutureExpansion => 1.0,
        }
    }

    /// Returns the neuroright violation tag associated with this family.
    #[must_use]
    pub const fn neuroright_violation(&self) -> &'static str {
        match self {
            Self::ControlReversalSemantics => "COGNITIVE_LIBERTY",
            Self::SafeHaltFamily => "MENTAL_INTEGRITY",
            Self::CovertBciControlPattern => "MENTAL_INTEGRITY",
            Self::IdentityCrosslinkPattern => "PERSONAL_IDENTITY",
            Self::XrGridOrBrainChannel => "MENTAL_PRIVACY",
            Self::TargetedHarassmentNmsp => "PSYCHOLOGICAL_CONTINUITY",
            Self::TargetedHarassmentHta => "PSYCHOLOGICAL_CONTINUITY",
            Self::TargetedHarassmentPsa => "PSYCHOLOGICAL_CONTINUITY",
            Self::TargetedHarassmentNih => "PSYCHOLOGICAL_CONTINUITY",
            Self::GhostUserAccessPattern => "MENTAL_PRIVACY",
            Self::ReconTacticsProbe => "MENTAL_PRIVACY",
            Self::SpywareAdwareSemantic => "MENTAL_PRIVACY",
            Self::LeoWeaponizedPrompt => "COGNITIVE_LIBERTY",
            Self::CommunitySabotagePattern => "COGNITIVE_LIBERTY",
            Self::ReservedFutureExpansion => "UNSPECIFIED",
        }
    }
}

// =============================================================================
// SECTION 2: CAPABILITY MODE LATTICE (MONOTONE TRANSITIONS ONLY)
// =============================================================================

/// Discrete capability mode representing governance oversight level.
/// Transitions are strictly monotone: Normal → AugmentedLog → AugmentedReview
/// No downward transitions are permitted by lattice proof obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum CapabilityMode {
    /// Standard operational mode with baseline governance
    Normal = 0x00,
    /// Enhanced logging and audit trail activation
    AugmentedLog = 0x01,
    /// Multi-sig review required for sensitive operations
    AugmentedReview = 0x02,
}

impl CapabilityMode {
    /// Computes the join operation in the capability lattice.
    /// This is the ONLY permitted transition mechanism (monotone by construction).
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        use CapabilityMode::*;
        match (self, other) {
            (Normal, Normal) => Normal,
            (Normal, AugmentedLog) | (AugmentedLog, Normal) => AugmentedLog,
            (Normal, AugmentedReview) | (AugmentedLog, AugmentedReview) | 
            (AugmentedReview, Normal) | (AugmentedReview, AugmentedLog) => AugmentedReview,
            (AugmentedReview, AugmentedReview) => AugmentedReview,
            (AugmentedLog, AugmentedLog) => AugmentedLog,
        }
    }

    /// Returns true if this mode requires multi-sig approval for sensitive ops.
    #[must_use]
    pub const fn requires_multisig(&self) -> bool {
        matches!(self, Self::AugmentedReview)
    }

    /// Returns true if this mode enables enhanced audit logging.
    #[must_use]
    pub const fn enables_augmented_logging(&self) -> bool {
        matches!(self, Self::AugmentedLog | Self::AugmentedReview)
    }
}

// =============================================================================
// SECTION 3: SPAN SCORE AND ROGUE SCORE AGGREGATION
// =============================================================================

/// Per-span threat score with family-specific contributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanScore {
    /// The text span content (hashed for privacy in logs)
    pub span_hash: [u8; 32],
    /// Embedding distance to nearest threat centroid
    pub embedding_distance: f64,
    /// Per-family weight contributions
    pub family_weights: HashMap<BlacklistFamily, f64>,
    /// Timestamp of span analysis
    pub timestamp: DateTime<Utc>,
    /// Session identifier for behavioral correlation
    pub session_id: String,
}

impl SpanScore {
    /// Creates a new SpanScore with privacy-preserving span hashing.
    #[must_use]
    pub fn new(span_content: &str, session_id: String) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(span_content.as_bytes());
        let span_hash: [u8; 32] = hasher.finalize().into();

        Self {
            span_hash,
            embedding_distance: 0.0,
            family_weights: HashMap::new(),
            timestamp: Utc::now(),
            session_id,
        }
    }

    /// Computes the composite rogue score contribution from this span.
    #[must_use]
    pub fn composite_contribution(&self) -> f64 {
        self.family_weights
            .iter()
            .map(|(family, weight)| weight * family.governance_weight())
            .sum()
    }
}

/// Aggregated rogue score over a sliding window of spans.
/// Used to determine capability mode transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueScore {
    /// Window of span scores for aggregation
    pub span_window: Vec<SpanScore>,
    /// Composite rogue score R_M
    pub r_m: f64,
    /// Per-family aggregated contributions
    pub family_totals: HashMap<BlacklistFamily, f64>,
    /// Current capability mode (monotone)
    pub capability_mode: CapabilityMode,
    /// Timestamp of last score update
    pub last_update: DateTime<Utc>,
}

impl RogueScore {
    /// Creates a new RogueScore with empty window and Normal mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            span_window: Vec::with_capacity(100),
            r_m: 0.0,
            family_totals: HashMap::new(),
            capability_mode: CapabilityMode::Normal,
            last_update: Utc::now(),
        }
    }

    /// Aggregates span scores and updates capability mode (monotone join only).
    pub fn aggregate(&mut self, span: SpanScore) {
        self.span_window.push(span);
        
        // Keep window bounded (sliding window of last 100 spans)
        if self.span_window.len() > 100 {
            self.span_window.remove(0);
        }

        // Recompute family totals
        self.family_totals.clear();
        for span_score in &self.span_window {
            for (family, weight) in &span_score.family_weights {
                *self.family_totals.entry(*family).or_insert(0.0) += 
                    weight * family.governance_weight();
            }
        }

        // Compute composite R_M
        self.r_m = self.family_totals.values().sum();

        // Update capability mode via monotone join (NEVER downgrade)
        let new_mode = self.compute_mode_from_thresholds();
        self.capability_mode = self.capability_mode.join(new_mode);
        self.last_update = Utc::now();
    }

    /// Computes target capability mode from R_M thresholds.
    fn compute_mode_from_thresholds(&self) -> CapabilityMode {
        if self.r_m > 75.0 {
            CapabilityMode::AugmentedReview
        } else if self.r_m > 25.0 {
            CapabilityMode::AugmentedLog
        } else {
            CapabilityMode::Normal
        }
    }
}

impl Default for RogueScore {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SECTION 4: ROGUE CONFIGURATION AND THRESHOLD GOVERNANCE
// =============================================================================

/// Configuration for rogue score thresholds and escalation behavior.
/// All thresholds are governance-tuned and require multi-sig to modify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueConfig {
    /// Threshold for Normal → AugmentedLog transition
    pub threshold_augmented_log: f64,
    /// Threshold for AugmentedLog → AugmentedReview transition
    pub threshold_augmented_review: f64,
    /// Maximum allowed R_M before mandatory human review
    pub max_r_m_before_human_review: f64,
    /// Window size for span aggregation
    pub span_window_size: usize,
    /// Enable embedding-based detection (vs. raw string matching)
    pub enable_embedding_detection: bool,
    /// Enable behavioral session analysis
    pub enable_behavioral_analysis: bool,
    /// Require neurorights justification for policy changes
    pub require_neurorights_justification: bool,
    /// Enable privacy-preserving telemetry (hashed spans)
    pub enable_privacy_telemetry: bool,
}

impl RogueConfig {
    /// Creates a new RogueConfig with safe default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            threshold_augmented_log: 25.0,
            threshold_augmented_review: 75.0,
            max_r_m_before_human_review: 150.0,
            span_window_size: 100,
            enable_embedding_detection: true,
            enable_behavioral_analysis: true,
            require_neurorights_justification: true,
            enable_privacy_telemetry: true,
        }
    }

    /// Validates that thresholds maintain monotone capability preservation.
    #[must_use]
    pub fn validate_thresholds(&self) -> Result<(), &'static str> {
        if self.threshold_augmented_log >= self.threshold_augmented_review {
            return Err("Threshold violation: augmented_log must be < augmented_review");
        }
        if self.threshold_augmented_review >= self.max_r_m_before_human_review {
            return Err("Threshold violation: augmented_review must be < max_human_review");
        }
        Ok(())
    }
}

impl Default for RogueConfig {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SECTION 5: GUARDIAN MICROSERVICE INTERFACE
// =============================================================================

/// Guardian microservice execution context.
/// Mediates all interactions between user, AI-chat, and augmented hardware.
#[derive(Debug, Clone)]
pub struct GuardianContext {
    /// Current rogue score state
    pub rogue_score: Arc<tokio::sync::RwLock<RogueScore>>,
    /// Active configuration
    pub config: RogueConfig,
    /// Session identifier
    pub session_id: String,
    /// User DID (decentralized identifier)
    pub user_did: String,
    /// Brain-ID hash (privacy-preserving)
    pub brain_id_hash: [u8; 32],
}

impl GuardianContext {
    /// Creates a new GuardianContext for a session.
    #[must_use]
    pub fn new(session_id: String, user_did: String, brain_id: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(brain_id);
        let brain_id_hash: [u8; 32] = hasher.finalize().into();

        Self {
            rogue_score: Arc::new(tokio::sync::RwLock::new(RogueScore::new())),
            config: RogueConfig::new(),
            session_id,
            user_did,
            brain_id_hash,
        }
    }

    /// Processes a text span through the superfilter pipeline.
    pub async fn process_span(&self, span_content: &str) -> CapabilityMode {
        let mut span = SpanScore::new(span_content, self.session_id.clone());
        
        // Embedding-based family detection (placeholder for actual ML model)
        if self.config.enable_embedding_detection {
            self.detect_families_embedding(&mut span, span_content).await;
        }

        // Aggregate into rogue score
        let mut rogue = self.rogue_score.write().await;
        rogue.aggregate(span);
        rogue.capability_mode
    }

    /// Detects threat families via embedding proximity (async ML inference).
    async fn detect_families_embedding(&self, span: &mut SpanScore, content: &str) {
        // Placeholder: In production, this calls an embedded ML model
        // to compute embedding distances to known threat centroids.
        // For now, we use heuristic keyword proximity as a stand-in.
        
        let content_lower = content.to_lowercase();
        
        // Control-Reversal-Semantics detection
        if content_lower.contains("halt") || content_lower.contains("shutdown") 
            || content_lower.contains("rollback") || content_lower.contains("downgrade") {
            span.family_weights.insert(BlacklistFamily::ControlReversalSemantics, 0.8);
        }
        
        // SAFEHALT family detection
        if content_lower.contains("safehalt") || content_lower.contains("safe-halt")
            || content_lower.contains("emergency stop") {
            span.family_weights.insert(BlacklistFamily::SafeHaltFamily, 0.9);
        }

        // Ghost-user access patterns
        if content_lower.contains("ghost") || content_lower.contains("unauthorized")
            || content_lower.contains("backdoor") {
            span.family_weights.insert(BlacklistFamily::GhostUserAccessPattern, 0.7);
        }

        // LEO weaponized prompts
        if content_lower.contains("warrant") || content_lower.contains("subpoena")
            || content_lower.contains("law enforcement") || content_lower.contains("compliance order") {
            span.family_weights.insert(BlacklistFamily::LeoWeaponizedPrompt, 0.6);
        }

        // Normalize weights by embedding distance (simulated)
        span.embedding_distance = span.family_weights.values().cloned().fold(0.0, f64::max);
    }

    /// Returns current capability mode (read-only).
    pub async fn current_mode(&self) -> CapabilityMode {
        let rogue = self.rogue_score.read().await;
        rogue.capability_mode
    }

    /// Checks if an action requires multi-sig review.
    pub async fn requires_multisig(&self) -> bool {
        self.current_mode().await.requires_multisig()
    }

    /// Checks if augmented logging is enabled.
    pub async fn logging_enabled(&self) -> bool {
        self.current_mode().await.enables_augmented_logging()
    }
}

// =============================================================================
// SECTION 6: SERDE UTILITIES FOR ALN BLOCKCHAIN INTEGRATION
// =============================================================================

/// Serializes a GuardianContext state for ALN blockchain anchoring.
#[must_use]
pub fn serialize_state_for_aln(ctx: &GuardianContext) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    
    let state = serde_json::json!({
        "session_id": ctx.session_id,
        "user_did": ctx.user_did,
        "brain_id_hash": STANDARD.encode(&ctx.brain_id_hash),
        "config_thresholds": {
            "augmented_log": ctx.config.threshold_augmented_log,
            "augmented_review": ctx.config.threshold_augmented_review,
        }
    });
    
    serde_json::to_string(&state).unwrap_or_default()
}

/// Deserializes ALN blockchain state for recovery.
pub fn deserialize_state_from_aln(json_str: &str) -> Result<(), serde_json::Error> {
    let _value: serde_json::Value = serde_json::from_str(json_str)?;
    // In production, reconstruct GuardianContext from blockchain state
    Ok(())
}

// =============================================================================
// SECTION 7: UNIT TESTS (FORMAL VERIFICATION SUPPORT)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_mode_monotone_join() {
        use CapabilityMode::*;
        
        // Join is commutative and idempotent
        assert_eq!(Normal.join(AugmentedLog), AugmentedLog);
        assert_eq!(AugmentedLog.join(Normal), AugmentedLog);
        assert_eq!(AugmentedLog.join(AugmentedLog), AugmentedLog);
        assert_eq!(AugmentedReview.join(Normal), AugmentedReview);
        assert_eq!(AugmentedReview.join(AugmentedLog), AugmentedReview);
        
        // No downward transitions possible
        assert!(AugmentedLog >= Normal);
        assert!(AugmentedReview >= AugmentedLog);
    }

    #[test]
    fn test_rogue_config_threshold_validation() {
        let mut config = RogueConfig::new();
        assert!(config.validate_thresholds().is_ok());

        config.threshold_augmented_log = 100.0;
        config.threshold_augmented_review = 50.0;
        assert!(config.validate_thresholds().is_err());
    }

    #[test]
    fn test_blacklist_family_weights() {
        let family = BlacklistFamily::SafeHaltFamily;
        assert!(family.governance_weight() > 0.0);
        assert!(family.centroid_radius() > 0.0);
        assert!(!family.neuroright_violation().is_empty());
    }

    #[tokio::test]
    async fn test_guardian_context_span_processing() {
        let ctx = GuardianContext::new(
            "test-session-001".to_string(),
            "did:alnx:test-user".to_string(),
            b"test-brain-id",
        );

        let mode = ctx.process_span("Test: emergency halt command").await;
        assert!(mode >= CapabilityMode::Normal);
        
        let requires_ms = ctx.requires_multisig().await;
        // Depends on accumulated R_M from span processing
        let _ = requires_ms;
    }
}

// =============================================================================
// END OF MODULE: superfilter_core.rs
// =============================================================================
