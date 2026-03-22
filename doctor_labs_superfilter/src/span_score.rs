// doctor_labs_superfilter/src/span_score.rs
// Span Score Module - Individual Interaction Span Analysis
// Doctor-Labs SuperFilter Core Library
// Version: 2026.03.23 | ALN-NanoNet HyperSafe Construct Compliant

#![deny(clippy::all)]
#![warn(missing_docs)]

use crate::{BlacklistFamily, RogueScore};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// ============================================================================
// WORD MATH ANALYTICS STRUCTURE
// ============================================================================

/// Core analytical metrics for span evaluation.
/// These five dimensions (y, z, T, K, E) form the basis for
/// harassment detection and capability escalation decisions.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WordMath {
    /// Repetition coefficient: measures pattern recurrence frequency.
    /// Range: 0.0 (unique) to 1.0 (highly repetitive)
    pub y_repetition: f64,
    /// Drift coefficient: measures semantic deviation from baseline.
    /// Range: 0.0 (stable) to 1.0 (high drift)
    pub z_drift: f64,
    /// Toxicity coefficient: measures harmful content intensity.
    /// Range: 0.0 (benign) to 1.0 (highly toxic)
    pub t_toxicity: f64,
    /// Kindness coefficient: measures prosocial content presence.
    /// Range: 0.0 (neutral) to 1.0 (highly prosocial)
    pub k_kindness: f64,
    /// Evidentiality coefficient: measures claim substantiation.
    /// Range: 0.0 (unsupported) to 1.0 (well-evidenced)
    pub e_evidentiality: f64,
}

impl WordMath {
    /// Creates a new WordMath instance with validated ranges.
    /// All coefficients are clamped to [0.0, 1.0] range.
    #[must_use]
    pub fn new(
        y_repetition: f64,
        z_drift: f64,
        t_toxicity: f64,
        k_kindness: f64,
        e_evidentiality: f64,
    ) -> Self {
        Self {
            y_repetition: y_repetition.clamp(0.0, 1.0),
            z_drift: z_drift.clamp(0.0, 1.0),
            t_toxicity: t_toxicity.clamp(0.0, 1.0),
            k_kindness: k_kindness.clamp(0.0, 1.0),
            e_evidentiality: e_evidentiality.clamp(0.0, 1.0),
        }
    }

    /// Creates a zero-initialized WordMath instance.
    #[must_use]
    pub fn zeros() -> Self {
        Self::new(0.0, 0.0, 0.0, 0.0, 0.0)
    }

    /// Creates a neutral baseline WordMath instance.
    #[must_use]
    pub fn neutral() -> Self {
        Self::new(0.1, 0.1, 0.0, 0.5, 0.5)
    }

    /// Computes a composite risk score from the five dimensions.
    /// Higher values indicate greater harassment potential.
    #[must_use]
    pub fn composite_risk(&self) -> f64 {
        // Weighted combination emphasizing toxicity and repetition
        let risk = (self.t_toxicity * 0.35)
            + (self.y_repetition * 0.25)
            + (self.z_drift * 0.20)
            + ((1.0 - self.k_kindness) * 0.15)
            + ((1.0 - self.e_evidentiality) * 0.05);
        risk.clamp(0.0, 1.0)
    }

    /// Returns true if this span exceeds risk thresholds.
    #[must_use]
    pub fn is_high_risk(&self, threshold: f64) -> bool {
        self.composite_risk() > threshold
    }

    /// Merges two WordMath instances by averaging coefficients.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self::new(
            (self.y_repetition + other.y_repetition) / 2.0,
            (self.z_drift + other.z_drift) / 2.0,
            (self.t_toxicity + other.t_toxicity) / 2.0,
            (self.k_kindness + other.k_kindness) / 2.0,
            (self.e_evidentiality + other.e_evidentiality) / 2.0,
        )
    }
}

impl Display for WordMath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WordMath[y={:.3}, z={:.3}, T={:.3}, K={:.3}, E={:.3}]",
            self.y_repetition, self.z_drift, self.t_toxicity, self.k_kindness, self.e_evidentiality
        )
    }
}

// ============================================================================
// SPAN SCORE STRUCTURE
// ============================================================================

/// Represents a single interaction span with harassment family weights.
/// This is the fundamental unit of analysis for the SuperFilter engine.
/// Each span captures semantic, behavioral, and neural features aligned in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanScore {
    /// WordMath analytical coefficients for this span.
    pub word_math: WordMath,
    /// Per-family harassment similarity weights (embedding-space distances).
    /// Higher values indicate closer match to harassment family centroid.
    pub family_weights: HashMap<BlacklistFamily, f64>,
    /// Unique session identifier for traceability.
    pub session_id: String,
    /// Unique span identifier within the session.
    pub span_id: u64,
    /// Timestamp of span creation (UNIX epoch milliseconds).
    pub timestamp: u64,
    /// Source node identifier (Prometheus, Bostrom, Loihi2, Nanoswarm, etc.).
    pub node_id: Option<String>,
    /// Interaction type (text, haptic, neural, bci_command, etc.).
    pub interaction_type: InteractionType,
    /// Raw content hash for audit purposes (content itself not stored).
    pub content_hash: String,
    /// Governance flags applied to this span.
    pub governance_flags: Vec<GovernanceFlag>,
}

/// Interaction type classification for span categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InteractionType {
    /// Text-based dialogue or command input.
    Text,
    /// Haptic feedback stimulation pattern.
    Haptic,
    /// Neural signal or BCI command.
    Neural,
    /// AR/VR overlay or environment interaction.
    ARVR,
    /// Node-interpreter graph operation.
    NodeInterpreter,
    /// Session management event (login, logout, timeout).
    Session,
    /// Biosensor telemetry stream.
    Biosensor,
    /// Multi-modal fused interaction.
    Multimodal,
}

impl Display for InteractionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Governance flags that can be applied to spans for audit and enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovernanceFlag {
    /// Span requires human review before processing.
    ReviewRequired,
    /// Span has been redacted for safety.
    Redacted,
    /// Span triggered an escalation event.
    EscalationTrigger,
    /// Span is part of an audit trail.
    AuditTrail,
    /// Span requires multi-signature validation.
    MultiSigRequired,
    /// Span exceeded physiological safety envelope.
    PhysioEnvelopeExceeded,
    /// Span violated neuroright boundary.
    NeurorightViolation,
    /// Span is under active investigation.
    UnderInvestigation,
}

impl Display for GovernanceFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl SpanScore {
    /// Creates a new SpanScore instance with validated parameters.
    #[must_use]
    pub fn new(
        session_id: String,
        span_id: u64,
        node_id: Option<String>,
        interaction_type: InteractionType,
        content_hash: String,
    ) -> Self {
        Self {
            word_math: WordMath::neutral(),
            family_weights: HashMap::new(),
            session_id,
            span_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            node_id,
            interaction_type,
            content_hash,
            governance_flags: Vec::new(),
        }
    }

    /// Sets the WordMath coefficients for this span.
    pub fn set_word_math(&mut self, word_math: WordMath) {
        self.word_math = word_math;
    }

    /// Sets a family weight for a specific harassment family.
    /// Weight is clamped to [0.0, 1.0] range.
    pub fn set_family_weight(&mut self, family: BlacklistFamily, weight: f64) {
        self.family_weights.insert(family, weight.clamp(0.0, 1.0));
    }

    /// Gets the weight for a specific harassment family.
    #[must_use]
    pub fn get_family_weight(&self, family: &BlacklistFamily) -> Option<f64> {
        self.family_weights.get(family).copied()
    }

    /// Adds a governance flag to this span.
    pub fn add_governance_flag(&mut self, flag: GovernanceFlag) {
        if !self.governance_flags.contains(&flag) {
            self.governance_flags.push(flag);
        }
    }

    /// Removes a governance flag from this span.
    pub fn remove_governance_flag(&mut self, flag: &GovernanceFlag) {
        self.governance_flags.retain(|f| f != flag);
    }

    /// Returns true if this span has the specified governance flag.
    #[must_use]
    pub fn has_governance_flag(&self, flag: &GovernanceFlag) -> bool {
        self.governance_flags.contains(flag)
    }

    /// Computes the total harassment weight across all families.
    #[must_use]
    pub fn total_harassment_weight(&self) -> f64 {
        self.family_weights.values().sum()
    }

    /// Returns the dominant harassment family for this span.
    #[must_use]
    pub fn dominant_family(&self) -> Option<BlacklistFamily> {
        self.family_weights
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(family, _)| *family)
    }

    /// Returns true if this span exceeds the harassment threshold.
    #[must_use]
    pub fn is_harassment_detected(&self, threshold: f64) -> bool {
        self.total_harassment_weight() > threshold
    }

    /// Returns true if this span involves high-priority families (HTA, NHSP).
    #[must_use]
    pub fn is_high_priority_harassment(&self) -> bool {
        self.family_weights
            .get(&BlacklistFamily::HTA)
            .copied()
            .unwrap_or(0.0)
            > 0.5
            || self
                .family_weights
                .get(&BlacklistFamily::NHSP)
                .copied()
                .unwrap_or(0.0)
                > 0.5
    }

    /// Merges another SpanScore into this one by averaging weights.
    pub fn merge(&mut self, other: &Self) {
        self.word_math = self.word_math.merge(&other.word_math);
        for (family, &weight) in &other.family_weights {
            let existing = self.family_weights.get(family).copied().unwrap_or(0.0);
            self.family_weights.insert(*family, (existing + weight) / 2.0);
        }
    }

    /// Creates a sanitized representation for logging (no raw content).
    #[must_use]
    pub fn to_audit_record(&self) -> AuditRecord {
        AuditRecord {
            session_id: self.session_id.clone(),
            span_id: self.span_id,
            timestamp: self.timestamp,
            node_id: self.node_id.clone(),
            interaction_type: self.interaction_type,
            content_hash: self.content_hash.clone(),
            word_math: self.word_math,
            dominant_family: self.dominant_family(),
            total_harassment_weight: self.total_harassment_weight(),
            governance_flags: self.governance_flags.clone(),
        }
    }
}

impl Display for SpanScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SpanScore[session={}, span={}, node={:?}, type={}, harassment={:.3}]",
            self.session_id,
            self.span_id,
            self.node_id,
            self.interaction_type,
            self.total_harassment_weight()
        )
    }
}

// ============================================================================
// AUDIT RECORD STRUCTURE
// ============================================================================

/// Sanitized audit record for logging and compliance purposes.
/// Contains no raw content, only metadata and computed scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Session identifier.
    pub session_id: String,
    /// Span identifier within session.
    pub span_id: u64,
    /// Timestamp of span creation.
    pub timestamp: u64,
    /// Source node identifier.
    pub node_id: Option<String>,
    /// Interaction type.
    pub interaction_type: InteractionType,
    /// Content hash for verification.
    pub content_hash: String,
    /// WordMath coefficients.
    pub word_math: WordMath,
    /// Dominant harassment family if detected.
    pub dominant_family: Option<BlacklistFamily>,
    /// Total harassment weight.
    pub total_harassment_weight: f64,
    /// Applied governance flags.
    pub governance_flags: Vec<GovernanceFlag>,
}

impl AuditRecord {
    /// Returns true if this record indicates a neuroright violation.
    #[must_use]
    pub fn is_neuroright_violation(&self) -> bool {
        self.governance_flags
            .contains(&GovernanceFlag::NeurorightViolation)
    }

    /// Returns true if this record requires human review.
    #[must_use]
    pub fn requires_review(&self) -> bool {
        self.governance_flags
            .contains(&GovernanceFlag::ReviewRequired)
    }
}

// ============================================================================
// SPAN BUILDER PATTERN
// ============================================================================

/// Builder for constructing SpanScore instances with validation.
#[derive(Debug, Clone)]
pub struct SpanScoreBuilder {
    session_id: Option<String>,
    span_id: Option<u64>,
    node_id: Option<String>,
    interaction_type: InteractionType,
    content_hash: Option<String>,
    word_math: WordMath,
    family_weights: HashMap<BlacklistFamily, f64>,
    governance_flags: Vec<GovernanceFlag>,
}

impl SpanScoreBuilder {
    /// Creates a new SpanScoreBuilder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_id: None,
            span_id: None,
            node_id: None,
            interaction_type: InteractionType::Text,
            content_hash: None,
            word_math: WordMath::neutral(),
            family_weights: HashMap::new(),
            governance_flags: Vec::new(),
        }
    }

    /// Sets the session identifier.
    pub fn session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Sets the span identifier.
    pub fn span_id(mut self, span_id: u64) -> Self {
        self.span_id = Some(span_id);
        self
    }

    /// Sets the node identifier.
    pub fn node_id(mut self, node_id: String) -> Self {
        self.node_id = Some(node_id);
        self
    }

    /// Sets the interaction type.
    pub fn interaction_type(mut self, interaction_type: InteractionType) -> Self {
        self.interaction_type = interaction_type;
        self
    }

    /// Sets the content hash.
    pub fn content_hash(mut self, content_hash: String) -> Self {
        self.content_hash = Some(content_hash);
        self
    }

    /// Sets the WordMath coefficients.
    pub fn word_math(mut self, word_math: WordMath) -> Self {
        self.word_math = word_math;
        self
    }

    /// Adds a family weight.
    pub fn family_weight(mut self, family: BlacklistFamily, weight: f64) -> Self {
        self.family_weights.insert(family, weight.clamp(0.0, 1.0));
        self
    }

    /// Adds a governance flag.
    pub fn governance_flag(mut self, flag: GovernanceFlag) -> Self {
        self.governance_flags.push(flag);
        self
    }

    /// Builds the SpanScore instance, returning None if required fields are missing.
    #[must_use]
    pub fn build(self) -> Option<SpanScore> {
        let session_id = self.session_id?;
        let span_id = self.span_id?;
        let content_hash = self.content_hash.unwrap_or_else(|| "UNHASHED".to_string());

        let mut span = SpanScore::new(
            session_id,
            span_id,
            self.node_id,
            self.interaction_type,
            content_hash,
        );

        span.word_math = self.word_math;
        span.family_weights = self.family_weights;
        span.governance_flags = self.governance_flags;

        Some(span)
    }

    /// Builds the SpanScore instance, panicking if required fields are missing.
    #[must_use]
    pub fn build_expect(self) -> SpanScore {
        self.build().expect("SpanScoreBuilder: missing required fields")
    }
}

impl Default for SpanScoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_math_range_clamping() {
        let wm = WordMath::new(1.5, -0.5, 2.0, -1.0, 0.5);
        assert_eq!(wm.y_repetition, 1.0);
        assert_eq!(wm.z_drift, 0.0);
        assert_eq!(wm.t_toxicity, 1.0);
        assert_eq!(wm.k_kindness, 0.0);
        assert_eq!(wm.e_evidentiality, 0.5);
    }

    #[test]
    fn test_word_math_composite_risk() {
        let high_risk = WordMath::new(0.9, 0.8, 0.9, 0.1, 0.1);
        let low_risk = WordMath::new(0.1, 0.1, 0.0, 0.9, 0.9);
        assert!(high_risk.composite_risk() > low_risk.composite_risk());
    }

    #[test]
    fn test_span_score_family_weights() {
        let mut span = SpanScore::new(
            "test_session".to_string(),
            1,
            Some("Prometheus".to_string()),
            InteractionType::Text,
            "hash123".to_string(),
        );
        span.set_family_weight(BlacklistFamily::HTA, 0.8);
        span.set_family_weight(BlacklistFamily::NHSP, 0.6);
        assert_eq!(span.get_family_weight(&BlacklistFamily::HTA), Some(0.8));
        assert!(span.is_high_priority_harassment());
    }

    #[test]
    fn test_span_score_builder() {
        let span = SpanScoreBuilder::new()
            .session_id("test".to_string())
            .span_id(42)
            .content_hash("abc123".to_string())
            .family_weight(BlacklistFamily::PSA, 0.7)
            .governance_flag(GovernanceFlag::AuditTrail)
            .build_expect();

        assert_eq!(span.session_id, "test");
        assert_eq!(span.span_id, 42);
        assert!(span.has_governance_flag(&GovernanceFlag::AuditTrail));
    }

    #[test]
    fn test_audit_record_neuroright_violation() {
        let mut span = SpanScoreBuilder::new()
            .session_id("test".to_string())
            .span_id(1)
            .content_hash("hash".to_string())
            .build_expect();
        span.add_governance_flag(GovernanceFlag::NeurorightViolation);
        let record = span.to_audit_record();
        assert!(record.is_neuroright_violation());
    }

    #[test]
    fn test_monotone_harassment_weight_accumulation() {
        let mut span = SpanScore::new(
            "test".to_string(),
            1,
            None,
            InteractionType::Neural,
            "hash".to_string(),
        );
        let initial_weight = span.total_harassment_weight();
        span.set_family_weight(BlacklistFamily::NHSP, 0.5);
        assert!(span.total_harassment_weight() >= initial_weight);
    }
}
