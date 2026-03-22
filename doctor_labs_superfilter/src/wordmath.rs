// doctor_labs_superfilter/src/wordmath.rs
// WordMath Adapter Module - Legacy Analysis to SpanScore Bridge
// Doctor-Labs SuperFilter Core Library
// Version: 2026.03.23 | ALN-NanoNet HyperSafe Construct Compliant

#![deny(clippy::all)]
#![warn(missing_docs)]

use crate::{
    BlacklistFamily, SpanScore,
    span_score::{InteractionType, GovernanceFlag, WordMath, SpanScoreBuilder},
};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// ============================================================================
// AS SPAN SCORE TRAIT
// ============================================================================

/// Trait for converting legacy analysis types into standardized SpanScore format.
/// This enables backward compatibility with existing WordMath analysis pipelines
/// while maintaining the new harassment detection architecture.
pub trait AsSpanScore {
    /// Converts the implementing type into a SpanScore instance.
    /// Returns None if required fields are missing or invalid.
    fn to_span_score(self) -> Option<SpanScore>;

    /// Converts the implementing type into a SpanScore instance, panicking on failure.
    fn to_span_score_expect(self) -> SpanScore {
        self.to_span_score().expect("AsSpanScore: conversion failed")
    }

    /// Converts with additional context (session_id, node_id, etc.).
    fn to_span_score_with_context(
        self,
        session_id: String,
        node_id: Option<String>,
        span_id: u64,
    ) -> Option<SpanScore>;
}

// ============================================================================
// LEGACY WORD MATH ANALYSIS STRUCTURE
// ============================================================================

/// Legacy WordMath analysis result from existing pipelines.
/// This structure represents the original five-dimensional analysis
/// before the harassment detection framework was introduced.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WordMathAnalysis {
    /// Repetition coefficient (y): pattern recurrence frequency.
    /// Range: 0.0 (unique) to 1.0 (highly repetitive)
    pub y: f64,
    /// Drift coefficient (z): semantic deviation from baseline.
    /// Range: 0.0 (stable) to 1.0 (high drift)
    pub z: f64,
    /// Toxicity coefficient (T): harmful content intensity.
    /// Range: 0.0 (benign) to 1.0 (highly toxic)
    pub t: f64,
    /// Kindness coefficient (K): prosocial content presence.
    /// Range: 0.0 (neutral) to 1.0 (highly prosocial)
    pub k: f64,
    /// Evidentiality coefficient (E): claim substantiation level.
    /// Range: 0.0 (unsupported) to 1.0 (well-evidenced)
    pub e: f64,
    /// Original analysis timestamp (UNIX epoch milliseconds).
    pub analyzed_at: u64,
    /// Source identifier for the analysis.
    pub source_id: String,
}

impl WordMathAnalysis {
    /// Creates a new WordMathAnalysis instance with validated ranges.
    /// All coefficients are clamped to [0.0, 1.0] range.
    #[must_use]
    pub fn new(
        y: f64,
        z: f64,
        t: f64,
        k: f64,
        e: f64,
        source_id: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            y: y.clamp(0.0, 1.0),
            z: z.clamp(0.0, 1.0),
            t: t.clamp(0.0, 1.0),
            k: k.clamp(0.0, 1.0),
            e: e.clamp(0.0, 1.0),
            analyzed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            source_id,
        }
    }

    /// Creates a zero-initialized WordMathAnalysis instance.
    #[must_use]
    pub fn zeros(source_id: String) -> Self {
        Self::new(0.0, 0.0, 0.0, 0.0, 0.0, source_id)
    }

    /// Creates a neutral baseline WordMathAnalysis instance.
    #[must_use]
    pub fn neutral(source_id: String) -> Self {
        Self::new(0.1, 0.1, 0.0, 0.5, 0.5, source_id)
    }

    /// Converts to the new WordMath structure.
    #[must_use]
    pub fn to_word_math(&self) -> WordMath {
        WordMath::new(self.y, self.z, self.t, self.k, self.e)
    }

    /// Computes composite risk score from the five dimensions.
    #[must_use]
    pub fn composite_risk(&self) -> f64 {
        self.to_word_math().composite_risk()
    }

    /// Returns true if this analysis exceeds risk thresholds.
    #[must_use]
    pub fn is_high_risk(&self, threshold: f64) -> bool {
        self.composite_risk() > threshold
    }

    /// Merges two WordMathAnalysis instances by averaging coefficients.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self::new(
            (self.y + other.y) / 2.0,
            (self.z + other.z) / 2.0,
            (self.t + other.t) / 2.0,
            (self.k + other.k) / 2.0,
            (self.e + other.e) / 2.0,
            format!("{}_merged_{}", self.source_id, other.source_id),
        )
    }
}

impl Display for WordMathAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WordMathAnalysis[y={:.3}, z={:.3}, T={:.3}, K={:.3}, E={:.3}, source={}]",
            self.y, self.z, self.t, self.k, self.e, self.source_id
        )
    }
}

// ============================================================================
// AS SPAN SCORE IMPLEMENTATION FOR WORD MATH ANALYSIS
// ============================================================================

impl AsSpanScore for WordMathAnalysis {
    fn to_span_score(self) -> Option<SpanScore> {
        let span_id = self.analyzed_at % 1_000_000_000; // Derive span_id from timestamp
        self.to_span_score_with_context(
            format!("session_{}", self.source_id),
            Some(self.source_id.clone()),
            span_id,
        )
    }

    fn to_span_score_with_context(
        self,
        session_id: String,
        node_id: Option<String>,
        span_id: u64,
    ) -> Option<SpanScore> {
        let mut span = SpanScore::new(
            session_id,
            span_id,
            node_id,
            InteractionType::Text,
            format!("wm_{}", self.analyzed_at),
        );

        span.set_word_math(self.to_word_math());

        // Map high toxicity to harassment family weights
        if self.t > 0.5 {
            span.set_family_weight(BlacklistFamily::CLLN, self.t);
        }
        if self.z > 0.6 {
            span.set_family_weight(BlacklistFamily::XGBC, self.z);
        }
        if self.y > 0.7 {
            span.set_family_weight(BlacklistFamily::PSA, self.y);
        }

        // Add governance flags based on risk levels
        if self.is_high_risk(0.7) {
            span.add_governance_flag(GovernanceFlag::AuditTrail);
        }
        if self.t > 0.8 {
            span.add_governance_flag(GovernanceFlag::ReviewRequired);
        }

        Some(span)
    }
}

// ============================================================================
// ENHANCED WORD MATH ANALYSIS WITH HARASSMENT FAMILIES
// ============================================================================

/// Enhanced WordMath analysis that includes harassment family weights.
/// This structure extends the legacy format with the new detection capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedWordMathAnalysis {
    /// Base WordMath coefficients.
    pub word_math: WordMath,
    /// Per-family harassment similarity weights.
    pub family_weights: HashMap<BlacklistFamily, f64>,
    /// Source identifier for the analysis.
    pub source_id: String,
    /// Analysis timestamp (UNIX epoch milliseconds).
    pub analyzed_at: u64,
    /// Content hash for audit purposes.
    pub content_hash: String,
    /// Interaction type being analyzed.
    pub interaction_type: InteractionType,
    /// Confidence score for the analysis (0.0-1.0).
    pub confidence: f64,
    /// Model version used for analysis.
    pub model_version: String,
}

impl EnhancedWordMathAnalysis {
    /// Creates a new EnhancedWordMathAnalysis instance.
    #[must_use]
    pub fn new(
        word_math: WordMath,
        source_id: String,
        interaction_type: InteractionType,
        content_hash: String,
        model_version: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            word_math,
            family_weights: HashMap::new(),
            source_id,
            analyzed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            content_hash,
            interaction_type,
            confidence: 1.0,
            model_version,
        }
    }

    /// Creates from legacy WordMathAnalysis with enhanced features.
    #[must_use]
    pub fn from_legacy(legacy: WordMathAnalysis, model_version: String) -> Self {
        let mut enhanced = Self::new(
            legacy.to_word_math(),
            legacy.source_id.clone(),
            InteractionType::Text,
            format!("legacy_{}", legacy.analyzed_at),
            model_version,
        );
        // Migrate legacy risk indicators to family weights
        if legacy.t > 0.5 {
            enhanced.family_weights.insert(BlacklistFamily::CLLN, legacy.t);
        }
        if legacy.z > 0.6 {
            enhanced.family_weights.insert(BlacklistFamily::XGBC, legacy.z);
        }
        enhanced.confidence = 0.85; // Legacy conversion has lower confidence
        enhanced
    }

    /// Sets a family weight for a specific harassment family.
    pub fn set_family_weight(&mut self, family: BlacklistFamily, weight: f64) {
        self.family_weights.insert(family, weight.clamp(0.0, 1.0));
    }

    /// Gets the weight for a specific harassment family.
    #[must_use]
    pub fn get_family_weight(&self, family: &BlacklistFamily) -> Option<f64> {
        self.family_weights.get(family).copied()
    }

    /// Sets the confidence score.
    pub fn set_confidence(&mut self, confidence: f64) {
        self.confidence = confidence.clamp(0.0, 1.0);
    }

    /// Computes weighted harassment score considering confidence.
    #[must_use]
    pub fn weighted_harassment_score(&self) -> f64 {
        let base_score: f64 = self.family_weights.values().sum();
        base_score * self.confidence
    }

    /// Returns the dominant harassment family.
    #[must_use]
    pub fn dominant_family(&self) -> Option<BlacklistFamily> {
        self.family_weights
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(family, _)| *family)
    }

    /// Returns true if high-priority harassment (HTA/NHSP) is detected.
    #[must_use]
    pub fn has_high_priority_harassment(&self) -> bool {
        let hta = self.family_weights.get(&BlacklistFamily::HTA).copied().unwrap_or(0.0);
        let nhsp = self.family_weights.get(&BlacklistFamily::NHSP).copied().unwrap_or(0.0);
        hta > 0.5 || nhsp > 0.5
    }

    /// Returns true if analysis confidence is below acceptable threshold.
    #[must_use]
    pub fn is_low_confidence(&self, threshold: f64) -> bool {
        self.confidence < threshold
    }
}

impl Display for EnhancedWordMathAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnhancedWordMathAnalysis[source={}, type={}, confidence={:.2}, families={}]",
            self.source_id,
            self.interaction_type,
            self.confidence,
            self.family_weights.len()
        )
    }
}

impl AsSpanScore for EnhancedWordMathAnalysis {
    fn to_span_score(self) -> Option<SpanScore> {
        let span_id = self.analyzed_at % 1_000_000_000;
        self.to_span_score_with_context(
            format!("session_{}", self.source_id),
            Some(self.source_id.clone()),
            span_id,
        )
    }

    fn to_span_score_with_context(
        self,
        session_id: String,
        node_id: Option<String>,
        span_id: u64,
    ) -> Option<SpanScore> {
        let mut span = SpanScoreBuilder::new()
            .session_id(session_id)
            .span_id(span_id)
            .node_id(node_id.unwrap_or_else(|| "unknown".to_string()))
            .interaction_type(self.interaction_type)
            .content_hash(self.content_hash)
            .word_math(self.word_math)
            .build()?;

        // Transfer family weights
        for (family, weight) in self.family_weights {
            span.set_family_weight(family, weight);
        }

        // Add governance flags based on analysis results
        if self.has_high_priority_harassment() {
            span.add_governance_flag(GovernanceFlag::ReviewRequired);
        }
        if self.is_low_confidence(0.5) {
            span.add_governance_flag(GovernanceFlag::UnderInvestigation);
        }
        if self.weighted_harassment_score() > 1.0 {
            span.add_governance_flag(GovernanceFlag::AuditTrail);
        }

        Some(span)
    }
}

// ============================================================================
// WORD MATH ANALYSIS PIPELINE
// ============================================================================

/// Pipeline for processing text through WordMath analysis and harassment detection.
/// Combines legacy compatibility with new harassment family detection.
pub struct WordMathPipeline {
    /// Model version for analysis.
    model_version: String,
    /// Default interaction type for pipeline outputs.
    default_interaction_type: InteractionType,
    /// Confidence threshold for flagging low-confidence analyses.
    confidence_threshold: f64,
    /// Risk threshold for high-risk classification.
    risk_threshold: f64,
}

impl WordMathPipeline {
    /// Creates a new WordMathPipeline with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            model_version: "2026.03.23".to_string(),
            default_interaction_type: InteractionType::Text,
            confidence_threshold: 0.5,
            risk_threshold: 0.7,
        }
    }

    /// Sets the model version.
    pub fn with_model_version(mut self, version: String) -> Self {
        self.model_version = version;
        self
    }

    /// Sets the default interaction type.
    pub fn with_interaction_type(mut self, interaction_type: InteractionType) -> Self {
        self.default_interaction_type = interaction_type;
        self
    }

    /// Sets the confidence threshold.
    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Sets the risk threshold.
    pub fn with_risk_threshold(mut self, threshold: f64) -> Self {
        self.risk_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Analyzes text and returns EnhancedWordMathAnalysis.
    /// Note: In production, this would call actual NLP models.
    #[must_use]
    pub fn analyze_text(&self, text: &str, source_id: String) -> EnhancedWordMathAnalysis {
        // Simulated analysis - in production, this would use actual NLP models
        let word_math = self.compute_word_math_from_text(text);
        let mut analysis = EnhancedWordMathAnalysis::new(
            word_math,
            source_id,
            self.default_interaction_type,
            self.compute_content_hash(text),
            self.model_version.clone(),
        );

        // Populate family weights based on text features
        self.populate_family_weights(&mut analysis, text);

        analysis
    }

    /// Computes WordMath coefficients from text (simulated).
    #[must_use]
    fn compute_word_math_from_text(&self, text: &str) -> WordMath {
        // In production, these would be computed by actual NLP models
        let char_count = text.len() as f64;
        let word_count = text.split_whitespace().count() as f64;

        // Simulated metrics based on text properties
        let repetition = if word_count > 0.0 {
            (1.0 - (char_count / word_count / 10.0)).clamp(0.0, 1.0)
        } else {
            0.1
        };

        let toxicity_indicators = ["hate", "threat", "harm", "attack", "abuse"];
        let toxicity = toxicity_indicators
            .iter()
            .filter(|&t| text.to_lowercase().contains(t))
            .count() as f64
            / 10.0;

        let kindness_indicators = ["please", "thank", "help", "support", "kind"];
        let kindness = kindness_indicators
            .iter()
            .filter(|&t| text.to_lowercase().contains(t))
            .count() as f64
            / 10.0;

        WordMath::new(
            repetition.clamp(0.0, 1.0),
            0.1, // drift would require baseline comparison
            toxicity.clamp(0.0, 1.0),
            kindness.clamp(0.0, 1.0),
            0.5, // evidentiality would require fact-checking
        )
    }

    /// Populates harassment family weights based on text analysis.
    fn populate_family_weights(&self, analysis: &mut EnhancedWordMathAnalysis, text: &str) {
        let text_lower = text.to_lowercase();

        // NHSP indicators (neural harassment patterns)
        if text_lower.contains("spike") || text_lower.contains("neural") || text_lower.contains("brain") {
            analysis.set_family_weight(BlacklistFamily::NHSP, 0.6);
        }

        // HTA indicators (haptic targeting)
        if text_lower.contains("haptic") || text_lower.contains("touch") || text_lower.contains("feel") {
            analysis.set_family_weight(BlacklistFamily::HTA, 0.5);
        }

        // PSA indicators (prolonged session abuse)
        if text_lower.contains("session") || text_lower.contains("login") || text_lower.contains("timeout") {
            analysis.set_family_weight(BlacklistFamily::PSA, 0.4);
        }

        // NIH indicators (node interpreter harassment)
        if text_lower.contains("node") || text_lower.contains("interpreter") || text_lower.contains("graph") {
            analysis.set_family_weight(BlacklistFamily::NIH, 0.4);
        }

        // Legacy families
        if text_lower.contains("coerce") || text_lower.contains("force") {
            analysis.set_family_weight(BlacklistFamily::CLLN, 0.7);
        }
        if text_lower.contains("bypass") || text_lower.contains("exploit") {
            analysis.set_family_weight(BlacklistFamily::XGBC, 0.7);
        }
    }

    /// Computes a simple hash for content audit purposes.
    #[must_use]
    fn compute_content_hash(&self, text: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        format!("hash_{:016x}", hasher.finish())
    }

    /// Analyzes and converts directly to SpanScore.
    #[must_use]
    pub fn analyze_to_span(
        &self,
        text: &str,
        session_id: String,
        node_id: String,
        span_id: u64,
    ) -> Option<SpanScore> {
        let analysis = self.analyze_text(text, node_id.clone());
        analysis.to_span_score_with_context(session_id, Some(node_id), span_id)
    }

    /// Analyzes a batch of texts and returns SpanScore vectors.
    #[must_use]
    pub fn analyze_batch(
        &self,
        texts: &[(&str, String, u64)], // (text, source_id, span_id)
        session_id: String,
    ) -> Vec<SpanScore> {
        texts
            .iter()
            .filter_map(|(text, source_id, span_id)| {
                self.analyze_to_span(text, session_id.clone(), source_id.clone(), *span_id)
            })
            .collect()
    }
}

impl Default for WordMathPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ANALYSIS RESULT AGGREGATOR
// ============================================================================

/// Aggregates multiple WordMath analyses into summary statistics.
/// Used for batch processing and trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisAggregator {
    /// Total number of analyses aggregated.
    pub count: usize,
    /// Average WordMath coefficients.
    pub avg_word_math: WordMath,
    /// Average family weights.
    pub avg_family_weights: HashMap<BlacklistFamily, f64>,
    /// Maximum toxicity observed.
    pub max_toxicity: f64,
    /// Minimum confidence observed.
    pub min_confidence: f64,
    /// High-risk analysis count.
    pub high_risk_count: usize,
    /// High-priority harassment count.
    pub high_priority_count: usize,
}

impl AnalysisAggregator {
    /// Creates a new AnalysisAggregator from a slice of EnhancedWordMathAnalysis.
    #[must_use]
    pub fn from_analyses(analyses: &[EnhancedWordMathAnalysis]) -> Self {
        if analyses.is_empty() {
            return Self {
                count: 0,
                avg_word_math: WordMath::zeros(),
                avg_family_weights: HashMap::new(),
                max_toxicity: 0.0,
                min_confidence: 1.0,
                high_risk_count: 0,
                high_priority_count: 0,
            };
        }

        let count = analyses.len();
        let mut sum_y = 0.0;
        let mut sum_z = 0.0;
        let mut sum_t = 0.0;
        let mut sum_k = 0.0;
        let mut sum_e = 0.0;
        let mut max_toxicity = 0.0;
        let mut min_confidence = 1.0;
        let mut high_risk_count = 0;
        let mut high_priority_count = 0;

        let mut family_sums: HashMap<BlacklistFamily, f64> = HashMap::new();
        let mut family_counts: HashMap<BlacklistFamily, usize> = HashMap::new();

        for analysis in analyses {
            sum_y += analysis.word_math.y_repetition;
            sum_z += analysis.word_math.z_drift;
            sum_t += analysis.word_math.t_toxicity;
            sum_k += analysis.word_math.k_kindness;
            sum_e += analysis.word_math.e_evidentiality;

            max_toxicity = max_toxicity.max(analysis.word_math.t_toxicity);
            min_confidence = min_confidence.min(analysis.confidence);

            if analysis.word_math.composite_risk() > 0.7 {
                high_risk_count += 1;
            }
            if analysis.has_high_priority_harassment() {
                high_priority_count += 1;
            }

            for (family, &weight) in &analysis.family_weights {
                *family_sums.entry(*family).or_insert(0.0) += weight;
                *family_counts.entry(*family).or_insert(0) += 1;
            }
        }

        let avg_word_math = WordMath::new(
            sum_y / count as f64,
            sum_z / count as f64,
            sum_t / count as f64,
            sum_k / count as f64,
            sum_e / count as f64,
        );

        let avg_family_weights = family_sums
            .into_iter()
            .map(|(family, sum)| (family, sum / family_counts[&family] as f64))
            .collect();

        Self {
            count,
            avg_word_math,
            avg_family_weights,
            max_toxicity,
            min_confidence,
            high_risk_count,
            high_priority_count,
        }
    }

    /// Returns the harassment risk level summary.
    #[must_use]
    pub fn risk_summary(&self) -> RiskLevel {
        if self.high_priority_count > 0 || self.max_toxicity > 0.8 {
            RiskLevel::Critical
        } else if self.high_risk_count > self.count / 4 {
            RiskLevel::High
        } else if self.high_risk_count > 0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

/// Risk level classification for aggregated analyses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// No significant risk detected.
    Low,
    /// Some risk indicators present.
    Medium,
    /// Multiple risk indicators detected.
    High,
    /// Critical risk requiring immediate attention.
    Critical,
}

impl Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl AnalysisAggregator {
    /// Returns a human-readable summary string.
    #[must_use]
    pub fn summary_string(&self) -> String {
        format!(
            "AnalysisAggregator[count={}, risk={:?}, high_risk={}, high_priority={}, max_toxicity={:.2}]",
            self.count,
            self.risk_summary(),
            self.high_risk_count,
            self.high_priority_count,
            self.max_toxicity
        )
    }
}

impl Display for AnalysisAggregator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary_string())
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_math_analysis_creation() {
        let analysis = WordMathAnalysis::new(0.5, 0.3, 0.7, 0.6, 0.4, "test_source".to_string());
        assert_eq!(analysis.y, 0.5);
        assert_eq!(analysis.t, 0.7);
        assert_eq!(analysis.source_id, "test_source");
    }

    #[test]
    fn test_word_math_analysis_range_clamping() {
        let analysis = WordMathAnalysis::new(1.5, -0.5, 2.0, -1.0, 0.5, "test".to_string());
        assert_eq!(analysis.y, 1.0);
        assert_eq!(analysis.z, 0.0);
        assert_eq!(analysis.t, 1.0);
        assert_eq!(analysis.k, 0.0);
    }

    #[test]
    fn test_word_math_analysis_to_span_score() {
        let analysis = WordMathAnalysis::new(0.8, 0.7, 0.9, 0.2, 0.3, "test_node".to_string());
        let span = analysis.to_span_score_expect();
        assert_eq!(span.word_math.t_toxicity, 0.9);
        assert!(span.get_family_weight(&BlacklistFamily::CLLN).is_some());
    }

    #[test]
    fn test_enhanced_word_math_analysis() {
        let word_math = WordMath::neutral();
        let mut enhanced = EnhancedWordMathAnalysis::new(
            word_math,
            "test".to_string(),
            InteractionType::Text,
            "hash123".to_string(),
            "v1.0".to_string(),
        );
        enhanced.set_family_weight(BlacklistFamily::NHSP, 0.7);
        enhanced.set_family_weight(BlacklistFamily::HTA, 0.6);

        assert!(enhanced.has_high_priority_harassment());
        assert_eq!(enhanced.get_family_weight(&BlacklistFamily::NHSP), Some(0.7));
    }

    #[test]
    fn test_enhanced_from_legacy() {
        let legacy = WordMathAnalysis::new(0.5, 0.7, 0.8, 0.3, 0.4, "legacy".to_string());
        let enhanced = EnhancedWordMathAnalysis::from_legacy(legacy, "v2.0".to_string());
        assert_eq!(enhanced.confidence, 0.85);
        assert!(enhanced.get_family_weight(&BlacklistFamily::CLLN).is_some());
    }

    #[test]
    fn test_word_math_pipeline_analysis() {
        let pipeline = WordMathPipeline::new()
            .with_model_version("test_v1".to_string())
            .with_confidence_threshold(0.6);

        let analysis = pipeline.analyze_text("This is a test message", "test_node".to_string());
        assert_eq!(analysis.model_version, "test_v1");
        assert!(analysis.confidence > 0.0);
    }

    #[test]
    fn test_word_math_pipeline_harassment_detection() {
        let pipeline = WordMathPipeline::new();
        let analysis = pipeline.analyze_text(
            "Neural spike manipulation and haptic targeting detected",
            "test_node".to_string(),
        );
        assert!(analysis.has_high_priority_harassment());
        assert!(analysis.get_family_weight(&BlacklistFamily::NHSP).is_some());
        assert!(analysis.get_family_weight(&BlacklistFamily::HTA).is_some());
    }

    #[test]
    fn test_analysis_aggregator() {
        let analyses = vec![
            EnhancedWordMathAnalysis::new(
                WordMath::new(0.2, 0.2, 0.1, 0.8, 0.7, "source1".to_string()),
                "source1".to_string(),
                InteractionType::Text,
                "hash1".to_string(),
                "v1.0".to_string(),
            ),
            EnhancedWordMathAnalysis::new(
                WordMath::new(0.8, 0.7, 0.9, 0.1, 0.2, "source2".to_string()),
                "source2".to_string(),
                InteractionType::Text,
                "hash2".to_string(),
                "v1.0".to_string(),
            ),
        ];

        let aggregator = AnalysisAggregator::from_analyses(&analyses);
        assert_eq!(aggregator.count, 2);
        assert!(aggregator.high_risk_count >= 1);
    }

    #[test]
    fn test_risk_level_classification() {
        let low_risk = vec![EnhancedWordMathAnalysis::new(
            WordMath::new(0.1, 0.1, 0.0, 0.9, 0.9, "safe".to_string()),
            "safe".to_string(),
            InteractionType::Text,
            "hash".to_string(),
            "v1.0".to_string(),
        )];
        let aggregator_low = AnalysisAggregator::from_analyses(&low_risk);
        assert_eq!(aggregator_low.risk_summary(), RiskLevel::Low);

        let high_risk = vec![EnhancedWordMathAnalysis::new(
            WordMath::new(0.9, 0.8, 0.9, 0.1, 0.1, "danger".to_string()),
            "danger".to_string(),
            InteractionType::Text,
            "hash".to_string(),
            "v1.0".to_string(),
        )];
        let mut enhanced_high = EnhancedWordMathAnalysis::from_legacy(
            WordMathAnalysis::new(0.9, 0.8, 0.9, 0.1, 0.1, "danger".to_string()),
            "v1.0".to_string(),
        );
        enhanced_high.set_family_weight(BlacklistFamily::HTA, 0.8);
        let high_risk_vec = vec![enhanced_high];
        let aggregator_high = AnalysisAggregator::from_analyses(&high_risk_vec);
        assert_eq!(aggregator_high.risk_summary(), RiskLevel::Critical);
    }

    #[test]
    fn test_as_span_score_trait() {
        let legacy = WordMathAnalysis::new(0.5, 0.5, 0.5, 0.5, 0.5, "test".to_string());
        let span: Option<SpanScore> = legacy.to_span_score();
        assert!(span.is_some());

        let span_with_context = legacy.to_span_score_with_context(
            "custom_session".to_string(),
            Some("custom_node".to_string()),
            42,
        );
        assert!(span_with_context.is_some());
        assert_eq!(span_with_context.unwrap().session_id, "custom_session");
    }

    #[test]
    fn test_word_math_pipeline_batch_analysis() {
        let pipeline = WordMathPipeline::new();
        let texts = vec![
            ("Normal message", "node1".to_string(), 1u64),
            ("Neural spike attack", "node2".to_string(), 2u64),
            ("Haptic abuse pattern", "node3".to_string(), 3u64),
        ];

        let spans = pipeline.analyze_batch(&texts, "batch_session".to_string());
        assert_eq!(spans.len(), 3);

        // Check that harassment patterns were detected
        let harassment_spans: Vec<_> = spans
            .iter()
            .filter(|s| s.is_high_priority_harassment())
            .collect();
        assert!(harassment_spans.len() >= 2);
    }

    #[test]
    fn test_content_hash_computation() {
        let pipeline = WordMathPipeline::new();
        let hash1 = pipeline.compute_content_hash("test message");
        let hash2 = pipeline.compute_content_hash("test message");
        let hash3 = pipeline.compute_content_hash("different message");

        assert_eq!(hash1, hash2); // Same content = same hash
        assert_ne!(hash1, hash3); // Different content = different hash
    }

    #[test]
    fn test_weighted_harassment_score() {
        let mut analysis = EnhancedWordMathAnalysis::new(
            WordMath::neutral(),
            "test".to_string(),
            InteractionType::Text,
            "hash".to_string(),
            "v1.0".to_string(),
        );
        analysis.set_family_weight(BlacklistFamily::HTA, 0.8);
        analysis.set_family_weight(BlacklistFamily::NHSP, 0.6);
        analysis.set_confidence(0.9);

        let score = analysis.weighted_harassment_score();
        assert!(score > 0.0);
        assert!(score <= 1.4); // 0.8 + 0.6 = 1.4, weighted by confidence
    }

    #[test]
    fn test_analysis_aggregator_empty_input() {
        let aggregator = AnalysisAggregator::from_analyses(&[]);
        assert_eq!(aggregator.count, 0);
        assert_eq!(aggregator.risk_summary(), RiskLevel::Low);
        assert_eq!(aggregator.min_confidence, 1.0);
    }

    #[test]
    fn test_word_math_merge() {
        let wm1 = WordMath::new(0.8, 0.6, 0.7, 0.3, 0.4);
        let wm2 = WordMath::new(0.2, 0.4, 0.1, 0.9, 0.8);
        let merged = wm1.merge(&wm2);

        assert!((merged.y_repetition - 0.5).abs() < 0.01);
        assert!((merged.t_toxicity - 0.4).abs() < 0.01);
        assert!((merged.k_kindness - 0.6).abs() < 0.01);
    }
}
