// doctor_labs_superfilter/src/harassment_detector.rs
// Harassment Detection Adapter - NHSP/HTA/PSA/NIH Specialized Wrapper
// Doctor-Labs SuperFilter Core Library
// Version: 2026.03.23 | ALN-NanoNet HyperSafe Construct Compliant

#![deny(clippy::all)]
#![warn(missing_docs)]

use crate::{
    BlacklistFamily, CapabilityMode, RogueConfig, RogueScore, SpanScore,
    span_score::{InteractionType, GovernanceFlag, WordMath},
    determine_capability_mode, validate_monotone_transition,
};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};

// ============================================================================
// HARASSMENT DETECTION CONTEXT
// ============================================================================

/// Contextual metadata for harassment detection across nodes and sessions.
/// Enables traceability and forensic analysis of detection events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionContext {
    /// Unique session identifier.
    pub session_id: String,
    /// Node identifier (Prometheus, Bostrom, Loihi2, Nanoswarm).
    pub node_id: String,
    /// User/device DID for accountability.
    pub user_did: Option<String>,
    /// Interaction type being analyzed.
    pub interaction_type: InteractionType,
    /// Timestamp of detection (UNIX epoch milliseconds).
    pub timestamp: u64,
    /// Geographic region for compliance routing (optional).
    pub region: Option<String>,
    /// Device fingerprint for anomaly detection (hashed).
    pub device_fingerprint_hash: Option<String>,
}

impl DetectionContext {
    /// Creates a new DetectionContext instance.
    #[must_use]
    pub fn new(
        session_id: String,
        node_id: String,
        user_did: Option<String>,
        interaction_type: InteractionType,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            session_id,
            node_id,
            user_did,
            interaction_type,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            region: None,
            device_fingerprint_hash: None,
        }
    }

    /// Sets the geographic region.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Sets the device fingerprint hash.
    pub fn with_device_fingerprint(mut self, hash: String) -> Self {
        self.device_fingerprint_hash = Some(hash);
        self
    }

    /// Returns true if this context involves high-priority interaction types.
    #[must_use]
    pub fn is_high_priority_interaction(&self) -> bool {
        matches!(
            self.interaction_type,
            InteractionType::Haptic | InteractionType::Neural | InteractionType::Biosensor
        )
    }
}

impl Display for DetectionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DetectionContext[session={}, node={}, type={}, ts={}]",
            self.session_id, self.node_id, self.interaction_type, self.timestamp
        )
    }
}

// ============================================================================
// HARASSMENT DETECTION RESULT
// ============================================================================

/// Result structure from harassment detection analysis.
/// Contains scores, flags, and recommended actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Computed rogue score for this detection window.
    pub rogue_score: RogueScore,
    /// Recommended capability mode based on score.
    pub recommended_mode: CapabilityMode,
    /// Current capability mode (for transition validation).
    pub current_mode: CapabilityMode,
    /// Detection context metadata.
    pub context: DetectionContext,
    /// Detected harassment families with confidence scores.
    pub detected_families: HashMap<BlacklistFamily, f64>,
    /// Governance flags triggered by this detection.
    pub triggered_flags: Vec<GovernanceFlag>,
    /// Whether escalation is recommended.
    pub escalation_recommended: bool,
    /// Whether monotone transition is valid.
    pub transition_valid: bool,
    /// Detection timestamp (UNIX epoch milliseconds).
    pub detected_at: u64,
    /// Processing latency in microseconds.
    pub processing_latency_us: u64,
}

impl DetectionResult {
    /// Creates a new DetectionResult instance.
    #[must_use]
    pub fn new(
        rogue_score: RogueScore,
        current_mode: CapabilityMode,
        context: DetectionContext,
        processing_latency_us: u64,
    ) -> Self {
        let config = RogueConfig::production();
        let recommended_mode = determine_capability_mode(&rogue_score, &config);
        let escalation_recommended = recommended_mode.is_escalation_from(&current_mode);
        let transition_valid = validate_monotone_transition(current_mode, recommended_mode);

        let mut detected_families = HashMap::new();
        for (idx, &score) in rogue_score.per_family.iter().enumerate() {
            if let Some(family) = BlacklistFamily::all_families().get(idx) {
                if score > 0.1 {
                    detected_families.insert(*family, score);
                }
            }
        }

        let mut triggered_flags = Vec::new();
        if escalation_recommended {
            triggered_flags.push(GovernanceFlag::EscalationTrigger);
        }
        if rogue_score.r_total > config.tau2 {
            triggered_flags.push(GovernanceFlag::ReviewRequired);
            triggered_flags.push(GovernanceFlag::MultiSigRequired);
        }

        Self {
            rogue_score,
            recommended_mode,
            current_mode,
            context,
            detected_families,
            triggered_flags,
            escalation_recommended,
            transition_valid,
            detected_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            processing_latency_us,
        }
    }

    /// Returns true if high-priority harassment (HTA/NHSP) was detected.
    #[must_use]
    pub fn has_high_priority_harassment(&self) -> bool {
        self.detected_families
            .get(&BlacklistFamily::HTA)
            .copied()
            .unwrap_or(0.0)
            > 0.5
            || self
                .detected_families
                .get(&BlacklistFamily::NHSP)
                .copied()
                .unwrap_or(0.0)
                > 0.5
    }

    /// Returns the dominant harassment family if any detected.
    #[must_use]
    pub fn dominant_family(&self) -> Option<BlacklistFamily> {
        self.detected_families
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(family, _)| *family)
    }

    /// Returns true if this result requires immediate intervention.
    #[must_use]
    pub fn requires_immediate_intervention(&self) -> bool {
        self.has_high_priority_harassment()
            && self.recommended_mode == CapabilityMode::AugmentedReview
    }

    /// Returns a sanitized audit record for logging.
    #[must_use]
    pub fn to_audit_record(&self) -> DetectionAuditRecord {
        DetectionAuditRecord {
            session_id: self.context.session_id.clone(),
            node_id: self.context.node_id.clone(),
            rogue_score_total: self.rogue_score.r_total,
            recommended_mode: self.recommended_mode,
            current_mode: self.current_mode,
            escalation_recommended: self.escalation_recommended,
            transition_valid: self.transition_valid,
            detected_families_count: self.detected_families.len(),
            triggered_flags_count: self.triggered_flags.len(),
            detected_at: self.detected_at,
            processing_latency_us: self.processing_latency_us,
        }
    }
}

impl Display for DetectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DetectionResult[score={:.2}, mode={:?}, escalation={}, high_priority={}]",
            self.rogue_score.r_total,
            self.recommended_mode,
            self.escalation_recommended,
            self.has_high_priority_harassment()
        )
    }
}

// ============================================================================
// DETECTION AUDIT RECORD
// ============================================================================

/// Sanitized audit record for compliance and forensic analysis.
/// Contains no raw content, only metadata and computed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionAuditRecord {
    /// Session identifier.
    pub session_id: String,
    /// Node identifier.
    pub node_id: String,
    /// Total rogue score.
    pub rogue_score_total: f64,
    /// Recommended capability mode.
    pub recommended_mode: CapabilityMode,
    /// Current capability mode.
    pub current_mode: CapabilityMode,
    /// Whether escalation was recommended.
    pub escalation_recommended: bool,
    /// Whether monotone transition is valid.
    pub transition_valid: bool,
    /// Number of detected harassment families.
    pub detected_families_count: usize,
    /// Number of triggered governance flags.
    pub triggered_flags_count: usize,
    /// Detection timestamp.
    pub detected_at: u64,
    /// Processing latency in microseconds.
    pub processing_latency_us: u64,
}

impl DetectionAuditRecord {
    /// Returns true if this record indicates a neuroright-level event.
    #[must_use]
    pub fn is_neuroright_event(&self) -> bool {
        self.escalation_recommended && self.transition_valid
    }

    /// Returns true if processing latency exceeded thresholds.
    #[must_use]
    pub fn is_latency_anomaly(&self) -> bool {
        self.processing_latency_us > 100_000  // 100ms threshold
    }
}

// ============================================================================
// NEURAL IO STREAM METRICS
// ============================================================================

/// Metrics extracted from neural I/O streams for harassment detection.
/// Used to populate SpanScore family weights for NHSP detection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NeuralIoMetrics {
    /// Spike rate deviation from baseline (standard deviations).
    pub spike_rate_zscore: f64,
    /// Neural coherence metric (0.0-1.0).
    pub coherence: f64,
    /// Spectral power in stress-associated frequency bands.
    pub stress_band_power: f64,
    /// Event-related potential anomaly score.
    pub erp_anomaly: f64,
    /// Signal-to-noise ratio.
    pub snr: f64,
}

impl NeuralIoMetrics {
    /// Creates new NeuralIoMetrics with validated ranges.
    #[must_use]
    pub fn new(
        spike_rate_zscore: f64,
        coherence: f64,
        stress_band_power: f64,
        erp_anomaly: f64,
        snr: f64,
    ) -> Self {
        Self {
            spike_rate_zscore,
            coherence: coherence.clamp(0.0, 1.0),
            stress_band_power: stress_band_power.clamp(0.0, 1.0),
            erp_anomaly: erp_anomaly.clamp(0.0, 1.0),
            snr: snr.max(0.0),
        }
    }

    /// Creates zero-initialized metrics.
    #[must_use]
    pub fn zeros() -> Self {
        Self::new(0.0, 0.5, 0.0, 0.0, 10.0)
    }

    /// Computes NHSP family weight from neural metrics.
    /// Higher values indicate closer match to harassment pattern.
    #[must_use]
    pub fn compute_nhsp_weight(&self) -> f64 {
        let spike_contribution = (self.spike_rate_zscore.abs() / 5.0).clamp(0.0, 1.0);
        let stress_contribution = self.stress_band_power;
        let erp_contribution = self.erp_anomaly;
        let coherence_penalty = (1.0 - self.coherence) * 0.5;
        (spike_contribution * 0.4)
            + (stress_contribution * 0.3)
            + (erp_contribution * 0.2)
            + (coherence_penalty * 0.1)
    }

    /// Returns true if metrics indicate anomalous neural activity.
    #[must_use]
    pub fn is_anomalous(&self, threshold: f64) -> bool {
        self.compute_nhsp_weight() > threshold
    }
}

// ============================================================================
// HAPTIC CHANNEL METRICS
// ============================================================================

/// Metrics extracted from haptic feedback channels for HTA detection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HapticChannelMetrics {
    /// Stimulation amplitude (normalized 0.0-1.0).
    pub amplitude: f64,
    /// Stimulation frequency in Hz.
    pub frequency_hz: f64,
    /// Duration of stimulation in milliseconds.
    pub duration_ms: f64,
    /// Body region identifier (hashed for privacy).
    pub body_region_hash: String,
    /// Pattern complexity score (0.0-1.0).
    pub pattern_complexity: f64,
    /// Repetition count in current window.
    pub repetition_count: u32,
}

impl HapticChannelMetrics {
    /// Creates new HapticChannelMetrics with validated ranges.
    #[must_use]
    pub fn new(
        amplitude: f64,
        frequency_hz: f64,
        duration_ms: f64,
        body_region_hash: String,
        pattern_complexity: f64,
        repetition_count: u32,
    ) -> Self {
        Self {
            amplitude: amplitude.clamp(0.0, 1.0),
            frequency_hz: frequency_hz.max(0.0),
            duration_ms: duration_ms.max(0.0),
            body_region_hash,
            pattern_complexity: pattern_complexity.clamp(0.0, 1.0),
            repetition_count,
        }
    }

    /// Creates default metrics for benign haptic feedback.
    #[must_use]
    pub fn benign() -> Self {
        Self::new(0.3, 50.0, 100.0, "neutral_region".to_string(), 0.2, 1)
    }

    /// Computes HTA family weight from haptic metrics.
    /// Higher values indicate closer match to abuse pattern.
    #[must_use]
    pub fn compute_hta_weight(&self, sensitive_regions: &[&str]) -> f64 {
        let amplitude_factor = self.amplitude.powf(2.0);
        let duration_factor = (self.duration_ms / 5000.0).clamp(0.0, 1.0);
        let repetition_factor = (self.repetition_count as f64 / 10.0).clamp(0.0, 1.0);
        let region_sensitivity = if sensitive_regions.iter().any(|r| r == &self.body_region_hash) {
            1.5
        } else {
            1.0
        };
        let complexity_factor = self.pattern_complexity;
        ((amplitude_factor * 0.3)
            + (duration_factor * 0.2)
            + (repetition_factor * 0.3)
            + (complexity_factor * 0.2))
            * region_sensitivity
    }

    /// Returns true if haptic pattern exceeds safety envelope.
    #[must_use]
    pub fn exceeds_safety_envelope(&self, max_amplitude: f64, max_duration_ms: f64) -> bool {
        self.amplitude > max_amplitude || self.duration_ms > max_duration_ms
    }
}

// ============================================================================
// HARASSMENT DETECTOR ENGINE
// ============================================================================

/// Core harassment detection engine with stateful tracking.
/// Maintains session state and provides monotone escalation guarantees.
pub struct HarassmentDetector {
    /// Configuration parameters.
    config: Arc<RogueConfig>,
    /// Current capability mode (protected by RwLock for thread safety).
    current_mode: Arc<RwLock<CapabilityMode>>,
    /// Session state cache.
    session_cache: Arc<RwLock<HashMap<String, SessionState>>>,
    /// Sensitive body region hashes for HTA detection.
    sensitive_regions: Arc<Vec<String>>,
    /// Detection event counter.
    detection_count: Arc<RwLock<u64>>,
}

/// Session state for tracking harassment patterns over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Session identifier.
    pub session_id: String,
    /// Cumulative rogue score for session.
    pub cumulative_score: f64,
    /// Span count in current window.
    pub span_count: usize,
    /// Last detection timestamp.
    pub last_detection_at: u64,
    /// Escalation history.
    pub escalation_history: Vec<CapabilityMode>,
    /// High-priority event count.
    pub high_priority_count: u32,
}

impl SessionState {
    /// Creates a new SessionState instance.
    #[must_use]
    pub fn new(session_id: String) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            session_id,
            cumulative_score: 0.0,
            span_count: 0,
            last_detection_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            escalation_history: vec![CapabilityMode::Normal],
            high_priority_count: 0,
        }
    }

    /// Updates session state with new detection result.
    pub fn update(&mut self, result: &DetectionResult) {
        self.cumulative_score += result.rogue_score.r_total;
        self.span_count += 1;
        self.last_detection_at = result.detected_at;
        if result.escalation_recommended {
            self.escalation_history.push(result.recommended_mode);
        }
        if result.has_high_priority_harassment() {
            self.high_priority_count += 1;
        }
    }

    /// Returns true if session shows persistent harassment patterns.
    #[must_use]
    pub fn is_persistent_harassment(&self, threshold: f64) -> bool {
        self.cumulative_score / (self.span_count as f64).max(1.0) > threshold
    }
}

impl HarassmentDetector {
    /// Creates a new HarassmentDetector with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: Arc::new(RogueConfig::production()),
            current_mode: Arc::new(RwLock::new(CapabilityMode::Normal)),
            session_cache: Arc::new(RwLock::new(HashMap::new())),
            sensitive_regions: Arc::new(vec![
                "head_region".to_string(),
                "chest_region".to_string(),
                "spine_region".to_string(),
            ]),
            detection_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Creates a HarassmentDetector with custom configuration.
    #[must_use]
    pub fn with_config(config: RogueConfig) -> Self {
        Self {
            config: Arc::new(config),
            current_mode: Arc::new(RwLock::new(CapabilityMode::Normal)),
            session_cache: Arc::new(RwLock::new(HashMap::new())),
            sensitive_regions: Arc::new(vec![
                "head_region".to_string(),
                "chest_region".to_string(),
                "spine_region".to_string(),
            ]),
            detection_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Sets sensitive body regions for HTA detection.
    pub fn set_sensitive_regions(&mut self, regions: Vec<String>) {
        self.sensitive_regions = Arc::new(regions);
    }

    /// Gets the current capability mode.
    #[must_use]
    pub fn current_mode(&self) -> CapabilityMode {
        *self.current_mode.read().unwrap()
    }

    /// Gets the detection count.
    #[must_use]
    pub fn detection_count(&self) -> u64 {
        *self.detection_count.read().unwrap()
    }

    /// Processes a batch of spans and returns detection result.
    pub fn detect(&self, spans: &[SpanScore], context: DetectionContext) -> DetectionResult {
        let start = std::time::Instant::now();

        // Compute rogue score from spans
        let rogue_score = RogueScore::from_spans(spans, &self.config);

        // Get current mode
        let current_mode = self.current_mode();

        // Create detection result
        let latency_us = start.elapsed().as_micros() as u64;
        let mut result = DetectionResult::new(rogue_score, current_mode, context, latency_us);

        // Update detection count
        {
            let mut count = self.detection_count.write().unwrap();
            *count += 1;
        }

        // Update session state
        {
            let mut cache = self.session_cache.write().unwrap();
            let state = cache
                .entry(result.context.session_id.clone())
                .or_insert_with(|| SessionState::new(result.context.session_id.clone()));
            state.update(&result);
        }

        // Validate monotone transition before applying
        if result.transition_valid && result.escalation_recommended {
            let mut mode = self.current_mode.write().unwrap();
            *mode = result.recommended_mode;
        }

        result
    }

    /// Processes neural I/O metrics and returns NHSP-weighted spans.
    #[must_use]
    pub fn process_neural_metrics(
        &self,
        metrics: NeuralIoMetrics,
        context: &DetectionContext,
    ) -> SpanScore {
        let mut span = SpanScore::new(
            context.session_id.clone(),
            self.detection_count(),
            Some(context.node_id.clone()),
            InteractionType::Neural,
            format!("neural_{}", context.timestamp),
        );

        let nhsp_weight = metrics.compute_nhsp_weight();
        span.set_family_weight(BlacklistFamily::NHSP, nhsp_weight);

        if metrics.is_anomalous(0.5) {
            span.add_governance_flag(GovernanceFlag::PhysioEnvelopeExceeded);
        }

        span.set_word_math(WordMath::new(
            0.2,
            metrics.spike_rate_zscore.abs() / 5.0,
            metrics.stress_band_power,
            0.5,
            0.5,
        ));

        span
    }

    /// Processes haptic channel metrics and returns HTA-weighted spans.
    #[must_use]
    pub fn process_haptic_metrics(
        &self,
        metrics: HapticChannelMetrics,
        context: &DetectionContext,
    ) -> SpanScore {
        let sensitive_refs: Vec<&str> = self.sensitive_regions.iter().map(|s| s.as_str()).collect();
        let mut span = SpanScore::new(
            context.session_id.clone(),
            self.detection_count(),
            Some(context.node_id.clone()),
            InteractionType::Haptic,
            format!("haptic_{}", context.timestamp),
        );

        let hta_weight = metrics.compute_hta_weight(&sensitive_refs);
        span.set_family_weight(BlacklistFamily::HTA, hta_weight);

        if metrics.exceeds_safety_envelope(0.8, 5000.0) {
            span.add_governance_flag(GovernanceFlag::PhysioEnvelopeExceeded);
            span.add_governance_flag(GovernanceFlag::NeurorightViolation);
        }

        span.set_word_math(WordMath::new(
            metrics.repetition_count as f64 / 10.0,
            metrics.pattern_complexity,
            metrics.amplitude,
            0.5,
            0.5,
        ));

        span
    }

    /// Gets session state for a given session ID.
    #[must_use]
    pub fn get_session_state(&self, session_id: &str) -> Option<SessionState> {
        let cache = self.session_cache.read().unwrap();
        cache.get(session_id).cloned()
    }

    /// Resets session state for a given session ID.
    pub fn reset_session(&self, session_id: &str) {
        let mut cache = self.session_cache.write().unwrap();
        cache.remove(session_id);
    }

    /// Resets capability mode to Normal (only valid in development).
    pub fn reset_mode(&self) {
        if self.config.environment == crate::rogue_config::DeploymentEnvironment::Development
            || self.config.environment == crate::rogue_config::DeploymentEnvironment::Research
        {
            let mut mode = self.current_mode.write().unwrap();
            *mode = CapabilityMode::Normal;
        }
    }

    /// Returns configuration audit summary.
    #[must_use]
    pub fn config_summary(&self) -> crate::rogue_config::ConfigAuditSummary {
        self.config.audit_summary()
    }
}

impl Default for HarassmentDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Computes harassment rogue score from spans (convenience wrapper).
#[must_use]
pub fn compute_harassment_rogue(spans: &[SpanScore], cfg: &RogueConfig) -> RogueScore {
    RogueScore::from_spans(spans, cfg)
}

/// Determines capability mode from rogue score (convenience wrapper).
#[must_use]
pub fn escalate_on_harassment(r: &RogueScore, cfg: &RogueConfig) -> CapabilityMode {
    determine_capability_mode(r, cfg)
}

/// Creates a detection context for neural interactions.
#[must_use]
pub fn neural_context(session_id: String, node_id: String, user_did: Option<String>) -> DetectionContext {
    DetectionContext::new(session_id, node_id, user_did, InteractionType::Neural)
}

/// Creates a detection context for haptic interactions.
#[must_use]
pub fn haptic_context(session_id: String, node_id: String, user_did: Option<String>) -> DetectionContext {
    DetectionContext::new(session_id, node_id, user_did, InteractionType::Haptic)
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neural_io_metrics_nhsp_weight() {
        let normal = NeuralIoMetrics::new(0.5, 0.8, 0.2, 0.1, 20.0);
        let anomalous = NeuralIoMetrics::new(4.0, 0.3, 0.8, 0.7, 5.0);
        assert!(anomalous.compute_nhsp_weight() > normal.compute_nhsp_weight());
        assert!(anomalous.is_anomalous(0.5));
    }

    #[test]
    fn test_haptic_channel_metrics_hta_weight() {
        let benign = HapticChannelMetrics::benign();
        let aggressive = HapticChannelMetrics::new(0.9, 200.0, 8000.0, "head_region".to_string(), 0.8, 15);
        let sensitive = vec!["head_region"];
        assert!(aggressive.compute_hta_weight(&sensitive) > benign.compute_hta_weight(&sensitive));
        assert!(aggressive.exceeds_safety_envelope(0.8, 5000.0));
    }

    #[test]
    fn test_harassment_detector_detection() {
        let detector = HarassmentDetector::new();
        let context = DetectionContext::new(
            "test_session".to_string(),
            "Prometheus".to_string(),
            Some("user_did".to_string()),
            InteractionType::Text,
        );

        let mut span = SpanScore::new(
            "test_session".to_string(),
            1,
            Some("Prometheus".to_string()),
            InteractionType::Text,
            "hash".to_string(),
        );
        span.set_family_weight(BlacklistFamily::NHSP, 0.7);

        let result = detector.detect(&[span], context);
        assert!(result.transition_valid);
        assert_eq!(result.context.session_id, "test_session");
    }

    #[test]
    fn test_session_state_tracking() {
        let mut state = SessionState::new("test".to_string());
        assert_eq!(state.span_count, 0);
        assert_eq!(state.cumulative_score, 0.0);

        let detector = HarassmentDetector::new();
        let context = DetectionContext::new(
            "test".to_string(),
            "TestNode".to_string(),
            None,
            InteractionType::Text,
        );
        let mut span = SpanScore::new(
            "test".to_string(),
            1,
            Some("TestNode".to_string()),
            InteractionType::Text,
            "hash".to_string(),
        );
        span.set_family_weight(BlacklistFamily::HTA, 0.6);

        let result = detector.detect(&[span], context);
        let updated_state = detector.get_session_state("test").unwrap();
        assert_eq!(updated_state.span_count, 1);
    }

    #[test]
    fn test_monotone_mode_transitions() {
        let detector = HarassmentDetector::new();
        assert_eq!(detector.current_mode(), CapabilityMode::Normal);

        // Simulate escalation through detection
        let context = DetectionContext::new(
            "escalation_test".to_string(),
            "TestNode".to_string(),
            None,
            InteractionType::Neural,
        );
        let mut span = SpanScore::new(
            "escalation_test".to_string(),
            1,
            Some("TestNode".to_string()),
            InteractionType::Neural,
            "hash".to_string(),
        );
        span.set_family_weight(BlacklistFamily::NHSP, 0.9);
        span.set_family_weight(BlacklistFamily::HTA, 0.9);

        let _result = detector.detect(&[span], context);
        // Mode should have escalated if thresholds exceeded
        let new_mode = detector.current_mode();
        assert!(new_mode as u8 >= CapabilityMode::Normal as u8);
    }

    #[test]
    fn test_detection_result_audit_record() {
        let detector = HarassmentDetector::new();
        let context = DetectionContext::new(
            "audit_test".to_string(),
            "TestNode".to_string(),
            None,
            InteractionType::Text,
        );
        let span = SpanScore::new(
            "audit_test".to_string(),
            1,
            Some("TestNode".to_string()),
            InteractionType::Text,
            "hash".to_string(),
        );
        let result = detector.detect(&[span], context);
        let audit = result.to_audit_record();
        assert_eq!(audit.session_id, "audit_test");
        assert!(audit.transition_valid);
    }

    #[test]
    fn test_convenience_functions() {
        let config = RogueConfig::production();
        let span = SpanScore::new(
            "test".to_string(),
            1,
            None,
            InteractionType::Text,
            "hash".to_string(),
        );
        let score = compute_harassment_rogue(&[span], &config);
        let mode = escalate_on_harassment(&score, &config);
        assert!(mode as u8 >= CapabilityMode::Normal as u8);
    }

    #[test]
    fn test_context_high_priority_interaction() {
        let neural_ctx = DetectionContext::new(
            "test".to_string(),
            "Node".to_string(),
            None,
            InteractionType::Neural,
        );
        let text_ctx = DetectionContext::new(
            "test".to_string(),
            "Node".to_string(),
            None,
            InteractionType::Text,
        );
        assert!(neural_ctx.is_high_priority_interaction());
        assert!(!text_ctx.is_high_priority_interaction());
    }

    #[test]
    fn test_detection_result_high_priority() {
        let detector = HarassmentDetector::new();
        let context = DetectionContext::new(
            "hp_test".to_string(),
            "Node".to_string(),
            None,
            InteractionType::Haptic,
        );
        let mut span = SpanScore::new(
            "hp_test".to_string(),
            1,
            Some("Node".to_string()),
            InteractionType::Haptic,
            "hash".to_string(),
        );
        span.set_family_weight(BlacklistFamily::HTA, 0.8);
        let result = detector.detect(&[span], context);
        assert!(result.has_high_priority_harassment());
    }

    #[test]
    fn test_session_reset() {
        let detector = HarassmentDetector::new();
        let context = DetectionContext::new(
            "reset_test".to_string(),
            "Node".to_string(),
            None,
            InteractionType::Text,
        );
        let span = SpanScore::new(
            "reset_test".to_string(),
            1,
            Some("Node".to_string()),
            InteractionType::Text,
            "hash".to_string(),
        );
        let _ = detector.detect(&[span], context);
        assert!(detector.get_session_state("reset_test").is_some());
        detector.reset_session("reset_test");
        assert!(detector.get_session_state("reset_test").is_none());
    }
}
