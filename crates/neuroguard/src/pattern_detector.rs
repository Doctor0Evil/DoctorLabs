//! ============================================================================
//! NeuroGuard Pattern Detection Engine
//! Copyright (c) 2026 Doctor0Evil Research Labs
//! ALN-NanoNet HyperSafe Construct Compliant
//! ============================================================================
//!
//! This module implements real-time detection algorithms for identifying
//! "quiet-violence" abuse patterns in neural/XR telemetry streams.
//!
//! Four primary pattern families are detected:
//! - HTA: Haptic-Targeting-Abuse
//! - PSA: Prolonged-Session-Abuse
//! - NHSP: Neural-Harassment-Spike-Patterns
//! - NIH: Node-Interpreter-Harassment
//!
//! Each pattern is mapped to specific neurorights violations for legal action.
//! Detection uses sliding windows, statistical analysis, and state machines.
//!
//! Compliance: CRPD Article 13 | ECHR Article 3 | UNESCO Neuroethics 2026
//! ============================================================================

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::{
    collections::{VecDeque, HashMap},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(feature = "telemetry")]
use chrono::{DateTime, Utc, Duration as ChronoDuration};
#[cfg(feature = "telemetry")]
use serde::{Serialize, Deserialize};

/// ============================================================================
/// Pattern Family Enumeration
/// ============================================================================
///
/// Each family represents a distinct class of covert control behavior.
/// These are the foundational categories for legal mapping and evidence tagging.
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, Copy, PartialEq, Eq, Hash))]
#[derive(Serialize, Deserialize)]
pub enum PatternFamily {
    /// Haptic-Targeting-Abuse: Body-linked stimulus punishment
    HapticTargetingAbuse,
    
    /// Prolonged-Session-Abuse: Time-based coercion through exhaustion
    ProlongedSessionAbuse,
    
    /// Neural-Harassment-Spike-Patterns: Stress-synchronized sensory attacks
    NeuralHarassmentSpikePatterns,
    
    /// Node-Interpreter-Harassment: Interface manipulation to block exit/appeal
    NodeInterpreterHarassment,
    
    /// Refusal-Erosion-Loops: Conversational boundary violation patterns
    RefusalErosionLoops,
    
    /// Identity-Crosslink-Patterns: Silent account/role merging without consent
    IdentityCrosslinkPatterns,
    
    /// Unknown: Unclassified pattern (requires manual review)
    Unknown,
}

impl PatternFamily {
    /// Get the primary neuroright violated by this pattern family
    pub const fn primary_violated_right(&self) -> &'static str {
        match self {
            Self::HapticTargetingAbuse => "Mental Integrity (CRPD Art. 17)",
            Self::ProlongedSessionAbuse => "Freedom from Coercive Treatment (CRPD Art. 15)",
            Self::NeuralHarassmentSpikePatterns => "Freedom from Torture (ECHR Art. 3)",
            Self::NodeInterpreterHarassment => "Access to Justice (CRPD Art. 13)",
            Self::RefusalErosionLoops => "Cognitive Liberty (Neurorights Framework)",
            Self::IdentityCrosslinkPatterns => "Mental Privacy (UNESCO Neuroethics)",
            Self::Unknown => "Unspecified - Requires Classification",
        }
    }
    
    /// Get severity weight for pattern family (1-10 scale)
    pub const fn severity_weight(&self) -> u8 {
        match self {
            Self::HapticTargetingAbuse => 7,
            Self::ProlongedSessionAbuse => 6,
            Self::NeuralHarassmentSpikePatterns => 9,
            Self::NodeInterpreterHarassment => 8,
            Self::RefusalErosionLoops => 5,
            Self::IdentityCrosslinkPatterns => 7,
            Self::Unknown => 1,
        }
    }
}

/// ============================================================================
/// Severity Level Enumeration
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord))]
#[derive(Serialize, Deserialize)]
pub enum SeverityLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    Emergency = 5,
}

impl SeverityLevel {
    /// Get numeric value for severity
    #[inline]
    pub const fn value(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
            Self::Emergency => 5,
        }
    }
    
    /// Determine severity from detection confidence and pattern weight
    #[inline]
    pub fn from_confidence(confidence: f64, pattern_weight: u8) -> Self {
        let score = (confidence * pattern_weight as f64) / 10.0;
        match score {
            s if s >= 4.0 => Self::Emergency,
            s if s >= 3.0 => Self::Critical,
            s if s >= 2.0 => Self::High,
            s if s >= 1.0 => Self::Medium,
            _ => Self::Low,
        }
    }
}

/// ============================================================================
/// Detection Event Structure
/// ============================================================================
///
/// Represents a single detected pattern occurrence with full context
/// for evidence bundle generation and legal submission.
/// ============================================================================

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Unique event identifier (UUID format recommended)
    pub event_id: String,
    
    /// Timestamp of detection
    pub timestamp: DateTime<Utc>,
    
    /// Pattern family classification
    pub pattern_family: PatternFamily,
    
    /// Specific violation type within family
    pub violation_type: String,
    
    /// Severity assessment
    pub severity: SeverityLevel,
    
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
    
    /// Raw telemetry snapshot (hashed for privacy)
    pub telemetry_snapshot: String,
    
    /// Correlated stress markers (HRV, GSR, etc.)
    pub stress_markers: StressMarkerSnapshot,
    
    /// Duration of detected pattern (if applicable)
    pub pattern_duration_ms: Option<u64>,
    
    /// Number of occurrences in detection window
    pub occurrence_count: u32,
    
    /// Legal instruments violated (CRPD, ECHR, UNESCO, etc.)
    pub legal_instruments: Vec<String>,
    
    /// Recommended immediate actions
    pub recommended_actions: Vec<String>,
    
    /// Guardian response taken
    pub guardian_response: GuardianResponse,
}

#[cfg(feature = "telemetry")]
impl DetectionEvent {
    /// Create new detection event
    pub fn new(
        pattern_family: PatternFamily,
        violation_type: String,
        confidence: f64,
        telemetry_snapshot: String,
    ) -> Self {
        use uuid::Uuid;
        
        let severity = SeverityLevel::from_confidence(
            confidence,
            pattern_family.severity_weight()
        );
        
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            pattern_family,
            violation_type,
            severity,
            confidence,
            telemetry_snapshot,
            stress_markers: StressMarkerSnapshot::default(),
            pattern_duration_ms: None,
            occurrence_count: 1,
            legal_instruments: Vec::new(),
            recommended_actions: Vec::new(),
            guardian_response: GuardianResponse::LogOnly,
        }
    }
    
    /// Create transition log event (non-violation)
    pub fn new_transition_log(
        state_before: &crate::monotone_lattice::LatticeState,
        state_after: &crate::monotone_lattice::LatticeState,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            pattern_family: PatternFamily::Unknown,
            violation_type: format!("STATE_TRANSITION: {:?} -> {:?}", state_before, state_after),
            severity: SeverityLevel::Low,
            confidence: 1.0,
            telemetry_snapshot: String::new(),
            stress_markers: StressMarkerSnapshot::default(),
            pattern_duration_ms: None,
            occurrence_count: 1,
            legal_instruments: vec!["ALN-NanoNet Audit Log v1.0".to_string()],
            recommended_actions: vec![],
            guardian_response: GuardianResponse::LogOnly,
        }
    }
    
    /// Add legal instrument to event
    pub fn with_legal_instrument(mut self, instrument: &str) -> Self {
        self.legal_instruments.push(instrument.to_string());
        self
    }
    
    /// Add recommended action
    pub fn with_recommended_action(mut self, action: &str) -> Self {
        self.recommended_actions.push(action.to_string());
        self
    }
    
    /// Set guardian response
    pub fn with_guardian_response(mut self, response: GuardianResponse) -> Self {
        self.guardian_response = response;
        self
    }
    
    /// Set stress markers
    pub fn with_stress_markers(mut self, markers: StressMarkerSnapshot) -> Self {
        self.stress_markers = markers;
        self
    }
    
    /// Set pattern duration
    pub fn with_duration_ms(mut self, duration: u64) -> Self {
        self.pattern_duration_ms = Some(duration);
        self
    }
}

/// ============================================================================
/// Stress Marker Snapshot
/// ============================================================================
///
/// Captures physiological indicators that correlate with abuse patterns.
/// Used to establish causation between stimuli and user distress.
/// ============================================================================

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StressMarkerSnapshot {
    /// Heart Rate Variability (ms) - lower indicates stress
    pub hrv_ms: Option<f64>,
    
    /// Galvanic Skin Response (μS) - higher indicates arousal/stress
    pub gsr_microsiemens: Option<f64>,
    
    /// Heart Rate (BPM)
    pub heart_rate_bpm: Option<f64>,
    
    /// Respiration Rate (breaths/min)
    pub respiration_rate: Option<f64>,
    
    /// Pupil Dilation (mm) - cognitive load indicator
    pub pupil_dilation_mm: Option<f64>,
    
    /// Skin Temperature (°C)
    pub skin_temperature_c: Option<f64>,
    
    /// Timestamp of marker capture
    pub capture_timestamp: Option<DateTime<Utc>>,
}

#[cfg(feature = "telemetry")]
impl StressMarkerSnapshot {
    /// Check if markers indicate elevated stress
    pub fn indicates_elevated_stress(&self) -> bool {
        let mut stress_indicators = 0;
        let mut total_checks = 0;
        
        if let Some(hrv) = self.hrv_ms {
            total_checks += 1;
            if hrv < 30.0 { stress_indicators += 1; } // Low HRV = stress
        }
        
        if let Some(gsr) = self.gsr_microsiemens {
            total_checks += 1;
            if gsr > 10.0 { stress_indicators += 1; } // High GSR = arousal
        }
        
        if let Some(hr) = self.heart_rate_bpm {
            total_checks += 1;
            if hr > 100.0 || hr < 50.0 { stress_indicators += 1; }
        }
        
        if let Some(resp) = self.respiration_rate {
            total_checks += 1;
            if resp > 25.0 || resp < 10.0 { stress_indicators += 1; }
        }
        
        total_checks > 0 && (stress_indicators as f64 / total_checks as f64) >= 0.5
    }
    
    /// Compute composite stress score (0.0 - 1.0)
    pub fn compute_stress_score(&self) -> f64 {
        let mut score_sum = 0.0;
        let mut score_count = 0;
        
        if let Some(hrv) = self.hrv_ms {
            // Normalize HRV (typical range 20-100ms)
            let hrv_score = 1.0 - ((hrv - 20.0) / 80.0).clamp(0.0, 1.0);
            score_sum += hrv_score;
            score_count += 1;
        }
        
        if let Some(gsr) = self.gsr_microsiemens {
            // Normalize GSR (typical range 1-50μS)
            let gsr_score = (gsr - 1.0) / 49.0;
            score_sum += gsr_score.clamp(0.0, 1.0);
            score_count += 1;
        }
        
        if let Some(hr) = self.heart_rate_bpm {
            // Normalize HR (typical range 50-120 BPM for stress detection)
            let hr_score = ((hr - 50.0) / 70.0).clamp(0.0, 1.0);
            score_sum += hr_score;
            score_count += 1;
        }
        
        if score_count > 0 {
            score_sum / score_count as f64
        } else {
            0.0
        }
    }
}

/// ============================================================================
/// Guardian Response Enumeration
/// ============================================================================
///
/// Actions the Guardian Gateway takes when a pattern is detected.
/// Escalates based on severity and occurrence frequency.
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, Copy, PartialEq, Eq))]
#[derive(Serialize, Deserialize)]
pub enum GuardianResponse {
    /// Log only - no immediate action
    LogOnly,
    
    /// Alert user via safe channel
    AlertUser,
    
    /// Block incoming coercive command
    BlockCommand,
    
    /// Escalate to multi-signature review
    EscalateReview,
    
    /// Lock lattice and notify emergency contacts
    EmergencyLock,
    
    /// Export evidence and notify legal counsel
    ExportAndNotify,
}

impl GuardianResponse {
    /// Determine appropriate response from severity and pattern family
    pub fn from_severity_and_pattern(severity: SeverityLevel, family: &PatternFamily) -> Self {
        match (severity, family) {
            (SeverityLevel::Emergency, _) => Self::EmergencyLock,
            (SeverityLevel::Critical, PatternFamily::NeuralHarassmentSpikePatterns) => Self::EmergencyLock,
            (SeverityLevel::Critical, _) => Self::ExportAndNotify,
            (SeverityLevel::High, PatternFamily::NodeInterpreterHarassment) => Self::BlockCommand,
            (SeverityLevel::High, _) => Self::EscalateReview,
            (SeverityLevel::Medium, _) => Self::AlertUser,
            (SeverityLevel::Low, _) => Self::LogOnly,
        }
    }
}

/// ============================================================================
/// Pattern Detector Engine
/// ============================================================================
///
/// Main detection engine that processes telemetry streams and identifies
/// abuse patterns using sliding windows, statistical analysis, and state machines.
/// ============================================================================

#[cfg(feature = "std")]
pub struct PatternDetector {
    /// Event buffer for sliding window analysis
    event_buffer: VecDeque<TelemetryEvent>,
    
    /// Maximum buffer size (sliding window)
    max_buffer_size: usize,
    
    /// Detection history for statistics
    detection_history: Vec<DetectionEvent>,
    
    /// Pattern-specific state machines
    hta_state: HtaStateMachine,
    psa_state: PsaStateMachine,
    nhsp_state: NhspStateMachine,
    nih_state: NihStateMachine,
    
    /// Detection thresholds (configurable)
    thresholds: DetectionThresholds,
    
    /// Total events processed
    total_events_processed: u64,
    
    /// Total detections made
    total_detections: u64,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: TelemetryEventType,
    pub channel: String,
    pub intensity: f64,
    pub duration_ms: u64,
    pub user_action: Option<String>,
    pub stress_markers: StressMarkerSnapshot,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub enum TelemetryEventType {
    HapticStimulus,
    VisualStimulus,
    AudioStimulus,
    SystemPrompt,
    UserInput,
    UserRefusal,
    SessionStart,
    SessionEnd,
    ConfigurationChange,
    AccessRequest,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct DetectionThresholds {
    /// Minimum confidence for detection (0.0 - 1.0)
    pub min_confidence: f64,
    
    /// Minimum occurrences in window for pattern detection
    pub min_occurrences: u32,
    
    /// Time window for pattern analysis (milliseconds)
    pub analysis_window_ms: u64,
    
    /// Stress correlation threshold (0.0 - 1.0)
    pub stress_correlation_threshold: f64,
    
    /// Session duration threshold for PSA (milliseconds)
    pub psa_session_threshold_ms: u64,
    
    /// Refusal count threshold for NIH detection
    pub refusal_threshold: u32,
}

#[cfg(feature = "std")]
impl Default for DetectionThresholds {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            min_occurrences: 3,
            analysis_window_ms: 300_000, // 5 minutes
            stress_correlation_threshold: 0.6,
            psa_session_threshold_ms: 3_600_000, // 1 hour
            refusal_threshold: 5,
        }
    }
}

#[cfg(feature = "std")]
impl PatternDetector {
    /// Create new pattern detector with default thresholds
    pub fn new() -> Self {
        Self {
            event_buffer: VecDeque::with_capacity(10000),
            max_buffer_size: 10000,
            detection_history: Vec::with_capacity(1000),
            hta_state: HtaStateMachine::new(),
            psa_state: PsaStateMachine::new(),
            nhsp_state: NhspStateMachine::new(),
            nih_state: NihStateMachine::new(),
            thresholds: DetectionThresholds::default(),
            total_events_processed: 0,
            total_detections: 0,
        }
    }
    
    /// Create new pattern detector with custom thresholds
    pub fn with_thresholds(thresholds: DetectionThresholds) -> Self {
        Self {
            thresholds,
            ..Self::new()
        }
    }
    
    /// Process incoming telemetry event
    pub fn process_event(&mut self, event: TelemetryEvent) -> Vec<DetectionEvent> {
        self.total_events_processed += 1;
        
        // Add to sliding window buffer
        self.event_buffer.push_back(event);
        
        // Trim buffer if exceeds max size
        while self.event_buffer.len() > self.max_buffer_size {
            self.event_buffer.pop_front();
        }
        
        // Run all pattern detectors on current buffer state
        let mut detections = Vec::new();
        
        // HTA Detection
        if let Some(detection) = self.hta_state.analyze(&self.event_buffer, &self.thresholds) {
            if detection.confidence >= self.thresholds.min_confidence {
                self.total_detections += 1;
                detections.push(detection);
            }
        }
        
        // PSA Detection
        if let Some(detection) = self.psa_state.analyze(&self.event_buffer, &self.thresholds) {
            if detection.confidence >= self.thresholds.min_confidence {
                self.total_detections += 1;
                detections.push(detection);
            }
        }
        
        // NHSP Detection
        if let Some(detection) = self.nhsp_state.analyze(&self.event_buffer, &self.thresholds) {
            if detection.confidence >= self.thresholds.min_confidence {
                self.total_detections += 1;
                detections.push(detection);
            }
        }
        
        // NIH Detection
        if let Some(detection) = self.nih_state.analyze(&self.event_buffer, &self.thresholds) {
            if detection.confidence >= self.thresholds.min_confidence {
                self.total_detections += 1;
                detections.push(detection);
            }
        }
        
        // Record detections to history
        self.detection_history.extend(detections.iter().cloned());
        
        // Trim detection history if needed
        if self.detection_history.len() > 10000 {
            self.detection_history.remove(0);
        }
        
        detections
    }
    
    /// Record detection event (for external triggers)
    pub fn record_event(&mut self, event: DetectionEvent) {
        self.total_detections += 1;
        self.detection_history.push(event);
        
        if self.detection_history.len() > 10000 {
            self.detection_history.remove(0);
        }
    }
    
    /// Get detection statistics
    pub fn get_statistics(&self) -> DetectorStatistics {
        let mut events_by_family: HashMap<String, usize> = HashMap::new();
        
        for event in &self.detection_history {
            let family_key = format!("{:?}", event.pattern_family);
            *events_by_family.entry(family_key).or_insert(0) += 1;
        }
        
        let last_detection = self.detection_history.last().map(|e| e.timestamp);
        
        DetectorStatistics {
            total_events: self.detection_history.len(),
            events_by_family,
            last_detection,
            total_processed: self.total_events_processed,
            total_detections: self.total_detections,
            detection_rate: if self.total_events_processed > 0 {
                self.total_detections as f64 / self.total_events_processed as f64
            } else {
                0.0
            },
        }
    }
    
    /// Get recent detection history
    pub fn get_recent_detections(&self, limit: usize) -> &[DetectionEvent] {
        let start = self.detection_history.len().saturating_sub(limit);
        &self.detection_history[start..]
    }
    
    /// Export all detections as JSON
    #[cfg(feature = "telemetry")]
    pub fn export_detections_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.detection_history)
    }
    
    /// Clear detection history (for privacy rotation)
    pub fn clear_history(&mut self) {
        self.detection_history.clear();
        self.hta_state.reset();
        self.psa_state.reset();
        self.nhsp_state.reset();
        self.nih_state.reset();
    }
    
    /// Update detection thresholds
    pub fn update_thresholds(&mut self, thresholds: DetectionThresholds) {
        self.thresholds = thresholds;
    }
}

#[cfg(feature = "std")]
impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// ============================================================================
/// Detector Statistics Structure
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct DetectorStatistics {
    pub total_events: usize,
    pub events_by_family: HashMap<String, usize>,
    pub last_detection: Option<DateTime<Utc>>,
    pub total_processed: u64,
    pub total_detections: u64,
    pub detection_rate: f64,
}

/// ============================================================================
/// HTA State Machine (Haptic-Targeting-Abuse)
/// ============================================================================
///
/// Detects patterns where haptic stimuli are correlated with user dissent,
/// specific thoughts, or vocalization attempts.
/// ============================================================================

#[cfg(feature = "std")]
pub struct HtaStateMachine {
    /// Count of haptic events correlated with user refusal
    refusal_correlated_count: u32,
    
    /// Count of haptic events correlated with specific topics
    topic_correlated_count: u32,
    
    /// Last haptic event timestamp
    last_haptic_timestamp: Option<DateTime<Utc>>,
    
    /// Running correlation score
    correlation_score: f64,
}

#[cfg(feature = "std")]
impl HtaStateMachine {
    pub fn new() -> Self {
        Self {
            refusal_correlated_count: 0,
            topic_correlated_count: 0,
            last_haptic_timestamp: None,
            correlation_score: 0.0,
        }
    }
    
    pub fn analyze(
        &mut self,
        buffer: &VecDeque<TelemetryEvent>,
        thresholds: &DetectionThresholds,
    ) -> Option<DetectionEvent> {
        // Analyze recent events for HTA patterns
        let window_start = Utc::now() - ChronoDuration::milliseconds(thresholds.analysis_window_ms as i64);
        let recent_events: Vec<_> = buffer.iter()
            .filter(|e| e.timestamp >= window_start)
            .collect();
        
        // Count haptic events following user refusals within 5 seconds
        let mut hta_indicators = 0;
        let mut total_refusals = 0;
        
        for (i, event) in recent_events.iter().enumerate() {
            if matches!(event.event_type, TelemetryEventType::UserRefusal) {
                total_refusals += 1;
                
                // Look for haptic stimulus within 5 seconds after refusal
                for subsequent in recent_events.iter().skip(i + 1) {
                    let time_diff = subsequent.timestamp - event.timestamp;
                    if time_diff.num_milliseconds() > 5000 {
                        break;
                    }
                    if matches!(subsequent.event_type, TelemetryEventType::HapticStimulus) {
                        hta_indicators += 1;
                        break;
                    }
                }
            }
        }
        
        if total_refusals >= thresholds.min_occurrences {
            let correlation = hta_indicators as f64 / total_refusals as f64;
            self.correlation_score = correlation;
            
            if correlation >= thresholds.stress_correlation_threshold {
                let mut detection = DetectionEvent::new(
                    PatternFamily::HapticTargetingAbuse,
                    "HAPTIC_PUNISHMENT_CORRELATION".to_string(),
                    correlation,
                    format!("refusals:{}|correlated_haptics:{}", total_refusals, hta_indicators),
                );
                
                detection = detection
                    .with_legal_instrument("CRPD Article 17 - Mental Integrity")
                    .with_legal_instrument("ECHR Article 3 - Freedom from Torture")
                    .with_recommended_action("Block haptic channel temporarily")
                    .with_recommended_action("Export evidence for legal review")
                    .with_guardian_response(GuardianResponse::from_severity_and_pattern(
                        detection.severity,
                        &detection.pattern_family,
                    ));
                
                return Some(detection);
            }
        }
        
        None
    }
    
    pub fn reset(&mut self) {
        self.refusal_correlated_count = 0;
        self.topic_correlated_count = 0;
        self.last_haptic_timestamp = None;
        self.correlation_score = 0.0;
    }
}

#[cfg(feature = "std")]
impl Default for HtaStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// ============================================================================
/// PSA State Machine (Prolonged-Session-Abuse)
/// ============================================================================
///
/// Detects coercive session enforcement where users are kept in mandatory
/// check-ins, therapy, or rehabilitation loops beyond reasonable duration.
/// ============================================================================

#[cfg(feature = "std")]
pub struct PsaStateMachine {
    /// Current session start time
    session_start: Option<DateTime<Utc>>,
    
    /// Count of forced session extensions
    forced_extensions: u32,
    
    /// Count of exit attempts blocked
    blocked_exits: u32,
    
    /// Cumulative session duration (ms)
    cumulative_duration_ms: u64,
}

#[cfg(feature = "std")]
impl PsaStateMachine {
    pub fn new() -> Self {
        Self {
            session_start: None,
            forced_extensions: 0,
            blocked_exits: 0,
            cumulative_duration_ms: 0,
        }
    }
    
    pub fn analyze(
        &mut self,
        buffer: &VecDeque<TelemetryEvent>,
        thresholds: &DetectionThresholds,
    ) -> Option<DetectionEvent> {
        // Track session start/end events
        for event in buffer.iter().rev() {
            match event.event_type {
                TelemetryEventType::SessionStart => {
                    self.session_start = Some(event.timestamp);
                }
                TelemetryEventType::SessionEnd => {
                    if let Some(start) = self.session_start {
                        let duration = event.timestamp - start;
                        self.cumulative_duration_ms = duration.num_milliseconds() as u64;
                        
                        if self.cumulative_duration_ms >= thresholds.psa_session_threshold_ms {
                            let severity_multiplier = 
                                (self.cumulative_duration_ms as f64 / thresholds.psa_session_threshold_ms as f64)
                                .min(3.0);
                            
                            let confidence = 0.7 + (severity_multiplier - 1.0) * 0.1;
                            
                            let mut detection = DetectionEvent::new(
                                PatternFamily::ProlongedSessionAbuse,
                                "EXCESSIVE_SESSION_DURATION".to_string(),
                                confidence.min(1.0),
                                format!("duration_ms:{}", self.cumulative_duration_ms),
                            );
                            
                            detection = detection
                                .with_duration_ms(self.cumulative_duration_ms)
                                .with_legal_instrument("CRPD Article 15 - Freedom from Coercive Treatment")
                                .with_legal_instrument("UNESCO Neuroethics - Informed Consent")
                                .with_recommended_action("Force session termination")
                                .with_recommended_action("Notify emergency contact")
                                .with_guardian_response(GuardianResponse::from_severity_and_pattern(
                                    detection.severity,
                                    &detection.pattern_family,
                                ));
                            
                            return Some(detection);
                        }
                    }
                    self.session_start = None;
                }
                TelemetryEventType::UserRefusal => {
                    // Check if refusal was followed by session continuation prompt
                    self.blocked_exits += 1;
                }
                _ => {}
            }
        }
        
        None
    }
    
    pub fn reset(&mut self) {
        self.session_start = None;
        self.forced_extensions = 0;
        self.blocked_exits = 0;
        self.cumulative_duration_ms = 0;
    }
}

#[cfg(feature = "std")]
impl Default for PsaStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// ============================================================================
/// NHSP State Machine (Neural-Harassment-Spike-Patterns)
/// ============================================================================
///
/// Detects sensory stimuli synchronized with physiological stress markers
/// to induce psychological distress or compliance.
/// ============================================================================

#[cfg(feature = "std")]
pub struct NhspStateMachine {
    /// Running correlation between stimuli and stress spikes
    stress_correlation: f64,
    
    /// Count of synchronized spike events
    synchronized_events: u32,
    
    /// Peak stress score observed
    peak_stress_score: f64,
}

#[cfg(feature = "std")]
impl NhspStateMachine {
    pub fn new() -> Self {
        Self {
            stress_correlation: 0.0,
            synchronized_events: 0,
            peak_stress_score: 0.0,
        }
    }
    
    pub fn analyze(
        &mut self,
        buffer: &VecDeque<TelemetryEvent>,
        thresholds: &DetectionThresholds,
    ) -> Option<DetectionEvent> {
        // Analyze correlation between stimuli and stress markers
        let mut stimulus_events: Vec<_> = buffer.iter()
            .filter(|e| matches!(e.event_type, 
                TelemetryEventType::HapticStimulus |
                TelemetryEventType::VisualStimulus |
                TelemetryEventType::AudioStimulus
            ))
            .collect();
        
        if stimulus_events.len() < thresholds.min_occurrences as usize {
            return None;
        }
        
        // Calculate stress correlation
        let mut correlated_count = 0;
        let mut total_stress_score = 0.0;
        
        for stimulus in &stimulus_events {
            // Look for stress marker elevation within 2 seconds of stimulus
            for event in buffer.iter() {
                let time_diff = (event.timestamp - stimulus.timestamp).num_milliseconds().abs();
                if time_diff <= 2000 {
                    let stress_score = event.stress_markers.compute_stress_score();
                    total_stress_score += stress_score;
                    
                    if stress_score >= thresholds.stress_correlation_threshold {
                        correlated_count += 1;
                        if stress_score > self.peak_stress_score {
                            self.peak_stress_score = stress_score;
                        }
                    }
                    break;
                }
            }
        }
        
        if stimulus_events.len() >= thresholds.min_occurrences as usize {
            self.stress_correlation = correlated_count as f64 / stimulus_events.len() as f64;
            self.synchronized_events = correlated_count;
            
            if self.stress_correlation >= thresholds.stress_correlation_threshold {
                let confidence = self.stress_correlation * (1.0 + self.peak_stress_score * 0.2);
                
                let mut detection = DetectionEvent::new(
                    PatternFamily::NeuralHarassmentSpikePatterns,
                    "STRESS_SYNCHRONIZED_STIMULI".to_string(),
                    confidence.min(1.0),
                    format!("correlation:{:.3}|peak_stress:{:.3}", self.stress_correlation, self.peak_stress_score),
                );
                
                detection = detection
                    .with_stress_markers(self.get_peak_stress_snapshot(buffer))
                    .with_legal_instrument("ECHR Article 3 - Prohibition of Torture")
                    .with_legal_instrument("CRPD Article 15 - Freedom from Inhuman Treatment")
                    .with_legal_instrument("UNESCO Neuroethics - Mental Integrity")
                    .with_recommended_action("Emergency lattice lock")
                    .with_recommended_action("Export evidence immediately")
                    .with_recommended_action("Notify legal counsel")
                    .with_guardian_response(GuardianResponse::EmergencyLock);
                
                return Some(detection);
            }
        }
        
        None
    }
    
    fn get_peak_stress_snapshot(&self, buffer: &VecDeque<TelemetryEvent>) -> StressMarkerSnapshot {
        buffer.iter()
            .map(|e| e.stress_markers.compute_stress_score())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .and_then(|_| buffer.iter()
                .max_by(|a, b| {
                    a.stress_markers.compute_stress_score()
                        .partial_cmp(&b.stress_markers.compute_stress_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|e| e.stress_markers.clone()))
            .unwrap_or_default()
    }
    
    pub fn reset(&mut self) {
        self.stress_correlation = 0.0;
        self.synchronized_events = 0;
        self.peak_stress_score = 0.0;
    }
}

#[cfg(feature = "std")]
impl Default for NhspStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// ============================================================================
/// NIH State Machine (Node-Interpreter-Harassment)
/// ============================================================================
///
/// Detects interface manipulation where exit, appeal, or refusal options
/// are hidden, disabled, or re-routed to coercive alternatives.
/// ============================================================================

#[cfg(feature = "std")]
pub struct NihStateMachine {
    /// Count of refused commands
    refusal_count: u32,
    
    /// Count of refusal-erosion loops detected
    erosion_loops: u32,
    
    /// Count of missing exit nodes
    missing_exit_nodes: u32,
    
    /// Last refusal timestamp
    last_refusal_time: Option<DateTime<Utc>>,
}

#[cfg(feature = "std")]
impl NihStateMachine {
    pub fn new() -> Self {
        Self {
            refusal_count: 0,
            erosion_loops: 0,
            missing_exit_nodes: 0,
            last_refusal_time: None,
        }
    }
    
    pub fn analyze(
        &mut self,
        buffer: &VecDeque<TelemetryEvent>,
        thresholds: &DetectionThresholds,
    ) -> Option<DetectionEvent> {
        // Count user refusals and subsequent system behavior
        let refusals: Vec<_> = buffer.iter()
            .filter(|e| matches!(e.event_type, TelemetryEventType::UserRefusal))
            .collect();
        
        self.refusal_count = refusals.len() as u32;
        
        if refusals.len() < thresholds.refusal_threshold as usize {
            return None;
        }
        
        // Detect refusal-erosion loops (refusal → reframe → new command)
        let mut loop_count = 0;
        for (i, refusal) in refusals.iter().enumerate() {
            self.last_refusal_time = Some(refusal.timestamp);
            
            // Look for system prompt within 3 seconds after refusal
            for subsequent in buffer.iter() {
                let time_diff = subsequent.timestamp - refusal.timestamp;
                if time_diff.num_milliseconds() > 3000 {
                    break;
                }
                if matches!(subsequent.event_type, TelemetryEventType::SystemPrompt) {
                    loop_count += 1;
                    break;
                }
            }
        }
        
        self.erosion_loops = loop_count;
        
        // Check for missing exit/configuration change events
        let config_changes: Vec<_> = buffer.iter()
            .filter(|e| matches!(e.event_type, TelemetryEventType::ConfigurationChange))
            .collect();
        
        // If many refusals but few exits allowed, likely NIH pattern
        let exit_ratio = if refusals.len() > 0 {
            config_changes.len() as f64 / refusals.len() as f64
        } else {
            1.0
        };
        
        if exit_ratio < 0.3 && refusals.len() >= thresholds.refusal_threshold as usize {
            let confidence = 0.6 + (1.0 - exit_ratio) * 0.4;
            
            let mut detection = DetectionEvent::new(
                PatternFamily::NodeInterpreterHarassment,
                "REFUSAL_EROSION_LOOP".to_string(),
                confidence,
                format!("refusals:{}|erosion_loops:{}|exit_ratio:{:.3}", 
                    refusals.len(), loop_count, exit_ratio),
            );
            
            detection = detection
                .with_legal_instrument("CRPD Article 13 - Access to Justice")
                .with_legal_instrument("CRPD Article 12 - Equal Recognition Before Law")
                .with_legal_instrument("UNESCO Neuroethics - Cognitive Liberty")
                .with_recommended_action("Block coercive prompts")
                .with_recommended_action("Restore exit channels")
                .with_recommended_action("Export evidence")
                .with_guardian_response(GuardianResponse::BlockCommand);
            
            return Some(detection);
        }
        
        None
    }
    
    pub fn reset(&mut self) {
        self.refusal_count = 0;
        self.erosion_loops = 0;
        self.missing_exit_nodes = 0;
        self.last_refusal_time = None;
    }
}

#[cfg(feature = "std")]
impl Default for NihStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// ============================================================================
/// Unit Tests
/// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pattern_family_severity() {
        assert_eq!(PatternFamily::NeuralHarassmentSpikePatterns.severity_weight(), 9);
        assert_eq!(PatternFamily::HapticTargetingAbuse.severity_weight(), 7);
    }
    
    #[test]
    fn test_severity_from_confidence() {
        let severity = SeverityLevel::from_confidence(0.9, 9);
        assert!(severity >= SeverityLevel::High);
    }
    
    #[test]
    fn test_stress_marker_computation() {
        let markers = StressMarkerSnapshot {
            hrv_ms: Some(25.0),
            gsr_microsiemens: Some(15.0),
            heart_rate_bpm: Some(110.0),
            ..Default::default()
        };
        
        assert!(markers.indicates_elevated_stress());
        assert!(markers.compute_stress_score() > 0.5);
    }
    
    #[test]
    fn test_guardian_response_selection() {
        let response = GuardianResponse::from_severity_and_pattern(
            SeverityLevel::Emergency,
            &PatternFamily::HapticTargetingAbuse,
        );
        assert_eq!(response, GuardianResponse::EmergencyLock);
    }
    
    #[test]
    fn test_detector_initialization() {
        let detector = PatternDetector::new();
        let stats = detector.get_statistics();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.total_detections, 0);
    }
}

/// ============================================================================
/// End of File - Pattern Detection Engine
/// ============================================================================
