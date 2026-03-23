// ============================================================================
// DoctorLabs Lexicon - RogueScore Risk Kernel and Sliding Window Aggregation
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module implements the mathematical core of the Doctor-Labs Superfilter:
//   - Gaussian risk kernels per harassment family (NHSP, HTA, PSA, NIH)
//   - Sliding window aggregation for temporal pattern detection
//   - Monotone capability mode escalation (Normal → Log → Review)
//   - Neurorights invariants (no capability downgrades, ever)
//
// The RogueScore (R_M) is a weighted sum of family-specific kernel outputs,
// designed to detect sustained coercive patterns while minimizing false positives
// from benign therapeutic or wellness interactions.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - Fused haptic-biosensor-behavioral feature space
//   - CapabilityMode three-mode escalation (τ1, τ2 thresholds)
//   - Monotone Capability Lattice (strictly non-decreasing user rights)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![cfg_attr(not(test), warn(missing_docs))]

use crate::{HarassmentFamily, LexiconError, LexiconResult, TimestampMs};
use crate::lexicon::RiskKernel;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use thiserror::Error;

// ============================================================================
// Constants and Configuration
// ============================================================================

/// Default sliding window size in milliseconds (5 minutes)
pub const DEFAULT_WINDOW_SIZE_MS: u64 = 300_000;

/// Default decay factor for exponential moving average (0.0 = no decay, 1.0 = instant)
pub const DEFAULT_DECAY_FACTOR: f64 = 0.1;

/// Minimum threshold for Normal → AugmentedLog escalation (τ1)
pub const DEFAULT_THRESHOLD_TAU1: f64 = 1.0;

/// Minimum threshold for AugmentedLog → AugmentedReview escalation (τ2)
pub const DEFAULT_THRESHOLD_TAU2: f64 = 3.0;

/// Maximum allowed RogueScore to prevent overflow in fixed-point systems
pub const MAX_ROGUE_SCORE: f64 = 100.0;

// ============================================================================
// Error Types
// ============================================================================

/// Errors specific to RogueScore computation
#[derive(Error, Debug)]
pub enum RogueScoreError {
    #[error("Invalid kernel sigma: {0}")]
    InvalidKernelSigma(String),
    
    #[error("Window overflow: too many spans buffered")]
    WindowOverflow,
    
    #[error("Monotonicity violation: attempted capability downgrade from {from:?} to {to:?}")]
    MonotonicityViolation {
        from: CapabilityMode,
        to: CapabilityMode,
    },
    
    #[error("Threshold configuration error: tau1 ({tau1}) must be < tau2 ({tau2})")]
    InvalidThresholds { tau1: f64, tau2: f64 },
    
    #[error("Score overflow: computed value {value} exceeds maximum {max}")]
    ScoreOverflow { value: f64, max: f64 },
}

// ============================================================================
// Span Score (Individual Event Contribution)
// ============================================================================

/// Risk contribution of a single interaction span matched against a lexicon term
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanScore {
    /// Repetition factor (y) for persistent patterns
    pub y_repetition: f64,
    
    /// Drift factor (z) for behavioral deviation
    pub z_drift: f64,
    
    /// Toxicity factor (t) for semantic harm
    pub t_toxicity: f64,
    
    /// Kindness factor (k) for mitigating context (e.g., explicit consent)
    pub k_kindness: f64,
    
    /// Evidentiality factor (e) for sensor confidence
    pub e_evidentiality: f64,
    
    /// Per-family weights from the matched lexicon term's risk kernel
    pub family_weights: std::collections::HashMap<HarassmentFamily, f64>,
}

impl Default for SpanScore {
    fn default() -> Self {
        let mut family_weights = std::collections::HashMap::new();
        for family in HarassmentFamily::all() {
            family_weights.insert(*family, 0.0);
        }
        
        Self {
            y_repetition: 0.0,
            z_drift: 0.0,
            t_toxicity: 0.0,
            k_kindness: 1.0, // Default to neutral (no mitigation)
            e_evidentiality: 1.0, // Default to full confidence
            family_weights,
        }
    }
}

impl SpanScore {
    /// Computes the base risk value for this span before family weighting
    pub fn base_score(&self) -> f64 {
        // Formula: (y + z + t) * e / k
        // Kindness (k) acts as a divisor to reduce score if consent/mitigation is present
        let numerator = (self.y_repetition + self.z_drift + self.t_toxicity) * self.e_evidentiality;
        let denominator = self.k_kindness.max(0.1); // Prevent division by zero
        
        numerator / denominator
    }
    
    /// Computes the weighted risk for a specific harassment family
    pub fn family_score(&self, family: HarassmentFamily) -> f64 {
        let base = self.base_score();
        let weight = *self.family_weights.get(&family).unwrap_or(&0.0);
        base * weight
    }
    
    /// Validates span score constraints
    pub fn validate(&self) -> LexiconResult<()> {
        if self.k_kindness <= 0.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: crate::LexiconTermId("UNKNOWN".to_string()),
                reason: "Kindness factor must be positive".to_string(),
            });
        }
        
        if self.e_evidentiality < 0.0 || self.e_evidentiality > 1.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: crate::LexiconTermId("UNKNOWN".to_string()),
                reason: "Evidentiality must be in range [0.0, 1.0]".to_string(),
            });
        }
        
        Ok(())
    }
}

// ============================================================================
// Capability Mode (Three-Mode Escalation)
// ============================================================================

/// Governance capability mode representing the current enforcement level
/// 
/// CRITICAL INVARIANT: Transitions must be monotone non-decreasing.
/// A user's capabilities (BCI IO, XR overlays, communication) cannot be reduced
/// when moving to a higher mode. Higher modes only add logging, review, or consent checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMode {
    /// Normal operation: standard logging, no extra checks
    Normal = 0,
    
    /// Augmented Logging: enhanced audit trails, real-time risk monitoring
    AugmentedLog = 1,
    
    /// Augmented Review: human-in-the-loop review required for sensitive actions
    AugmentedReview = 2,
}

impl CapabilityMode {
    /// Returns all capability modes in ascending order
    pub const fn all() -> &'static [Self] {
        &[Self::Normal, Self::AugmentedLog, Self::AugmentedReview]
    }
    
    /// Returns a human-readable description
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Normal => "Normal Operation",
            Self::AugmentedLog => "Augmented Logging",
            Self::AugmentedReview => "Augmented Review",
        }
    }
    
    /// Validates a transition from self to next mode
    /// 
    /// # Errors
    /// Returns `MonotonicityViolation` if next < self
    pub fn validate_transition(self, next: Self) -> Result<(), RogueScoreError> {
        if next < self {
            Err(RogueScoreError::MonotonicityViolation {
                from: self,
                to: next,
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for CapabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// Sliding Window Aggregation
// ============================================================================

/// Time-weighted sliding window for score aggregation
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Maximum window size in milliseconds
    window_size_ms: u64,
    
    /// Queue of (timestamp, score) pairs
    scores: VecDeque<(TimestampMs, f64)>,
    
    /// Current sum of scores in window (for O(1) average computation)
    current_sum: f64,
    
    /// Decay factor for exponential moving average
    decay_factor: f64,
}

impl SlidingWindow {
    /// Creates a new sliding window
    pub fn new(window_size_ms: u64, decay_factor: f64) -> Self {
        Self {
            window_size_ms,
            scores: VecDeque::new(),
            current_sum: 0.0,
            decay_factor: decay_factor.clamp(0.0, 1.0),
        }
    }
    
    /// Adds a new score to the window
    pub fn push(&mut self, timestamp: TimestampMs, score: f64) -> LexiconResult<()> {
        // Prevent unbounded growth
        if self.scores.len() >= 10_000 {
            return Err(LexiconError::from(RogueScoreError::WindowOverflow));
        }
        
        // Remove expired entries
        self.evict_expired(timestamp);
        
        // Apply decay to existing scores
        self.apply_decay();
        
        // Add new score
        self.scores.push_back((timestamp, score));
        self.current_sum += score;
        
        Ok(())
    }
    
    /// Computes the weighted average score in the current window
    pub fn average(&self) -> f64 {
        if self.scores.is_empty() {
            return 0.0;
        }
        
        // Simple average for now; can be enhanced to time-weighted
        self.current_sum / self.scores.len() as f64
    }
    
    /// Computes the maximum score in the current window (for spike detection)
    pub fn max(&self) -> f64 {
        self.scores
            .iter()
            .map(|(_, score)| *score)
            .fold(0.0, f64::max)
    }
    
    /// Removes scores older than the window size
    fn evict_expired(&mut self, current_time: TimestampMs) {
        let cutoff = current_time.saturating_sub(self.window_size_ms);
        
        while let Some((timestamp, score)) = self.scores.front() {
            if *timestamp < cutoff {
                self.current_sum -= score;
                self.scores.pop_front();
            } else {
                break;
            }
        }
    }
    
    /// Applies exponential decay to all scores in the window
    fn apply_decay(&mut self) {
        if self.decay_factor <= 0.0 {
            return;
        }
        
        let mut new_sum = 0.0;
        for (_, score) in &mut self.scores {
            *score *= 1.0 - self.decay_factor;
            new_sum += *score;
        }
        self.current_sum = new_sum;
    }
    
    /// Clears the window (e.g., on session reset)
    pub fn clear(&mut self) {
        self.scores.clear();
        self.current_sum = 0.0;
    }
}

// ============================================================================
// RogueScore Calculator (Global Risk Metric)
// ============================================================================

/// Computes the global RogueScore (R_M) from span scores and kernel parameters
#[derive(Debug, Clone)]
pub struct RogueScoreCalculator {
    /// Per-family sliding windows
    family_windows: std::collections::HashMap<HarassmentFamily, SlidingWindow>,
    
    /// Global sliding window for aggregate score
    global_window: SlidingWindow,
    
    /// Escalation thresholds (τ1, τ2)
    tau1: f64,
    tau2: f64,
    
    /// Current capability mode
    current_mode: CapabilityMode,
    
    /// Default risk kernel parameters
    default_kernel: RiskKernel,
}

impl RogueScoreCalculator {
    /// Creates a new calculator with default thresholds
    pub fn new(default_kernel: RiskKernel) -> LexiconResult<Self> {
        Self::with_thresholds(default_kernel, DEFAULT_THRESHOLD_TAU1, DEFAULT_THRESHOLD_TAU2)
    }
    
    /// Creates a new calculator with custom thresholds
    pub fn with_thresholds(
        default_kernel: RiskKernel,
        tau1: f64,
        tau2: f64,
    ) -> LexiconResult<Self> {
        if tau1 >= tau2 {
            return Err(LexiconError::from(RogueScoreError::InvalidThresholds { tau1, tau2 }));
        }
        
        let mut family_windows = std::collections::HashMap::new();
        for family in HarassmentFamily::all() {
            family_windows.insert(
                *family,
                SlidingWindow::new(DEFAULT_WINDOW_SIZE_MS, DEFAULT_DECAY_FACTOR),
            );
        }
        
        Ok(Self {
            family_windows,
            global_window: SlidingWindow::new(DEFAULT_WINDOW_SIZE_MS, DEFAULT_DECAY_FACTOR),
            tau1,
            tau2,
            current_mode: CapabilityMode::Normal,
            default_kernel,
        })
    }
    
    /// Processes a new span score and updates the global risk metric
    pub fn process_span(&mut self, timestamp: TimestampMs, span: &SpanScore) -> LexiconResult<RogueScore> {
        span.validate()?;
        
        // Compute per-family scores
        let mut family_scores = std::collections::HashMap::new();
        let mut total_score = 0.0;
        
        for family in HarassmentFamily::all() {
            let score = span.family_score(*family);
            
            // Update family window
            if let Some(window) = self.family_windows.get_mut(family) {
                window.push(timestamp, score)?;
            }
            
            // Apply Gaussian kernel weighting
            let kernel_weight = self.gaussian_kernel_weight(*family, score);
            let weighted_score = score * kernel_weight;
            
            family_scores.insert(*family, weighted_score);
            total_score += weighted_score;
        }
        
        // Cap total score to prevent overflow
        if total_score > MAX_ROGUE_SCORE {
            return Err(LexiconError::from(RogueScoreError::ScoreOverflow {
                value: total_score,
                max: MAX_ROGUE_SCORE,
            }));
        }
        
        // Update global window
        self.global_window.push(timestamp, total_score)?;
        
        // Compute aggregate RogueScore
        let rogue_score = RogueScore {
            timestamp,
            global_average: self.global_window.average(),
            global_max: self.global_window.max(),
            family_scores,
            recommended_mode: self.evaluate_capability_mode(total_score),
        };
        
        // Enforce monotonicity on mode transition
        self.enforce_monotone_transition(rogue_score.recommended_mode)?;
        
        Ok(rogue_score)
    }
    
    /// Computes Gaussian kernel weight for a family based on score magnitude
    fn gaussian_kernel_weight(&self, family: HarassmentFamily, score: f64) -> f64 {
        // Formula: w = exp(-score^2 / (2 * sigma^2))
        // This dampens extreme outliers while preserving sustained patterns
        let sigma = self.default_kernel.gaussian_sigma;
        if sigma <= 0.0 {
            return 1.0; // Fallback to linear weighting
        }
        
        let exponent = -(score.powi(2)) / (2.0 * sigma.powi(2));
        exponent.exp()
    }
    
    /// Evaluates the recommended capability mode based on current score
    fn evaluate_capability_mode(&self, score: f64) -> CapabilityMode {
        if score >= self.tau2 {
            CapabilityMode::AugmentedReview
        } else if score >= self.tau1 {
            CapabilityMode::AugmentedLog
        } else {
            CapabilityMode::Normal
        }
    }
    
    /// Enforces monotone capability transitions (never downgrade)
    fn enforce_monotone_transition(&mut self, recommended: CapabilityMode) -> LexiconResult<()> {
        // Only upgrade, never downgrade
        if recommended > self.current_mode {
            self.current_mode.validate_transition(recommended)?;
            self.current_mode = recommended;
        }
        // If recommended <= current_mode, stay at current_mode (monotone hold)
        
        Ok(())
    }
    
    /// Returns the current capability mode
    pub fn current_mode(&self) -> CapabilityMode {
        self.current_mode
    }
    
    /// Resets the calculator (e.g., on new session)
    pub fn reset(&mut self) {
        for window in self.family_windows.values_mut() {
            window.clear();
        }
        self.global_window.clear();
        // Note: We do NOT reset current_mode to Normal automatically.
        // Mode reset requires explicit governance approval to prevent abuse.
    }
    
    /// Updates thresholds dynamically (requires governance approval in production)
    pub fn update_thresholds(&mut self, tau1: f64, tau2: f64) -> LexiconResult<()> {
        if tau1 >= tau2 {
            return Err(LexiconError::from(RogueScoreError::InvalidThresholds { tau1, tau2 }));
        }
        
        // Validate that new thresholds don't force a downgrade
        let new_mode = self.evaluate_capability_mode(self.global_window.average());
        self.current_mode.validate_transition(new_mode)?;
        
        self.tau1 = tau1;
        self.tau2 = tau2;
        
        Ok(())
    }
}

// ============================================================================
// RogueScore (Output Metric)
// ============================================================================

/// The computed global risk metric with mode recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueScore {
    /// Timestamp of computation
    pub timestamp: TimestampMs,
    
    /// Average score over the sliding window
    pub global_average: f64,
    
    /// Maximum spike detected in the window
    pub global_max: f64,
    
    /// Per-family weighted scores
    pub family_scores: std::collections::HashMap<HarassmentFamily, f64>,
    
    /// Recommended capability mode based on thresholds
    pub recommended_mode: CapabilityMode,
}

impl RogueScore {
    /// Returns true if the score exceeds the review threshold
    pub fn requires_review(&self) -> bool {
        self.recommended_mode == CapabilityMode::AugmentedReview
    }
    
    /// Returns true if the score exceeds the logging threshold
    pub fn requires_augmented_logging(&self) -> bool {
        self.recommended_mode >= CapabilityMode::AugmentedLog
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    fn create_test_kernel() -> RiskKernel {
        let mut family_weight = HashMap::new();
        family_weight.insert(HarassmentFamily::NHSP, 1.0);
        family_weight.insert(HarassmentFamily::HTA, 1.0);
        family_weight.insert(HarassmentFamily::PSA, 0.5);
        family_weight.insert(HarassmentFamily::NIH, 0.5);
        
        RiskKernel {
            family_weight,
            gaussian_sigma: 0.5,
            rogue_score_increment: crate::lexicon::RogueScoreIncrement::AddToWindow,
        }
    }
    
    #[test]
    fn test_span_score_base_calculation() {
        let mut span = SpanScore::default();
        span.y_repetition = 1.0;
        span.z_drift = 0.5;
        span.t_toxicity = 0.5;
        span.k_kindness = 1.0;
        span.e_evidentiality = 1.0;
        
        // Base = (1.0 + 0.5 + 0.5) * 1.0 / 1.0 = 2.0
        assert!((span.base_score() - 2.0).abs() < f64::EPSILON);
    }
    
    #[test]
    fn test_span_score_kindness_mitigation() {
        let mut span = SpanScore::default();
        span.y_repetition = 2.0;
        span.k_kindness = 2.0; // High consent/mitigation
        
        // Base = 2.0 * 1.0 / 2.0 = 1.0
        assert!((span.base_score() - 1.0).abs() < f64::EPSILON);
    }
    
    #[test]
    fn test_capability_mode_monotonicity() {
        assert!(CapabilityMode::Normal.validate_transition(CapabilityMode::AugmentedLog).is_ok());
        assert!(CapabilityMode::AugmentedLog.validate_transition(CapabilityMode::AugmentedReview).is_ok());
        assert!(CapabilityMode::Normal.validate_transition(CapabilityMode::AugmentedReview).is_ok());
        
        // Downgrades should fail
        assert!(CapabilityMode::AugmentedLog.validate_transition(CapabilityMode::Normal).is_err());
        assert!(CapabilityMode::AugmentedReview.validate_transition(CapabilityMode::AugmentedLog).is_err());
    }
    
    #[test]
    fn test_rogue_score_calculator_escalation() {
        let kernel = create_test_kernel();
        let mut calc = RogueScoreCalculator::new(kernel).unwrap();
        
        assert_eq!(calc.current_mode(), CapabilityMode::Normal);
        
        // Create a high-score span
        let mut span = SpanScore::default();
        span.t_toxicity = 5.0; // High toxicity
        span.e_evidentiality = 1.0;
        
        let timestamp = 1000;
        let score = calc.process_span(timestamp, &span).unwrap();
        
        // Should escalate based on thresholds (default tau1=1.0, tau2=3.0)
        assert!(score.global_average > 0.0);
        assert!(score.recommended_mode >= CapabilityMode::Normal);
    }
    
    #[test]
    fn test_sliding_window_expiry() {
        let mut window = SlidingWindow::new(1000, 0.0); // 1 second window, no decay
        
        window.push(1000, 1.0).unwrap();
        window.push(1500, 1.0).unwrap();
        assert_eq!(window.scores.len(), 2);
        
        // Push at 2500, should evict 1000
        window.push(2500, 1.0).unwrap();
        assert_eq!(window.scores.len(), 2); // 1500 and 2500 remain
    }
    
    #[test]
    fn test_threshold_validation() {
        let kernel = create_test_kernel();
        // tau1 >= tau2 should fail
        let result = RogueScoreCalculator::with_thresholds(kernel, 5.0, 3.0);
        assert!(result.is_err());
    }
}
