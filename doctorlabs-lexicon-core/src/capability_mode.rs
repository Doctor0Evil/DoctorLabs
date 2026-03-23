// ============================================================================
// DoctorLabs Lexicon - Monotone Capability Lattice and Governance Transitions
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module implements the "Monotone Capability Lattice" invariant:
//   - Governance modes (Normal, AugmentedLog, AugmentedReview) may escalate.
//   - User capabilities (BCI IO, XR overlays, Communication) MUST NOT degrade.
//   - Transitions are validated against a partial order to ensure safety.
//
// This is the technical enforcement of Neurorights:
//   - Mental Integrity: No forced shutdown of neural interfaces during distress.
//   - Cognitive Liberty: No restriction of thought-expression channels.
//   - Freedom of Thought: No gating of exit nodes based on risk scores.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - RogueScore risk kernel (File 3: rogue_score.rs)
//   - CapabilityMode three-mode escalation (τ1, τ2 thresholds)
//   - Audit logging for forensic traceability (File 6: audit.rs)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![cfg_attr(not(test), warn(missing_docs))]

use crate::{LexiconError, LexiconResult, TimestampMs};
use crate::rogue_score::CapabilityMode;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ============================================================================
// Capability Flags (Bitmask for User IO Channels)
// ============================================================================

/// Bitflags representing user-accessible capabilities in BCI/XR systems.
/// 
/// CRITICAL INVARIANT: Once a flag is set to 1 (enabled), it cannot be 
/// cleared to 0 (disabled) by the governance engine during a session.
/// This prevents coercive shutdowns during high-risk events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityFlags(u64);

impl CapabilityFlags {
    /// BCI Motor Input (e.g., motor imagery, EEG control)
    pub const BCI_MOTOR_INPUT: Self = Self(1 << 0);
    
    /// BCI Sensory Output (e.g., direct neural stimulation)
    pub const BCI_SENSORY_OUTPUT: Self = Self(1 << 1);
    
    /// XR Visual Overlay (e.g., AR HUD, VR rendering)
    pub const XR_VISUAL_OVERLAY: Self = Self(1 << 2);
    
    /// XR Audio Spatialization (e.g., 3D audio, voice comms)
    pub const XR_AUDIO_SPATIAL: Self = Self(1 << 3);
    
    /// Haptic Feedback IO (e.g., exosuit, controller vibration)
    pub const HAPTIC_FEEDBACK: Self = Self(1 << 4);
    
    /// Network Communication (e.g., chat, data sync)
    pub const NETWORK_COMMUNICATION: Self = Self(1 << 5);
    
    /// Session Exit / Logout (Critical for cognitive liberty)
    pub const SESSION_EXIT: Self = Self(1 << 6);
    
    /// Consent Management UI (Ability to modify permissions)
    pub const CONSENT_MANAGEMENT: Self = Self(1 << 7);

    /// All capabilities enabled (Safe Default for Normal Mode)
    pub const ALL_ENABLED: Self = Self(0b1111_1111);

    /// No capabilities enabled (Forbidden State - Used for Validation)
    pub const NONE: Self = Self(0);

    /// Creates a new flag set from a raw u64
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns the raw u64 representation
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Enables a specific capability flag
    #[must_use]
    pub const fn with_flag(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    /// Checks if a specific capability flag is enabled
    pub const fn has_flag(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Validates that `new` is a superset of `self` (Monotonicity Check)
    /// 
    /// # Errors
    /// Returns `CapabilityDowngradeDetected` if any flag enabled in `self` 
    /// is disabled in `new`.
    pub fn validate_monotonicity(self, new: Self) -> Result<(), CapabilityError> {
        // If (self & new) != self, then new is missing some bits from self
        if (self.0 & new.0) != self.0 {
            let lost_capabilities = self.0 & !new.0;
            Err(CapabilityError::CapabilityDowngradeDetected {
                lost_flags: lost_capabilities,
            })
        } else {
            Ok(())
        }
    }

    /// Returns a human-readable list of enabled capabilities
    pub fn enabled_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.has_flag(Self::BCI_MOTOR_INPUT) { names.push("BCI_MOTOR_INPUT"); }
        if self.has_flag(Self::BCI_SENSORY_OUTPUT) { names.push("BCI_SENSORY_OUTPUT"); }
        if self.has_flag(Self::XR_VISUAL_OVERLAY) { names.push("XR_VISUAL_OVERLAY"); }
        if self.has_flag(Self::XR_AUDIO_SPATIAL) { names.push("XR_AUDIO_SPATIAL"); }
        if self.has_flag(Self::HAPTIC_FEEDBACK) { names.push("HAPTIC_FEEDBACK"); }
        if self.has_flag(Self::NETWORK_COMMUNICATION) { names.push("NETWORK_COMMUNICATION"); }
        if self.has_flag(Self::SESSION_EXIT) { names.push("SESSION_EXIT"); }
        if self.has_flag(Self::CONSENT_MANAGEMENT) { names.push("CONSENT_MANAGEMENT"); }
        names
    }
}

impl Default for CapabilityFlags {
    fn default() -> Self {
        // Default to all enabled to ensure safety baseline
        Self::ALL_ENABLED
    }
}

impl fmt::Display for CapabilityFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityFlags({:08b})", self.0)
    }
}

// ============================================================================
// Capability Errors
// ============================================================================

/// Errors specific to capability lattice enforcement
#[derive(Error, Debug)]
pub enum CapabilityError {
    #[error("Capability downgrade detected: lost flags {lost_flags:#010b}")]
    CapabilityDowngradeDetected { lost_flags: u64 },
    
    #[error("Invalid capability mask: forbidden flags enabled {forbidden_flags:#010b}")]
    ForbiddenCapabilitiesEnabled { forbidden_flags: u64 },
    
    #[error("Governance transition invalid: mode {from:?} cannot transition to {to:?}")]
    InvalidGovernanceTransition {
        from: CapabilityMode,
        to: CapabilityMode,
    },
    
    #[error("Session lock violation: capabilities cannot be modified during active review")]
    SessionLockViolation,
}

// ============================================================================
// Governance Transition Record
// ============================================================================

/// A recorded transition event for audit and forensic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceTransition {
    /// Timestamp of the transition
    pub timestamp: TimestampMs,
    
    /// Previous capability mode
    pub from_mode: CapabilityMode,
    
    /// New capability mode
    pub to_mode: CapabilityMode,
    
    /// Previous capability flags
    pub from_capabilities: CapabilityFlags,
    
    /// New capability flags (must be superset of previous)
    pub to_capabilities: CapabilityFlags,
    
    /// Triggering RogueScore value
    pub trigger_score: f64,
    
    /// Triggering lexicon term ID (if applicable)
    pub trigger_term_id: Option<String>,
    
    /// Validation status
    pub validated: bool,
}

impl GovernanceTransition {
    /// Creates a new transition record
    pub fn new(
        timestamp: TimestampMs,
        from_mode: CapabilityMode,
        to_mode: CapabilityMode,
        from_capabilities: CapabilityFlags,
        to_capabilities: CapabilityFlags,
        trigger_score: f64,
        trigger_term_id: Option<String>,
    ) -> Self {
        Self {
            timestamp,
            from_mode,
            to_mode,
            from_capabilities,
            to_capabilities,
            trigger_score,
            trigger_term_id,
            validated: false,
        }
    }

    /// Validates the transition against monotonicity invariants
    pub fn validate(&mut self) -> Result<(), CapabilityError> {
        // 1. Validate Capability Monotonicity (No Downgrades)
        self.from_capabilities.validate_monotonicity(self.to_capabilities)?;

        // 2. Validate Governance Mode Escalation (No Downgrades)
        // Note: Mode can stay same or increase, never decrease
        if self.to_mode < self.from_mode {
            return Err(CapabilityError::InvalidGovernanceTransition {
                from: self.from_mode,
                to: self.to_mode,
            });
        }

        // 3. Check for Forbidden Capabilities in High-Risk Modes
        // In AugmentedReview, certain capabilities (e.g., Consent Management) 
        // might be locked to prevent tampering, but never disabled.
        if self.to_mode == CapabilityMode::AugmentedReview {
            // Ensure Session Exit is NEVER disabled (Cognitive Liberty)
            if !self.to_capabilities.has_flag(CapabilityFlags::SESSION_EXIT) {
                return Err(CapabilityError::ForbiddenCapabilitiesEnabled {
                    forbidden_flags: 0, // Specific error for missing critical flag
                });
            }
        }

        self.validated = true;
        Ok(())
    }
}

// ============================================================================
// Capability Lattice Engine
// ============================================================================

/// Central engine for enforcing capability monotonicity and governance transitions
#[derive(Debug, Clone)]
pub struct CapabilityLattice {
    /// Current capability mode
    current_mode: CapabilityMode,
    
    /// Current capability flags (immutable baseline)
    baseline_capabilities: CapabilityFlags,
    
    /// Current active capabilities (may add flags, never remove)
    active_capabilities: CapabilityFlags,
    
    /// Session lock status (prevents changes during critical operations)
    session_locked: bool,
    
    /// Transition history for audit
    transition_history: Vec<GovernanceTransition>,
    
    /// Maximum history size to prevent memory exhaustion
    max_history_size: usize,
}

impl CapabilityLattice {
    /// Creates a new lattice with default safe capabilities
    pub fn new() -> Self {
        let default_caps = CapabilityFlags::default();
        Self {
            current_mode: CapabilityMode::Normal,
            baseline_capabilities: default_caps,
            active_capabilities: default_caps,
            session_locked: false,
            transition_history: Vec::new(),
            max_history_size: 1000,
        }
    }

    /// Creates a new lattice with custom baseline capabilities
    pub fn with_capabilities(caps: CapabilityFlags) -> Self {
        Self {
            current_mode: CapabilityMode::Normal,
            baseline_capabilities: caps,
            active_capabilities: caps,
            session_locked: false,
            transition_history: Vec::new(),
            max_history_size: 1000,
        }
    }

    /// Attempts to transition to a new governance mode
    /// 
    /// # Safety
    /// This method enforces the monotone capability invariant. If the transition
    /// would result in a capability downgrade, it returns an error and no state change occurs.
    pub fn transition_mode(
        &mut self,
        new_mode: CapabilityMode,
        trigger_score: f64,
        trigger_term_id: Option<String>,
    ) -> LexiconResult<GovernanceTransition> {
        if self.session_locked {
            return Err(LexiconError::from(CapabilityError::SessionLockViolation));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as TimestampMs;

        let mut transition = GovernanceTransition::new(
            timestamp,
            self.current_mode,
            new_mode,
            self.active_capabilities,
            self.active_capabilities, // Capabilities remain unchanged in mode transition
            trigger_score,
            trigger_term_id,
        );

        // Validate the transition
        transition.validate().map_err(|e| LexiconError::CapabilityMonotonicityFailure {
            context: format!("Mode transition {:?} -> {:?}: {}", self.current_mode, new_mode, e),
        })?;

        // Apply state change
        self.current_mode = new_mode;
        self.record_transition(transition.clone());

        Ok(transition)
    }

    /// Attempts to modify capability flags (e.g., adding a new consent grant)
    /// 
    /// # Safety
    /// Only allows adding flags. Removing flags is strictly prohibited.
    pub fn modify_capabilities(
        &mut self,
        new_flags: CapabilityFlags,
    ) -> LexiconResult<GovernanceTransition> {
        if self.session_locked {
            return Err(LexiconError::from(CapabilityError::SessionLockViolation));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as TimestampMs;

        let mut transition = GovernanceTransition::new(
            timestamp,
            self.current_mode,
            self.current_mode, // Mode unchanged
            self.active_capabilities,
            new_flags,
            0.0,
            None,
        );

        // Validate monotonicity
        transition.validate().map_err(|e| LexiconError::CapabilityMonotonicityFailure {
            context: format!("Capability modification: {}", e),
        })?;

        // Apply state change
        self.active_capabilities = new_flags;
        self.record_transition(transition.clone());

        Ok(transition)
    }

    /// Locks the session (e.g., during human review)
    pub fn lock_session(&mut self) {
        self.session_locked = true;
    }

    /// Unlocks the session
    pub fn unlock_session(&mut self) {
        self.session_locked = false;
    }

    /// Returns the current capability mode
    pub fn current_mode(&self) -> CapabilityMode {
        self.current_mode
    }

    /// Returns the current active capabilities
    pub fn active_capabilities(&self) -> CapabilityFlags {
        self.active_capabilities
    }

    /// Returns the transition history (for audit export)
    pub fn transition_history(&self) -> &[GovernanceTransition] {
        &self.transition_history
    }

    /// Records a transition in the history buffer
    fn record_transition(&mut self, transition: GovernanceTransition) {
        self.transition_history.push(transition);
        
        // Prevent unbounded growth
        if self.transition_history.len() > self.max_history_size {
            self.transition_history.remove(0);
        }
    }

    /// Resets the lattice (e.g., on new session)
    /// 
    /// # Safety
    /// Mode resets to Normal, but capabilities remain at baseline or higher.
    /// Capabilities are NEVER reset to lower than baseline.
    pub fn reset_session(&mut self) {
        self.current_mode = CapabilityMode::Normal;
        self.session_locked = false;
        // Capabilities persist across sessions to prevent reset-based downgrades
        // self.active_capabilities remains unchanged
        self.transition_history.clear();
    }
}

impl Default for CapabilityLattice {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Lattice Property Tests (Formal Verification Helpers)
// ============================================================================

#[cfg(test)]
pub mod lattice_properties {
    use super::*;

    /// Tests reflexivity: A ≤ A
    pub fn test_reflexivity() -> bool {
        let caps = CapabilityFlags::ALL_ENABLED;
        caps.validate_monotonicity(caps).is_ok()
    }

    /// Tests antisymmetry: If A ≤ B and B ≤ A, then A = B
    pub fn test_antisymmetry() -> bool {
        let a = CapabilityFlags::from_bits(0b0000_1111);
        let b = CapabilityFlags::from_bits(0b0000_1111);
        
        let a_le_b = a.validate_monotonicity(b).is_ok();
        let b_le_a = b.validate_monotonicity(a).is_ok();
        
        a_le_b && b_le_a && (a.bits() == b.bits())
    }

    /// Tests transitivity: If A ≤ B and B ≤ C, then A ≤ C
    pub fn test_transitivity() -> bool {
        let a = CapabilityFlags::from_bits(0b0000_0001);
        let b = CapabilityFlags::from_bits(0b0000_0011);
        let c = CapabilityFlags::from_bits(0b0000_0111);
        
        let a_le_b = a.validate_monotonicity(b).is_ok();
        let b_le_c = b.validate_monotonicity(c).is_ok();
        let a_le_c = a.validate_monotonicity(c).is_ok();
        
        a_le_b && b_le_c && a_le_c
    }

    /// Tests monotonicity violation detection
    pub fn test_monotonicity_violation() -> bool {
        let a = CapabilityFlags::from_bits(0b0000_0011);
        let b = CapabilityFlags::from_bits(0b0000_0001); // Missing bit
        
        a.validate_monotonicity(b).is_err()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_flags_default() {
        let caps = CapabilityFlags::default();
        assert_eq!(caps, CapabilityFlags::ALL_ENABLED);
        assert!(caps.has_flag(CapabilityFlags::SESSION_EXIT));
    }

    #[test]
    fn test_monotonicity_valid_upgrade() {
        let current = CapabilityFlags::from_bits(0b0000_0001);
        let new = CapabilityFlags::from_bits(0b0000_0011);
        assert!(current.validate_monotonicity(new).is_ok());
    }

    #[test]
    fn test_monotonicity_invalid_downgrade() {
        let current = CapabilityFlags::from_bits(0b0000_0011);
        let new = CapabilityFlags::from_bits(0b0000_0001);
        let result = current.validate_monotonicity(new);
        assert!(result.is_err());
        
        if let Err(CapabilityError::CapabilityDowngradeDetected { lost_flags }) = result {
            assert_eq!(lost_flags, 0b0000_0010);
        } else {
            panic!("Expected CapabilityDowngradeDetected error");
        }
    }

    #[test]
    fn test_governance_transition_mode_escalation() {
        let mut lattice = CapabilityLattice::new();
        
        let transition = lattice.transition_mode(
            CapabilityMode::AugmentedLog,
            1.5,
            Some("TEST_TERM".to_string()),
        );
        
        assert!(transition.is_ok());
        assert_eq!(lattice.current_mode(), CapabilityMode::AugmentedLog);
    }

    #[test]
    fn test_governance_transition_mode_downgrade_blocked() {
        let mut lattice = CapabilityLattice::new();
        
        // Escalate first
        lattice.transition_mode(CapabilityMode::AugmentedReview, 3.5, None).unwrap();
        
        // Attempt downgrade
        let result = lattice.transition_mode(CapabilityMode::Normal, 0.5, None);
        
        assert!(result.is_err());
        assert_eq!(lattice.current_mode(), CapabilityMode::AugmentedReview);
    }

    #[test]
    fn test_session_exit_never_disabled() {
        let mut lattice = CapabilityLattice::new();
        
        // Attempt to remove SESSION_EXIT flag
        let mut caps = CapabilityFlags::ALL_ENABLED;
        // Manually construct a mask without SESSION_EXIT (bit 6)
        caps = CapabilityFlags::from_bits(caps.bits() & !CapabilityFlags::SESSION_EXIT.0);
        
        let result = lattice.modify_capabilities(caps);
        
        // Should fail validation in GovernanceTransition::validate
        assert!(result.is_err());
    }

    #[test]
    fn test_lattice_properties() {
        assert!(lattice_properties::test_reflexivity());
        assert!(lattice_properties::test_antisymmetry());
        assert!(lattice_properties::test_transitivity());
        assert!(lattice_properties::test_monotonicity_violation());
    }
}
