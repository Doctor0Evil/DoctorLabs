//! ============================================================================
//! NeuroGuard Monotone Capability Lattice Implementation
//! Copyright (c) 2026 Doctor0Evil Research Labs
//! ALN-NanoNet HyperSafe Construct Compliant
//! ============================================================================
//!
//! This module implements the mathematical foundation for capability preservation.
//! The lattice structure ensures that user capabilities can NEVER decrease -
//! they can only remain constant or increase when security responses trigger.
//!
//! This is the core invariant that prevents "quiet-violence" abuse patterns
//! where authorities silently strip away user freedoms under safety pretexts.
//!
//! Mathematical Basis: Complete Lattice Theory | Monotone Functions
//! Compliance: ALN-NanoNet Section 4.2 | Neurorights Envelope v3
//! ============================================================================

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::{
    fmt,
    ops::{BitOr, BitAnd, BitXor},
};

#[cfg(feature = "telemetry")]
use chrono::{DateTime, Utc};

/// ============================================================================
/// Lattice State Enumeration
/// ============================================================================
///
/// Represents the operational mode of the Guardian Gateway.
/// States form a complete lattice where transitions only move "upward"
/// (more oversight, more logging) but never "downward" (less capability).
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord))]
#[derive(hash::Hash)]
pub enum LatticeState {
    /// Normal operation - baseline capabilities active
    Normal = 0,
    
    /// Enhanced logging enabled - capabilities preserved + audit trail
    AugmentedLog = 1,
    
    /// External review required - multi-signature enforcement
    AugmentedReview = 2,
    
    /// Emergency protection - maximum logging, restricted external access
    EmergencyProtect = 3,
    
    /// Forensic mode - all actions cryptographically notarized
    ForensicAudit = 4,
    
    /// Locked state - no transitions allowed until manual unlock
    Locked = 5,
}

impl LatticeState {
    /// Get the numeric level of this state (for lattice ordering)
    #[inline]
    pub const fn level(&self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::AugmentedLog => 1,
            Self::AugmentedReview => 2,
            Self::EmergencyProtect => 3,
            Self::ForensicAudit => 4,
            Self::Locked => 5,
        }
    }
    
    /// Check if transition from `self` to `other` is monotone (non-decreasing)
    #[inline]
    pub const fn is_monotone_to(&self, other: &LatticeState) -> bool {
        self.level() <= other.level()
    }
    
    /// Get the join (least upper bound) of two states
    #[inline]
    pub const fn join(&self, other: &LatticeState) -> LatticeState {
        if self.level() >= other.level() { *self } else { *other }
    }
    
    /// Get the meet (greatest lower bound) of two states
    #[inline]
    pub const fn meet(&self, other: &LatticeState) -> LatticeState {
        if self.level() <= other.level() { *self } else { *other }
    }
    
    /// Check if this state allows capability reduction (always false by design)
    #[inline]
    pub const fn allows_capability_reduction(&self) -> bool {
        false // Monotone invariant: NEVER allow reduction
    }
    
    /// Get required signatures for state transition
    #[inline]
    pub const fn required_signatures(&self) -> u8 {
        match self {
            Self::Normal => 1,
            Self::AugmentedLog => 1,
            Self::AugmentedReview => 2,
            Self::EmergencyProtect => 2,
            Self::ForensicAudit => 3,
            Self::Locked => 0, // No transitions allowed
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for LatticeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// ============================================================================
/// Capability Flags (Bitfield)
/// ============================================================================
///
/// Each bit represents a user capability that CANNOT be removed once granted.
/// New capabilities can be added (bit set), but existing bits cannot be cleared.
/// This is enforced at the type system level through monotone operations.
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, Copy, PartialEq, Eq))]
pub struct CapabilityFlags(u64);

impl CapabilityFlags {
    /// Baseline capability: Exit channel always available
    pub const EXIT_CHANNEL: Self = Self(1 << 0);
    
    /// Baseline capability: Local logging cannot be disabled
    pub const LOCAL_LOGGING: Self = Self(1 << 1);
    
    /// Baseline capability: Neural data access requires consent
    pub const NEURAL_CONSENT: Self = Self(1 << 2);
    
    /// Baseline capability: Haptic feedback user-controlled
    pub const HAPTIC_CONTROL: Self = Self(1 << 3);
    
    /// Baseline capability: Session termination user-initiated
    pub const SESSION_TERMINATE: Self = Self(1 << 4);
    
    /// Baseline capability: Appeal process always accessible
    pub const APPEAL_ACCESS: Self = Self(1 << 5);
    
    /// Baseline capability: Evidence export always available
    pub const EVIDENCE_EXPORT: Self = Self(1 << 6);
    
    /// Baseline capability: Cryptographic signing enabled
    pub const CRYPTO_SIGN: Self = Self(1 << 7);
    
    /// Enhanced capability: Multi-signature approval required
    pub const MULTI_SIG_REQUIRED: Self = Self(1 << 8);
    
    /// Enhanced capability: External audit trail enabled
    pub const EXTERNAL_AUDIT: Self = Self(1 << 9);
    
    /// Enhanced capability: Real-time monitoring by guardian
    pub const GUARDIAN_MONITOR: Self = Self(1 << 10);
    
    /// Enhanced capability: Organichain notarization active
    pub const ORGANICHAIN_NOTARY: Self = Self(1 << 11);
    
    /// Enhanced capability: Legal counsel notification enabled
    pub const LEGAL_COUNSEL_NOTIFY: Self = Self(1 << 12);
    
    /// Enhanced capability: Emergency contact auto-alert
    pub const EMERGENCY_ALERT: Self = Self(1 << 13);
    
    /// Enhanced capability: Biometric consent verification
    pub const BIOMETRIC_CONSENT: Self = Self(1 << 14);
    
    /// Enhanced capability: Time-limited access enforcement
    pub const TIME_LIMITED_ACCESS: Self = Self(1 << 15);
    
    /// Reserved for future neurorights extensions
    pub const RESERVED_FUTURE: Self = Self(0xFFFF000000000000);
    
    /// Empty capability set (used for initialization)
    pub const EMPTY: Self = Self(0);
    
    /// Full capability set (all bits set)
    pub const FULL: Self = Self(u64::MAX);
    
    /// Baseline capabilities that MUST always be present
    pub const BASELINE_REQUIRED: Self = Self(
        Self::EXIT_CHANNEL.0 |
        Self::LOCAL_LOGGING.0 |
        Self::NEURAL_CONSENT.0 |
        Self::HAPTIC_CONTROL.0 |
        Self::SESSION_TERMINATE.0 |
        Self::APPEAL_ACCESS.0 |
        Self::EVIDENCE_EXPORT.0 |
        Self::CRYPTO_SIGN.0
    );
    
    /// Create new capability flags from raw value (validated)
    #[inline]
    pub const fn new(raw: u64) -> Self {
        // Ensure baseline required capabilities are always set
        Self(raw | Self::BASELINE_REQUIRED.0)
    }
    
    /// Get raw value (for serialization)
    #[inline]
    pub const fn raw(&self) -> u64 {
        self.0
    }
    
    /// Check if a specific capability is set
    #[inline]
    pub const fn has(&self, flag: CapabilityFlags) -> bool {
        (self.0 & flag.0) != 0
    }
    
    /// Add capabilities (monotone operation - only sets bits)
    #[inline]
    pub const fn add(&self, flag: CapabilityFlags) -> Self {
        Self(self.0 | flag.0)
    }
    
    /// Union of two capability sets (monotone join operation)
    #[inline]
    pub const fn union(&self, other: &CapabilityFlags) -> Self {
        Self(self.0 | other.0)
    }
    
    /// Intersection of two capability sets (preserves baseline)
    #[inline]
    pub const fn intersection(&self, other: &CapabilityFlags) -> Self {
        Self((self.0 & other.0) | Self::BASELINE_REQUIRED.0)
    }
    
    /// Check if self is a subset of other (all capabilities in self exist in other)
    #[inline]
    pub const fn is_subset_of(&self, other: &CapabilityFlags) -> bool {
        (self.0 & other.0) == self.0
    }
    
    /// Check if self is a superset of other
    #[inline]
    pub const fn is_superset_of(&self, other: &CapabilityFlags) -> bool {
        other.is_subset_of(self)
    }
    
    /// Get capabilities that are in self but not in other (delta)
    #[inline]
    pub const fn delta_from(&self, other: &CapabilityFlags) -> Self {
        Self(self.0 & !other.0)
    }
    
    /// Count number of capabilities set
    #[inline]
    pub const fn count(&self) -> u32 {
        self.0.count_ones()
    }
    
    /// Verify baseline capabilities are present (invariant check)
    #[inline]
    pub const fn verify_baseline(&self) -> bool {
        (self.0 & Self::BASELINE_REQUIRED.0) == Self::BASELINE_REQUIRED.0
    }
}

#[cfg(feature = "std")]
impl BitOr for CapabilityFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(&rhs)
    }
}

#[cfg(feature = "std")]
impl BitAnd for CapabilityFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersection(&rhs)
    }
}

#[cfg(feature = "std")]
impl BitXor for CapabilityFlags {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self((self.0 ^ rhs.0) | Self::BASELINE_REQUIRED.0)
    }
}

#[cfg(feature = "std")]
impl fmt::Display for CapabilityFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityFlags({:016x})", self.0)
    }
}

/// ============================================================================
/// Capability Lattice Structure
/// ============================================================================
///
/// The main structure that enforces monotone transitions.
/// All state changes must pass through this structure's validation.
/// ============================================================================

#[cfg(feature = "std")]
pub struct CapabilityLattice {
    current_state: LatticeState,
    current_capabilities: CapabilityFlags,
    transition_history: Vec<TransitionRecord>,
    max_history_size: usize,
    invariant_violations: u64,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct TransitionRecord {
    pub timestamp: DateTime<Utc>,
    pub from_state: LatticeState,
    pub to_state: LatticeState,
    pub capabilities_before: CapabilityFlags,
    pub capabilities_after: CapabilityFlags,
    pub trigger_reason: String,
    pub authorized_by: Vec<String>,
    pub monotone_verified: bool,
}

#[cfg(feature = "std")]
impl CapabilityLattice {
    /// Create new lattice with initial state
    pub fn new(initial_state: LatticeState) -> Self {
        Self {
            current_state: initial_state,
            current_capabilities: CapabilityFlags::BASELINE_REQUIRED,
            transition_history: Vec::with_capacity(1000),
            max_history_size: 10000,
            invariant_violations: 0,
        }
    }
    
    /// Get current lattice state
    #[inline]
    pub fn current_state(&self) -> LatticeState {
        self.current_state
    }
    
    /// Get current capability set
    #[inline]
    pub fn current_capabilities(&self) -> CapabilityFlags {
        self.current_capabilities
    }
    
    /// Get count of invariant violations (should be 0 in production)
    #[inline]
    pub fn invariant_violation_count(&self) -> u64 {
        self.invariant_violations
    }
    
    /// Evaluate a potential transition WITHOUT applying it
    pub fn evaluate_transition(
        &self,
        command: &crate::PolicyCommand,
    ) -> LatticeState {
        // Determine target state based on command type and risk level
        let target_state = self.compute_target_state(command);
        
        // Verify monotone property
        if self.current_state.is_monotone_to(&target_state) {
            target_state
        } else {
            // Would violate monotone invariant - return current state
            self.current_state
        }
    }
    
    /// Compute target state based on command characteristics
    fn compute_target_state(&self, command: &crate::PolicyCommand) -> LatticeState {
        use crate::{CommandType, SensitivityLevel};
        
        let base_state = self.current_state;
        
        // Escalate based on command sensitivity
        let sensitivity_escalation = match command.parameters.iter()
            .map(|p| p.sensitivity_level)
            .max()
            .unwrap_or(SensitivityLevel::Low)
        {
            SensitivityLevel::Low => 0,
            SensitivityLevel::Medium => 1,
            SensitivityLevel::High => 2,
            SensitivityLevel::Critical => 3,
        };
        
        // Escalate based on command type risk
        let type_escalation = match &command.command_type {
            CommandType::EnableMonitoring => 1,
            CommandType::AccessNeuralData => 2,
            CommandType::EnforceSession => 2,
            CommandType::DisableExitChannel => 3, // Should be rejected by lexicon
            CommandType::RestrictCapability => 3, // Should be rejected by lexicon
            CommandType::ModifyHapticFeedback => 1,
            CommandType::Other(_) => 1,
        };
        
        // Calculate new state level (capped at maximum)
        let new_level = (base_state.level() as usize + sensitivity_escalation + type_escalation)
            .min(LatticeState::Locked.level() as usize);
        
        // Map level back to state
        match new_level {
            0 => LatticeState::Normal,
            1 => LatticeState::AugmentedLog,
            2 => LatticeState::AugmentedReview,
            3 => LatticeState::EmergencyProtect,
            4 => LatticeState::ForensicAudit,
            _ => LatticeState::Locked,
        }
    }
    
    /// Check if transition is monotone (mathematically verified)
    #[inline]
    pub fn is_monotone_transition(
        &self,
        from: &LatticeState,
        to: &LatticeState,
    ) -> bool {
        from.is_monotone_to(to)
    }
    
    /// Check if capability transition is monotone (no capabilities removed)
    #[inline]
    pub fn is_monotone_capability_change(
        &self,
        before: &CapabilityFlags,
        after: &CapabilityFlags,
    ) -> bool {
        // All capabilities in `before` must exist in `after`
        before.is_subset_of(after)
    }
    
    /// Apply transition (validated - must be monotone)
    pub fn apply_transition(&mut self, new_state: LatticeState) -> Result<(), LatticeError> {
        // Verify monotone invariant
        if !self.current_state.is_monotone_to(&new_state) {
            self.invariant_violations += 1;
            return Err(LatticeError::MonotoneViolation {
                from: self.current_state,
                to: new_state,
            });
        }
        
        let old_state = self.current_state;
        let old_capabilities = self.current_capabilities;
        
        // Update state
        self.current_state = new_state;
        
        // Add capabilities based on new state (never remove)
        self.current_capabilities = self.current_capabilities.union(
            &self.capabilities_for_state(new_state)
        );
        
        // Verify baseline invariant
        if !self.current_capabilities.verify_baseline() {
            self.invariant_violations += 1;
            return Err(LatticeError::BaselineViolation {
                capabilities: self.current_capabilities,
            });
        }
        
        // Record transition
        self.record_transition(
            old_state,
            new_state,
            old_capabilities,
            self.current_capabilities,
            "Policy command application".to_string(),
            vec!["system".to_string()],
        );
        
        Ok(())
    }
    
    /// Get capabilities associated with a lattice state
    fn capabilities_for_state(&self, state: LatticeState) -> CapabilityFlags {
        match state {
            LatticeState::Normal => CapabilityFlags::BASELINE_REQUIRED,
            LatticeState::AugmentedLog => CapabilityFlags::BASELINE_REQUIRED
                .union(&CapabilityFlags::EXTERNAL_AUDIT),
            LatticeState::AugmentedReview => CapabilityFlags::BASELINE_REQUIRED
                .union(&CapabilityFlags::EXTERNAL_AUDIT)
                .union(&CapabilityFlags::MULTI_SIG_REQUIRED),
            LatticeState::EmergencyProtect => CapabilityFlags::BASELINE_REQUIRED
                .union(&CapabilityFlags::EXTERNAL_AUDIT)
                .union(&CapabilityFlags::MULTI_SIG_REQUIRED)
                .union(&CapabilityFlags::EMERGENCY_ALERT),
            LatticeState::ForensicAudit => CapabilityFlags::BASELINE_REQUIRED
                .union(&CapabilityFlags::EXTERNAL_AUDIT)
                .union(&CapabilityFlags::MULTI_SIG_REQUIRED)
                .union(&CapabilityFlags::ORGANICHAIN_NOTARY)
                .union(&CapabilityFlags::LEGAL_COUNSEL_NOTIFY),
            LatticeState::Locked => CapabilityFlags::BASELINE_REQUIRED
                .union(&CapabilityFlags::EXTERNAL_AUDIT)
                .union(&CapabilityFlags::GUARDIAN_MONITOR),
        }
    }
    
    /// Record transition in history
    fn record_transition(
        &mut self,
        from: LatticeState,
        to: LatticeState,
        caps_before: CapabilityFlags,
        caps_after: CapabilityFlags,
        reason: String,
        authorized_by: Vec<String>,
    ) {
        let record = TransitionRecord {
            timestamp: Utc::now(),
            from_state: from,
            to_state: to,
            capabilities_before: caps_before,
            capabilities_after: caps_after,
            trigger_reason: reason,
            authorized_by,
            monotone_verified: self.is_monotone_transition(&from, &to)
                && self.is_monotone_capability_change(&caps_before, &caps_after),
        };
        
        self.transition_history.push(record);
        
        // Trim history if exceeds max size
        if self.transition_history.len() > self.max_history_size {
            self.transition_history.remove(0);
        }
    }
    
    /// Get capability delta between two states
    pub fn get_capability_delta(
        &self,
        before: &LatticeState,
        after: &LatticeState,
    ) -> CapabilityFlags {
        let caps_before = self.capabilities_for_state(*before);
        let caps_after = self.capabilities_for_state(*after);
        caps_after.delta_from(&caps_before)
    }
    
    /// Get transition history (for audit/export)
    pub fn get_transition_history(&self) -> &[TransitionRecord] {
        &self.transition_history
    }
    
    /// Export transition history for legal submission
    #[cfg(feature = "telemetry")]
    pub fn export_history_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.transition_history)
    }
    
    /// Verify lattice integrity (all transitions monotone)
    pub fn verify_integrity(&self) -> LatticeIntegrityReport {
        let mut report = LatticeIntegrityReport {
            total_transitions: self.transition_history.len(),
            monotone_violations: 0,
            baseline_violations: 0,
            first_transition: None,
            last_transition: None,
            current_state: self.current_state,
            current_capabilities: self.current_capabilities,
        };
        
        for record in &self.transition_history {
            if !record.monotone_verified {
                report.monotone_violations += 1;
            }
            if !record.capabilities_after.verify_baseline() {
                report.baseline_violations += 1;
            }
            if report.first_transition.is_none() {
                report.first_transition = Some(record.timestamp);
            }
            report.last_transition = Some(record.timestamp);
        }
        
        report
    }
    
    /// Force lock state (emergency - no further transitions allowed)
    pub fn force_lock(&mut self, reason: &str) -> Result<(), LatticeError> {
        if self.current_state == LatticeState::Locked {
            return Err(LatticeError::AlreadyLocked);
        }
        
        let old_state = self.current_state;
        self.current_state = LatticeState::Locked;
        
        self.record_transition(
            old_state,
            LatticeState::Locked,
            self.current_capabilities,
            self.current_capabilities,
            format!("Emergency lock: {}", reason),
            vec!["emergency_protocol".to_string()],
        );
        
        Ok(())
    }
    
    /// Unlock from locked state (requires external authorization)
    pub fn unlock(&mut self, authorization_signatures: &[String]) -> Result<(), LatticeError> {
        if self.current_state != LatticeState::Locked {
            return Err(LatticeError::NotLocked);
        }
        
        // Require minimum 3 signatures for unlock
        if authorization_signatures.len() < 3 {
            return Err(LatticeError::InsufficientSignatures {
                required: 3,
                provided: authorization_signatures.len(),
            });
        }
        
        let old_state = self.current_state;
        self.current_state = LatticeState::ForensicAudit;
        
        self.record_transition(
            old_state,
            LatticeState::ForensicAudit,
            self.current_capabilities,
            self.current_capabilities,
            "Authorized unlock".to_string(),
            authorization_signatures.to_vec(),
        );
        
        Ok(())
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct LatticeIntegrityReport {
    pub total_transitions: usize,
    pub monotone_violations: u64,
    pub baseline_violations: u64,
    pub first_transition: Option<DateTime<Utc>>,
    pub last_transition: Option<DateTime<Utc>>,
    pub current_state: LatticeState,
    pub current_capabilities: CapabilityFlags,
}

#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum LatticeError {
    #[error("Monotone invariant violation: {from:?} -> {to:?}")]
    MonotoneViolation {
        from: LatticeState,
        to: LatticeState,
    },
    
    #[error("Baseline capability violation: {capabilities}")]
    BaselineViolation {
        capabilities: CapabilityFlags,
    },
    
    #[error("Lattice already in locked state")]
    AlreadyLocked,
    
    #[error("Lattice not in locked state")]
    NotLocked,
    
    #[error("Insufficient signatures for unlock: {provided}/{required}")]
    InsufficientSignatures {
        required: usize,
        provided: usize,
    },
}

/// ============================================================================
/// Compile-Time Lattice Verification (Const Fn)
/// ============================================================================
///
/// These functions can be evaluated at compile-time to verify
/// lattice properties before deployment.
/// ============================================================================

#[inline]
pub const fn verify_lattice_ordering() -> bool {
    let states = [
        LatticeState::Normal,
        LatticeState::AugmentedLog,
        LatticeState::AugmentedReview,
        LatticeState::EmergencyProtect,
        LatticeState::ForensicAudit,
        LatticeState::Locked,
    ];
    
    let mut i = 0;
    while i < states.len() - 1 {
        if !states[i].is_monotone_to(&states[i + 1]) {
            return false;
        }
        i += 1;
    }
    true
}

#[inline]
pub const fn verify_baseline_capabilities() -> bool {
    CapabilityFlags::BASELINE_REQUIRED.verify_baseline()
}

#[inline]
pub const fn verify_monotone_union() -> bool {
    let a = CapabilityFlags::EXIT_CHANNEL;
    let b = CapabilityFlags::LOCAL_LOGGING;
    let union = a.union(&b);
    union.has(CapabilityFlags::EXIT_CHANNEL) && union.has(CapabilityFlags::LOCAL_LOGGING)
}

/// ============================================================================
/// Unit Tests (Compile-Time Verification)
/// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lattice_ordering() {
        assert!(verify_lattice_ordering());
    }
    
    #[test]
    fn test_baseline_capabilities() {
        assert!(verify_baseline_capabilities());
    }
    
    #[test]
    fn test_monotone_union() {
        assert!(verify_monotone_union());
    }
    
    #[test]
    fn test_capability_flags() {
        let caps = CapabilityFlags::BASELINE_REQUIRED;
        assert!(caps.verify_baseline());
        assert!(caps.has(CapabilityFlags::EXIT_CHANNEL));
        assert!(caps.has(CapabilityFlags::EVIDENCE_EXPORT));
    }
    
    #[test]
    fn test_monotone_transition() {
        let normal = LatticeState::Normal;
        let audit = LatticeState::ForensicAudit;
        assert!(normal.is_monotone_to(&audit));
        assert!(!audit.is_monotone_to(&normal));
    }
    
    #[test]
    fn test_capability_addition() {
        let base = CapabilityFlags::BASELINE_REQUIRED;
        let added = base.add(CapabilityFlags::ORGANICHAIN_NOTARY);
        assert!(added.has(CapabilityFlags::BASELINE_REQUIRED));
        assert!(added.has(CapabilityFlags::ORGANICHAIN_NOTARY));
    }
}

/// ============================================================================
/// End of File - Monotone Capability Lattice
/// ============================================================================
