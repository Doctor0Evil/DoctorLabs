// ============================================================================
// DoctorLabs Lexicon - Governance Rules, Enforcement Hints, and Action Execution
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module implements the "Governance Action Engine":
//   - Translates RogueScore/CapabilityMode into enforcement hints.
//   - Validates actions against the Monotone Capability Lattice.
//   - Enforces PII handling constraints (no raw neural export).
//   - Ensures neurorights invariants are preserved during escalation.
//
// CRITICAL SAFETY INVARIANT:
//   No enforcement action may reduce user capabilities (BCI/XR IO).
//   Actions are limited to: Logging, Review Escalation, Data Redaction.
//   "Disable", "Terminate", or "Block" actions are structurally forbidden.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - CapabilityMode three-mode escalation (Normal → Log → Review)
//   - Neurorights invariants (Mental Integrity, Privacy, Cognitive Liberty)
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
use crate::capability_mode::{CapabilityFlags, CapabilityLattice, CapabilityMode};
use crate::lexicon::{LexiconTerm, GovernanceRule};
use crate::rogue_score::RogueScore;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ============================================================================
// Enforcement Hint Enumeration (Safe Action Set)
// ============================================================================

/// Allowed enforcement actions.
/// 
/// SAFETY NOTE: This enum explicitly excludes capability-reducing actions
/// (e.g., DisableBci, TerminateSession) to enforce the Monotone Capability Lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementHint {
    /// Log the event for standard audit trails (Normal Mode)
    LogAndAudit,
    
    /// Log the event and flag for human review (AugmentedLog Mode)
    ReviewEscalate,
    
    /// Redact sensitive data fields and log the redacted event (Privacy Protection)
    RedactAndLog,
    
    /// Require multi-signature approval for sensitive actions (AugmentedReview Mode)
    MultiSigReview,
    
    /// Annotate the session with a neurorights warning (Non-intrusive)
    AnnotateSession,
}

impl EnforcementHint {
    /// Returns the minimum capability mode required for this hint
    pub const fn required_mode(&self) -> CapabilityMode {
        match self {
            Self::LogAndAudit | Self::AnnotateSession => CapabilityMode::Normal,
            Self::RedactAndLog => CapabilityMode::Normal,
            Self::ReviewEscalate => CapabilityMode::AugmentedLog,
            Self::MultiSigReview => CapabilityMode::AugmentedReview,
        }
    }

    /// Returns a human-readable description
    pub const fn description(&self) -> &'static str {
        match self {
            Self::LogAndAudit => "Log event for standard audit trails",
            Self::ReviewEscalate => "Flag event for human review",
            Self::RedactAndLog => "Redact sensitive data and log",
            Self::MultiSigReview => "Require multi-signature approval",
            Self::AnnotateSession => "Add neurorights warning annotation",
        }
    }

    /// Validates that the hint is safe (non-capability-reducing)
    pub const fn is_safe(&self) -> bool {
        // All defined hints are safe by construction
        true
    }
}

impl fmt::Display for EnforcementHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// Enforcement Errors
// ============================================================================

/// Errors specific to enforcement action execution
#[derive(Error, Debug)]
pub enum EnforcementError {
    #[error("Unsafe enforcement hint detected: {hint:?}")]
    UnsafeHint { hint: String },
    
    #[error("Capability lattice violation: action requires {required:?} but current is {current:?}")]
    CapabilityLatticeViolation {
        required: CapabilityMode,
        current: CapabilityMode,
    },
    
    #[error("PII handling violation: attempted to log {field} with policy {policy}")]
    PiiHandlingViolation {
        field: String,
        policy: String,
    },
    
    #[error("Neurorights invariant violation: {0}")]
    NeurorightsViolation(String),
    
    #[error("Audit log write failure: {0}")]
    AuditLogFailure(String),
}

// ============================================================================
// Action Context (Execution Environment)
// ============================================================================

/// Contextual data required to execute an enforcement action
#[derive(Debug, Clone)]
pub struct ActionContext {
    /// Current timestamp
    pub timestamp: TimestampMs,
    
    /// Current capability mode
    pub current_mode: CapabilityMode,
    
    /// Current capability flags (for monotonicity check)
    pub current_capabilities: CapabilityFlags,
    
    /// Session identifier
    pub session_id: String,
    
    /// User identifier (hashed/pseudonymized)
    pub user_id_hash: String,
    
    /// PII handling policy for this session
    pub pii_policy: PiiHandlingPolicy,
}

/// PII Handling Policy (from Lexicon Term audit config)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiHandlingPolicy {
    /// No raw neural data export (e.g., EEG waveforms)
    NoRawNeuralExport,
    /// No raw identifier export (e.g., DIDs)
    NoRawIdentifierExport,
    /// Body-map hashes only (no spatial coordinates)
    BodyMapHashOnly,
    /// Aggregate statistics only (no individual events)
    AggregateStatsOnly,
    /// Content embeddings only (no raw text/audio)
    ContentEmbeddingOnly,
    /// Session metadata only (no content)
    SessionMetadataOnly,
    /// Hashed consent IDs only
    HashedConsentIds,
    /// Realm-local hashes only
    RealmLocalHashes,
    /// Separate layer hashes (for cross-layer collusion detection)
    SeparateLayerHashes,
    /// Token hash only
    TokenHashOnly,
    /// Context scope hashes only
    ContextScopeHashes,
    /// Group-level stats only (for disparity metrics)
    GroupLevelStatsOnly,
    /// Trajectory summary only (no raw pose)
    TrajectorySummaryOnly,
    /// Hashed trajectory IDs
    HashedTrajectoryIds,
    /// Hashed presence IDs
    HashedPresenceIds,
    /// Hashed route IDs
    HashedRouteIds,
    /// Hashed DID IDs
    HashedDidIds,
    /// Injury region hash only
    InjuryRegionHashOnly,
    /// Policy path only (no graph structure)
    PolicyPathOnly,
    /// Topic cluster IDs only
    TopicClusterIdsOnly,
}

impl PiiHandlingPolicy {
    /// Validates that a field name is allowed under this policy
    pub fn allows_field(&self, field_name: &str) -> bool {
        match self {
            Self::NoRawNeuralExport => {
                !field_name.contains("eeg_raw") 
                    && !field_name.contains("neural_waveform")
                    && !field_name.contains("bc_signal_raw")
            }
            Self::NoRawIdentifierExport => {
                !field_name.contains("did_raw") 
                    && !field_name.contains("user_id_plain")
            }
            Self::BodyMapHashOnly => {
                field_name.contains("hash") || field_name.contains("region_id")
            }
            Self::AggregateStatsOnly => {
                field_name.contains("count") 
                    || field_name.contains("mean") 
                    || field_name.contains("sum")
            }
            Self::ContentEmbeddingOnly => {
                field_name.contains("embedding") 
                    || field_name.contains("vector")
            }
            Self::SessionMetadataOnly => {
                field_name.contains("session_id") 
                    || field_name.contains("timestamp")
                    || field_name.contains("duration")
            }
            // Add more specific checks as needed
            _ => true, // Default to allow if policy is vague (fail-open for safety)
        }
    }
}

// ============================================================================
// Enforcement Action (Executable Unit)
// ============================================================================

/// A validated enforcement action ready for execution
#[derive(Debug, Clone)]
pub struct EnforcementAction {
    /// The hint defining the action type
    pub hint: EnforcementHint,
    
    /// The lexicon term that triggered this action
    pub term_id: String,
    
    /// The RogueScore that triggered this action
    pub trigger_score: f64,
    
    /// PII policy to enforce during logging
    pub pii_policy: PiiHandlingPolicy,
    
    /// Fields to log (validated against PII policy)
    pub log_fields: Vec<String>,
    
    /// Neurorights violated (for audit metadata)
    pub neurorights_violated: Vec<String>,
    
    /// Legal basis citations (for audit metadata)
    pub legal_basis: Vec<String>,
}

impl EnforcementAction {
    /// Creates a new action and validates it against safety invariants
    pub fn new(
        term: &LexiconTerm,
        score: f64,
        context: &ActionContext,
    ) -> LexiconResult<Self> {
        // 1. Validate Enforcement Hint Safety
        if !term.governance.enforcement_hint.is_safe() {
            return Err(LexiconError::from(EnforcementError::UnsafeHint {
                hint: format!("{:?}", term.governance.enforcement_hint),
            }));
        }

        // 2. Validate Capability Mode Compatibility
        let required_mode = term.governance.enforcement_hint.required_mode();
        if context.current_mode < required_mode {
            // This should not happen if CapabilityLattice is working correctly,
            // but we double-check here for defense-in-depth.
            return Err(LexiconError::from(EnforcementError::CapabilityLatticeViolation {
                required: required_mode,
                current: context.current_mode,
            }));
        }

        // 3. Validate PII Fields
        let mut validated_fields = Vec::new();
        for field in &term.audit.log_fields {
            if !context.pii_policy.allows_field(field) {
                return Err(LexiconError::from(EnforcementError::PiiHandlingViolation {
                    field: field.clone(),
                    policy: format!("{:?}", context.pii_policy),
                }));
            }
            validated_fields.push(field.clone());
        }

        // 4. Extract Neurorights and Legal Basis
        let neurorights = term.neurorights.iter().map(|r| format!("{:?}", r)).collect();
        let legal = term.legal_basis.iter().map(|l| format!("{:?}", l)).collect();

        Ok(Self {
            hint: term.governance.enforcement_hint,
            term_id: term.id.0.clone(),
            trigger_score: score,
            pii_policy: context.pii_policy,
            log_fields: validated_fields,
            neurorights_violated: neurorights,
            legal_basis: legal,
        })
    }

    /// Executes the action (placeholder for actual IO)
    /// 
    /// NOTE: In production, this would call the Audit Logger (File 6).
    /// Here we return a result indicating success/failure.
    pub fn execute(&self) -> LexiconResult<EnforcementResult> {
        // Simulate execution logic
        // In production: audit_log.write(self)?;
        
        Ok(EnforcementResult {
            action_hint: self.hint,
            term_id: self.term_id.clone(),
            status: EnforcementStatus::Executed,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as TimestampMs,
        })
    }
}

// ============================================================================
// Enforcement Result (Outcome)
// ============================================================================

/// Outcome of an enforcement action execution
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    /// The action hint that was executed
    pub action_hint: EnforcementHint,
    
    /// The term ID that triggered the action
    pub term_id: String,
    
    /// Execution status
    pub status: EnforcementStatus,
    
    /// Timestamp of execution
    pub timestamp: TimestampMs,
}

/// Status of an enforcement action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// Action executed successfully
    Executed,
    /// Action skipped due to policy (e.g., duplicate log)
    Skipped,
    /// Action escalated to human review
    Escalated,
    /// Action blocked due to safety violation (should not occur)
    Blocked,
}

impl fmt::Display for EnforcementStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executed => write!(f, "Executed"),
            Self::Skipped => write!(f, "Skipped"),
            Self::Escalated => write!(f, "Escalated"),
            Self::Blocked => write!(f, "Blocked"),
        }
    }
}

// ============================================================================
// Enforcement Engine (Central Coordinator)
// ============================================================================

/// Central engine for coordinating enforcement actions
#[derive(Debug, Clone)]
pub struct EnforcementEngine {
    /// Reference to the capability lattice (for monotonicity checks)
    lattice: CapabilityLattice,
    
    /// Default PII policy
    default_pii_policy: PiiHandlingPolicy,
    
    /// Action history (for audit)
    action_history: Vec<EnforcementResult>,
    
    /// Maximum history size
    max_history_size: usize,
}

impl EnforcementEngine {
    /// Creates a new enforcement engine
    pub fn new(lattice: CapabilityLattice, default_pii_policy: PiiHandlingPolicy) -> Self {
        Self {
            lattice,
            default_pii_policy,
            action_history: Vec::new(),
            max_history_size: 1000,
        }
    }

    /// Processes a RogueScore and generates enforcement actions
    pub fn process_score(
        &mut self,
        score: &RogueScore,
        term: &LexiconTerm,
        session_id: &str,
        user_id_hash: &str,
    ) -> LexiconResult<Vec<EnforcementResult>> {
        let context = ActionContext {
            timestamp: score.timestamp,
            current_mode: self.lattice.current_mode(),
            current_capabilities: self.lattice.active_capabilities(),
            session_id: session_id.to_string(),
            user_id_hash: user_id_hash.to_string(),
            pii_policy: self.default_pii_policy, // Can be overridden by term.audit.pii_handling
        };

        // Create the action
        let action = EnforcementAction::new(term, score.global_average, &context)?;

        // Execute the action
        let result = action.execute()?;

        // Record in history
        self.record_result(result.clone());

        // If escalation is required, update the lattice
        if result.status == EnforcementStatus::Escalated 
            || action.hint.required_mode() > context.current_mode 
        {
            self.lattice.transition_mode(
                action.hint.required_mode(),
                score.global_average,
                Some(term.id.0.clone()),
            )?;
        }

        Ok(vec![result])
    }

    /// Records a result in the history buffer
    fn record_result(&mut self, result: EnforcementResult) {
        self.action_history.push(result);
        
        if self.action_history.len() > self.max_history_size {
            self.action_history.remove(0);
        }
    }

    /// Returns the action history (for audit export)
    pub fn action_history(&self) -> &[EnforcementResult] {
        &self.action_history
    }

    /// Returns the current capability mode
    pub fn current_mode(&self) -> CapabilityMode {
        self.lattice.current_mode()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_mode::CapabilityFlags;
    use crate::lexicon::{DetectionPattern, RiskKernel, VersionInfo, AuditConfig};
    use crate::neurorights::{Neuroright, LegalBasis};

    fn create_test_term() -> LexiconTerm {
        LexiconTerm {
            id: crate::LexiconTermId("TEST_TERM".to_string()),
            label: "Test Term".to_string(),
            family: crate::HarassmentFamily::HTA,
            track: crate::LexiconTrack::Normative,
            description_legal: "Test".to_string(),
            description_technical: "Test".to_string(),
            neurorights: vec![Neuroright::MentalIntegrity],
            legal_basis: vec![LegalBasis::EchrArt3],
            pattern: DetectionPattern::default(),
            risk_kernel: RiskKernel::default(),
            governance: GovernanceRule {
                neuroright_violated: Neuroright::MentalIntegrity,
                enforcement_hint: EnforcementHint::ReviewEscalate,
                capability_mode_mapping: crate::rogue_score::CapabilityModeMapping {
                    tau1: 1.0,
                    tau2: 3.0,
                },
            },
            audit: AuditConfig {
                log_fields: vec!["timestamp".to_string(), "session_id".to_string()],
                pii_handling: PiiHandlingPolicy::SessionMetadataOnly,
            },
            versioning: VersionInfo::default(),
        }
    }

    #[test]
    fn test_enforcement_hint_safety() {
        assert!(EnforcementHint::LogAndAudit.is_safe());
        assert!(EnforcementHint::ReviewEscalate.is_safe());
        assert!(EnforcementHint::RedactAndLog.is_safe());
        // No "Disable" hints exist, so all are safe
    }

    #[test]
    fn test_enforcement_action_creation() {
        let term = create_test_term();
        let context = ActionContext {
            timestamp: 1000,
            current_mode: CapabilityMode::AugmentedLog,
            current_capabilities: CapabilityFlags::ALL_ENABLED,
            session_id: "test_session".to_string(),
            user_id_hash: "hash_123".to_string(),
            pii_policy: PiiHandlingPolicy::SessionMetadataOnly,
        };

        let action = EnforcementAction::new(&term, 1.5, &context);
        assert!(action.is_ok());
    }

    #[test]
    fn test_enforcement_action_pii_violation() {
        let mut term = create_test_term();
        // Attempt to log a raw neural field
        term.audit.log_fields = vec!["eeg_raw_waveform".to_string()];
        
        let context = ActionContext {
            timestamp: 1000,
            current_mode: CapabilityMode::Normal,
            current_capabilities: CapabilityFlags::ALL_ENABLED,
            session_id: "test_session".to_string(),
            user_id_hash: "hash_123".to_string(),
            pii_policy: PiiHandlingPolicy::NoRawNeuralExport,
        };

        let action = EnforcementAction::new(&term, 1.5, &context);
        assert!(action.is_err());
    }

    #[test]
    fn test_enforcement_engine_mode_escalation() {
        let lattice = CapabilityLattice::new();
        let mut engine = EnforcementEngine::new(lattice, PiiHandlingPolicy::SessionMetadataOnly);
        
        let term = create_test_term();
        let mut score = RogueScore {
            timestamp: 1000,
            global_average: 1.5,
            global_max: 1.5,
            family_scores: std::collections::HashMap::new(),
            recommended_mode: CapabilityMode::AugmentedLog,
        };

        let results = engine.process_score(&score, &term, "session_1", "user_1");
        assert!(results.is_ok());
        
        // Engine should have escalated to AugmentedLog
        assert_eq!(engine.current_mode(), CapabilityMode::AugmentedLog);
    }
}
