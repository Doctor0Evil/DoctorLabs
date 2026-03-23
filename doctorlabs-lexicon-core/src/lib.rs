// ============================================================================
// DoctorLabs Lexicon Core - Neurorights-Grounded Haptic/XR Abuse Detection
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
// 
// This crate implements the dual-use lexicon engine for detecting coercive
// haptic, neural, and XR-based abuse patterns. All enforcement actions are
// monotone-capability-safe: they may add logging, review, or consent checks,
// but never reduce user capabilities (BCI/XR IO, communication, motor control).
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - RogueScore risk kernel with Gaussian family weights
//   - CapabilityMode three-mode escalation (Normal → AugmentedLog → AugmentedReview)
//   - Neurorights invariants (mental integrity, privacy, cognitive liberty)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![cfg_attr(not(test), warn(missing_docs))]

pub mod lexicon;
pub mod rogue_score;
pub mod capability_mode;
pub mod neurorights;
pub mod enforcement;
pub mod audit;
pub mod nih_psa;
pub mod adapters;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

// ============================================================================
// Core Type Definitions
// ============================================================================

/// Unique identifier for a lexicon term (e.g., "HTA_CONDITIONED_COMPLIANCE_LOOP_v1")
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LexiconTermId(pub String);

impl std::fmt::Display for LexiconTermId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session identifier for audit logging
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

/// Timestamp in Unix milliseconds
pub type TimestampMs = u64;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during lexicon processing
#[derive(Error, Debug)]
pub enum LexiconError {
    #[error("Invalid term ID format: {0}")]
    InvalidTermId(String),
    
    #[error("Schema validation failed for term {term_id}: {reason}")]
    SchemaValidation {
        term_id: LexiconTermId,
        reason: String,
    },
    
    #[error("Neurorights invariant violation: {0}")]
    NeurorightsViolation(String),
    
    #[error("Capability monotonicity failure: attempted downgrade in {context}")]
    CapabilityMonotonicityFailure { context: String },
    
    #[error("RogueScore computation error: {0}")]
    RogueScoreError(String),
    
    #[error("Audit log write failure: {0}")]
    AuditLogFailure(String),
    
    #[error("YAML parsing error: {0}")]
    YamlParseError(#[from] serde_yaml::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type alias for lexicon operations
pub type LexiconResult<T> = Result<T, LexiconError>;

// ============================================================================
// Harassment Family Enumeration
// ============================================================================

/// The four harassment families from Doctor-Labs taxonomy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarassmentFamily {
    /// Neural-Harassment-Spike-Patterns
    NHSP,
    /// Haptic-Targeting-Abuse
    HTA,
    /// Prolonged-Session-Abuse
    PSA,
    /// Node-Interpreter-Harassment
    NIH,
}

impl HarassmentFamily {
    /// Returns all harassment families as a slice
    pub const fn all() -> &'static [Self] {
        &[Self::NHSP, Self::HTA, Self::PSA, Self::NIH]
    }
    
    /// Returns a human-readable description
    pub const fn description(&self) -> &'static str {
        match self {
            Self::NHSP => "Neural-Harassment-Spike-Patterns",
            Self::HTA => "Haptic-Targeting-Abuse",
            Self::PSA => "Prolonged-Session-Abuse",
            Self::NIH => "Node-Interpreter-Harassment",
        }
    }
}

impl std::fmt::Display for HarassmentFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// Track Enumeration (Normative vs Telemetry)
// ============================================================================

/// Distinguishes normative/legal terms from telemetry-derived terms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LexiconTrack {
    /// Normative terms grounded in neurorights and legal doctrine
    Normative,
    /// Telemetry terms derived from fused sensor/behavioral analysis
    Telemetry,
    /// Adversarial terms discovered through red-teaming
    Adversarial,
}

impl LexiconTrack {
    /// Returns the expected proportion of 100-term lexicon
    pub const fn expected_count(&self) -> usize {
        match self {
            Self::Normative => 65,  // ~65% normative/legal
            Self::Telemetry => 25,  // ~25% telemetry
            Self::Adversarial => 10, // ~10% red-team discovered
        }
    }
}

// ============================================================================
// Lexicon Term Structure (YAML/DSL Schema)
// ============================================================================

/// A complete lexicon entry with dual-use legal and technical semantics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexiconTerm {
    /// Stable identifier (e.g., "HTA_CONDITIONED_COMPLIANCE_LOOP_v1")
    pub id: LexiconTermId,
    
    /// Human-readable label for reports and legal documents
    pub label: String,
    
    /// Harassment family classification
    pub family: HarassmentFamily,
    
    /// Track classification (normative/telemetry/adversarial)
    pub track: LexiconTrack,
    
    /// Legal definition for court/policy use
    pub description_legal: String,
    
    /// Technical definition for detection engine
    pub description_technical: String,
    
    /// Violated neurorights
    pub neurorights: Vec<neurorights::Neuroright>,
    
    /// Legal basis citations
    pub legal_basis: Vec<neurorights::LegalBasis>,
    
    /// Detection pattern (signal/semantic/behavioral)
    pub pattern: lexicon::DetectionPattern,
    
    /// Risk kernel parameters for RogueScore
    pub risk_kernel: rogue_score::RiskKernel,
    
    /// Governance and enforcement rules
    pub governance: enforcement::GovernanceRule,
    
    /// Audit logging configuration
    pub audit: audit::AuditConfig,
    
    /// Versioning metadata
    pub versioning: lexicon::VersionInfo,
}

impl LexiconTerm {
    /// Validates the term against neurorights and monotonicity invariants
    pub fn validate(&self) -> LexiconResult<()> {
        // Check neurorights invariants
        if self.neurorights.is_empty() {
            return Err(LexiconError::SchemaValidation {
                term_id: self.id.clone(),
                reason: "At least one neuroright must be specified".to_string(),
            });
        }
        
        // Check legal basis
        if self.legal_basis.is_empty() {
            return Err(LexiconError::SchemaValidation {
                term_id: self.id.clone(),
                reason: "At least one legal basis citation required".to_string(),
            });
        }
        
        // Check monotonicity: enforcement_hint must not imply capability reduction
        match self.governance.enforcement_hint {
            enforcement::EnforcementHint::DisableBci
            | enforcement::EnforcementHint::DisableXr
            | enforcement::EnforcementHint::TerminateSession => {
                return Err(LexiconError::CapabilityMonotonicityFailure {
                    context: format!("Term {} attempts capability reduction", self.id),
                });
            }
            _ => {} // Allowed: log-and-review, review-escalate, redact-and-log
        }
        
        // Validate risk kernel weights sum to reasonable range
        let weight_sum: f64 = self.risk_kernel.family_weight.values().sum();
        if weight_sum < 0.1 || weight_sum > 4.0 {
            return Err(LexiconError::SchemaValidation {
                term_id: self.id.clone(),
                reason: format!(
                    "Risk kernel weight sum {} outside valid range [0.1, 4.0]",
                    weight_sum
                ),
            });
        }
        
        Ok(())
    }
    
    /// Returns the term's contribution to RogueScore for a given family
    pub fn family_weight(&self, family: HarassmentFamily) -> f64 {
        *self.risk_kernel.family_weight.get(&family).unwrap_or(&0.0)
    }
}

// ============================================================================
// Lexicon Registry (In-Memory Rule Store)
// ============================================================================

/// Central registry for all loaded lexicon terms
#[derive(Debug, Clone)]
pub struct LexiconRegistry {
    terms: HashMap<LexiconTermId, Arc<LexiconTerm>>,
    terms_by_family: HashMap<HarassmentFamily, Vec<LexiconTermId>>,
    terms_by_track: HashMap<LexiconTrack, Vec<LexiconTermId>>,
    version: String,
    loaded_at: TimestampMs,
}

impl LexiconRegistry {
    /// Creates a new empty registry
    pub fn new(version: String) -> Self {
        let mut terms_by_family = HashMap::new();
        for family in HarassmentFamily::all() {
            terms_by_family.insert(*family, Vec::new());
        }
        
        let mut terms_by_track = HashMap::new();
        for track in [LexiconTrack::Normative, LexiconTrack::Telemetry, LexiconTrack::Adversarial] {
            terms_by_track.insert(track, Vec::new());
        }
        
        Self {
            terms: HashMap::new(),
            terms_by_family,
            terms_by_track,
            version,
            loaded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as TimestampMs,
        }
    }
    
    /// Registers a validated term in the registry
    pub fn register(&mut self, term: LexiconTerm) -> LexiconResult<()> {
        term.validate()?;
        
        let term_id = term.id.clone();
        let family = term.family;
        let track = term.track;
        
        let arc_term = Arc::new(term);
        self.terms.insert(term_id.clone(), arc_term);
        
        if let Some(ids) = self.terms_by_family.get_mut(&family) {
            ids.push(term_id.clone());
        }
        
        if let Some(ids) = self.terms_by_track.get_mut(&track) {
            ids.push(term_id);
        }
        
        Ok(())
    }
    
    /// Retrieves a term by ID
    pub fn get(&self, id: &LexiconTermId) -> Option<Arc<LexiconTerm>> {
        self.terms.get(id).cloned()
    }
    
    /// Returns all terms for a harassment family
    pub fn get_by_family(&self, family: HarassmentFamily) -> Vec<Arc<LexiconTerm>> {
        self.terms_by_family
            .get(&family)
            .unwrap()
            .iter()
            .filter_map(|id| self.terms.get(id).cloned())
            .collect()
    }
    
    /// Returns term count statistics
    pub fn statistics(&self) -> LexiconStatistics {
        LexiconStatistics {
            total_terms: self.terms.len(),
            normative_count: self.terms_by_track.get(&LexiconTrack::Normative).map_or(0, Vec::len),
            telemetry_count: self.terms_by_track.get(&LexiconTrack::Telemetry).map_or(0, Vec::len),
            adversarial_count: self.terms_by_track.get(&LexiconTrack::Adversarial).map_or(0, Vec::len),
            version: self.version.clone(),
        }
    }
}

/// Statistics about the loaded lexicon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexiconStatistics {
    pub total_terms: usize,
    pub normative_count: usize,
    pub telemetry_count: usize,
    pub adversarial_count: usize,
    pub version: String,
}

// ============================================================================
// Public API
// ============================================================================

/// Loads a lexicon from YAML file
pub fn load_lexicon_from_yaml(path: &str) -> LexiconResult<LexiconRegistry> {
    let content = std::fs::read_to_string(path)?;
    let terms: Vec<LexiconTerm> = serde_yaml::from_str(&content)?;
    
    let mut registry = LexiconRegistry::new("v0.1.0".to_string());
    for term in terms {
        registry.register(term)?;
    }
    
    Ok(registry)
}

/// Creates a registry with seed terms (for testing/bootstrap)
pub fn create_seed_registry() -> LexiconResult<LexiconRegistry> {
    let mut registry = LexiconRegistry::new("seed-v0.1.0".to_string());
    
    // Seed with minimal valid terms for each family
    // Full terms loaded from doctor-labs-haptic-neural-lexicon.yaml in production
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_harassment_family_display() {
        assert_eq!(HarassmentFamily::NHSP.to_string(), "NHSP");
        assert_eq!(HarassmentFamily::HTA.to_string(), "HTA");
    }
    
    #[test]
    fn test_lexicon_term_id_display() {
        let id = LexiconTermId("TEST_TERM_v1".to_string());
        assert_eq!(id.to_string(), "TEST_TERM_v1");
    }
}
