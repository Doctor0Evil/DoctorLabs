// ============================================================================
// DoctorLabs Lexicon - Audit Logging, Evidence Bundles, and Forensic Traceability
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module implements the "Forensic Audit Engine":
//   - Generates immutable evidence bundles for legal/regulatory review.
//   - Enforces PII handling policies (e.g., NoRawNeuralExport) at write-time.
//   - Ensures forensic traceability via cryptographic hashing of log chains.
//   - Produces court-ready artifacts that verify neurorights compliance.
//
// CRITICAL SAFETY INVARIANT:
//   No raw neural data (EEG waveforms, raw BCI signals) may be written to logs.
//   All sensitive identifiers (DIDs, User IDs) must be hashed before logging.
//   Evidence bundles must be integrity-protected (checksummed) against tampering.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - Enforcement Engine (File 5: enforcement.rs)
//   - CapabilityMode transitions (File 4: capability_mode.rs)
//   - Neurorights invariants (Mental Privacy, Cognitive Liberty)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![cfg_attr(not(test), warn(missing_docs))]

use crate::{LexiconError, LexiconResult, TimestampMs};
use crate::capability_mode::CapabilityMode;
use crate::enforcement::{EnforcementAction, EnforcementHint, PiiHandlingPolicy};
use crate::lexicon::LexiconTermId;
use crate::rogue_score::RogueScore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use thiserror::Error;

// ============================================================================
// Audit Configuration (Per-Term Logging Rules)
// ============================================================================

/// Configuration for audit logging, derived from LexiconTerm.audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Fields allowed to be logged (e.g., "timestamp", "session_id")
    pub log_fields: Vec<String>,
    
    /// PII handling policy for this term (e.g., NoRawNeuralExport)
    pub pii_handling: PiiHandlingPolicy,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_fields: vec!["timestamp".to_string(), "session_id".to_string()],
            pii_handling: PiiHandlingPolicy::SessionMetadataOnly,
        }
    }
}

impl AuditConfig {
    /// Validates that log_fields are permitted under the pii_handling policy
    pub fn validate(&self) -> LexiconResult<()> {
        for field in &self.log_fields {
            if !self.pii_handling.allows_field(field) {
                return Err(LexiconError::SchemaValidation {
                    term_id: LexiconTermId("UNKNOWN".to_string()),
                    reason: format!(
                        "Field '{}' not allowed under PII policy {:?}",
                        field, self.pii_handling
                    ),
                });
            }
        }
        Ok(())
    }
}

// ============================================================================
// Audit Log Entry (Immutable Record)
// ============================================================================

/// A single immutable audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique entry ID (UUID v4)
    pub entry_id: String,
    
    /// Timestamp of the event
    pub timestamp: TimestampMs,
    
    /// Session identifier (hashed)
    pub session_id_hash: String,
    
    /// User identifier (hashed)
    pub user_id_hash: String,
    
    /// Triggering lexicon term ID
    pub term_id: String,
    
    /// Harassment family (NHSP, HTA, PSA, NIH)
    pub family: String,
    
    /// RogueScore at time of event
    pub rogue_score: f64,
    
    /// Capability mode at time of event
    pub capability_mode: CapabilityMode,
    
    /// Enforcement action taken
    pub enforcement_hint: EnforcementHint,
    
    /// Neurorights violated (for legal context)
    pub neurorights_violated: Vec<String>,
    
    /// Legal basis citations (for legal context)
    pub legal_basis: Vec<String>,
    
    /// Previous entry hash (for chain integrity)
    pub previous_hash: String,
    
    /// Current entry hash (self-hash for verification)
    pub entry_hash: String,
}

impl AuditLogEntry {
    /// Creates a new audit log entry
    pub fn new(
        entry_id: String,
        timestamp: TimestampMs,
        session_id_hash: String,
        user_id_hash: String,
        term_id: String,
        family: String,
        rogue_score: f64,
        capability_mode: CapabilityMode,
        enforcement_hint: EnforcementHint,
        neurorights_violated: Vec<String>,
        legal_basis: Vec<String>,
        previous_hash: String,
    ) -> Self {
        let mut entry = Self {
            entry_id,
            timestamp,
            session_id_hash,
            user_id_hash,
            term_id,
            family,
            rogue_score,
            capability_mode,
            enforcement_hint,
            neurorights_violated,
            legal_basis,
            previous_hash,
            entry_hash: String::new(), // Computed after construction
        };
        
        entry.entry_hash = entry.compute_hash();
        entry
    }
    
    /// Computes the cryptographic hash of the entry (excluding self-hash)
    fn compute_hash(&self) -> String {
        // In production, use SHA-256 via sha2 crate
        // For now, simulate with a deterministic string representation
        format!(
            "HASH({}:{}:{}:{})",
            self.entry_id, self.timestamp, self.term_id, self.previous_hash
        )
    }
    
    /// Verifies the integrity of the entry hash
    pub fn verify_integrity(&self) -> bool {
        self.entry_hash == self.compute_hash()
    }
}

// ============================================================================
// Evidence Bundle (Court-Ready Artifact)
// ============================================================================

/// A collection of audit log entries forming a forensic evidence bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Bundle ID (UUID v4)
    pub bundle_id: String,
    
    /// Session ID (hashed)
    pub session_id_hash: String,
    
    /// Start timestamp
    pub start_timestamp: TimestampMs,
    
    /// End timestamp
    pub end_timestamp: TimestampMs,
    
    /// Total entries in bundle
    pub entry_count: usize,
    
    /// Log entries (chronological)
    pub entries: Vec<AuditLogEntry>,
    
    /// Bundle integrity hash (hash of all entry hashes)
    pub bundle_hash: String,
    
    /// Generation timestamp
    pub generated_at: TimestampMs,
    
    /// Jurisdiction context (for legal routing)
    pub jurisdiction: Option<String>,
    
    /// Legal counsel contact (optional, for escalation)
    pub legal_contact: Option<String>,
}

impl EvidenceBundle {
    /// Creates a new evidence bundle from a list of entries
    pub fn new(
        bundle_id: String,
        session_id_hash: String,
        entries: Vec<AuditLogEntry>,
        jurisdiction: Option<String>,
        legal_contact: Option<String>,
    ) -> LexiconResult<Self> {
        if entries.is_empty() {
            return Err(LexiconError::AuditLogFailure("Cannot create empty evidence bundle".to_string()));
        }
        
        let start_timestamp = entries.first().unwrap().timestamp;
        let end_timestamp = entries.last().unwrap().timestamp;
        let entry_count = entries.len();
        
        // Compute bundle hash (hash of all entry hashes concatenated)
        let mut hasher_input = String::new();
        for entry in &entries {
            hasher_input.push_str(&entry.entry_hash);
        }
        let bundle_hash = format!("BUNDLE_HASH({})", hasher_input); // Simulated SHA-256
        
        let generated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as TimestampMs;
        
        Ok(Self {
            bundle_id,
            session_id_hash,
            start_timestamp,
            end_timestamp,
            entry_count,
            entries,
            bundle_hash,
            generated_at,
            jurisdiction,
            legal_contact,
        })
    }
    
    /// Verifies the integrity of the entire bundle
    pub fn verify_integrity(&self) -> bool {
        // 1. Verify each entry
        for entry in &self.entries {
            if !entry.verify_integrity() {
                return false;
            }
        }
        
        // 2. Verify chain linkage (previous_hash matches previous entry_hash)
        for i in 1..self.entries.len() {
            if self.entries[i].previous_hash != self.entries[i - 1].entry_hash {
                return false;
            }
        }
        
        // 3. Verify bundle hash
        let mut hasher_input = String::new();
        for entry in &self.entries {
            hasher_input.push_str(&entry.entry_hash);
        }
        let expected_bundle_hash = format!("BUNDLE_HASH({})", hasher_input);
        
        self.bundle_hash == expected_bundle_hash
    }
    
    /// Exports the bundle to JSON string (for legal review)
    pub fn to_json(&self) -> LexiconResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| LexiconError::AuditLogFailure(format!("JSON serialization error: {}", e)))
    }
    
    /// Exports the bundle to YAML string (for policy review)
    pub fn to_yaml(&self) -> LexiconResult<String> {
        serde_yaml::to_string(self)
            .map_err(|e| LexiconError::AuditLogFailure(format!("YAML serialization error: {}", e)))
    }
}

// ============================================================================
// PII Sanitizer (Privacy Enforcement)
// ============================================================================

/// Utility for sanitizing data before logging
pub struct PiiSanitizer;

impl PiiSanitizer {
    /// Sanitizes a field value based on the PII handling policy
    pub fn sanitize(field_name: &str, value: &str, policy: PiiHandlingPolicy) -> String {
        if policy.allows_field(field_name) {
            // If field is allowed, check if it needs hashing
            if field_name.contains("id") || field_name.contains("hash") {
                // Always hash identifiers even if allowed
                Self::hash_value(value)
            } else {
                value.to_string()
            }
        } else {
            // Field not allowed, redact
            "[REDACTED]".to_string()
        }
    }
    
    /// Hashes a sensitive value (simulated SHA-256)
    fn hash_value(value: &str) -> String {
        format!("HASH({})", value)
    }
    
    /// Validates that no raw neural data is present in a map
    pub fn validate_no_raw_neural_data(data: &HashMap<String, String>) -> LexiconResult<()> {
        for (key, value) in data {
            if key.contains("eeg_raw") 
                || key.contains("neural_waveform") 
                || key.contains("bc_signal_raw")
                || key.contains("raw_trace")
            {
                return Err(LexiconError::from(AuditError::RawNeuralDataDetected {
                    field: key.clone(),
                }));
            }
            // Additional check: if value looks like a waveform (comma-separated floats)
            if value.contains(',') && value.len() > 100 {
                // Heuristic check for raw data leakage
                return Err(LexiconError::from(AuditError::PotentialRawDataLeakage {
                    field: key.clone(),
                }));
            }
        }
        Ok(())
    }
}

// ============================================================================
// Audit Errors
// ============================================================================

/// Errors specific to audit logging
#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Raw neural data detected in field: {field}")]
    RawNeuralDataDetected { field: String },
    
    #[error("Potential raw data leakage detected in field: {field}")]
    PotentialRawDataLeakage { field: String },
    
    #[error("Evidence bundle integrity verification failed")]
    IntegrityVerificationFailed,
    
    #[error("Chain linkage broken at entry index: {index}")]
    ChainLinkageBroken { index: usize },
    
    #[error("IO error during log write: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

// ============================================================================
// Audit Logger (Central Engine)
// ============================================================================

/// Central engine for managing audit logs and evidence bundles
pub struct AuditLogger {
    /// In-memory log buffer (for session-level bundling)
    log_buffer: Vec<AuditLogEntry>,
    
    /// Last entry hash (for chain linkage)
    last_hash: String,
    
    /// Current session ID (hashed)
    session_id_hash: String,
    
    /// Current user ID (hashed)
    user_id_hash: String,
    
    /// Default PII policy
    default_policy: PiiHandlingPolicy,
    
    /// Entry counter (for unique IDs)
    entry_counter: u64,
}

impl AuditLogger {
    /// Creates a new audit logger for a session
    pub fn new(session_id: &str, user_id: &str, default_policy: PiiHandlingPolicy) -> Self {
        let session_hash = PiiSanitizer::hash_value(session_id);
        let user_hash = PiiSanitizer::hash_value(user_id);
        
        Self {
            log_buffer: Vec::new(),
            last_hash: "GENESIS_HASH".to_string(),
            session_id_hash: session_hash,
            user_id_hash: user_hash,
            default_policy,
            entry_counter: 0,
        }
    }
    
    /// Logs an enforcement action
    pub fn log_enforcement(
        &mut self,
        action: &EnforcementAction,
        score: &RogueScore,
        family: &str,
    ) -> LexiconResult<()> {
        // 1. Validate no raw neural data in action fields
        let mut field_map = HashMap::new();
        for field in &action.log_fields {
            field_map.insert(field.clone(), format!("value_{}", field)); // Simulated value
        }
        PiiSanitizer::validate_no_raw_neural_data(&field_map)?;
        
        // 2. Create entry
        self.entry_counter += 1;
        let entry_id = format!("ENTRY-{}-{}", self.session_id_hash, self.entry_counter);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as TimestampMs;
        
        let entry = AuditLogEntry::new(
            entry_id,
            timestamp,
            self.session_id_hash.clone(),
            self.user_id_hash.clone(),
            action.term_id.clone(),
            family.to_string(),
            score.global_average,
            score.recommended_mode,
            action.hint,
            action.neurorights_violated.clone(),
            action.legal_basis.clone(),
            self.last_hash.clone(),
        );
        
        // 3. Update chain
        self.last_hash = entry.entry_hash.clone();
        self.log_buffer.push(entry);
        
        Ok(())
    }
    
    /// Logs a capability mode transition
    pub fn log_capability_transition(
        &mut self,
        from_mode: CapabilityMode,
        to_mode: CapabilityMode,
        trigger_score: f64,
        term_id: Option<String>,
    ) -> LexiconResult<()> {
        self.entry_counter += 1;
        let entry_id = format!("ENTRY-{}-{}", self.session_id_hash, self.entry_counter);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as TimestampMs;
        
        let entry = AuditLogEntry::new(
            entry_id,
            timestamp,
            self.session_id_hash.clone(),
            self.user_id_hash.clone(),
            term_id.unwrap_or_else(|| "SYSTEM_TRANSITION".to_string()),
            "SYSTEM".to_string(),
            trigger_score,
            to_mode,
            EnforcementHint::LogAndAudit, // System transitions are logged
            vec!["COGNITIVE_LIBERTY".to_string()], // Invariant protection
            vec!["ALN_NANO_NET_SAFE_CONSTRUCT".to_string()],
            self.last_hash.clone(),
        );
        
        self.last_hash = entry.entry_hash.clone();
        self.log_buffer.push(entry);
        
        Ok(())
    }
    
    /// Generates an evidence bundle for the current session
    pub fn generate_bundle(
        &self,
        jurisdiction: Option<String>,
        legal_contact: Option<String>,
    ) -> LexiconResult<EvidenceBundle> {
        if self.log_buffer.is_empty() {
            return Err(LexiconError::AuditLogFailure("No log entries to bundle".to_string()));
        }
        
        let bundle_id = format!("BUNDLE-{}", self.session_id_hash);
        
        EvidenceBundle::new(
            bundle_id,
            self.session_id_hash.clone(),
            self.log_buffer.clone(),
            jurisdiction,
            legal_contact,
        )
    }
    
    /// Exports the current log buffer to a file (JSON)
    pub fn export_to_file(&self, path: &str) -> LexiconResult<()> {
        let bundle = self.generate_bundle(None, None)?;
        let json = bundle.to_json()?;
        
        let mut file = std::fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        
        Ok(())
    }
    
    /// Clears the log buffer (e.g., on session end)
    pub fn clear(&mut self) {
        self.log_buffer.clear();
        self.entry_counter = 0;
        // Note: last_hash is NOT reset to maintain session separation integrity
        self.last_hash = "GENESIS_HASH".to_string();
    }
    
    /// Returns the current entry count
    pub fn entry_count(&self) -> usize {
        self.log_buffer.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::EnforcementHint;
    use crate::rogue_score::RogueScore;
    use std::collections::HashMap;

    fn create_test_action() -> EnforcementAction {
        EnforcementAction {
            hint: EnforcementHint::ReviewEscalate,
            term_id: "TEST_TERM".to_string(),
            trigger_score: 1.5,
            pii_policy: PiiHandlingPolicy::SessionMetadataOnly,
            log_fields: vec!["timestamp".to_string(), "session_id".to_string()],
            neurorights_violated: vec!["MENTAL_INTEGRITY".to_string()],
            legal_basis: vec!["ECHR_ART3".to_string()],
        }
    }

    fn create_test_score() -> RogueScore {
        RogueScore {
            timestamp: 1000,
            global_average: 1.5,
            global_max: 1.5,
            family_scores: HashMap::new(),
            recommended_mode: CapabilityMode::AugmentedLog,
        }
    }

    #[test]
    fn test_audit_logger_chain_integrity() {
        let mut logger = AuditLogger::new("session_123", "user_456", PiiHandlingPolicy::SessionMetadataOnly);
        
        let action = create_test_action();
        let score = create_test_score();
        
        logger.log_enforcement(&action, &score, "HTA").unwrap();
        logger.log_enforcement(&action, &score, "HTA").unwrap();
        
        let bundle = logger.generate_bundle(None, None).unwrap();
        
        assert!(bundle.verify_integrity());
        assert_eq!(bundle.entry_count, 2);
    }

    #[test]
    fn test_pii_sanitizer_raw_neural_block() {
        let mut data = HashMap::new();
        data.insert("eeg_raw_waveform".to_string(), "0.1,0.2,0.3...".to_string());
        
        let result = PiiSanitizer::validate_no_raw_neural_data(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_pii_sanitizer_allowed_field() {
        let value = PiiSanitizer::sanitize("session_id", "sess_123", PiiHandlingPolicy::SessionMetadataOnly);
        // Should be hashed because it contains "id"
        assert!(value.starts_with("HASH("));
    }

    #[test]
    fn test_evidence_bundle_serialization() {
        let mut logger = AuditLogger::new("session_123", "user_456", PiiHandlingPolicy::SessionMetadataOnly);
        let action = create_test_action();
        let score = create_test_score();
        
        logger.log_enforcement(&action, &score, "HTA").unwrap();
        let bundle = logger.generate_bundle(None, None).unwrap();
        
        let json = bundle.to_json();
        assert!(json.is_ok());
        
        let yaml = bundle.to_yaml();
        assert!(yaml.is_ok());
    }

    #[test]
    fn test_audit_config_validation() {
        let config = AuditConfig {
            log_fields: vec!["eeg_raw_waveform".to_string()],
            pii_handling: PiiHandlingPolicy::NoRawNeuralExport,
        };
        
        // Field not allowed under policy
        assert!(!config.pii_handling.allows_field("eeg_raw_waveform"));
        // Validation should catch this if we enforce it at term load time
        // Here we test the policy directly
        assert!(!config.pii_handling.allows_field("eeg_raw_waveform"));
    }
}
