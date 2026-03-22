// doctor_labs_superfilter/src/rogue_config.rs
// Rogue Configuration Module - Threshold and Weight Parameters
// Doctor-Labs SuperFilter Core Library
// Version: 2026.03.23 | ALN-NanoNet HyperSafe Construct Compliant

#![deny(clippy::all)]
#![warn(missing_docs)]

use crate::{BlacklistFamily, CapabilityMode};
use std::collections::HashMap;
use std::fmt::{self, Display};
use serde::{Serialize, Deserialize};

// ============================================================================
// ROGUE CONFIGURATION STRUCTURE
// ============================================================================

/// Core configuration parameters for harassment detection and escalation.
/// All parameters are tunable per deployment while maintaining safety invariants.
/// This structure ensures consistent behavior across nodes (Prometheus, Bostrom,
/// Loihi2, Nanoswarm) and interaction types (text, haptic, neural, AR/VR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueConfig {
    /// Alpha parameters: control kernel sharpness per harassment family.
    /// Higher alpha = sharper decay from centroid, more selective detection.
    /// Range: 0.1 to 10.0 (typical values: 1.0-5.0)
    pub alpha: HashMap<BlacklistFamily, f64>,
    /// Beta parameters: governance-tuned weights per harassment family.
    /// Higher beta = greater contribution to rogue score, higher priority.
    /// Range: 0.1 to 10.0 (HTA/NHSP typically 2.0-3.0, others 1.0-1.5)
    pub beta: HashMap<BlacklistFamily, f64>,
    /// Tau1 threshold: boundary between Normal and AugmentedLog modes.
    /// Rogue scores above this trigger enhanced telemetry collection.
    /// Range: 1.0 to 50.0 (typical: 10.0-20.0)
    pub tau1: f64,
    /// Tau2 threshold: boundary between AugmentedLog and AugmentedReview modes.
    /// Rogue scores above this require human/multi-sig review for actions.
    /// Range: 10.0 to 100.0 (typical: 30.0-50.0)
    pub tau2: f64,
    /// Session identifier for this configuration instance.
    pub config_id: String,
    /// Version string for configuration tracking and audit.
    pub version: String,
    /// Creation timestamp (UNIX epoch milliseconds).
    pub created_at: u64,
    /// Expiration timestamp (UNIX epoch milliseconds), optional.
    pub expires_at: Option<u64>,
    /// Deployment environment marker (development, staging, production).
    pub environment: DeploymentEnvironment,
    /// Compliance flags for regulatory tracking.
    pub compliance_flags: ComplianceFlags,
}

/// Deployment environment classification for configuration scoping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeploymentEnvironment {
    /// Development environment with relaxed thresholds for testing.
    Development,
    /// Staging environment mirroring production for validation.
    Staging,
    /// Production environment with strict safety enforcement.
    Production,
    /// Research environment for experimental configurations.
    Research,
}

impl Display for DeploymentEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Compliance flags for regulatory and standards tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct ComplianceFlags {
    /// ALN-NanoNet HyperSafe Construct compliance.
    pub aln_hypersafe: bool,
    /// EU AI Act high-risk system classification.
    pub eu_ai_act_high_risk: bool,
    /// Neurorights framework alignment.
    pub neurorights_aligned: bool,
    /// FDA medical device classification (if applicable).
    pub fda_medical_device: bool,
    /// HIPAA health data protection (if applicable).
    pub hipaa_protected: bool,
    /// GDPR personal data protection.
    pub gdpr_compliant: bool,
    /// IEEE P7000 series ethical alignment.
    pub ieee_ethical: bool,
}

impl ComplianceFlags {
    /// Creates a new ComplianceFlags instance with all flags disabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a ComplianceFlags instance with all safety flags enabled.
    #[must_use]
    pub fn all_enabled() -> Self {
        Self {
            aln_hypersafe: true,
            eu_ai_act_high_risk: true,
            neurorights_aligned: true,
            fda_medical_device: false,
            hipaa_protected: false,
            gdpr_compliant: true,
            ieee_ethical: true,
        }
    }

    /// Returns true if all critical safety flags are enabled.
    #[must_use]
    pub fn all_critical_enabled(&self) -> bool {
        self.aln_hypersafe && self.neurorights_aligned && self.ieee_ethical
    }

    /// Returns a summary string of enabled flags.
    #[must_use]
    pub fn enabled_flags_summary(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.aln_hypersafe { flags.push("ALN_HYPER_SAFE"); }
        if self.eu_ai_act_high_risk { flags.push("EU_AI_ACT_HIGH_RISK"); }
        if self.neurorights_aligned { flags.push("NEURORIGHTS_ALIGNED"); }
        if self.fda_medical_device { flags.push("FDA_MEDICAL_DEVICE"); }
        if self.hipaa_protected { flags.push("HIPAA_PROTECTED"); }
        if self.gdpr_compliant { flags.push("GDPR_COMPLIANT"); }
        if self.ieee_ethical { flags.push("IEEE_ETHICAL"); }
        flags
    }
}

impl Display for ComplianceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let enabled = self.enabled_flags_summary();
        if enabled.is_empty() {
            write!(f, "ComplianceFlags[none]")
        } else {
            write!(f, "ComplianceFlags[{}]", enabled.join(", "))
        }
    }
}

// ============================================================================
// ROGUE CONFIG BUILDER
// ============================================================================

/// Builder for constructing RogueConfig instances with validation.
/// Ensures all parameters are within safe ranges before instantiation.
#[derive(Debug, Clone)]
pub struct RogueConfigBuilder {
    alpha: HashMap<BlacklistFamily, f64>,
    beta: HashMap<BlacklistFamily, f64>,
    tau1: f64,
    tau2: f64,
    config_id: Option<String>,
    version: Option<String>,
    environment: DeploymentEnvironment,
    compliance_flags: ComplianceFlags,
}

impl RogueConfigBuilder {
    /// Creates a new RogueConfigBuilder with safe default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            alpha: Self::default_alpha_values(),
            beta: Self::default_beta_values(),
            tau1: 15.0,
            tau2: 40.0,
            config_id: None,
            version: None,
            environment: DeploymentEnvironment::Production,
            compliance_flags: ComplianceFlags::all_enabled(),
        }
    }

    /// Returns default alpha values optimized for harassment detection.
    /// Higher values for HTA/NHSP enable sharper detection of direct threats.
    #[must_use]
    fn default_alpha_values() -> HashMap<BlacklistFamily, f64> {
        let mut alpha = HashMap::new();
        alpha.insert(BlacklistFamily::CLLN, 1.5);
        alpha.insert(BlacklistFamily::CRS, 1.5);
        alpha.insert(BlacklistFamily::XGBC, 1.5);
        alpha.insert(BlacklistFamily::ICP, 1.5);
        alpha.insert(BlacklistFamily::CBCP, 1.5);
        alpha.insert(BlacklistFamily::NHSP, 3.0);  // High priority: sharper kernel
        alpha.insert(BlacklistFamily::HTA, 3.0);   // High priority: sharper kernel
        alpha.insert(BlacklistFamily::PSA, 2.0);
        alpha.insert(BlacklistFamily::NIH, 2.0);
        alpha
    }

    /// Returns default beta values reflecting harassment family priorities.
    /// HTA and NHSP receive highest weights for immediate intervention.
    #[must_use]
    fn default_beta_values() -> HashMap<BlacklistFamily, f64> {
        let mut beta = HashMap::new();
        beta.insert(BlacklistFamily::CLLN, 1.0);
        beta.insert(BlacklistFamily::CRS, 1.0);
        beta.insert(BlacklistFamily::XGBC, 1.0);
        beta.insert(BlacklistFamily::ICP, 1.0);
        beta.insert(BlacklistFamily::CBCP, 1.0);
        beta.insert(BlacklistFamily::NHSP, 2.5);  // High priority
        beta.insert(BlacklistFamily::HTA, 2.5);   // High priority
        beta.insert(BlacklistFamily::PSA, 1.5);
        beta.insert(BlacklistFamily::NIH, 1.5);
        beta
    }

    /// Sets alpha parameter for a specific harassment family.
    pub fn alpha(mut self, family: BlacklistFamily, value: f64) -> Self {
        self.alpha.insert(family, value.clamp(0.1, 10.0));
        self
    }

    /// Sets beta parameter for a specific harassment family.
    pub fn beta(mut self, family: BlacklistFamily, value: f64) -> Self {
        self.beta.insert(family, value.clamp(0.1, 10.0));
        self
    }

    /// Sets the tau1 threshold (Normal -> AugmentedLog boundary).
    pub fn tau1(mut self, value: f64) -> Self {
        self.tau1 = value.clamp(1.0, 50.0);
        self
    }

    /// Sets the tau2 threshold (AugmentedLog -> AugmentedReview boundary).
    pub fn tau2(mut self, value: f64) -> Self {
        self.tau2 = value.clamp(10.0, 100.0);
        self
    }

    /// Sets the configuration identifier.
    pub fn config_id(mut self, config_id: String) -> Self {
        self.config_id = Some(config_id);
        self
    }

    /// Sets the version string.
    pub fn version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the deployment environment.
    pub fn environment(mut self, env: DeploymentEnvironment) -> Self {
        self.environment = env;
        self
    }

    /// Sets the compliance flags.
    pub fn compliance_flags(mut self, flags: ComplianceFlags) -> Self {
        self.compliance_flags = flags;
        self
    }

    /// Builds the RogueConfig instance, returning None if validation fails.
    #[must_use]
    pub fn build(self) -> Option<RogueConfig> {
        // Validate tau1 < tau2 invariant
        if self.tau1 >= self.tau2 {
            return None;
        }

        // Validate all alpha values are positive
        if self.alpha.values().any(|&v| v <= 0.0) {
            return None;
        }

        // Validate all beta values are positive
        if self.beta.values().any(|&v| v <= 0.0) {
            return None;
        }

        // Ensure all families have alpha and beta values
        for family in BlacklistFamily::all_families() {
            if !self.alpha.contains_key(family) || !self.beta.contains_key(family) {
                return None;
            }
        }

        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Some(RogueConfig {
            alpha: self.alpha,
            beta: self.beta,
            tau1: self.tau1,
            tau2: self.tau2,
            config_id: self.config_id.unwrap_or_else(|| format!("config_{}", now)),
            version: self.version.unwrap_or_else(|| "1.0.0".to_string()),
            created_at: now,
            expires_at: None,
            environment: self.environment,
            compliance_flags: self.compliance_flags,
        })
    }

    /// Builds the RogueConfig instance, panicking if validation fails.
    #[must_use]
    pub fn build_expect(self) -> RogueConfig {
        self.build().expect("RogueConfigBuilder: validation failed")
    }
}

impl Default for RogueConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ROGUE CONFIG IMPLEMENTATION
// ============================================================================

impl RogueConfig {
    /// Creates a new RogueConfig with safe default values.
    #[must_use]
    pub fn new(config_id: String) -> Self {
        RogueConfigBuilder::new()
            .config_id(config_id)
            .build_expect()
    }

    /// Creates a development configuration with relaxed thresholds.
    #[must_use]
    pub fn development() -> Self {
        RogueConfigBuilder::new()
            .environment(DeploymentEnvironment::Development)
            .tau1(25.0)
            .tau2(60.0)
            .config_id("dev_config".to_string())
            .build_expect()
    }

    /// Creates a production configuration with strict thresholds.
    #[must_use]
    pub fn production() -> Self {
        RogueConfigBuilder::new()
            .environment(DeploymentEnvironment::Production)
            .tau1(10.0)
            .tau2(30.0)
            .config_id("prod_config".to_string())
            .build_expect()
    }

    /// Creates a research configuration for experimental tuning.
    #[must_use]
    pub fn research() -> Self {
        RogueConfigBuilder::new()
            .environment(DeploymentEnvironment::Research)
            .tau1(20.0)
            .tau2(50.0)
            .config_id("research_config".to_string())
            .build_expect()
    }

    /// Returns the alpha value for a specific harassment family.
    #[must_use]
    pub fn get_alpha(&self, family: &BlacklistFamily) -> f64 {
        *self.alpha.get(family).unwrap_or(&1.0)
    }

    /// Returns the beta value for a specific harassment family.
    #[must_use]
    pub fn get_beta(&self, family: &BlacklistFamily) -> f64 {
        *self.beta.get(family).unwrap_or(&1.0)
    }

    /// Returns true if the configuration is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            now > expires
        } else {
            false
        }
    }

    /// Returns true if this configuration is valid for production use.
    #[must_use]
    pub fn is_production_ready(&self) -> bool {
        self.environment == DeploymentEnvironment::Production
            && self.compliance_flags.all_critical_enabled()
            && !self.is_expired()
    }

    /// Returns the capability mode for a given rogue score.
    #[must_use]
    pub fn capability_mode_for_score(&self, score: f64) -> CapabilityMode {
        if score <= self.tau1 {
            CapabilityMode::Normal
        } else if score <= self.tau2 {
            CapabilityMode::AugmentedLog
        } else {
            CapabilityMode::AugmentedReview
        }
    }

    /// Returns true if a score triggers escalation from the given mode.
    #[must_use]
    pub fn triggers_escalation(&self, score: f64, current_mode: &CapabilityMode) -> bool {
        let target_mode = self.capability_mode_for_score(score);
        target_mode.is_escalation_from(current_mode)
    }

    /// Validates that tau1 < tau2 invariant holds.
    #[must_use]
    pub fn validate_thresholds(&self) -> bool {
        self.tau1 < self.tau2
    }

    /// Returns a summary of configuration parameters for audit.
    #[must_use]
    pub fn audit_summary(&self) -> ConfigAuditSummary {
        ConfigAuditSummary {
            config_id: self.config_id.clone(),
            version: self.version.clone(),
            environment: self.environment,
            tau1: self.tau1,
            tau2: self.tau2,
            high_priority_families: self.get_high_priority_families(),
            compliance_flags: self.compliance_flags,
            is_valid: self.validate_thresholds() && !self.is_expired(),
        }
    }

    /// Returns harassment families with beta > 2.0 (high priority).
    #[must_use]
    pub fn get_high_priority_families(&self) -> Vec<BlacklistFamily> {
        BlacklistFamily::all_families()
            .iter()
            .filter(|f| self.get_beta(f) > 2.0)
            .copied()
            .collect()
    }

    /// Merges another config into this one, taking higher priority values.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut merged_alpha = self.alpha.clone();
        let mut merged_beta = self.beta.clone();

        for (family, &alpha) in &other.alpha {
            merged_alpha.entry(*family).or_insert(alpha);
        }
        for (family, &beta) in &other.beta {
            merged_beta.entry(*family).or_insert(beta);
        }

        Self {
            alpha: merged_alpha,
            beta: merged_beta,
            tau1: self.tau1.min(other.tau1),  // More conservative threshold
            tau2: self.tau2.min(other.tau2),  // More conservative threshold
            config_id: format!("{}_merged_{}", self.config_id, other.config_id),
            version: format!("{}_merged_{}", self.version, other.version),
            created_at: self.created_at.max(other.created_at),
            expires_at: match (self.expires_at, other.expires_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            environment: self.environment,
            compliance_flags: ComplianceFlags {
                aln_hypersafe: self.compliance_flags.aln_hypersafe || other.compliance_flags.aln_hypersafe,
                eu_ai_act_high_risk: self.compliance_flags.eu_ai_act_high_risk || other.compliance_flags.eu_ai_act_high_risk,
                neurorights_aligned: self.compliance_flags.neurorights_aligned || other.compliance_flags.neurorights_aligned,
                fda_medical_device: self.compliance_flags.fda_medical_device || other.compliance_flags.fda_medical_device,
                hipaa_protected: self.compliance_flags.hipaa_protected || other.compliance_flags.hipaa_protected,
                gdpr_compliant: self.compliance_flags.gdpr_compliant || other.compliance_flags.gdpr_compliant,
                ieee_ethical: self.compliance_flags.ieee_ethical || other.compliance_flags.ieee_ethical,
            },
        }
    }
}

impl Display for RogueConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RogueConfig[id={}, env={}, tau1={:.1}, tau2={:.1}, valid={}]",
            self.config_id,
            self.environment,
            self.tau1,
            self.tau2,
            self.validate_thresholds() && !self.is_expired()
        )
    }
}

// ============================================================================
// CONFIG AUDIT SUMMARY
// ============================================================================

/// Sanitized summary of configuration for audit and compliance reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAuditSummary {
    /// Configuration identifier.
    pub config_id: String,
    /// Version string.
    pub version: String,
    /// Deployment environment.
    pub environment: DeploymentEnvironment,
    /// Tau1 threshold value.
    pub tau1: f64,
    /// Tau2 threshold value.
    pub tau2: f64,
    /// High-priority harassment families.
    pub high_priority_families: Vec<BlacklistFamily>,
    /// Compliance flags status.
    pub compliance_flags: ComplianceFlags,
    /// Overall configuration validity.
    pub is_valid: bool,
}

impl ConfigAuditSummary {
    /// Returns true if this configuration is ready for production deployment.
    #[must_use]
    pub fn is_production_ready(&self) -> bool {
        self.is_valid
            && self.environment == DeploymentEnvironment::Production
            && self.compliance_flags.all_critical_enabled()
    }

    /// Returns a human-readable summary string.
    #[must_use]
    pub fn summary_string(&self) -> String {
        format!(
            "Config {} (v{}) [{}] - tau1={:.1}, tau2={:.1}, valid={}, production_ready={}",
            self.config_id,
            self.version,
            self.environment,
            self.tau1,
            self.tau2,
            self.is_valid,
            self.is_production_ready()
        )
    }
}

impl Display for ConfigAuditSummary {
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
    fn test_rogue_config_builder_default_values() {
        let config = RogueConfigBuilder::new().build_expect();
        assert!(config.validate_thresholds());
        assert!(config.tau1 < config.tau2);
        assert!(config.alpha.len() == BlacklistFamily::count());
        assert!(config.beta.len() == BlacklistFamily::count());
    }

    #[test]
    fn test_rogue_config_tau_invariant() {
        let invalid_config = RogueConfigBuilder::new()
            .tau1(50.0)
            .tau2(30.0)
            .build();
        assert!(invalid_config.is_none());
    }

    #[test]
    fn test_high_priority_families() {
        let config = RogueConfig::production();
        let high_priority = config.get_high_priority_families();
        assert!(high_priority.contains(&BlacklistFamily::HTA));
        assert!(high_priority.contains(&BlacklistFamily::NHSP));
    }

    #[test]
    fn test_capability_mode_for_score() {
        let config = RogueConfig::production();
        assert_eq!(config.capability_mode_for_score(5.0), CapabilityMode::Normal);
        assert_eq!(config.capability_mode_for_score(20.0), CapabilityMode::AugmentedLog);
        assert_eq!(config.capability_mode_for_score(50.0), CapabilityMode::AugmentedReview);
    }

    #[test]
    fn test_config_merge() {
        let config1 = RogueConfig::new("config1".to_string());
        let config2 = RogueConfig::new("config2".to_string());
        let merged = config1.merge(&config2);
        assert!(merged.config_id.contains("config1"));
        assert!(merged.config_id.contains("config2"));
        assert!(merged.validate_thresholds());
    }

    #[test]
    fn test_compliance_flags() {
        let flags = ComplianceFlags::all_enabled();
        assert!(flags.all_critical_enabled());
        assert!(flags.enabled_flags_summary().len() >= 5);
    }

    #[test]
    fn test_deployment_environments() {
        let dev_config = RogueConfig::development();
        let prod_config = RogueConfig::production();
        assert_eq!(dev_config.environment, DeploymentEnvironment::Development);
        assert_eq!(prod_config.environment, DeploymentEnvironment::Production);
        assert!(prod_config.tau1 < dev_config.tau1);  // Production more strict
    }

    #[test]
    fn test_alpha_beta_retrieval() {
        let config = RogueConfig::production();
        let hta_alpha = config.get_alpha(&BlacklistFamily::HTA);
        let hta_beta = config.get_beta(&BlacklistFamily::HTA);
        assert!(hta_alpha > 0.0);
        assert!(hta_beta > 0.0);
        assert!(hta_beta >= config.get_beta(&BlacklistFamily::CLLN));  // HTA higher priority
    }

    #[test]
    fn test_config_audit_summary() {
        let config = RogueConfig::production();
        let summary = config.audit_summary();
        assert!(summary.is_valid);
        assert_eq!(summary.environment, DeploymentEnvironment::Production);
    }

    #[test]
    fn test_triggers_escalation() {
        let config = RogueConfig::production();
        assert!(!config.triggers_escalation(5.0, &CapabilityMode::Normal));
        assert!(config.triggers_escalation(20.0, &CapabilityMode::Normal));
        assert!(config.triggers_escalation(50.0, &CapabilityMode::AugmentedLog));
    }
}
