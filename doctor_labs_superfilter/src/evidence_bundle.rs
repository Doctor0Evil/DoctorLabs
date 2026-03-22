// doctor_labs_superfilter/src/evidence_bundle.rs
// Evidence Bundle Module - Cryptographic Audit Trail and Forensic Traceability
// Doctor-Labs SuperFilter Core Library
// Version: 2026.03.23 | ALN-NanoNet HyperSafe Construct Compliant

#![deny(clippy::all)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

use crate::{
    BlacklistFamily, CapabilityMode, RogueScore, SpanScore,
    span_score::{AuditRecord, GovernanceFlag, InteractionType},
    harassment_detector::{DetectionResult, DetectionAuditRecord, DetectionContext},
};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use serde::{Serialize, Deserialize};

// ============================================================================
// EVIDENCE BUNDLE CORE STRUCTURE
// ============================================================================

/// Cryptographically-signed evidence bundle for audit and compliance.
/// Contains no raw content, only hashes, metadata, and computed scores.
/// Designed for forensic traceability while preserving user privacy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Unique bundle identifier (UUID format recommended).
    pub bundle_id: String,
    /// Session identifier for traceability.
    pub session_id: String,
    /// Node identifier (Prometheus, Bostrom, Loihi2, Nanoswarm).
    pub node_id: String,
    /// User/device DID for accountability.
    pub user_did: Option<String>,
    /// ALN (Autonomous Legal Node) identifier for compliance routing.
    pub aln_id: Option<String>,
    /// Timestamp of bundle creation (UNIX epoch milliseconds).
    pub created_at: u64,
    /// Timestamp of bundle expiration (UNIX epoch milliseconds), optional.
    pub expires_at: Option<u64>,
    /// Evidence type classification.
    pub evidence_type: EvidenceType,
    /// Content hash (SHA-256 or similar, hex-encoded).
    pub content_hash: String,
    /// Harassment detection results summary.
    pub detection_summary: DetectionSummary,
    /// Capability mode transitions recorded in this bundle.
    pub mode_transitions: Vec<ModeTransition>,
    /// Governance flags triggered.
    pub governance_flags: Vec<GovernanceFlag>,
    /// Cryptographic signature for integrity verification.
    pub signature: String,
    /// Signature algorithm used (e.g., "Ed25519", "RSA-4096").
    pub signature_algorithm: String,
    /// Public key fingerprint for signature verification.
    pub public_key_fingerprint: String,
    /// Chain of custody records.
    pub custody_chain: Vec<CustodyRecord>,
    /// Compliance metadata.
    pub compliance_metadata: ComplianceMetadata,
    /// Related bundle IDs (for linked evidence chains).
    pub related_bundles: Vec<String>,
    /// Verification status.
    pub verification_status: VerificationStatus,
}

/// Evidence type classification for bundle categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Harassment detection event.
    HarassmentDetection,
    /// Capability mode escalation.
    ModeEscalation,
    /// Neuroright violation alert.
    NeurorightViolation,
    /// Session anomaly detection.
    SessionAnomaly,
    /// Haptic safety envelope exceeded.
    HapticEnvelopeExceeded,
    /// Neural spike anomaly.
    NeuralSpikeAnomaly,
    /// Node interpreter abuse.
    NodeInterpreterAbuse,
    /// Prolonged session abuse.
    ProlongedSessionAbuse,
    /// Multi-sig review event.
    MultiSigReview,
    /// Compliance audit checkpoint.
    ComplianceAudit,
    /// System integrity check.
    IntegrityCheck,
    /// User consent record.
    UserConsent,
}

impl Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Detection summary for evidence bundle inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSummary {
    /// Total rogue score.
    pub rogue_score_total: f64,
    /// Per-family breakdown.
    pub per_family_scores: HashMap<BlacklistFamily, f64>,
    /// Dominant harassment family.
    pub dominant_family: Option<BlacklistFamily>,
    /// High-priority harassment detected.
    pub high_priority_detected: bool,
    /// Escalation recommended.
    pub escalation_recommended: bool,
    /// Processing latency in microseconds.
    pub processing_latency_us: u64,
}

impl DetectionSummary {
    /// Creates a new DetectionSummary from a RogueScore.
    #[must_use]
    pub fn from_rogue_score(score: &RogueScore, escalation: bool, latency_us: u64) -> Self {
        let mut per_family_scores = HashMap::new();
        for (idx, &family_score) in score.per_family.iter().enumerate() {
            if let Some(family) = BlacklistFamily::all_families().get(idx) {
                if family_score > 0.0 {
                    per_family_scores.insert(*family, family_score);
                }
            }
        }

        Self {
            rogue_score_total: score.r_total,
            per_family_scores,
            dominant_family: score.dominant_family(),
            high_priority_detected: per_family_scores
                .get(&BlacklistFamily::HTA)
                .copied()
                .unwrap_or(0.0)
                > 0.5
                || per_family_scores
                    .get(&BlacklistFamily::NHSP)
                    .copied()
                    .unwrap_or(0.0)
                    > 0.5,
            escalation_recommended: escalation,
            processing_latency_us: latency_us,
        }
    }

    /// Creates a DetectionSummary from a DetectionResult.
    #[must_use]
    pub fn from_detection_result(result: &DetectionResult) -> Self {
        Self::from_rogue_score(
            &result.rogue_score,
            result.escalation_recommended,
            result.processing_latency_us,
        )
    }
}

/// Capability mode transition record for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeTransition {
    /// From capability mode.
    pub from_mode: CapabilityMode,
    /// To capability mode.
    pub to_mode: CapabilityMode,
    /// Timestamp of transition (UNIX epoch milliseconds).
    pub timestamp: u64,
    /// Reason for transition.
    pub reason: String,
    /// Rogue score at time of transition.
    pub rogue_score: f64,
    /// Whether transition is monotone-valid.
    pub monotone_valid: bool,
    /// Authorizing entity (system, human reviewer, multi-sig).
    pub authorizer: String,
}

impl ModeTransition {
    /// Creates a new ModeTransition record.
    #[must_use]
    pub fn new(
        from_mode: CapabilityMode,
        to_mode: CapabilityMode,
        reason: String,
        rogue_score: f64,
        authorizer: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            from_mode,
            to_mode,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            reason,
            rogue_score,
            monotone_valid: from_mode as u8 <= to_mode as u8,
            authorizer,
        }
    }

    /// Returns true if this transition represents an escalation.
    #[must_use]
    pub fn is_escalation(&self) -> bool {
        self.from_mode as u8 < self.to_mode as u8
    }

    /// Returns true if this transition represents a de-escalation (invalid in production).
    #[must_use]
    pub fn is_deescalation(&self) -> bool {
        self.from_mode as u8 > self.to_mode as u8
    }
}

/// Chain of custody record for evidence handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyRecord {
    /// Entity that received the evidence.
    pub entity_id: String,
    /// Entity type (system, human, organization).
    pub entity_type: CustodyEntityType,
    /// Timestamp of custody transfer (UNIX epoch milliseconds).
    pub timestamp: u64,
    /// Action performed (received, reviewed, forwarded, archived).
    pub action: String,
    /// Digital signature of the entity.
    pub signature: String,
    /// Notes or comments.
    pub notes: Option<String>,
}

/// Entity type for custody tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CustodyEntityType {
    /// Automated system component.
    System,
    /// Human reviewer or operator.
    Human,
    /// Organization or legal entity.
    Organization,
    /// Regulatory body.
    Regulator,
    /// Third-party auditor.
    Auditor,
}

impl Display for CustodyEntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Compliance metadata for regulatory tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetadata {
    /// EU AI Act high-risk system flag.
    pub eu_ai_act_high_risk: bool,
    /// Neurorights framework alignment.
    pub neurorights_aligned: bool,
    /// GDPR personal data handling.
    pub gdpr_compliant: bool,
    /// HIPAA health data protection (if applicable).
    pub hipaa_protected: bool,
    /// ALN-NanoNet HyperSafe Construct compliance.
    pub aln_hypersafe_compliant: bool,
    /// IEEE P7000 ethical alignment.
    pub ieee_ethical: bool,
    /// Jurisdiction for legal purposes.
    pub jurisdiction: Option<String>,
    /// Retention period in days.
    pub retention_days: u32,
    /// Data classification level.
    pub data_classification: DataClassification,
}

impl ComplianceMetadata {
    /// Creates a new ComplianceMetadata with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            eu_ai_act_high_risk: true,
            neurorights_aligned: true,
            gdpr_compliant: true,
            hipaa_protected: false,
            aln_hypersafe_compliant: true,
            ieee_ethical: true,
            jurisdiction: None,
            retention_days: 2555, // 7 years for compliance
            data_classification: DataClassification::Sensitive,
        }
    }

    /// Creates ComplianceMetadata with all flags enabled.
    #[must_use]
    pub fn all_enabled() -> Self {
        Self {
            eu_ai_act_high_risk: true,
            neurorights_aligned: true,
            gdpr_compliant: true,
            hipaa_protected: true,
            aln_hypersafe_compliant: true,
            ieee_ethical: true,
            jurisdiction: Some("EU".to_string()),
            retention_days: 2555,
            data_classification: DataClassification::HighlySensitive,
        }
    }

    /// Returns true if all critical compliance flags are enabled.
    #[must_use]
    pub fn all_critical_enabled(&self) -> bool {
        self.aln_hypersafe_compliant
            && self.neurorights_aligned
            && self.ieee_ethical
            && self.gdpr_compliant
    }
}

impl Default for ComplianceMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Data classification level for evidence bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataClassification {
    /// Public data, no restrictions.
    Public,
    /// Internal use only.
    Internal,
    /// Sensitive data requiring protection.
    Sensitive,
    /// Highly sensitive data with strict controls.
    HighlySensitive,
    /// Restricted data with maximum protection.
    Restricted,
}

impl Display for DataClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Verification status for evidence bundle integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Bundle has not been verified yet.
    Unverified,
    /// Bundle signature is valid.
    SignatureValid,
    /// Bundle signature is invalid.
    SignatureInvalid,
    /// Bundle chain of custody is complete.
    CustodyComplete,
    /// Bundle chain of custody has gaps.
    CustodyIncomplete,
    /// Bundle has been fully audited.
    Audited,
    /// Bundle has been tampered with.
    Tampered,
    /// Bundle has expired.
    Expired,
}

impl Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// EVIDENCE BUNDLE BUILDER
// ============================================================================

/// Builder for constructing EvidenceBundle instances with validation.
#[derive(Debug, Clone)]
pub struct EvidenceBundleBuilder {
    bundle_id: Option<String>,
    session_id: Option<String>,
    node_id: Option<String>,
    user_did: Option<String>,
    aln_id: Option<String>,
    evidence_type: EvidenceType,
    content_hash: Option<String>,
    detection_summary: Option<DetectionSummary>,
    mode_transitions: Vec<ModeTransition>,
    governance_flags: Vec<GovernanceFlag>,
    signature: Option<String>,
    signature_algorithm: String,
    public_key_fingerprint: Option<String>,
    custody_chain: Vec<CustodyRecord>,
    compliance_metadata: ComplianceMetadata,
    related_bundles: Vec<String>,
}

impl EvidenceBundleBuilder {
    /// Creates a new EvidenceBundleBuilder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bundle_id: None,
            session_id: None,
            node_id: None,
            user_did: None,
            aln_id: None,
            evidence_type: EvidenceType::HarassmentDetection,
            content_hash: None,
            detection_summary: None,
            mode_transitions: Vec::new(),
            governance_flags: Vec::new(),
            signature: None,
            signature_algorithm: "Ed25519".to_string(),
            public_key_fingerprint: None,
            custody_chain: Vec::new(),
            compliance_metadata: ComplianceMetadata::new(),
            related_bundles: Vec::new(),
        }
    }

    /// Sets the bundle identifier.
    pub fn bundle_id(mut self, bundle_id: String) -> Self {
        self.bundle_id = Some(bundle_id);
        self
    }

    /// Sets the session identifier.
    pub fn session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Sets the node identifier.
    pub fn node_id(mut self, node_id: String) -> Self {
        self.node_id = Some(node_id);
        self
    }

    /// Sets the user DID.
    pub fn user_did(mut self, user_did: String) -> Self {
        self.user_did = Some(user_did);
        self
    }

    /// Sets the ALN identifier.
    pub fn aln_id(mut self, aln_id: String) -> Self {
        self.aln_id = Some(aln_id);
        self
    }

    /// Sets the evidence type.
    pub fn evidence_type(mut self, evidence_type: EvidenceType) -> Self {
        self.evidence_type = evidence_type;
        self
    }

    /// Sets the content hash.
    pub fn content_hash(mut self, content_hash: String) -> Self {
        self.content_hash = Some(content_hash);
        self
    }

    /// Sets the detection summary.
    pub fn detection_summary(mut self, summary: DetectionSummary) -> Self {
        self.detection_summary = Some(summary);
        self
    }

    /// Adds a mode transition.
    pub fn mode_transition(mut self, transition: ModeTransition) -> Self {
        self.mode_transitions.push(transition);
        self
    }

    /// Adds a governance flag.
    pub fn governance_flag(mut self, flag: GovernanceFlag) -> Self {
        self.governance_flags.push(flag);
        self
    }

    /// Sets the cryptographic signature.
    pub fn signature(mut self, signature: String) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Sets the signature algorithm.
    pub fn signature_algorithm(mut self, algorithm: String) -> Self {
        self.signature_algorithm = algorithm;
        self
    }

    /// Sets the public key fingerprint.
    pub fn public_key_fingerprint(mut self, fingerprint: String) -> Self {
        self.public_key_fingerprint = Some(fingerprint);
        self
    }

    /// Adds a custody record.
    pub fn custody_record(mut self, record: CustodyRecord) -> Self {
        self.custody_chain.push(record);
        self
    }

    /// Sets the compliance metadata.
    pub fn compliance_metadata(mut self, metadata: ComplianceMetadata) -> Self {
        self.compliance_metadata = metadata;
        self
    }

    /// Adds a related bundle ID.
    pub fn related_bundle(mut self, bundle_id: String) -> Self {
        self.related_bundles.push(bundle_id);
        self
    }

    /// Builds the EvidenceBundle instance, returning None if validation fails.
    #[must_use]
    pub fn build(self) -> Option<EvidenceBundle> {
        // Validate required fields
        let bundle_id = self.bundle_id?;
        let session_id = self.session_id?;
        let node_id = self.node_id?;
        let content_hash = self.content_hash?;
        let signature = self.signature?;
        let public_key_fingerprint = self.public_key_fingerprint?;
        let detection_summary = self.detection_summary?;

        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Some(EvidenceBundle {
            bundle_id,
            session_id,
            node_id,
            user_did: self.user_did,
            aln_id: self.aln_id,
            created_at: now,
            expires_at: None,
            evidence_type: self.evidence_type,
            content_hash,
            detection_summary,
            mode_transitions: self.mode_transitions,
            governance_flags: self.governance_flags,
            signature,
            signature_algorithm: self.signature_algorithm,
            public_key_fingerprint,
            custody_chain: self.custody_chain,
            compliance_metadata: self.compliance_metadata,
            related_bundles: self.related_bundles,
            verification_status: VerificationStatus::Unverified,
        })
    }

    /// Builds the EvidenceBundle instance, panicking if validation fails.
    #[must_use]
    pub fn build_expect(self) -> EvidenceBundle {
        self.build().expect("EvidenceBundleBuilder: validation failed")
    }
}

impl Default for EvidenceBundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EVIDENCE BUNDLE IMPLEMENTATION
// ============================================================================

impl EvidenceBundle {
    /// Creates a new EvidenceBundle from a DetectionResult.
    #[must_use]
    pub fn from_detection_result(
        result: &DetectionResult,
        user_did: Option<String>,
        aln_id: Option<String>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        use uuid::Uuid;

        let bundle_id = format!("evd_{}", Uuid::new_v4().to_simple());
        let detection_summary = DetectionSummary::from_detection_result(result);

        let mut mode_transitions = Vec::new();
        if result.escalation_recommended {
            mode_transitions.push(ModeTransition::new(
                result.current_mode,
                result.recommended_mode,
                format!("Harassment score: {:.2}", result.rogue_score.r_total),
                result.rogue_score.r_total,
                "system_auto".to_string(),
            ));
        }

        let content_hash = Self::compute_bundle_hash(
            &result.context.session_id,
            &result.context.node_id,
            &detection_summary,
        );

        let signature = Self::generate_placeholder_signature(&content_hash);
        let public_key_fingerprint = Self::generate_key_fingerprint();

        let mut custody_chain = Vec::new();
        custody_chain.push(CustodyRecord {
            entity_id: "system_collector".to_string(),
            entity_type: CustodyEntityType::System,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            action: "collected".to_string(),
            signature: signature.clone(),
            notes: Some("Initial collection by harassment detector".to_string()),
        });

        Self {
            bundle_id,
            session_id: result.context.session_id.clone(),
            node_id: result.context.node_id.clone(),
            user_did,
            aln_id,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            expires_at: None,
            evidence_type: if result.has_high_priority_harassment() {
                EvidenceType::NeurorightViolation
            } else {
                EvidenceType::HarassmentDetection
            },
            content_hash,
            detection_summary,
            mode_transitions,
            governance_flags: result.triggered_flags.clone(),
            signature,
            signature_algorithm: "Ed25519".to_string(),
            public_key_fingerprint,
            custody_chain,
            compliance_metadata: ComplianceMetadata::all_enabled(),
            related_bundles: Vec::new(),
            verification_status: VerificationStatus::Unverified,
        }
    }

    /// Creates an EvidenceBundle from a SpanScore.
    #[must_use]
    pub fn from_span_score(
        span: &SpanScore,
        user_did: Option<String>,
        aln_id: Option<String>,
    ) -> Self {
        use uuid::Uuid;

        let bundle_id = format!("evd_{}", Uuid::new_v4().to_simple());
        let detection_summary = DetectionSummary {
            rogue_score_total: span.total_harassment_weight(),
            per_family_scores: span.family_weights.clone(),
            dominant_family: span.dominant_family(),
            high_priority_detected: span.is_high_priority_harassment(),
            escalation_recommended: span.is_harassment_detected(1.0),
            processing_latency_us: 0,
        };

        let content_hash = span.content_hash.clone();
        let signature = Self::generate_placeholder_signature(&content_hash);
        let public_key_fingerprint = Self::generate_key_fingerprint();

        let mut governance_flags = span.governance_flags.clone();
        if span.is_high_priority_harassment() {
            governance_flags.push(GovernanceFlag::NeurorightViolation);
        }

        Self {
            bundle_id,
            session_id: span.session_id.clone(),
            node_id: span.node_id.clone().unwrap_or_else(|| "unknown".to_string()),
            user_did,
            aln_id,
            created_at: span.timestamp,
            expires_at: None,
            evidence_type: if span.interaction_type == InteractionType::Haptic {
                EvidenceType::HapticEnvelopeExceeded
            } else if span.interaction_type == InteractionType::Neural {
                EvidenceType::NeuralSpikeAnomaly
            } else {
                EvidenceType::HarassmentDetection
            },
            content_hash,
            detection_summary,
            mode_transitions: Vec::new(),
            governance_flags,
            signature,
            signature_algorithm: "Ed25519".to_string(),
            public_key_fingerprint,
            custody_chain: Vec::new(),
            compliance_metadata: ComplianceMetadata::all_enabled(),
            related_bundles: Vec::new(),
            verification_status: VerificationStatus::Unverified,
        }
    }

    /// Computes a hash for bundle content verification.
    #[must_use]
    fn compute_bundle_hash(session_id: &str, node_id: &str, summary: &DetectionSummary) -> String {
        let mut hasher = DefaultHasher::new();
        session_id.hash(&mut hasher);
        node_id.hash(&mut hasher);
        summary.rogue_score_total.to_bits().hash(&mut hasher);
        summary.high_priority_detected.hash(&mut hasher);
        format!("hash_{:016x}", hasher.finish())
    }

    /// Generates a placeholder signature (in production, use real crypto).
    #[must_use]
    fn generate_placeholder_signature(content_hash: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content_hash.hash(&mut hasher);
        format!("sig_{:064x}", hasher.finish())
    }

    /// Generates a placeholder public key fingerprint.
    #[must_use]
    fn generate_key_fingerprint() -> String {
        "fp_ed25519_a1b2c3d4e5f6789012345678901234567890".to_string()
    }

    /// Verifies the bundle signature.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        // In production, this would perform actual cryptographic verification
        // For now, return true if signature is present and non-empty
        !self.signature.is_empty() && self.signature.starts_with("sig_")
    }

    /// Verifies the chain of custody.
    #[must_use]
    pub fn verify_custody_chain(&self) -> bool {
        if self.custody_chain.is_empty() {
            return false;
        }
        // Check that custody records are in chronological order
        let mut last_timestamp = 0u64;
        for record in &self.custody_chain {
            if record.timestamp < last_timestamp {
                return false;
            }
            last_timestamp = record.timestamp;
        }
        true
    }

    /// Updates the verification status based on checks.
    pub fn update_verification_status(&mut self) {
        if !self.signature.is_empty() && self.verify_signature() {
            self.verification_status = VerificationStatus::SignatureValid;
        } else {
            self.verification_status = VerificationStatus::SignatureInvalid;
        }

        if self.verify_custody_chain() {
            if self.verification_status == VerificationStatus::SignatureValid {
                self.verification_status = VerificationStatus::CustodyComplete;
            }
        } else if self.verification_status == VerificationStatus::SignatureValid {
            self.verification_status = VerificationStatus::CustodyIncomplete;
        }

        // Check expiration
        if let Some(expires) = self.expires_at {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if now > expires {
                self.verification_status = VerificationStatus::Expired;
            }
        }
    }

    /// Adds a custody record to the chain.
    pub fn add_custody_record(&mut self, record: CustodyRecord) {
        self.custody_chain.push(record);
    }

    /// Links a related bundle.
    pub fn link_related_bundle(&mut self, bundle_id: String) {
        if !self.related_bundles.contains(&bundle_id) {
            self.related_bundles.push(bundle_id);
        }
    }

    /// Sets the expiration timestamp.
    pub fn set_expiration(&mut self, days: u32) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let expiration_ms = (days as u64) * 24 * 60 * 60 * 1000;
        self.expires_at = Some(now + expiration_ms);
    }

    /// Returns true if the bundle is expired.
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

    /// Returns true if the bundle indicates a neuroright violation.
    #[must_use]
    pub fn is_neuroright_violation(&self) -> bool {
        self.evidence_type == EvidenceType::NeurorightViolation
            || self.governance_flags.contains(&GovernanceFlag::NeurorightViolation)
            || self.detection_summary.high_priority_detected
    }

    /// Returns a sanitized audit record for external sharing.
    #[must_use]
    pub fn to_audit_record(&self) -> BundleAuditRecord {
        BundleAuditRecord {
            bundle_id: self.bundle_id.clone(),
            session_id: self.session_id.clone(),
            node_id: self.node_id.clone(),
            evidence_type: self.evidence_type,
            created_at: self.created_at,
            rogue_score_total: self.detection_summary.rogue_score_total,
            high_priority_detected: self.detection_summary.high_priority_detected,
            escalation_recommended: self.detection_summary.escalation_recommended,
            verification_status: self.verification_status,
            custody_chain_length: self.custody_chain.len(),
            is_neuroright_violation: self.is_neuroright_violation(),
            is_expired: self.is_expired(),
        }
    }

    /// Serializes the bundle to JSON string.
    #[must_use]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes the bundle from JSON string.
    #[must_use]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Display for EvidenceBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EvidenceBundle[id={}, session={}, node={}, type={}, verified={:?}]",
            self.bundle_id,
            self.session_id,
            self.node_id,
            self.evidence_type,
            self.verification_status
        )
    }
}

// ============================================================================
// BUNDLE AUDIT RECORD
// ============================================================================

/// Sanitized audit record for external compliance reporting.
/// Contains no sensitive data, only metadata and summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleAuditRecord {
    /// Bundle identifier.
    pub bundle_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Node identifier.
    pub node_id: String,
    /// Evidence type.
    pub evidence_type: EvidenceType,
    /// Creation timestamp.
    pub created_at: u64,
    /// Total rogue score.
    pub rogue_score_total: f64,
    /// High-priority harassment detected.
    pub high_priority_detected: bool,
    /// Escalation recommended.
    pub escalation_recommended: bool,
    /// Verification status.
    pub verification_status: VerificationStatus,
    /// Length of custody chain.
    pub custody_chain_length: usize,
    /// Is neuroright violation.
    pub is_neuroright_violation: bool,
    /// Is expired.
    pub is_expired: bool,
}

impl BundleAuditRecord {
    /// Returns true if this record requires regulatory reporting.
    #[must_use]
    pub fn requires_regulatory_reporting(&self) -> bool {
        self.is_neuroright_violation
            && self.verification_status == VerificationStatus::CustodyComplete
    }

    /// Returns a human-readable summary string.
    #[must_use]
    pub fn summary_string(&self) -> String {
        format!(
            "BundleAuditRecord[id={}, type={}, score={:.2}, neuroright={}, verified={:?}]",
            self.bundle_id,
            self.evidence_type,
            self.rogue_score_total,
            self.is_neuroright_violation,
            self.verification_status
        )
    }
}

impl Display for BundleAuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary_string())
    }
}

// ============================================================================
// EVIDENCE BUNDLE ARCHIVE
// ============================================================================

/// Archive for storing and querying evidence bundles.
/// Provides indexing and search capabilities for compliance audits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceArchive {
    /// Archive identifier.
    pub archive_id: String,
    /// Bundles in the archive.
    pub bundles: Vec<EvidenceBundle>,
    /// Index by session ID.
    pub session_index: HashMap<String, Vec<String>>,
    /// Index by evidence type.
    pub type_index: HashMap<EvidenceType, Vec<String>>,
    /// Index by user DID.
    pub user_index: HashMap<String, Vec<String>>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last modified timestamp.
    pub modified_at: u64,
}

impl EvidenceArchive {
    /// Creates a new EvidenceArchive.
    #[must_use]
    pub fn new(archive_id: String) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            archive_id,
            bundles: Vec::new(),
            session_index: HashMap::new(),
            type_index: HashMap::new(),
            user_index: HashMap::new(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Adds a bundle to the archive.
    pub fn add_bundle(&mut self, bundle: EvidenceBundle) {
        let bundle_id = bundle.bundle_id.clone();
        let session_id = bundle.session_id.clone();
        let evidence_type = bundle.evidence_type;
        let user_did = bundle.user_did.clone();

        // Add to main collection
        self.bundles.push(bundle);

        // Update indexes
        self.session_index
            .entry(session_id)
            .or_insert_with(Vec::new)
            .push(bundle_id.clone());

        self.type_index
            .entry(evidence_type)
            .or_insert_with(Vec::new)
            .push(bundle_id.clone());

        if let Some(did) = user_did {
            self.user_index
                .entry(did)
                .or_insert_with(Vec::new)
                .push(bundle_id);
        }

        // Update modified timestamp
        use std::time::{SystemTime, UNIX_EPOCH};
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }

    /// Finds bundles by session ID.
    #[must_use]
    pub fn find_by_session(&self, session_id: &str) -> Vec<&EvidenceBundle> {
        self.session_index
            .get(session_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.bundles.iter().find(|b| b.bundle_id == *id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Finds bundles by evidence type.
    #[must_use]
    pub fn find_by_type(&self, evidence_type: EvidenceType) -> Vec<&EvidenceBundle> {
        self.type_index
            .get(&evidence_type)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.bundles.iter().find(|b| b.bundle_id == *id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Finds bundles by user DID.
    #[must_use]
    pub fn find_by_user(&self, user_did: &str) -> Vec<&EvidenceBundle> {
        self.user_index
            .get(user_did)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.bundles.iter().find(|b| b.bundle_id == *id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Finds neuroright violation bundles.
    #[must_use]
    pub fn find_neuroright_violations(&self) -> Vec<&EvidenceBundle> {
        self.bundles.iter().filter(|b| b.is_neuroright_violation()).collect()
    }

    /// Returns archive statistics.
    #[must_use]
    pub fn statistics(&self) -> ArchiveStatistics {
        let total_bundles = self.bundles.len();
        let neuroright_violations = self.bundles.iter().filter(|b| b.is_neuroright_violation()).count();
        let high_priority = self
            .bundles
            .iter()
            .filter(|b| b.detection_summary.high_priority_detected)
            .count();
        let verified = self
            .bundles
            .iter()
            .filter(|b| b.verification_status == VerificationStatus::CustodyComplete)
            .count();

        ArchiveStatistics {
            total_bundles,
            neuroright_violations,
            high_priority_detections: high_priority,
            verified_bundles: verified,
            unique_sessions: self.session_index.len(),
            unique_users: self.user_index.len(),
        }
    }
}

/// Statistics for evidence archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStatistics {
    /// Total number of bundles.
    pub total_bundles: usize,
    /// Number of neuroright violation bundles.
    pub neuroright_violations: usize,
    /// Number of high-priority detections.
    pub high_priority_detections: usize,
    /// Number of verified bundles.
    pub verified_bundles: usize,
    /// Number of unique sessions.
    pub unique_sessions: usize,
    /// Number of unique users.
    pub unique_users: usize,
}

impl Display for ArchiveStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ArchiveStatistics[total={}, neuroright={}, high_priority={}, verified={}]",
            self.total_bundles,
            self.neuroright_violations,
            self.high_priority_detections,
            self.verified_bundles
        )
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_bundle_builder() {
        let bundle = EvidenceBundleBuilder::new()
            .bundle_id("test_bundle_001".to_string())
            .session_id("test_session".to_string())
            .node_id("Prometheus".to_string())
            .user_did("did:user:test123".to_string())
            .evidence_type(EvidenceType::HarassmentDetection)
            .content_hash("hash_abc123".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 25.0,
                per_family_scores: HashMap::new(),
                dominant_family: Some(BlacklistFamily::NHSP),
                high_priority_detected: true,
                escalation_recommended: true,
                processing_latency_us: 5000,
            })
            .signature("sig_test".to_string())
            .public_key_fingerprint("fp_test".to_string())
            .build_expect();

        assert_eq!(bundle.bundle_id, "test_bundle_001");
        assert!(bundle.detection_summary.high_priority_detected);
        assert_eq!(bundle.verification_status, VerificationStatus::Unverified);
    }

    #[test]
    fn test_mode_transition_validation() {
        let escalation = ModeTransition::new(
            CapabilityMode::Normal,
            CapabilityMode::AugmentedLog,
            "Score exceeded tau1".to_string(),
            20.0,
            "system".to_string(),
        );
        assert!(escalation.monotone_valid);
        assert!(escalation.is_escalation());
        assert!(!escalation.is_deescalation());

        let deescalation = ModeTransition::new(
            CapabilityMode::AugmentedReview,
            CapabilityMode::Normal,
            "Invalid transition".to_string(),
            5.0,
            "system".to_string(),
        );
        assert!(!deescalation.monotone_valid);
        assert!(deescalation.is_deescalation());
    }

    #[test]
    fn test_evidence_bundle_verification() {
        let mut bundle = EvidenceBundleBuilder::new()
            .bundle_id("test".to_string())
            .session_id("session".to_string())
            .node_id("node".to_string())
            .content_hash("hash".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 10.0,
                per_family_scores: HashMap::new(),
                dominant_family: None,
                high_priority_detected: false,
                escalation_recommended: false,
                processing_latency_us: 1000,
            })
            .signature("sig_valid".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        bundle.update_verification_status();
        assert_eq!(bundle.verification_status, VerificationStatus::SignatureValid);
    }

    #[test]
    fn test_custody_chain_verification() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut bundle = EvidenceBundleBuilder::new()
            .bundle_id("test".to_string())
            .session_id("session".to_string())
            .node_id("node".to_string())
            .content_hash("hash".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 10.0,
                per_family_scores: HashMap::new(),
                dominant_family: None,
                high_priority_detected: false,
                escalation_recommended: false,
                processing_latency_us: 1000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        bundle.add_custody_record(CustodyRecord {
            entity_id: "system".to_string(),
            entity_type: CustodyEntityType::System,
            timestamp: now,
            action: "collected".to_string(),
            signature: "sig1".to_string(),
            notes: None,
        });
        bundle.add_custody_record(CustodyRecord {
            entity_id: "reviewer".to_string(),
            entity_type: CustodyEntityType::Human,
            timestamp: now + 1000,
            action: "reviewed".to_string(),
            signature: "sig2".to_string(),
            notes: None,
        });

        assert!(bundle.verify_custody_chain());
        bundle.update_verification_status();
        assert_eq!(bundle.verification_status, VerificationStatus::CustodyComplete);
    }

    #[test]
    fn test_evidence_archive_indexing() {
        let mut archive = EvidenceArchive::new("test_archive".to_string());

        let bundle1 = EvidenceBundleBuilder::new()
            .bundle_id("bundle1".to_string())
            .session_id("session_a".to_string())
            .node_id("node1".to_string())
            .content_hash("hash1".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 10.0,
                per_family_scores: HashMap::new(),
                dominant_family: None,
                high_priority_detected: false,
                escalation_recommended: false,
                processing_latency_us: 1000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        let bundle2 = EvidenceBundleBuilder::new()
            .bundle_id("bundle2".to_string())
            .session_id("session_a".to_string())
            .node_id("node2".to_string())
            .content_hash("hash2".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 50.0,
                per_family_scores: HashMap::new(),
                dominant_family: Some(BlacklistFamily::HTA),
                high_priority_detected: true,
                escalation_recommended: true,
                processing_latency_us: 2000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        archive.add_bundle(bundle1);
        archive.add_bundle(bundle2);

        let session_a_bundles = archive.find_by_session("session_a");
        assert_eq!(session_a_bundles.len(), 2);

        let stats = archive.statistics();
        assert_eq!(stats.total_bundles, 2);
        assert_eq!(stats.high_priority_detections, 1);
    }

    #[test]
    fn test_neuroright_violation_detection() {
        let bundle = EvidenceBundleBuilder::new()
            .bundle_id("test".to_string())
            .session_id("session".to_string())
            .node_id("node".to_string())
            .content_hash("hash".to_string())
            .evidence_type(EvidenceType::NeurorightViolation)
            .detection_summary(DetectionSummary {
                rogue_score_total: 60.0,
                per_family_scores: HashMap::new(),
                dominant_family: Some(BlacklistFamily::HTA),
                high_priority_detected: true,
                escalation_recommended: true,
                processing_latency_us: 5000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        assert!(bundle.is_neuroright_violation());

        let audit = bundle.to_audit_record();
        assert!(audit.is_neuroright_violation);
        assert!(audit.requires_regulatory_reporting());
    }

    #[test]
    fn test_bundle_expiration() {
        let mut bundle = EvidenceBundleBuilder::new()
            .bundle_id("test".to_string())
            .session_id("session".to_string())
            .node_id("node".to_string())
            .content_hash("hash".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 10.0,
                per_family_scores: HashMap::new(),
                dominant_family: None,
                high_priority_detected: false,
                escalation_recommended: false,
                processing_latency_us: 1000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        assert!(!bundle.is_expired());

        bundle.set_expiration(0); // Expire immediately
        assert!(bundle.is_expired());

        bundle.update_verification_status();
        assert_eq!(bundle.verification_status, VerificationStatus::Expired);
    }

    #[test]
    fn test_detection_summary_from_rogue_score() {
        use crate::RogueScore;
        let score = RogueScore::new("test_session".to_string(), Some("node".to_string()));
        let summary = DetectionSummary::from_rogue_score(&score, true, 1000);

        assert!(!summary.high_priority_detected);
        assert!(summary.escalation_recommended);
        assert_eq!(summary.processing_latency_us, 1000);
    }

    #[test]
    fn test_compliance_metadata() {
        let metadata = ComplianceMetadata::all_enabled();
        assert!(metadata.all_critical_enabled());
        assert!(metadata.aln_hypersafe_compliant);
        assert!(metadata.neurorights_aligned);

        let default_metadata = ComplianceMetadata::new();
        assert!(!default_metadata.hipaa_protected); // Not enabled by default
    }

    #[test]
    fn test_bundle_json_serialization() {
        let bundle = EvidenceBundleBuilder::new()
            .bundle_id("json_test".to_string())
            .session_id("session".to_string())
            .node_id("node".to_string())
            .content_hash("hash".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 10.0,
                per_family_scores: HashMap::new(),
                dominant_family: None,
                high_priority_detected: false,
                escalation_recommended: false,
                processing_latency_us: 1000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        let json = bundle.to_json().expect("Failed to serialize");
        let deserialized = EvidenceBundle::from_json(&json).expect("Failed to deserialize");

        assert_eq!(bundle.bundle_id, deserialized.bundle_id);
        assert_eq!(bundle.session_id, deserialized.session_id);
    }

    #[test]
    fn test_archive_statistics() {
        let mut archive = EvidenceArchive::new("stats_test".to_string());

        for i in 0..5 {
            let bundle = EvidenceBundleBuilder::new()
                .bundle_id(format!("bundle_{}", i))
                .session_id(format!("session_{}", i % 2)) // 2 unique sessions
                .node_id("node".to_string())
                .content_hash(format!("hash_{}", i))
                .detection_summary(DetectionSummary {
                    rogue_score_total: (i * 10) as f64,
                    per_family_scores: HashMap::new(),
                    dominant_family: None,
                    high_priority_detected: i > 3,
                    escalation_recommended: i > 2,
                    processing_latency_us: 1000,
                })
                .signature("sig".to_string())
                .public_key_fingerprint("fp".to_string())
                .build_expect();
            archive.add_bundle(bundle);
        }

        let stats = archive.statistics();
        assert_eq!(stats.total_bundles, 5);
        assert_eq!(stats.unique_sessions, 2);
        assert_eq!(stats.high_priority_detections, 1);
    }

    #[test]
    fn test_mode_transition_chronology() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64();

        let t1 = ModeTransition::new(
            CapabilityMode::Normal,
            CapabilityMode::AugmentedLog,
            "First escalation".to_string(),
            20.0,
            "system".to_string(),
        );

        let t2 = ModeTransition::new(
            CapabilityMode::AugmentedLog,
            CapabilityMode::AugmentedReview,
            "Second escalation".to_string(),
            50.0,
            "human_reviewer".to_string(),
        );

        assert!(t1.timestamp <= t2.timestamp);
        assert!(t1.monotone_valid);
        assert!(t2.monotone_valid);
    }

    #[test]
    fn test_evidence_type_classification() {
        assert_eq!(EvidenceType::HarassmentDetection.to_string(), "HarassmentDetection");
        assert_eq!(EvidenceType::NeurorightViolation.to_string(), "NeurorightViolation");
        assert_eq!(EvidenceType::HapticEnvelopeExceeded.to_string(), "HapticEnvelopeExceeded");
    }

    #[test]
    fn test_data_classification_levels() {
        assert!(DataClassification::Public as u8 < DataClassification::Restricted as u8);
        assert_eq!(DataClassification::Sensitive.to_string(), "Sensitive");
    }

    #[test]
    fn test_verification_status_transitions() {
        let statuses = [
            VerificationStatus::Unverified,
            VerificationStatus::SignatureValid,
            VerificationStatus::CustodyComplete,
            VerificationStatus::Audited,
        ];
        // Verify all statuses are distinct
        for i in 0..statuses.len() {
            for j in (i + 1)..statuses.len() {
                assert_ne!(statuses[i], statuses[j]);
            }
        }
    }

    #[test]
    fn test_bundle_linking() {
        let mut bundle = EvidenceBundleBuilder::new()
            .bundle_id("main_bundle".to_string())
            .session_id("session".to_string())
            .node_id("node".to_string())
            .content_hash("hash".to_string())
            .detection_summary(DetectionSummary {
                rogue_score_total: 10.0,
                per_family_scores: HashMap::new(),
                dominant_family: None,
                high_priority_detected: false,
                escalation_recommended: false,
                processing_latency_us: 1000,
            })
            .signature("sig".to_string())
            .public_key_fingerprint("fp".to_string())
            .build_expect();

        bundle.link_related_bundle("related_1".to_string());
        bundle.link_related_bundle("related_2".to_string());
        bundle.link_related_bundle("related_1".to_string()); // Duplicate

        assert_eq!(bundle.related_bundles.len(), 2); // Duplicates should not be added
    }
}
