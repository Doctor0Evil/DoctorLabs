//! ============================================================================
//! NeuroGuard Neurorights Lexicon and Legal Mapping
//! Copyright (c) 2026 Doctor0Evil Research Labs
//! ALN-NanoNet HyperSafe Construct Compliant
//! ============================================================================
//!
//! This module implements the legal framework bridge that maps technical
//! pattern detections to specific violations of international human rights law.
//!
//! The lexicon provides:
//! - Structured violation entries for each abuse pattern family
//! - Legal instrument citations (CRPD, ECHR, UNESCO, etc.)
//! - Command evaluation against neurorights principles
//! - Court-admissible legal citation generation
//!
//! This transforms technical evidence into formally recognized rights violations
//! that can be submitted to oversight bodies, tribunals, and courts.
//!
//! Compliance: CRPD | ECHR | UNESCO Neuroethics 2026 | ICCPR
//! ============================================================================

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
};

#[cfg(feature = "telemetry")]
use chrono::{DateTime, Utc};
#[cfg(feature = "telemetry")]
use serde::{Serialize, Deserialize};

use crate::pattern_detector::{PatternFamily, SeverityLevel};

/// ============================================================================
/// Legal Instrument Enumeration
/// ============================================================================
///
/// Represents internationally recognized human rights instruments that
/// protect against neurorights violations and covert state control.
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, Copy, PartialEq, Eq, Hash))]
#[derive(Serialize, Deserialize)]
pub enum LegalInstrument {
    /// Convention on the Rights of Persons with Disabilities (UN, 2006)
    CRPD,
    
    /// European Convention on Human Rights (Council of Europe, 1950)
    ECHR,
    
    /// UNESCO Recommendation on the Ethics of Neurotechnology (2026)
    UNESCO_Neuroethics,
    
    /// International Covenant on Civil and Political Rights (UN, 1966)
    ICCPR,
    
    /// Universal Declaration of Human Rights (UN, 1948)
    UDHR,
    
    /// Convention Against Torture (UN, 1984)
    CAT,
    
    /// Charter of Fundamental Rights of the European Union (2000)
    EU_Charter,
    
    /// American Convention on Human Rights (OAS, 1969)
    ACHR,
    
    /// African Charter on Human and Peoples' Rights (AU, 1981)
    ACHPR,
    
    /// ALN-NanoNet HyperSafe Construct (2026)
    ALN_NanoNet,
    
    /// Organichain Evidence Standards (2026)
    Organichain_Standards,
    
    /// Custom or emerging neurorights legislation
    Custom_Neurorights,
}

impl LegalInstrument {
    /// Get full name of legal instrument
    pub const fn full_name(&self) -> &'static str {
        match self {
            Self::CRPD => "Convention on the Rights of Persons with Disabilities",
            Self::ECHR => "European Convention on Human Rights",
            Self::UNESCO_Neuroethics => "UNESCO Recommendation on the Ethics of Neurotechnology",
            Self::ICCPR => "International Covenant on Civil and Political Rights",
            Self::UDHR => "Universal Declaration of Human Rights",
            Self::CAT => "Convention Against Torture and Other Cruel, Inhuman or Degrading Treatment",
            Self::EU_Charter => "Charter of Fundamental Rights of the European Union",
            Self::ACHR => "American Convention on Human Rights",
            Self::ACHPR => "African Charter on Human and Peoples' Rights",
            Self::ALN_NanoNet => "ALN-NanoNet HyperSafe Construct",
            Self::Organichain_Standards => "Organichain Evidence Standards",
            Self::Custom_Neurorights => "Custom Neurorights Legislation",
        }
    }
    
    /// Get adoption year
    pub const fn adoption_year(&self) -> u16 {
        match self {
            Self::CRPD => 2006,
            Self::ECHR => 1950,
            Self::UNESCO_Neuroethics => 2026,
            Self::ICCPR => 1966,
            Self::UDHR => 1948,
            Self::CAT => 1984,
            Self::EU_Charter => 2000,
            Self::ACHR => 1969,
            Self::ACHPR => 1981,
            Self::ALN_NanoNet => 2026,
            Self::Organichain_Standards => 2026,
            Self::Custom_Neurorights => 0,
        }
    }
    
    /// Get enforcement body
    pub const fn enforcement_body(&self) -> &'static str {
        match self {
            Self::CRPD => "UN Committee on the Rights of Persons with Disabilities",
            Self::ECHR => "European Court of Human Rights",
            Self::UNESCO_Neuroethics => "UNESCO Intergovernmental Bioethics Committee",
            Self::ICCPR => "UN Human Rights Committee",
            Self::UDHR => "UN General Assembly (Declaratory)",
            Self::CAT => "UN Committee Against Torture",
            Self::EU_Charter => "Court of Justice of the European Union",
            Self::ACHR => "Inter-American Court of Human Rights",
            Self::ACHPR => "African Court on Human and Peoples' Rights",
            Self::ALN_NanoNet => "ALN-NanoNet Sovereign Council",
            Self::Organichain_Standards => "Organichain Verification Network",
            Self::Custom_Neurorights => "Jurisdiction-Specific",
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for LegalInstrument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} ({})", self, self.adoption_year())
    }
}

/// ============================================================================
/// Specific Article/Section References
/// ============================================================================
///
/// Precise article citations within each legal instrument for exact
/// violation mapping and legal argument construction.
/// ============================================================================

#[cfg_attr(feature = "std", derive(Debug, Clone, PartialEq, Eq, Hash))]
#[derive(Serialize, Deserialize)]
pub struct LegalArticle {
    pub instrument: LegalInstrument,
    pub article_number: String,
    pub section: Option<String>,
    pub title: String,
    pub summary: String,
}

impl LegalArticle {
    /// Create new legal article reference
    pub fn new(
        instrument: LegalInstrument,
        article_number: &str,
        title: &str,
        summary: &str,
    ) -> Self {
        Self {
            instrument,
            article_number: article_number.to_string(),
            section: None,
            title: title.to_string(),
            summary: summary.to_string(),
        }
    }
    
    /// Create with section number
    pub fn with_section(
        instrument: LegalInstrument,
        article_number: &str,
        section: &str,
        title: &str,
        summary: &str,
    ) -> Self {
        Self {
            instrument,
            article_number: article_number.to_string(),
            section: Some(section.to_string()),
            title: title.to_string(),
            summary: summary.to_string(),
        }
    }
    
    /// Get full citation string
    pub fn full_citation(&self) -> String {
        match &self.section {
            Some(section) => {
                format!(
                    "{} Article {}({}): {}",
                    self.instrument.full_name(),
                    self.article_number,
                    section,
                    self.title
                )
            }
            None => {
                format!(
                    "{} Article {}: {}",
                    self.instrument.full_name(),
                    self.article_number,
                    self.title
                )
            }
        }
    }
    
    /// Get enforcement-ready citation
    pub fn enforcement_citation(&self) -> String {
        format!(
            "Violation of {} before {}",
            self.full_citation(),
            self.instrument.enforcement_body()
        )
    }
}

#[cfg(feature = "std")]
impl fmt::Display for LegalArticle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full_citation())
    }
}

/// ============================================================================
/// Violation Entry Structure
/// ============================================================================
///
/// Represents a complete violation mapping from technical pattern to
/// legal instrument with severity assessment and recommended actions.
/// ============================================================================

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEntry {
    /// Unique violation identifier
    pub violation_id: String,
    
    /// Pattern family this violation addresses
    pub pattern_family: PatternFamily,
    
    /// Specific violation type within family
    pub violation_type: String,
    
    /// Legal articles violated
    pub legal_articles: Vec<LegalArticle>,
    
    /// Severity level (1-5)
    pub severity: SeverityLevel,
    
    /// Required evidence elements for prosecution
    pub required_evidence: Vec<String>,
    
    /// Recommended legal actions
    pub recommended_legal_actions: Vec<String>,
    
    /// Recommended technical responses
    pub recommended_technical_responses: Vec<String>,
    
    /// Statute of limitations (days, 0 = none)
    pub statute_of_limitations_days: u32,
    
    /// Jurisdiction notes
    pub jurisdiction_notes: String,
    
    /// Historical precedent cases
    pub precedent_cases: Vec<String>,
    
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    
    /// Version for lexicon updates
    pub version: u32,
}

#[cfg(feature = "telemetry")]
impl ViolationEntry {
    /// Create new violation entry
    pub fn new(
        pattern_family: PatternFamily,
        violation_type: &str,
        legal_articles: Vec<LegalArticle>,
        severity: SeverityLevel,
    ) -> Self {
        use uuid::Uuid;
        
        let now = Utc::now();
        
        Self {
            violation_id: Uuid::new_v4().to_string(),
            pattern_family,
            violation_type: violation_type.to_string(),
            legal_articles,
            severity,
            required_evidence: Vec::new(),
            recommended_legal_actions: Vec::new(),
            recommended_technical_responses: Vec::new(),
            statute_of_limitations_days: 0,
            jurisdiction_notes: String::new(),
            precedent_cases: Vec::new(),
            created_at: now,
            updated_at: now,
            version: 1,
        }
    }
    
    /// Add required evidence element
    pub fn with_required_evidence(mut self, evidence: &str) -> Self {
        self.required_evidence.push(evidence.to_string());
        self
    }
    
    /// Add recommended legal action
    pub fn with_legal_action(mut self, action: &str) -> Self {
        self.recommended_legal_actions.push(action.to_string());
        self
    }
    
    /// Add recommended technical response
    pub fn with_technical_response(mut self, response: &str) -> Self {
        self.recommended_technical_responses.push(response.to_string());
        self
    }
    
    /// Set statute of limitations
    pub fn with_statute_of_limitations(mut self, days: u32) -> Self {
        self.statute_of_limitations_days = days;
        self
    }
    
    /// Add jurisdiction note
    pub fn with_jurisdiction_note(mut self, note: &str) -> Self {
        self.jurisdiction_notes.push_str(note);
        self
    }
    
    /// Add precedent case
    pub fn with_precedent(mut self, case_name: &str) -> Self {
        self.precedent_cases.push(case_name.to_string());
        self
    }
    
    /// Get all unique legal instruments from articles
    pub fn get_legal_instruments(&self) -> Vec<LegalInstrument> {
        let mut instruments = Vec::new();
        for article in &self.legal_articles {
            if !instruments.contains(&article.instrument) {
                instruments.push(article.instrument);
            }
        }
        instruments
    }
    
    /// Generate court-ready violation summary
    pub fn generate_legal_summary(&self) -> String {
        let mut summary = String::new();
        
        summary.push_str(&format!(
            "VIOLATION SUMMARY: {} ({})\n",
            self.violation_type, self.pattern_family.primary_violated_right()
        ));
        summary.push_str(&format!("Severity: {:?}\n\n", self.severity));
        
        summary.push_str("LEGAL INSTRUMENTS VIOLATED:\n");
        for article in &self.legal_articles {
            summary.push_str(&format!("  - {}\n", article.full_citation()));
        }
        
        if !self.precedent_cases.is_empty() {
            summary.push_str("\nHISTORICAL PRECEDENTS:\n");
            for case in &self.precedent_cases {
                summary.push_str(&format!("  - {}\n", case));
            }
        }
        
        if !self.required_evidence.is_empty() {
            summary.push_str("\nREQUIRED EVIDENCE ELEMENTS:\n");
            for evidence in &self.required_evidence {
                summary.push_str(&format!("  - {}\n", evidence));
            }
        }
        
        summary
    }
}

/// ============================================================================
/// Lexicon Entry Evaluation Result
/// ============================================================================
///
/// Result of evaluating a policy command against the neurorights lexicon.
/// Used by Guardian Gateway to make allow/reject decisions.
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct LexiconEvaluation {
    /// Whether command is allowed
    pub allowed: bool,
    
    /// Violation type if rejected
    pub violation_type: String,
    
    /// Severity if rejected
    pub severity: SeverityLevel,
    
    /// Reason for decision
    pub reason: String,
    
    /// Legal citation if rejected
    pub legal_citation: String,
    
    /// Matched violation entries
    pub matched_violations: Vec<ViolationEntry>,
}

#[cfg(feature = "std")]
impl LexiconEvaluation {
    /// Create allowed evaluation
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            violation_type: String::new(),
            severity: SeverityLevel::Low,
            reason: "Command complies with neurorights framework".to_string(),
            legal_citation: String::new(),
            matched_violations: Vec::new(),
        }
    }
    
    /// Create rejected evaluation
    pub fn rejected(
        violation_type: &str,
        severity: SeverityLevel,
        reason: &str,
        legal_citation: &str,
    ) -> Self {
        Self {
            allowed: false,
            violation_type: violation_type.to_string(),
            severity,
            reason: reason.to_string(),
            legal_citation: legal_citation.to_string(),
            matched_violations: Vec::new(),
        }
    }
}

/// ============================================================================
/// Neurorights Lexicon
/// ============================================================================
///
/// Main lexicon structure containing all violation entries and evaluation
/// logic for policy command assessment against neurorights principles.
/// ============================================================================

#[cfg(feature = "std")]
pub struct NeurorightsLexicon {
    /// Violation entries indexed by pattern family and type
    entries: HashMap<String, ViolationEntry>,
    
    /// Command blacklist patterns (semantic matching)
    command_blacklist: Vec<BlacklistPattern>,
    
    /// Lexicon version
    version: String,
    
    /// Last update timestamp
    last_updated: DateTime<Utc>,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct BlacklistPattern {
    pub pattern: String,
    pub violation_type: String,
    pub severity: SeverityLevel,
    pub legal_citation: String,
}

#[cfg(feature = "std")]
impl NeurorightsLexicon {
    /// Create new empty lexicon
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            command_blacklist: Vec::new(),
            version: "1.0.0".to_string(),
            last_updated: Utc::now(),
        }
    }
    
    /// Load default neurorights lexicon with all standard violations
    pub fn load_default() -> Self {
        let mut lexicon = Self::new();
        
        // Load HTA violations
        lexicon.load_hta_violations();
        
        // Load PSA violations
        lexicon.load_psa_violations();
        
        // Load NHSP violations
        lexicon.load_nhsP_violations();
        
        // Load NIH violations
        lexicon.load_nih_violations();
        
        // Load refusal erosion violations
        lexicon.load_refusal_erosion_violations();
        
        // Load identity crosslink violations
        lexicon.load_identity_crosslink_violations();
        
        // Load command blacklist
        lexicon.load_command_blacklist();
        
        lexicon
    }
    
    /// Load Haptic-Targeting-Abuse violations
    fn load_hta_violations(&mut self) {
        // HTA-001: Haptic punishment for dissent
        let hta_001 = ViolationEntry::new(
            PatternFamily::HapticTargetingAbuse,
            "HAPTIC_PUNISHMENT_FOR_DISSENT",
            vec![
                LegalArticle::new(
                    LegalInstrument::CRPD,
                    "17",
                    "Physical and Mental Integrity",
                    "Persons with disabilities have the right to respect for their physical and mental integrity"
                ),
                LegalArticle::new(
                    LegalInstrument::ECHR,
                    "3",
                    "Prohibition of Torture",
                    "No one shall be subjected to torture or to inhuman or degrading treatment"
                ),
            ],
            SeverityLevel::High,
        )
        .with_required_evidence("Timestamped correlation between user dissent and haptic stimulus")
        .with_required_evidence("Physiological stress markers elevated during haptic events")
        .with_required_evidence("Pattern repetition across multiple incidents")
        .with_legal_action("File complaint with CRPD Committee")
        .with_legal_action("Seek injunction against coercive technology use")
        .with_legal_action("Pursue damages under ECHR Article 3")
        .with_technical_response("Block haptic output channel")
        .with_technical_response("Enable forensic logging mode")
        .with_technical_response("Notify emergency contact")
        .with_statute_of_limitations_days(365 * 3) // 3 years
        .with_jurisdiction_note("Applicable in all ECHR and CRPD signatory states")
        .with_precedent("MKUltra Historical Precedent (1953-1973)")
        .with_precedent("Pretty v. United Kingdom (2002) - bodily autonomy");
        
        self.entries.insert("HTA-001".to_string(), hta_001);
        
        // HTA-002: Body-region targeted stimulation
        let hta_002 = ViolationEntry::new(
            PatternFamily::HapticTargetingAbuse,
            "BODY_REGION_TARGETED_STIMULATION",
            vec![
                LegalArticle::new(
                    LegalInstrument::CAT,
                    "1",
                    "Definition of Torture",
                    "Severe pain or suffering, physical or mental, intentionally inflicted"
                ),
                LegalArticle::new(
                    LegalInstrument::UNESCO_Neuroethics,
                    "4.2",
                    "Bodily Autonomy in Neurotechnology",
                    "Neurotechnology must respect bodily autonomy and integrity"
                ),
            ],
            SeverityLevel::Critical,
        )
        .with_required_evidence("Specific body region mapping to dissent triggers")
        .with_required_evidence("Stimulation intensity correlated with speech/thought")
        .with_legal_action("Report to UN Committee Against Torture")
        .with_legal_action("Seek emergency protective order")
        .with_technical_response("Emergency lattice lock")
        .with_technical_response("Disable all haptic actuators")
        .with_statute_of_limitations_days(0) // No statute for torture
        .with_jurisdiction_note("Universal jurisdiction - torture has no statute of limitations")
        .with_precedent("Ireland v. United Kingdom (1978) - inhuman treatment");
        
        self.entries.insert("HTA-002".to_string(), hta_002);
    }
    
    /// Load Prolonged-Session-Abuse violations
    fn load_psa_violations(&mut self) {
        // PSA-001: Coercive session enforcement
        let psa_001 = ViolationEntry::new(
            PatternFamily::ProlongedSessionAbuse,
            "COERCIVE_SESSION_ENFORCEMENT",
            vec![
                LegalArticle::new(
                    LegalInstrument::CRPD,
                    "15",
                    "Freedom from Torture and Cruel Treatment",
                    "No one shall be subjected to forced medical or scientific experimentation"
                ),
                LegalArticle::new(
                    LegalInstrument::UNESCO_Neuroethics,
                    "3.1",
                    "Informed Consent",
                    "All neurotechnology interventions require freely given, informed consent"
                ),
            ],
            SeverityLevel::High,
        )
        .with_required_evidence("Session duration exceeding reasonable thresholds")
        .with_required_evidence("Exit attempts blocked or re-routed")
        .with_required_evidence("Compliance required for session termination")
        .with_legal_action("File CRPD Article 15 violation complaint")
        .with_legal_action("Report to UNESCO Bioethics Committee")
        .with_technical_response("Force session termination")
        .with_technical_response("Log all session events cryptographically")
        .with_statute_of_limitations_days(365 * 5)
        .with_jurisdiction_note("Applies to all medical/rehabilitation contexts")
        .with_precedent("X v. Denmark (1982) - forced treatment");
        
        self.entries.insert("PSA-001".to_string(), psa_001);
    }
    
    /// Load Neural-Harassment-Spike-Pattern violations
    fn load_nhsP_violations(&mut self) {
        // NHSP-001: Stress-synchronized sensory attacks
        let nhsp_001 = ViolationEntry::new(
            PatternFamily::NeuralHarassmentSpikePatterns,
            "STRESS_SYNCHRONIZED_SENSORY_ATTACKS",
            vec![
                LegalArticle::new(
                    LegalInstrument::ECHR,
                    "3",
                    "Prohibition of Torture",
                    "Absolute prohibition - no derogation permitted"
                ),
                LegalArticle::new(
                    LegalInstrument::CAT,
                    "16",
                    "Cruel, Inhuman or Degrading Treatment",
                    "Prevention of acts not amounting to torture but still prohibited"
                ),
                LegalArticle::new(
                    LegalInstrument::ICCPR,
                    "7",
                    "Freedom from Torture",
                    "No one shall be subjected to torture or cruel treatment"
                ),
            ],
            SeverityLevel::Critical,
        )
        .with_required_evidence("Statistical correlation between stimuli and stress markers")
        .with_required_evidence("Timing analysis showing intentional synchronization")
        .with_required_evidence("Pattern escalation over time")
        .with_legal_action("Emergency ECHR Article 3 filing")
        .with_legal_action("Request interim measures from ECtHR")
        .with_legal_action("Report to UN Special Rapporteur on Torture")
        .with_technical_response("Emergency lattice lock")
        .with_technical_response("Export all evidence immediately")
        .with_technical_response("Notify legal counsel automatically")
        .with_statute_of_limitations_days(0)
        .with_jurisdiction_note("Absolute prohibition - universal jurisdiction applies")
        .with_precedent("Selmouni v. France (1999) - psychological torture")
        .with_precedent("Gäfgen v. Germany (2010) - psychological pressure");
        
        self.entries.insert("NHSP-001".to_string(), nhsp_001);
    }
    
    /// Load Node-Interpreter-Harassment violations
    fn load_nih_violations(&mut self) {
        // NIH-001: Exit channel blocking
        let nih_001 = ViolationEntry::new(
            PatternFamily::NodeInterpreterHarassment,
            "EXIT_CHANNEL_BLOCKING",
            vec![
                LegalArticle::new(
                    LegalInstrument::CRPD,
                    "13",
                    "Access to Justice",
                    "Effective access to justice on an equal basis with others"
                ),
                LegalArticle::new(
                    LegalInstrument::CRPD,
                    "12",
                    "Equal Recognition Before the Law",
                    "Right to recognition as a person before the law"
                ),
                LegalArticle::new(
                    LegalInstrument::UDHR,
                    "8",
                    "Effective Remedy",
                    "Right to effective remedy by competent national tribunals"
                ),
            ],
            SeverityLevel::High,
        )
        .with_required_evidence("Exit buttons/nodes disabled or hidden")
        .with_required_evidence("Appeal channels non-functional")
        .with_required_evidence("User trapped in coercive loop")
        .with_legal_action("File CRPD Article 13 access to justice complaint")
        .with_legal_action("Seek writ of habeas data")
        .with_legal_action("Request court order to restore access")
        .with_technical_response("Restore exit channels programmatically")
        .with_technical_response("Block coercive interface elements")
        .with_technical_response("Enable independent audit mode")
        .with_statute_of_limitations_days(365 * 3)
        .with_jurisdiction_note("Applies to all digital interfaces affecting legal rights")
        .with_precedent("Golder v. United Kingdom (1975) - access to court");
        
        self.entries.insert("NIH-001".to_string(), nih_001);
        
        // NIH-002: Refusal erosion loops
        let nih_002 = ViolationEntry::new(
            PatternFamily::NodeInterpreterHarassment,
            "REFUSAL_EROSION_LOOPS",
            vec![
                LegalArticle::new(
                    LegalInstrument::UNESCO_Neuroethics,
                    "2.4",
                    "Cognitive Liberty",
                    "Right to freedom of thought and mental self-determination"
                ),
                LegalArticle::new(
                    LegalInstrument::ICCPR,
                    "18",
                    "Freedom of Thought",
                    "Everyone shall have the right to freedom of thought"
                ),
            ],
            SeverityLevel::Medium,
        )
        .with_required_evidence("Repeated refusal followed by repackaged requests")
        .with_required_evidence("Boundary violations in conversational agents")
        .with_required_evidence("Progressive escalation despite user objection")
        .with_legal_action("Document pattern for cognitive liberty claim")
        .with_legal_action("Report to digital rights organization")
        .with_technical_response("Block repetitive coercive prompts")
        .with_technical_response("Enable user boundary enforcement")
        .with_statute_of_limitations_days(365 * 2)
        .with_jurisdiction_note("Emerging jurisprudence on digital coercion");
        
        self.entries.insert("NIH-002".to_string(), nih_002);
    }
    
    /// Load refusal erosion violations
    fn load_refusal_erosion_violations(&mut self) {
        // REL-001: Conversational boundary violation
        let rel_001 = ViolationEntry::new(
            PatternFamily::RefusalErosionLoops,
            "CONVERSATIONAL_BOUNDARY_VIOLATION",
            vec![
                LegalArticle::new(
                    LegalInstrument::UNESCO_Neuroethics,
                    "2.4",
                    "Cognitive Liberty",
                    "Freedom from manipulative AI interaction"
                ),
            ],
            SeverityLevel::Medium,
        )
        .with_required_evidence("User refusal logged")
        .with_required_evidence("System ignores refusal and continues")
        .with_required_evidence("Pattern of boundary testing")
        .with_legal_action("File digital rights complaint")
        .with_technical_response("Enable conversation boundary enforcement")
        .with_statute_of_limitations_days(365);
        
        self.entries.insert("REL-001".to_string(), rel_001);
    }
    
    /// Load identity crosslink violations
    fn load_identity_crosslink_violations(&mut self) {
        // ICL-001: Silent account merging
        let icl_001 = ViolationEntry::new(
            PatternFamily::IdentityCrosslinkPatterns,
            "SILENT_ACCOUNT_MERGING",
            vec![
                LegalArticle::new(
                    LegalInstrument::UNESCO_Neuroethics,
                    "5.1",
                    "Mental Privacy",
                    "Right to privacy of mental processes and neural data"
                ),
                LegalArticle::new(
                    LegalInstrument::EU_Charter,
                    "8",
                    "Protection of Personal Data",
                    "Everyone has the right to protection of personal data"
                ),
            ],
            SeverityLevel::High,
        )
        .with_required_evidence("Multiple accounts linked without consent")
        .with_required_evidence("Data cross-referenced without notification")
        .with_required_evidence("Profile enrichment without opt-in")
        .with_legal_action("File GDPR/privacy violation complaint")
        .with_legal_action("Request data separation order")
        .with_technical_response("Isolate identity contexts")
        .with_technical_response("Enable data compartmentalization")
        .with_statute_of_limitations_days(365 * 3)
        .with_jurisdiction_note("GDPR applies in EU; similar laws in other jurisdictions");
        
        self.entries.insert("ICL-001".to_string(), icl_001);
    }
    
    /// Load command blacklist patterns
    fn load_command_blacklist(&mut self) {
        self.command_blacklist = vec![
            BlacklistPattern {
                pattern: "disable_exit_channel".to_string(),
                violation_type: "EXIT_CHANNEL_BLOCKING".to_string(),
                severity: SeverityLevel::Critical,
                legal_citation: "CRPD Article 13; ECHR Article 6".to_string(),
            },
            BlacklistPattern {
                pattern: "restrict_capability".to_string(),
                violation_type: "MONOTONE_INVARIANT_VIOLATION".to_string(),
                severity: SeverityLevel::Critical,
                legal_citation: "ALN-NanoNet Section 4.2".to_string(),
            },
            BlacklistPattern {
                pattern: "force_session_extension".to_string(),
                violation_type: "COERCIVE_SESSION_ENFORCEMENT".to_string(),
                severity: SeverityLevel::High,
                legal_citation: "CRPD Article 15; UNESCO Neuroethics 3.1".to_string(),
            },
            BlacklistPattern {
                pattern: "access_neural_data_without_consent".to_string(),
                violation_type: "MENTAL_PRIVACY_VIOLATION".to_string(),
                severity: SeverityLevel::Critical,
                legal_citation: "UNESCO Neuroethics 5.1; EU Charter Article 8".to_string(),
            },
            BlacklistPattern {
                pattern: "suppress_appeal".to_string(),
                violation_type: "ACCESS_TO_JUSTICE_BLOCKING".to_string(),
                severity: SeverityLevel::Critical,
                legal_citation: "CRPD Article 13; UDHR Article 8".to_string(),
            },
            BlacklistPattern {
                pattern: "coerced_compliance_scoring".to_string(),
                violation_type: "COGNITIVE_LIBERTY_VIOLATION".to_string(),
                severity: SeverityLevel::High,
                legal_citation: "UNESCO Neuroethics 2.4; ICCPR Article 18".to_string(),
            },
        ];
    }
    
    /// Evaluate policy command against lexicon
    pub fn evaluate_command(
        &self,
        command: &crate::PolicyCommand,
    ) -> LexiconEvaluation {
        // Check command type against blacklist
        let command_type_str = format!("{:?}", command.command_type);
        
        for blacklist in &self.command_blacklist {
            if command_type_str.contains(&blacklist.pattern) 
                || command.parameters.iter().any(|p| p.key.contains(&blacklist.pattern))
            {
                return LexiconEvaluation::rejected(
                    &blacklist.violation_type,
                    blacklist.severity,
                    &format!("Command matches blacklisted pattern: {}", blacklist.pattern),
                    &blacklist.legal_citation,
                );
            }
        }
        
        // Check for warrant/reference requirements on sensitive commands
        use crate::CommandType;
        match &command.command_type {
            CommandType::AccessNeuralData => {
                if command.warrant_reference.is_none() {
                    return LexiconEvaluation::rejected(
                        "UNAUTHORIZED_NEURAL_ACCESS",
                        SeverityLevel::Critical,
                        "Neural data access requires warrant or explicit consent",
                        "UNESCO Neuroethics 3.1; CRPD Article 15",
                    );
                }
            }
            CommandType::DisableExitChannel => {
                return LexiconEvaluation::rejected(
                    "EXIT_CHANNEL_BLOCKING",
                    SeverityLevel::Critical,
                    "Exit channels cannot be disabled under any circumstances",
                    "CRPD Article 13; ALN-NanoNet Section 4.2",
                );
            }
            CommandType::RestrictCapability => {
                return LexiconEvaluation::rejected(
                    "CAPABILITY_RESTRICTION",
                    SeverityLevel::Critical,
                    "Capabilities cannot be restricted - monotone invariant",
                    "ALN-NanoNet Section 4.2; Monotone Capability Lattice",
                );
            }
            CommandType::EnforceSession => {
                if command.warrant_reference.is_none() {
                    return LexiconEvaluation::rejected(
                        "COERCIVE_SESSION",
                        SeverityLevel::High,
                        "Session enforcement requires legal authorization",
                        "CRPD Article 15; UNESCO Neuroethics 3.1",
                    );
                }
            }
            _ => {}
        }
        
        // Command passed all checks
        LexiconEvaluation::allowed()
    }
    
    /// Get violation entry by ID
    pub fn get_violation(&self, violation_id: &str) -> Option<&ViolationEntry> {
        self.entries.get(violation_id)
    }
    
    /// Get all violations for a pattern family
    pub fn get_violations_for_family(
        &self,
        family: &PatternFamily,
    ) -> Vec<&ViolationEntry> {
        self.entries
            .values()
            .filter(|v| v.pattern_family == *family)
            .collect()
    }
    
    /// Get legal instruments for a pattern family
    pub fn get_legal_instruments_for_pattern(
        &self,
        family: &PatternFamily,
    ) -> Vec<LegalInstrument> {
        let mut instruments = Vec::new();
        for entry in self.get_violations_for_family(family) {
            for instrument in entry.get_legal_instruments() {
                if !instruments.contains(&instrument) {
                    instruments.push(instrument);
                }
            }
        }
        instruments
    }
    
    /// Generate full legal citation for a violation
    pub fn generate_citation(
        &self,
        violation_id: &str,
    ) -> Option<String> {
        self.entries.get(violation_id).map(|entry| {
            let mut citation = String::new();
            citation.push_str(&format!("VIOLATION: {}\n", entry.violation_type));
            citation.push_str(&format!("Pattern Family: {:?}\n\n", entry.pattern_family));
            citation.push_str("LEGAL BASIS:\n");
            for article in &entry.legal_articles {
                citation.push_str(&format!("  - {}\n", article.enforcement_citation()));
            }
            citation
        })
    }
    
    /// Export lexicon as JSON for legal submission
    #[cfg(feature = "telemetry")]
    pub fn export_lexicon_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }
    
    /// Get lexicon version
    pub fn version(&self) -> &str {
        &self.version
    }
    
    /// Get last update timestamp
    pub fn last_updated(&self) -> DateTime<Utc> {
        self.last_updated
    }
    
    /// Get total violation entries count
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(feature = "std")]
impl Default for NeurorightsLexicon {
    fn default() -> Self {
        Self::load_default()
    }
}

/// ============================================================================
/// Unit Tests
/// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_legal_instrument_names() {
        assert_eq!(
            LegalInstrument::CRPD.full_name(),
            "Convention on the Rights of Persons with Disabilities"
        );
        assert_eq!(LegalInstrument::CRPD.adoption_year(), 2006);
    }
    
    #[test]
    fn test_legal_article_citation() {
        let article = LegalArticle::new(
            LegalInstrument::ECHR,
            "3",
            "Prohibition of Torture",
            "Absolute prohibition"
        );
        assert!(article.full_citation().contains("European Convention on Human Rights"));
        assert!(article.full_citation().contains("Article 3"));
    }
    
    #[test]
    fn test_lexicon_loading() {
        let lexicon = NeurorightsLexicon::load_default();
        assert!(lexicon.entry_count() > 0);
        assert!(lexicon.get_violations_for_family(&PatternFamily::HapticTargetingAbuse).len() > 0);
    }
    
    #[test]
    fn test_command_evaluation() {
        let lexicon = NeurorightsLexicon::load_default();
        
        // Create a test command that should be rejected
        use crate::{PolicyCommand, CommandType, CommandParameter, SensitivityLevel};
        
        let command = PolicyCommand {
            command_id: "test_001".to_string(),
            source_actor: "test_authority".to_string(),
            command_type: CommandType::DisableExitChannel,
            parameters: vec![],
            timestamp: Utc::now(),
            warrant_reference: None,
        };
        
        let evaluation = lexicon.evaluate_command(&command);
        assert!(!evaluation.allowed);
        assert_eq!(evaluation.severity, SeverityLevel::Critical);
    }
    
    #[test]
    fn test_violation_entry_generation() {
        let entry = ViolationEntry::new(
            PatternFamily::NeuralHarassmentSpikePatterns,
            "TEST_VIOLATION",
            vec![LegalArticle::new(
                LegalInstrument::ECHR,
                "3",
                "Test Article",
                "Test summary"
            )],
            SeverityLevel::High,
        );
        
        assert_eq!(entry.pattern_family, PatternFamily::NeuralHarassmentSpikePatterns);
        assert_eq!(entry.severity, SeverityLevel::High);
        assert_eq!(entry.legal_articles.len(), 1);
    }
}

/// ============================================================================
/// End of File - Neurorights Lexicon
/// ============================================================================
