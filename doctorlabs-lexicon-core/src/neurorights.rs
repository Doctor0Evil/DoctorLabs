// ============================================================================
// DoctorLabs Lexicon - Neuroright Enumerations and Legal Basis Citations
// ============================================================================
// Copyright © 2026 DoctorLabs Working Group
// License: ALN-NanoNet HyperSafe Construct (Non-Commercial Research Use)
//
// This module defines the normative anchor layer for the lexicon:
//   - Neuroright enumerations (Mental Integrity, Privacy, Cognitive Liberty).
//   - Legal Instrument identifiers (ECHR, CRPD, UNESCO, EU AI Act, Chilean Law).
//   - Legal Basis structures (Instrument + Article + Notes).
//
// Every LexiconTerm must cite at least one Neuroright and one Legal Basis,
// ensuring that technical detection patterns are legally legible in court,
// policy, and regulatory contexts without translation loss.
//
// Architecture Alignment:
//   - Doctor-Labs Superfilter DSL (YAML/ALN rule syntax)
//   - LexiconTerm structure (File 2: lexicon.rs)
//   - Evidence Bundle generation (File 6: audit.rs)
//   - Neurorights invariants (Mental Integrity, Privacy, Cognitive Liberty)
//
// Citation: Doctor-Labs Blacklisting Superfilter Specification v2.1 (2026)
// ============================================================================

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![cfg_attr(not(test), warn(missing_docs))]

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ============================================================================
// Neuroright Enumerations
// ============================================================================

/// Core neurorights protected by the lexicon framework.
/// 
/// These rights are derived from international human rights law, 
/// neurotechnology ethics proposals (e.g., Chilean Neurorights), 
/// and the Doctor-Labs Monotone Capability Lattice.
/// 
/// Serialization Note: Uses SCREAMING_SNAKE_CASE to match YAML/DSL specifications
/// and legal document conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Neuroright {
    /// Right to mental integrity: Protection from non-consensual alteration 
    /// of thoughts, emotions, or consciousness.
    MentalIntegrity,
    
    /// Right to mental privacy: Confidentiality of brain activity and neural data.
    MentalPrivacy,
    
    /// Right to cognitive liberty: Freedom from coercive interference with thought processes.
    CognitiveLiberty,
    
    /// Right to free will: Protection against manipulation of decision-making autonomy.
    FreeWill,
    
    /// Right to personal identity: Protection against unauthorized identity cross-linking 
    /// or profiling via neural/behavioral data.
    PersonalIdentity,
    
    /// Right to freedom of thought: Absolute internal dimension (forum internum) 
    /// guarding the inner world of thought and emotion.
    FreedomOfThought,
    
    /// Right to psychological continuity: Protection against fragmentation of self 
    /// via disruptive neural stimulation.
    PsychologicalContinuity,
    
    /// Right to equal recognition: Protection against algorithmic discrimination 
    /// in therapeutic or forensic triage.
    EqualRecognition,
}

impl Neuroright {
    /// Returns a human-readable description of the right
    pub const fn description(&self) -> &'static str {
        match self {
            Self::MentalIntegrity => "Protection from non-consensual alteration of mental states",
            Self::MentalPrivacy => "Confidentiality of brain activity and neural data",
            Self::CognitiveLiberty => "Freedom from coercive interference with thought processes",
            Self::FreeWill => "Protection against manipulation of decision-making autonomy",
            Self::PersonalIdentity => "Protection against unauthorized identity cross-linking",
            Self::FreedomOfThought => "Absolute internal dimension guarding inner thought",
            Self::PsychologicalContinuity => "Protection against fragmentation of self",
            Self::EqualRecognition => "Protection against algorithmic discrimination",
        }
    }
    
    /// Returns all neurorights as a slice
    pub const fn all() -> &'static [Self] {
        &[
            Self::MentalIntegrity,
            Self::MentalPrivacy,
            Self::CognitiveLiberty,
            Self::FreeWill,
            Self::PersonalIdentity,
            Self::FreedomOfThought,
            Self::PsychologicalContinuity,
            Self::EqualRecognition,
        ]
    }
}

impl fmt::Display for Neuroright {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serialize as SCREAMING_SNAKE_CASE for display consistency
        write!(f, "{:?}", self)
    }
}

// ============================================================================
// Legal Instrument Enumerations
// ============================================================================

/// Recognized international and regional legal instruments.
/// 
/// These instruments provide the doctrinal backbone for neurorights claims 
/// in the lexicon. Each instrument has specific articles relevant to 
/// haptic/XR abuse contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegalInstrument {
    /// European Convention on Human Rights (ECHR)
    ECHR,
    
    /// UN Convention on the Rights of Persons with Disabilities (CRPD)
    UN_CRPD,
    
    /// UNESCO Recommendation on the Ethics of Artificial Intelligence (2021)
    UNESCO_AI_Ethics_2021,
    
    /// European Union Artificial Intelligence Act (Regulation 2024/1689)
    EU_AI_Act,
    
    /// Chilean Supreme Court Ruling on Mental Privacy (2023)
    Chile_Supreme_Court_2023_Mental_Privacy,
    
    /// Chilean Neurorights Amendment (Constitutional Proposal)
    Chile_Neurorights_Amendment,
    
    /// General Data Protection Regulation (GDPR)
    GDPR,
    
    /// OECD Principles on Artificial Intelligence
    OECD_AI_Principles,
    
    /// Universal Declaration of Human Rights (UDHR)
    UDHR,
    
    /// Latin American Parliament Model Law on NeuroRights
    Latin_American_Parliament_NeuroRights,
    
    /// Doctor-Labs ALN-NanoNet HyperSafe Construct (Internal Governance)
    ALN_NanoNet_Safe_Construct,
    
    /// DID Privacy Guidelines (Decentralized Identity)
    DID_Privacy_Guidelines,
    
    /// Identity Host List Specification (Internal Governance)
    Identity_Host_List_Spec,
    
    /// Brain Data Governance Proposal (Emerging Standard)
    Brain_Data_Governance,
    
    /// Research on XR Grid Tapping (Academic/Technical Reference)
    Research_XR_Grid_Tapping,
}

impl LegalInstrument {
    /// Returns a human-readable name for the instrument
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ECHR => "European Convention on Human Rights",
            Self::UN_CRPD => "UN Convention on the Rights of Persons with Disabilities",
            Self::UNESCO_AI_Ethics_2021 => "UNESCO AI Ethics Recommendation (2021)",
            Self::EU_AI_Act => "EU Artificial Intelligence Act (2024/1689)",
            Self::Chile_Supreme_Court_2023_Mental_Privacy => "Chilean Supreme Court Ruling (2023)",
            Self::Chile_Neurorights_Amendment => "Chilean Neurorights Constitutional Amendment",
            Self::GDPR => "General Data Protection Regulation",
            Self::OECD_AI_Principles => "OECD AI Principles",
            Self::UDHR => "Universal Declaration of Human Rights",
            Self::Latin_American_Parliament_NeuroRights => "Latin American Parliament Model Law on NeuroRights",
            Self::ALN_NanoNet_Safe_Construct => "ALN-NanoNet HyperSafe Construct",
            Self::DID_Privacy_Guidelines => "DID Privacy Guidelines",
            Self::Identity_Host_List_Spec => "Identity Host List Specification",
            Self::Brain_Data_Governance => "Brain Data Governance Proposal",
            Self::Research_XR_Grid_Tapping => "Research on XR Grid Tapping",
        }
    }
    
    /// Returns a URL or reference link (placeholder for production)
    pub const fn reference_url(&self) -> Option<&'static str> {
        match self {
            Self::ECHR => Some("https://www.echr.coe.int/"),
            Self::UN_CRPD => Some("https://www.un.org/development/desa/disabilities/convention-on-the-rights-of-persons-with-disabilities.html"),
            Self::UNESCO_AI_Ethics_2021 => Some("https://unesdoc.unesco.org/ark:/48223/pf0000381137"),
            Self::EU_AI_Act => Some("https://artificialintelligenceact.eu/"),
            Self::Chile_Supreme_Court_2023_Mental_Privacy => None, // Specific case reference
            Self::Chile_Neurorights_Amendment => None, // Legislative reference
            Self::GDPR => Some("https://gdpr.eu/"),
            Self::OECD_AI_Principles => Some("https://oecd.ai/en/dashboards/ai-principles"),
            Self::UDHR => Some("https://www.un.org/en/universal-declaration-human-rights/"),
            _ => None,
        }
    }
}

impl fmt::Display for LegalInstrument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Legal Basis Structure
// ============================================================================

/// A specific citation within a legal instrument.
/// 
/// This struct allows lexicon terms to anchor technical patterns 
/// to specific articles, recitals, or legal notes, enabling 
/// precise legal argumentation in evidence bundles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LegalBasis {
    /// The legal instrument (e.g., ECHR, CRPD)
    pub instrument: LegalInstrument,
    
    /// The specific article, recital, or section (e.g., "Art. 3", "Recital 26")
    pub article: String,
    
    /// Optional explanatory note (e.g., "Protection against non-consensual mental-state interference")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LegalBasis {
    /// Creates a new legal basis citation
    pub fn new(instrument: LegalInstrument, article: &str, note: Option<&str>) -> Self {
        Self {
            instrument,
            article: article.to_string(),
            note: note.map(String::from),
        }
    }
    
    /// Returns a formatted citation string (e.g., "ECHR Art. 3")
    pub fn citation_string(&self) -> String {
        match &self.note {
            Some(note) => format!("{} {} ({})", self.instrument, self.article, note),
            None => format!("{} {}", self.instrument, self.article),
        }
    }
    
    /// Validates the legal basis structure
    pub fn validate(&self) -> Result<(), NeurorightsError> {
        if self.article.is_empty() {
            return Err(NeurorightsError::EmptyArticle {
                instrument: self.instrument,
            });
        }
        
        // Basic sanity check: article should not be excessively long
        if self.article.len() > 256 {
            return Err(NeurorightsError::ArticleTooLong {
                instrument: self.instrument,
                length: self.article.len(),
            });
        }
        
        Ok(())
    }
}

impl fmt::Display for LegalBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.citation_string())
    }
}

// ============================================================================
// Neurorights Errors
// ============================================================================

/// Errors specific to neurorights and legal basis validation
#[derive(Error, Debug)]
pub enum NeurorightsError {
    #[error("Legal basis article is empty for instrument {instrument:?}")]
    EmptyArticle { instrument: LegalInstrument },
    
    #[error("Legal basis article too long ({length} chars) for instrument {instrument:?}")]
    ArticleTooLong {
        instrument: LegalInstrument,
        length: usize,
    },
    
    #[error("Invalid neuroright mapping: {0}")]
    InvalidMapping(String),
    
    #[error("Legal instrument not recognized: {0}")]
    UnknownInstrument(String),
}

// ============================================================================
// Neurorights Validator (Utility)
// ============================================================================

/// Utility for validating neurorights and legal basis combinations
pub struct NeurorightsValidator;

impl NeurorightsValidator {
    /// Validates a list of neurorights and legal bases for a lexicon term
    pub fn validate_term_anchors(
        neurorights: &[Neuroright],
        legal_bases: &[LegalBasis],
    ) -> Result<(), NeurorightsError> {
        // Must have at least one neuroright
        if neurorights.is_empty() {
            return Err(NeurorightsError::InvalidMapping(
                "At least one neuroright must be specified".to_string(),
            ));
        }
        
        // Must have at least one legal basis
        if legal_bases.is_empty() {
            return Err(NeurorightsError::InvalidMapping(
                "At least one legal basis must be specified".to_string(),
            ));
        }
        
        // Validate each legal basis
        for basis in legal_bases {
            basis.validate()?;
        }
        
        // Check for coherent mappings (e.g., MentalPrivacy should typically cite GDPR or Chilean Law)
        // This is a soft check; we log warnings rather than hard failures for flexibility
        for right in neurorights {
            match right {
                Neuroright::MentalPrivacy => {
                    // Should ideally have GDPR, Chilean, or UNESCO citation
                    let has_privacy_instrument = legal_bases.iter().any(|b| {
                        matches!(
                            b.instrument,
                            LegalInstrument::GDPR
                                | LegalInstrument::Chile_Supreme_Court_2023_Mental_Privacy
                                | LegalInstrument::Chile_Neurorights_Amendment
                                | LegalInstrument::UNESCO_AI_Ethics_2021
                        )
                    });
                    if !has_privacy_instrument {
                        // Log warning in production; for now we allow it
                        // eprintln!("Warning: MentalPrivacy right lacks specific privacy instrument citation");
                    }
                }
                Neuroright::MentalIntegrity => {
                    // Should ideally have ECHR, CRPD, or UNESCO citation
                    let has_integrity_instrument = legal_bases.iter().any(|b| {
                        matches!(
                            b.instrument,
                            LegalInstrument::ECHR
                                | LegalInstrument::UN_CRPD
                                | LegalInstrument::UNESCO_AI_Ethics_2021
                        )
                    });
                    if !has_integrity_instrument {
                        // Log warning
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Returns recommended legal bases for a given neuroright
    pub fn recommended_instruments(right: Neuroright) -> &'static [LegalInstrument] {
        match right {
            Neuroright::MentalIntegrity => &[
                LegalInstrument::ECHR,
                LegalInstrument::UN_CRPD,
                LegalInstrument::UNESCO_AI_Ethics_2021,
            ],
            Neuroright::MentalPrivacy => &[
                LegalInstrument::GDPR,
                LegalInstrument::Chile_Supreme_Court_2023_Mental_Privacy,
                LegalInstrument::UNESCO_AI_Ethics_2021,
            ],
            Neuroright::CognitiveLiberty => &[
                LegalInstrument::ECHR,
                LegalInstrument::UDHR,
                LegalInstrument::Latin_American_Parliament_NeuroRights,
            ],
            Neuroright::FreeWill => &[
                LegalInstrument::UNESCO_AI_Ethics_2021,
                LegalInstrument::EU_AI_Act,
            ],
            Neuroright::PersonalIdentity => &[
                LegalInstrument::GDPR,
                LegalInstrument::DID_Privacy_Guidelines,
                LegalInstrument::Identity_Host_List_Spec,
            ],
            Neuroright::FreedomOfThought => &[
                LegalInstrument::ECHR,
                LegalInstrument::UDHR,
            ],
            Neuroright::PsychologicalContinuity => &[
                LegalInstrument::UN_CRPD,
                LegalInstrument::ALN_NanoNet_Safe_Construct,
            ],
            Neuroright::EqualRecognition => &[
                LegalInstrument::UN_CRPD,
                LegalInstrument::EU_AI_Act,
                LegalInstrument::OECD_AI_Principles,
            ],
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neuroright_serialization() {
        let right = Neuroright::MentalIntegrity;
        let json = serde_json::to_string(&right).unwrap();
        assert_eq!(json, "\"MENTAL_INTEGRITY\"");
        
        let deserialized: Neuroright = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, right);
    }

    #[test]
    fn test_legal_instrument_display() {
        let instrument = LegalInstrument::ECHR;
        assert_eq!(instrument.to_string(), "European Convention on Human Rights");
    }

    #[test]
    fn test_legal_basis_creation() {
        let basis = LegalBasis::new(
            LegalInstrument::ECHR,
            "Art. 3",
            Some("Prohibition of torture"),
        );
        
        assert_eq!(basis.instrument, LegalInstrument::ECHR);
        assert_eq!(basis.article, "Art. 3");
        assert_eq!(basis.note, Some("Prohibition of torture".to_string()));
    }

    #[test]
    fn test_legal_basis_citation_string() {
        let basis = LegalBasis::new(
            LegalInstrument::GDPR,
            "Recital 26",
            Some("Pseudonymisation"),
        );
        
        let citation = basis.citation_string();
        assert!(citation.contains("GDPR"));
        assert!(citation.contains("Recital 26"));
        assert!(citation.contains("Pseudonymisation"));
    }

    #[test]
    fn test_legal_basis_validation_empty_article() {
        let basis = LegalBasis::new(LegalInstrument::ECHR, "", None);
        assert!(basis.validate().is_err());
    }

    #[test]
    fn test_legal_basis_validation_long_article() {
        let long_article = "a".repeat(300);
        let basis = LegalBasis::new(LegalInstrument::ECHR, &long_article, None);
        assert!(basis.validate().is_err());
    }

    #[test]
    fn test_neurorights_validator_term_anchors() {
        let neurorights = vec![Neuroright::MentalIntegrity];
        let legal_bases = vec![LegalBasis::new(
            LegalInstrument::ECHR,
            "Art. 3",
            Some("Inhuman treatment"),
        )];
        
        let result = NeurorightsValidator::validate_term_anchors(&neurorights, &legal_bases);
        assert!(result.is_ok());
    }

    #[test]
    fn test_neurorights_validator_empty_rights() {
        let neurorights: Vec<Neuroright> = vec![];
        let legal_bases = vec![LegalBasis::new(LegalInstrument::ECHR, "Art. 3", None)];
        
        let result = NeurorightsValidator::validate_term_anchors(&neurorights, &legal_bases);
        assert!(result.is_err());
    }

    #[test]
    fn test_neurorights_validator_empty_bases() {
        let neurorights = vec![Neuroright::MentalIntegrity];
        let legal_bases: Vec<LegalBasis> = vec![];
        
        let result = NeurorightsValidator::validate_term_anchors(&neurorights, &legal_bases);
        assert!(result.is_err());
    }

    #[test]
    fn test_recommended_instruments() {
        let recommended = NeurorightsValidator::recommended_instruments(Neuroright::MentalPrivacy);
        assert!(recommended.contains(&LegalInstrument::GDPR));
        assert!(recommended.contains(&LegalInstrument::Chile_Supreme_Court_2023_Mental_Privacy));
    }

    #[test]
    fn test_neuroright_all_count() {
        assert_eq!(Neuroright::all().len(), 8);
    }
}
