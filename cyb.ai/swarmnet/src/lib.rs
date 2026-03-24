// Cargo.toml (top-level)
//
// [package]
// name = "swarmnet-operator"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// thiserror = "1"
// time = { version = "0.3", features = ["formatting", "macros"] }

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Abstract signature produced by an HSM/wallet.
/// No hash algorithm is exposed here: it's just opaque bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub key_id: String,   // e.g., "did:ion:...#key-1" or Bostrom/ALN DID fragment
    pub sig: Vec<u8>,     // opaque, HSM-generated
}

/// EvidenceBundle is a capability-preserving forensic object.
/// It never contains raw neural data, only metadata and governance fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub event_id: String,
    pub timestamp: String,
    pub threat_family: Option<String>,
    pub neurorights_at_stake: Vec<String>,
    pub risk_score: f64,
    pub mode: String,
    pub key_ids: Vec<String>,
    pub signatures: Vec<Signature>,
    pub tx_id: Option<String>,
}

impl EvidenceBundle {
    pub fn new(event_id: impl Into<String>, key_ids: Vec<String>) -> Self {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        Self {
            event_id: event_id.into(),
            timestamp: now,
            threat_family: None,
            neurorights_at_stake: Vec::new(),
            risk_score: 0.0,
            mode: "Normal".to_string(),
            key_ids,
            signatures: Vec::new(),
            tx_id: None,
        }
    }

    pub fn add_evidence(
        &mut self,
        threat_family: impl Into<String>,
        neurorights: Vec<String>,
        risk_score: f64,
        mode: impl Into<String>,
    ) {
        self.threat_family = Some(threat_family.into());
        self.neurorights_at_stake = neurorights;
        self.risk_score = risk_score;
        self.mode = mode.into();
    }

    /// Attach signatures provided by an external HSM/wallet.
    /// No private key or algorithm is handled here.
    pub fn attach_signatures(&mut self, sigs: Vec<Signature>) {
        self.signatures.extend(sigs);
    }

    pub fn set_tx_id(&mut self, tx_id: impl Into<String>) {
        self.tx_id = Some(tx_id.into());
    }

    pub fn save_to_path(&self, path: &str) -> std::io::Result<()> {
        let mut f = File::create(path)?;
        let data = serde_json::to_vec_pretty(self).expect("serialize EvidenceBundle");
        f.write_all(&data)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("monotonicity violation: {0}")]
    MonotonicityViolation(String),
}

/// Minimal representation of capability modes.
/// Matches the ALN lattice: Normal -> AugmentedLog -> AugmentedReview.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityMode {
    Normal,
    AugmentedLog,
    AugmentedReview,
}

impl CapabilityMode {
    pub fn from_risk(risk_score: f64) -> Self {
        if risk_score >= 0.75 {
            CapabilityMode::AugmentedReview
        } else if risk_score >= 0.30 {
            CapabilityMode::AugmentedLog
        } else {
            CapabilityMode::Normal
        }
    }

    /// Monotone escalation: new_mode must be >= current_mode.
    pub fn check_monotone(self, next: CapabilityMode) -> Result<(), PolicyError> {
        use CapabilityMode::*;
        let ok = matches!(
            (self, next),
            (Normal, Normal | AugmentedLog | AugmentedReview)
                | (AugmentedLog, AugmentedLog | AugmentedReview)
                | (AugmentedReview, AugmentedReview)
        );
        if ok {
            Ok(())
        } else {
            Err(PolicyError::MonotonicityViolation(format!(
                "attempted downgrade from {:?} to {:?}",
                self, next
            )))
        }
    }
}

/// SwarmNetOperator orchestrates lattice checks and multisig.
/// It treats ALN policies as opaque artifacts identified by content_id.
#[derive(Debug, Clone)]
pub struct SwarmNetOperator {
    pub key_ids: Vec<String>,
    pub policy_content_id: String,
    pub governance_content_id: String,
    pub current_mode: CapabilityMode,
}

impl SwarmNetOperator {
    pub fn new(key_ids: Vec<String>, policy_content_id: String, governance_content_id: String) -> Self {
        Self {
            key_ids,
            policy_content_id,
            governance_content_id,
            current_mode: CapabilityMode::Normal,
        }
    }

    /// Delegate to an external ALN / Bostrom contract.
    /// Here we only enforce the local, monotone check.
    fn check_monotonicity(
        &self,
        next_mode: CapabilityMode,
    ) -> Result<(), PolicyError> {
        self.current_mode.check_monotone(next_mode)
    }

    /// Orchestrate: lattice check, mode derivation, multisig expectation, evidence bundle.
    pub fn enforce_policy(
        &mut self,
        event_id: &str,
        risk_score: f64,
        threat_family: &str,
        neurorights_at_stake: Vec<String>,
        tx_id_hint: Option<String>,
        external_sigs: Vec<Signature>,
    ) -> Result<EvidenceBundle, PolicyError> {
        // 1. Derive next mode from risk.
        let next_mode = CapabilityMode::from_risk(risk_score);

        // 2. Monotone enforcement.
        self.check_monotonicity(next_mode)?;

        // 3. Update current mode (monotone).
        self.current_mode = next_mode;

        // 4. Build EvidenceBundle.
        let mut bundle = EvidenceBundle::new(event_id, self.key_ids.clone());
        bundle.add_evidence(
            threat_family.to_string(),
            neurorights_at_stake,
            risk_score,
            format!("{:?}", self.current_mode),
        );

        // 5. Attach external signatures (N-of-M multisig is enforced by caller).
        bundle.attach_signatures(external_sigs);

        // 6. Attach tx_id hint (actual chain write is external).
        if let Some(txid) = tx_id_hint {
            bundle.set_tx_id(txid);
        }

        Ok(bundle)
    }
}

// Example integration stub (not executed in libraries):
//
// fn main() -> anyhow::Result<()> {
//     let key_ids = vec![
//         "did:bostrom:...#key-1".to_string(),
//         "did:bostrom:...#key-2".to_string(),
//     ];
//     let mut op = SwarmNetOperator::new(
//         key_ids,
//         "content-id:extended_capability_lattice.aii".to_string(),
//         "content-id:governance_triad.aii".to_string(),
//     );
//
//     // risk_score from DoctorLabs superfilter
//     let risk_score = 0.85;
//     let threat_family = "LEO_Safety_Request";
//     let neurorights = vec!["MentalPrivacy".into(), "CognitiveLiberty".into()];
//
//     // External multisig signatures (HSM/wallet).
//     let sigs = vec![Signature {
//         key_id: "did:bostrom:...#key-1".into(),
//         sig: vec![1, 2, 3], // opaque
//     }];
//
//     let mut bundle = op.enforce_policy(
//         "account_action_12345",
//         risk_score,
//         threat_family,
//         neurorights,
//         Some("bostrom_tx_hash_placeholder".into()),
//         sigs,
//     )?;
//
//     bundle.save_to_path(
//         "/var/log/cyb_ai/evidence_bundles/account_action_12345.json",
//     )?;
//
//     Ok(())
// }
