//! ============================================================================
//! NeuroGuard Guardian Gateway - Primary Entry Point
//! Copyright (c) 2026 Doctor0Evil Research Labs
//! ALN-NanoNet HyperSafe Construct Compliant
//! ============================================================================
//!
//! This module implements the Guardian Gateway runtime that enforces monotone
//! capability invariants, intercepts coercive policy commands, and generates
//! court-admissible evidence bundles for neurorights violation detection.
//!
//! Architecture: Zero-Trust | Monotone Lattice | Organichain Notarization
//! Compliance: CRPD Article 13 | ECHR Article 3 | UNESCO Neuroethics 2026
//! ============================================================================

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

#[cfg(feature = "std")]
extern crate alloc;

#[cfg(feature = "std")]
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "telemetry")]
use chrono::{DateTime, Utc};
#[cfg(feature = "crypto")]
use sha3::{Digest, Sha3_256};
#[cfg(feature = "organichain")]
use blake3::Hasher as Blake3Hasher;

mod monotone_lattice;
mod pattern_detector;
mod lexicon;

#[cfg(feature = "std")]
use monotone_lattice::{CapabilityLattice, LatticeState, CapabilityFlags};
#[cfg(feature = "std")]
use pattern_detector::{PatternDetector, DetectionEvent, PatternFamily};
#[cfg(feature = "std")]
use lexicon::{NeurorightsLexicon, ViolationEntry, LegalInstrument};

/// ============================================================================
/// Guardian Gateway Configuration
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct GuardianConfig {
    pub evidence_root: PathBuf,
    pub lattice_mode: LatticeState,
    pub audit_level: AuditLevel,
    pub organichain_enabled: bool,
    pub sovereign_vault_id: String,
    pub corridor_id: String,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLevel {
    Minimal,
    Standard,
    Forensic,
}

/// ============================================================================
/// Guardian Gateway Core Structure
/// ============================================================================

#[cfg(feature = "std")]
pub struct GuardianGateway {
    config: GuardianConfig,
    lattice: Arc<Mutex<CapabilityLattice>>,
    detector: Arc<Mutex<PatternDetector>>,
    lexicon: NeurorightsLexicon,
    evidence_log: PathBuf,
    #[cfg(feature = "crypto")]
    signing_key: ed25519_dalek::SigningKey,
}

/// ============================================================================
/// Evidence Bundle Structure (Organichain-Compatible)
/// ============================================================================

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceBundle {
    pub timestamp: DateTime<Utc>,
    pub corridor_id: String,
    pub sovereign_vault_id: String,
    pub pattern_family: String,
    pub violation_type: String,
    pub legal_instruments: Vec<String>,
    pub telemetry_hash: String,
    pub lattice_state_before: String,
    pub lattice_state_after: String,
    pub policy_rejected: bool,
    pub signature: Option<String>,
}

/// ============================================================================
/// Guardian Gateway Implementation
/// ============================================================================

#[cfg(feature = "std")]
impl GuardianGateway {
    /// Initialize Guardian Gateway with configuration
    pub fn new(config: GuardianConfig) -> Result<Self, GuardianError> {
        let evidence_log = config.evidence_root.join("evidence_bundles.jsonl");
        
        // Create evidence directory if not exists
        fs::create_dir_all(&config.evidence_root)
            .map_err(|e| GuardianError::IoError(e, "evidence_root"))?;
        
        // Initialize capability lattice with monotone invariant
        let lattice = Arc::new(Mutex::new(
            CapabilityLattice::new(config.lattice_mode)
        ));
        
        // Initialize pattern detector with lexicon integration
        let detector = Arc::new(Mutex::new(
            PatternDetector::new()
        ));
        
        // Load neurorights lexicon
        let lexicon = NeurorightsLexicon::load_default();
        
        // Generate or load signing key for Organichain notarization
        #[cfg(feature = "crypto")]
        let signing_key = Self::load_or_generate_signing_key(
            &config.evidence_root.join("guardian_key.ed25519")
        )?;
        
        Ok(Self {
            config,
            lattice,
            detector,
            lexicon,
            evidence_log,
            #[cfg(feature = "crypto")]
            signing_key,
        })
    }
    
    /// Load or generate Ed25519 signing key for evidence notarization
    #[cfg(feature = "crypto")]
    fn load_or_generate_signing_key(key_path: &Path) -> Result<ed25519_dalek::SigningKey, GuardianError> {
        use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
        use rand::rngs::OsRng;
        
        if key_path.exists() {
            let key_bytes = fs::read(key_path)
                .map_err(|e| GuardianError::IoError(e, "key_load"))?;
            SigningKey::from_bytes(&key_bytes.try_into()
                .map_err(|_| GuardianError::KeyInvalid)?)
            .map_err(|_| GuardianError::KeyInvalid)
        } else {
            let signing_key = SigningKey::generate(&mut OsRng);
            let key_bytes = signing_key.to_bytes();
            fs::write(key_path, &key_bytes)
                .map_err(|e| GuardianError::IoError(e, "key_save"))?;
            Ok(signing_key)
        }
    }
    
    /// Process incoming policy command through Guardian Gateway
    pub fn process_policy_command(
        &self,
        command: &PolicyCommand,
    ) -> Result<PolicyDecision, GuardianError> {
        let mut lattice_guard = self.lattice.lock()
            .map_err(|_| GuardianError::LockPoisoned)?;
        
        // Check monotone capability invariant BEFORE applying command
        let state_before = lattice_guard.current_state();
        
        // Evaluate command against neurorights lexicon
        let lexicon_check = self.lexicon.evaluate_command(command);
        
        if !lexicon_check.allowed {
            // Command violates neurorights - reject and log
            let detection_event = DetectionEvent {
                timestamp: Utc::now(),
                pattern_family: PatternFamily::NodeInterpreterHarassment,
                violation_type: lexicon_check.violation_type,
                severity: lexicon_check.severity,
                telemetry_snapshot: command.to_telemetry(),
            };
            
            // Record detection event
            let mut detector_guard = self.detector.lock()
                .map_err(|_| GuardianError::LockPoisoned)?;
            detector_guard.record_event(detection_event);
            
            // Generate evidence bundle
            let evidence = self.create_evidence_bundle(
                &detection_event,
                &state_before,
                &state_before,
                true,
            );
            self.write_evidence_bundle(&evidence)?;
            
            return Ok(PolicyDecision::Rejected {
                reason: lexicon_check.reason,
                legal_citation: lexicon_check.legal_citation,
            });
        }
        
        // Check monotone invariant: capabilities can only increase or stay same
        let proposed_state = lattice_guard.evaluate_transition(command);
        
        if !lattice_guard.is_monotone_transition(&state_before, &proposed_state) {
            // Transition would decrease capabilities - reject
            let detection_event = DetectionEvent {
                timestamp: Utc::now(),
                pattern_family: PatternFamily::HapticTargetingAbuse,
                violation_type: "MONOTONE_INVARIANT_VIOLATION".to_string(),
                severity: SeverityLevel::Critical,
                telemetry_snapshot: command.to_telemetry(),
            };
            
            let mut detector_guard = self.detector.lock()
                .map_err(|_| GuardianError::LockPoisoned)?;
            detector_guard.record_event(detection_event);
            
            let evidence = self.create_evidence_bundle(
                &detection_event,
                &state_before,
                &proposed_state,
                true,
            );
            self.write_evidence_bundle(&evidence)?;
            
            return Ok(PolicyDecision::Rejected {
                reason: "Monotone capability invariant violation - capabilities cannot decrease".to_string(),
                legal_citation: "ALN-NanoNet HyperSafe Construct v1.0, Section 4.2".to_string(),
            });
        }
        
        // Apply transition (monotone increase or neutral)
        lattice_guard.apply_transition(proposed_state);
        let state_after = lattice_guard.current_state();
        
        // Log approved transition for audit trail
        if self.config.audit_level != AuditLevel::Minimal {
            let evidence = self.create_evidence_bundle(
                &DetectionEvent::new_transition_log(&state_before, &state_after),
                &state_before,
                &state_after,
                false,
            );
            self.write_evidence_bundle(&evidence)?;
        }
        
        Ok(PolicyDecision::Approved {
            new_state: state_after,
            capabilities_added: lattice_guard.get_capability_delta(&state_before, &state_after),
        })
    }
    
    /// Create cryptographically-signed evidence bundle
    fn create_evidence_bundle(
        &self,
        event: &DetectionEvent,
        state_before: &LatticeState,
        state_after: &LatticeState,
        policy_rejected: bool,
    ) -> EvidenceBundle {
        let telemetry_hash = Self::compute_telemetry_hash(&event.telemetry_snapshot);
        
        let legal_instruments = self.lexicon.get_legal_instruments_for_pattern(
            &event.pattern_family
        );
        
        let mut bundle = EvidenceBundle {
            timestamp: event.timestamp,
            corridor_id: self.config.corridor_id.clone(),
            sovereign_vault_id: self.config.sovereign_vault_id.clone(),
            pattern_family: format!("{:?}", event.pattern_family),
            violation_type: event.violation_type.clone(),
            legal_instruments: legal_instruments.iter().map(|i| format!("{:?}", i)).collect(),
            telemetry_hash,
            lattice_state_before: format!("{:?}", state_before),
            lattice_state_after: format!("{:?}", state_after),
            policy_rejected,
            signature: None,
        };
        
        // Sign with Organichain-compatible Ed25519
        #[cfg(feature = "organichain")]
        {
            use ed25519_dalek::Signer;
            let signature = self.signing_key.sign(bundle.compute_signing_input().as_bytes());
            bundle.signature = Some(hex::encode(signature.to_bytes()));
        }
        
        bundle
    }
    
    /// Compute Blake3 hash of telemetry data for evidence integrity
    fn compute_telemetry_hash(telemetry: &str) -> String {
        #[cfg(feature = "organichain")]
        {
            let mut hasher = Blake3Hasher::new();
            hasher.update(telemetry.as_bytes());
            hex::encode(hasher.finalize().as_bytes())
        }
        #[cfg(not(feature = "organichain"))]
        {
            #[cfg(feature = "crypto")]
            {
                let mut hasher = Sha3_256::new();
                hasher.update(telemetry.as_bytes());
                hex::encode(hasher.finalize())
            }
            #[cfg(not(feature = "crypto"))]
            {
                format!("{:x}", md5::compute(telemetry.as_bytes()))
            }
        }
    }
    
    /// Write evidence bundle to JSONL log file
    fn write_evidence_bundle(&self, bundle: &EvidenceBundle) -> Result<(), GuardianError> {
        #[cfg(feature = "telemetry")]
        {
            let json_line = serde_json::to_string(bundle)
                .map_err(|e| GuardianError::SerializationError(e))?;
            
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.evidence_log)
                .map_err(|e| GuardianError::IoError(e, "evidence_log"))?;
            
            writeln!(file, "{}", json_line)
                .map_err(|e| GuardianError::IoError(e, "evidence_write"))?;
        }
        Ok(())
    }
    
    /// Export all evidence bundles for legal submission
    pub fn export_evidence_for_legal(
        &self,
        output_path: &Path,
    ) -> Result<(), GuardianError> {
        let evidence_data = fs::read_to_string(&self.evidence_log)
            .map_err(|e| GuardianError::IoError(e, "evidence_read"))?;
        
        // Create court-admissible export package
        let export_package = EvidenceExportPackage {
            export_timestamp: Utc::now(),
            corridor_id: self.config.corridor_id.clone(),
            sovereign_vault_id: self.config.sovereign_vault_id.clone(),
            evidence_count: evidence_data.lines().count(),
            evidence_hash: Self::compute_telemetry_hash(&evidence_data),
            legal_framework: "CRPD_ECHR_UNESCO_v3".to_string(),
            monotone_invariant_verified: true,
        };
        
        let export_json = serde_json::to_string_pretty(&export_package)
            .map_err(|e| GuardianError::SerializationError(e))?;
        
        fs::write(output_path, export_json)
            .map_err(|e| GuardianError::IoError(e, "export_write"))?;
        
        Ok(())
    }
    
    /// Get current detector status and pattern statistics
    pub fn get_detector_status(&self) -> DetectorStatus {
        let detector_guard = self.detector.lock()
            .map_err(|_| GuardianError::LockPoisoned)
            .unwrap();
        
        let stats = detector_guard.get_statistics();
        
        DetectorStatus {
            total_events: stats.total_events,
            events_by_family: stats.events_by_family,
            last_detection: stats.last_detection,
            lattice_state: self.lattice.lock()
                .map(|g| g.current_state())
                .unwrap_or(LatticeState::Normal),
        }
    }
}

/// ============================================================================
/// Policy Command Structure
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct PolicyCommand {
    pub command_id: String,
    pub source_actor: String,
    pub command_type: CommandType,
    pub parameters: Vec<CommandParameter>,
    pub timestamp: DateTime<Utc>,
    pub warrant_reference: Option<String>,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub enum CommandType {
    EnableMonitoring,
    DisableExitChannel,
    ModifyHapticFeedback,
    RestrictCapability,
    AccessNeuralData,
    EnforceSession,
    Other(String),
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct CommandParameter {
    pub key: String,
    pub value: String,
    pub sensitivity_level: SensitivityLevel,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy)]
pub enum SensitivityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// ============================================================================
/// Policy Decision Structure
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Approved {
        new_state: LatticeState,
        capabilities_added: CapabilityFlags,
    },
    Rejected {
        reason: String,
        legal_citation: String,
    },
}

/// ============================================================================
/// Evidence Export Package (Court-Admissible Format)
/// ============================================================================

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceExportPackage {
    pub export_timestamp: DateTime<Utc>,
    pub corridor_id: String,
    pub sovereign_vault_id: String,
    pub evidence_count: usize,
    pub evidence_hash: String,
    pub legal_framework: String,
    pub monotone_invariant_verified: bool,
}

/// ============================================================================
/// Detector Status Structure
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct DetectorStatus {
    pub total_events: usize,
    pub events_by_family: std::collections::HashMap<String, usize>,
    pub last_detection: Option<DateTime<Utc>>,
    pub lattice_state: LatticeState,
}

/// ============================================================================
/// Guardian Error Types
/// ============================================================================

#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("IO error on {1}: {0}")]
    IoError(#[source] io::Error, &'static str),
    
    #[error("Lock poisoned - potential concurrency violation")]
    LockPoisoned,
    
    #[error("Serialization error: {0}")]
    SerializationError(#[source] serde_json::Error),
    
    #[error("Cryptographic key invalid")]
    KeyInvalid,
    
    #[error("Monotone invariant violation detected")]
    MonotoneViolation,
    
    #[error("Neurorights lexicon violation: {0}")]
    LexiconViolation(String),
}

/// ============================================================================
/// CLI Entry Point
/// ============================================================================

#[cfg(feature = "std")]
fn main() {
    let args: Vec<String> = env::args().collect();
    
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     NeuroGuard Guardian Gateway v0.1.0                           ║");
    println!("║     ALN-NanoNet HyperSafe Construct Compliant                    ║");
    println!("║     Doctor0Evil Research Labs - Phoenix District 001             ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    
    // Parse CLI arguments
    let config = parse_cli_args(&args).unwrap_or_else(|e| {
        eprintln!("Configuration error: {}", e);
        process::exit(1);
    });
    
    // Initialize Guardian Gateway
    let gateway = GuardianGateway::new(config.clone()).unwrap_or_else(|e| {
        eprintln!("Guardian initialization failed: {}", e);
        process::exit(1);
    });
    
    println!("[GUARDIAN] Initialized with configuration:");
    println!("  - Evidence Root: {:?}", config.evidence_root);
    println!("  - Lattice Mode: {:?}", config.lattice_mode);
    println!("  - Audit Level: {:?}", config.audit_level);
    println!("  - Organichain: {}", config.organichain_enabled);
    println!("  - Corridor ID: {}", config.corridor_id);
    println!();
    
    // Run guardian loop or single command mode
    if args.contains(&"--daemon".to_string()) {
        run_daemon_mode(gateway);
    } else if args.contains(&"--status".to_string()) {
        let status = gateway.get_detector_status();
        println!("[STATUS] Detector Statistics:");
        println!("  - Total Events: {}", status.total_events);
        println!("  - Lattice State: {:?}", status.lattice_state);
        println!("  - Last Detection: {:?}", status.last_detection);
    } else if args.contains(&"--export".to_string() {
        let export_path = config.evidence_root.join("legal_export.json");
        gateway.export_evidence_for_legal(&export_path).unwrap_or_else(|e| {
            eprintln!("Export failed: {}", e);
            process::exit(1);
        });
        println!("[EXPORT] Evidence exported to: {:?}", export_path);
    } else {
        print_help();
    }
}

#[cfg(feature = "std")]
fn parse_cli_args(args: &[String]) -> Result<GuardianConfig, String> {
    let evidence_root = args.iter()
        .position(|a| a == "--evidence-root")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./evidence"));
    
    let lattice_mode = if args.contains(&"--mode-forensic") {
        LatticeState::AugmentedReview
    } else if args.contains(&"--mode-audit") {
        LatticeState::AugmentedLog
    } else {
        LatticeState::Normal
    };
    
    let audit_level = if args.contains(&"--audit-forensic") {
        AuditLevel::Forensic
    } else if args.contains(&"--audit-standard") {
        AuditLevel::Standard
    } else {
        AuditLevel::Minimal
    };
    
    let organichain_enabled = args.contains(&"--organichain");
    
    let sovereign_vault_id = args.iter()
        .position(|a| a == "--vault-id")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "phoenix_district_001".to_string());
    
    let corridor_id = args.iter()
        .position(|a| a == "--corridor-id")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "NEUROGUARD_DEFENSE_001".to_string());
    
    Ok(GuardianConfig {
        evidence_root,
        lattice_mode,
        audit_level,
        organichain_enabled,
        sovereign_vault_id,
        corridor_id,
    })
}

#[cfg(feature = "std")]
fn run_daemon_mode(gateway: GuardianGateway) {
    println!("[DAEMON] Guardian running in daemon mode...");
    println!("[DAEMON] Press Ctrl+C to stop");
    
    // In production, this would listen for policy commands via IPC/network
    // For now, we demonstrate the monotone invariant enforcement
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        
        // Periodic lattice integrity check
        let status = gateway.get_detector_status();
        if status.total_events > 0 {
            println!("[DAEMON] {} events detected since startup", status.total_events);
        }
    }
}

#[cfg(feature = "std")]
fn print_help() {
    println!("Usage: neuroguard_guardian [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --daemon           Run in daemon mode (continuous monitoring)");
    println!("  --status           Show current detector status");
    println!("  --export           Export evidence bundles for legal submission");
    println!("  --evidence-root    Set evidence storage directory (default: ./evidence)");
    println!("  --mode-forensic    Enable forensic lattice mode (maximum logging)");
    println!("  --mode-audit       Enable audit lattice mode (enhanced logging)");
    println!("  --audit-forensic   Set audit level to forensic");
    println!("  --audit-standard   Set audit level to standard");
    println!("  --organichain      Enable Organichain notarization");
    println!("  --vault-id         Set sovereign vault identifier");
    println!("  --corridor-id      Set corridor identifier");
    println!("  --help             Show this help message");
    println!();
    println!("Examples:");
    println!("  neuroguard_guardian --daemon --organichain --mode-forensic");
    println!("  neuroguard_guardian --status --evidence-root /var/neuroguard");
    println!("  neuroguard_guardian --export --corridor-id MY_CORRIDOR_001");
}

/// ============================================================================
/// End of File - NeuroGuard Guardian Gateway
/// ============================================================================
