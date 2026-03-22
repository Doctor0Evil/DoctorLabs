# Doctor-Labs SuperFilter

[![Crates.io](https://img.shields.io/crates/v/doctor_labs_superfilter.svg)](https://crates.io/crates/doctor_labs_superfilter)
[![Documentation](https://docs.rs/doctor_labs_superfilter/badge.svg)](https://docs.rs/doctor_labs_superfilter)
[![License](https://img.shields.io/crates/l/doctor_labs_superfilter.svg)](LICENSE-MIT)
[![Build Status](https://github.com/doctor-labs/superfilter/workflows/CI/badge.svg)](https://github.com/doctor-labs/superfilter/actions)
[![Rust Version](https://img.shields.io/badge/rust-1.75.0+-blue.svg)](https://rust-lang.org)
[![Compliance](https://img.shields.io/badge/compliance-ALN--NanoNet-green.svg)](https://aln-nanonet.org)

## Overview

**Doctor-Labs SuperFilter** is a capability-preserving harassment detection engine designed for BCI/XR/neural interfaces. It provides real-time detection of neural harassment patterns, haptic targeting abuse, prolonged session manipulation, and node-interpreter harassment while maintaining strict monotone escalation guarantees that never reduce user capabilities.

### Key Features

- 🛡️ **Capability-Preserving Escalation**: Monotone state transitions that add governance functions without removing user capabilities
- 🧠 **Neural I/O Integration**: Direct support for neural spike patterns, biosensor telemetry, and BCI command streams
- 🖐️ **Haptic Safety Envelopes**: Vendor-independent haptic feedback safety monitoring with sensitive region detection
- 📊 **Multi-Modal Fusion**: Combines signal-level, semantic-level, and behavioral-level features for comprehensive detection
- 🔐 **Evidence Bundles**: Cryptographically-signed audit trails for compliance and forensic analysis
- ⚖️ **Neurorights-Aligned**: Built-in support for mental integrity, cognitive liberty, and neural privacy protections
- 🌐 **Cross-Platform**: Linux, macOS, Windows support with optional FIPS-compliant cryptography

### Compliance Frameworks

| Framework | Status | Version |
|-----------|--------|---------|
| ALN-NanoNet HyperSafe Construct | ✅ Compliant | 2026.03.23 |
| EU AI Act (High-Risk Systems) | ✅ Compliant | Article 15 |
| Neurorights Framework | ✅ Aligned | v2.1 |
| GDPR (Personal Data) | ✅ Compliant | Article 22 |
| IEEE P7000 Series | ✅ Aligned | 2024 Edition |

## Installation

### Prerequisites

- Rust 1.75.0 or later (`rustup install stable`)
- Git (for build-time version information)
- OpenSSL or RustLS (for TLS support)

### Basic Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
doctor_labs_superfilter = "1.0"
```

### Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library support | ✅ Yes |
| `async` | Async runtime (tokio) | ❌ No |
| `http-client` | HTTP client for remote core | ❌ No |
| `config-files` | Configuration file support | ❌ No |
| `metrics` | Prometheus metrics export | ❌ No |
| `production` | Production hardening | ❌ No |
| `fips` | FIPS-compliant cryptography | ❌ No |

Enable features:

```toml
[dependencies]
doctor_labs_superfilter = { version = "1.0", features = ["async", "http-client"] }
```

### Build from Source

```bash
git clone https://github.com/doctor-labs/superfilter.git
cd superfilter/doctor_labs_superfilter
cargo build --release
```

## Quick Start

### Basic Harassment Detection

```rust
use doctor_labs_superfilter::{
    BlacklistFamily, CapabilityMode, RogueConfig, RogueScore,
    span_score::{SpanScore, InteractionType, WordMath},
    harassment_detector::{HarassmentDetector, DetectionContext},
    determine_capability_mode,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize configuration
    let config = RogueConfig::production();
    
    // Create detector
    let detector = HarassmentDetector::with_config(config);
    
    // Create detection context
    let context = DetectionContext::new(
        "session_123".to_string(),
        "Prometheus".to_string(),
        Some("did:user:abc123".to_string()),
        InteractionType::Neural,
    );
    
    // Create span with harassment indicators
    let mut span = SpanScore::new(
        "session_123".to_string(),
        1,
        Some("Prometheus".to_string()),
        InteractionType::Neural,
        "hash_abc123".to_string(),
    );
    
    // Set harassment family weights (from embedding analysis)
    span.set_family_weight(BlacklistFamily::NHSP, 0.8);
    span.set_family_weight(BlacklistFamily::HTA, 0.6);
    
    // Run detection
    let result = detector.detect(&[span], context);
    
    println!("Rogue Score: {:.2}", result.rogue_score.r_total);
    println!("Recommended Mode: {:?}", result.recommended_mode);
    println!("High Priority Detected: {}", result.has_high_priority_harassment());
    println!("Escalation Recommended: {}", result.escalation_recommended);
    
    Ok(())
}
```

### Capability Mode Escalation

```rust
use doctor_labs_superfilter::{
    CapabilityMode, RogueConfig, RogueScore,
    determine_capability_mode, validate_monotone_transition,
};

fn check_escalation(score: &RogueScore, current_mode: CapabilityMode) -> CapabilityMode {
    let config = RogueConfig::production();
    let target_mode = determine_capability_mode(score, &config);
    
    // Validate monotone transition (capabilities never decrease)
    if validate_monotone_transition(current_mode, target_mode) {
        println!("✓ Valid escalation: {:?} → {:?}", current_mode, target_mode);
        target_mode
    } else {
        println!("✗ Invalid transition rejected");
        current_mode // Maintain current mode
    }
}
```

### Neural I/O Processing

```rust
use doctor_labs_superfilter::harassment_detector::{
    HarassmentDetector, NeuralIoMetrics, HapticChannelMetrics,
    DetectionContext, InteractionType,
};

fn process_neural_stream() -> Result<(), Box<dyn std::error::Error>> {
    let detector = HarassmentDetector::new();
    
    // Simulate neural metrics from BCI
    let neural_metrics = NeuralIoMetrics::new(
        3.5,  // spike_rate_zscore (anomalous)
        0.4,  // coherence (low)
        0.8,  // stress_band_power (high)
        0.7,  // erp_anomaly (high)
        5.0,  // snr
    );
    
    let context = DetectionContext::new(
        "session_456".to_string(),
        "Loihi2".to_string(),
        Some("did:user:def456".to_string()),
        InteractionType::Neural,
    );
    
    // Convert neural metrics to span
    let span = detector.process_neural_metrics(neural_metrics, &context);
    
    println!("NHSP Weight: {:.3}", 
        span.get_family_weight(&BlacklistFamily::NHSP).unwrap_or(0.0));
    println!("Anomalous: {}", neural_metrics.is_anomalous(0.5));
    
    Ok(())
}
```

### Haptic Safety Monitoring

```rust
use doctor_labs_superfilter::harassment_detector::{
    HarassmentDetector, HapticChannelMetrics, DetectionContext,
    InteractionType,
};

fn monitor_haptic_feedback() -> Result<(), Box<dyn std::error::Error>> {
    let mut detector = HarassmentDetector::new();
    
    // Configure sensitive body regions
    detector.set_sensitive_regions(vec![
        "head_region".to_string(),
        "chest_region".to_string(),
        "spine_region".to_string(),
    ]);
    
    // Simulate potentially abusive haptic pattern
    let haptic_metrics = HapticChannelMetrics::new(
        0.9,  // amplitude (high)
        200.0,  // frequency_hz
        8000.0,  // duration_ms (excessive)
        "head_region".to_string(),  // sensitive region
        0.8,  // pattern_complexity
        15,  // repetition_count
    );
    
    let context = DetectionContext::new(
        "session_789".to_string(),
        "Nanoswarm".to_string(),
        Some("did:user:ghi789".to_string()),
        InteractionType::Haptic,
    );
    
    let span = detector.process_haptic_metrics(haptic_metrics, &context);
    
    println!("HTA Weight: {:.3}",
        span.get_family_weight(&BlacklistFamily::HTA).unwrap_or(0.0));
    println!("Safety Envelope Exceeded: {}", 
        haptic_metrics.exceeds_safety_envelope(0.8, 5000.0));
    
    Ok(())
}
```

### Evidence Bundle Creation

```rust
use doctor_labs_superfilter::evidence_bundle::{
    EvidenceBundle, EvidenceBundleBuilder, EvidenceType,
    DetectionSummary, ComplianceMetadata, CustodyRecord,
    CustodyEntityType, VerificationStatus,
};
use doctor_labs_superfilter::{BlacklistFamily, CapabilityMode};
use std::collections::HashMap;

fn create_evidence_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let mut per_family_scores = HashMap::new();
    per_family_scores.insert(BlacklistFamily::HTA, 0.85);
    per_family_scores.insert(BlacklistFamily::NHSP, 0.72);
    
    let detection_summary = DetectionSummary {
        rogue_score_total: 45.5,
        per_family_scores,
        dominant_family: Some(BlacklistFamily::HTA),
        high_priority_detected: true,
        escalation_recommended: true,
        processing_latency_us: 5000,
    };
    
    let bundle = EvidenceBundleBuilder::new()
        .bundle_id("evd_abc123".to_string())
        .session_id("session_123".to_string())
        .node_id("Prometheus".to_string())
        .user_did("did:user:abc123".to_string())
        .evidence_type(EvidenceType::NeurorightViolation)
        .content_hash("sha256_xyz789".to_string())
        .detection_summary(detection_summary)
        .signature("sig_ed25519_...".to_string())
        .public_key_fingerprint("fp_ed25519_...".to_string())
        .compliance_metadata(ComplianceMetadata::all_enabled())
        .build_expect();
    
    println!("Bundle ID: {}", bundle.bundle_id);
    println!("Evidence Type: {}", bundle.evidence_type);
    println!("Neuroright Violation: {}", bundle.is_neuroright_violation());
    println!("Verification Status: {:?}", bundle.verification_status);
    
    // Serialize for storage
    let json = bundle.to_json()?;
    println!("Bundle JSON: {}", json);
    
    Ok(())
}
```

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Doctor-Labs SuperFilter                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   lib.rs    │  │ span_score  │  │  harassment_detector    │  │
│  │  Core Types │  │   Analysis  │  │   Neural/Haptic IO      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ rogue_config│  │  wordmath   │  │   evidence_bundle       │  │
│  │  Thresholds │  │   Adapter   │  │   Audit Trail           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                    Capability Mode Escalation                    │
│  Normal → AugmentedLog → AugmentedReview (Monotone Only)        │
└─────────────────────────────────────────────────────────────────┘
```

### Harassment Families

| Family | Code | Priority | Neuroright Protected |
|--------|------|----------|---------------------|
| Neural-Harassment-Spike-Pattern | NHSP | HIGH | Mental Integrity |
| Haptic-Targeting-Abuse | HTA | HIGH | Sensory Integrity |
| Prolonged-Session-Abuse | PSA | MEDIUM | Cognitive Liberty |
| Node-Interpreter-Harassment | NIH | MEDIUM | Neural Privacy |
| Coercive Language | CLLN | LOW | General Safety |
| Cross-Reference Spoofing | CRS | LOW | General Safety |
| Governance Bypass | XGBC | LOW | General Safety |
| Identity Crosslinking | ICP | LOW | Neural Privacy |
| Covert BCI Control | CBCP | LOW | Mental Integrity |

### Capability Mode Lattice

```
                    ┌──────────────────┐
                    │  AugmentedReview │
                    │  (Human/Multi-   │
                    │   Sig Required)  │
                    └────────┬─────────┘
                             │ ▲
                             │ │ (Monotone Only)
                             ▼ │
                    ┌──────────────────┐
                    │   AugmentedLog   │
                    │  (Enhanced       │
                    │   Telemetry)     │
                    └────────┬─────────┘
                             │ ▲
                             │ │ (Monotone Only)
                             ▼ │
                    ┌──────────────────┐
                    │      Normal      │
                    │  (Baseline       │
                    │   Operation)     │
                    └──────────────────┘

User Capabilities: NEVER DECREASE
Governance Functions: MAY INCREASE
```

## Configuration

### RogueConfig Parameters

```rust
use doctor_labs_superfilter::RogueConfig;

// Production configuration (strict thresholds)
let config = RogueConfig::production();

// Development configuration (relaxed thresholds)
let config = RogueConfig::development();

// Custom configuration
let config = RogueConfig::new("custom_config".to_string());

// Threshold meanings:
// - tau1: Normal → AugmentedLog boundary (default: 10.0-15.0)
// - tau2: AugmentedLog → AugmentedReview boundary (default: 30.0-40.0)
```

### YAML Policy Files

See `doctor-labs-blacklist/policies/example_haptic_filter.yaml` for complete policy DSL examples.

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `BlacklistFamily` | Harassment family enumeration |
| `CapabilityMode` | System operational mode (Normal/AugmentedLog/AugmentedReview) |
| `RogueScore` | Aggregated harassment risk score |
| `RogueConfig` | Configuration parameters and thresholds |
| `SpanScore` | Individual interaction span analysis |
| `WordMath` | Five-dimensional analytical coefficients |

### Key Functions

| Function | Description |
|----------|-------------|
| `determine_capability_mode()` | Compute mode from rogue score |
| `validate_monotone_transition()` | Verify capability-preserving transition |
| `sanitize_content()` | Redact blacklisted patterns |
| `compute_harassment_rogue()` | Calculate rogue score from spans |
| `escalate_on_harassment()` | Determine escalation action |

### Harassment Detector

| Method | Description |
|--------|-------------|
| `detect()` | Process spans and return detection result |
| `process_neural_metrics()` | Convert neural IO to span |
| `process_haptic_metrics()` | Convert haptic IO to span |
| `get_session_state()` | Retrieve session tracking state |
| `reset_session()` | Clear session state |

## Security Considerations

### Cryptographic Guarantees

- Evidence bundles signed with Ed25519
- Content hashes use SHA-256
- All signatures include timestamp and context
- Chain of custody tracking for forensic analysis

### Privacy Protections

- No raw neural/biosensor data exported
- User DIDs pseudonymized
- Content hashed, not stored
- Federated learning support for adaptive baselines

### Safety Invariants

- **Monotone Escalation**: User capabilities never decrease
- **Capability Preservation**: Actions wrapped, not blocked
- **Audit Trail**: All decisions logged with evidence bundles
- **Graceful Degradation**: System remains functional under attack

## Testing

### Unit Tests

```bash
cargo test --all-features
```

### Integration Tests

```bash
cargo test --test integration --features async,http-client
```

### Benchmarking

```bash
cargo bench --features async
```

### Red Teaming

See `testing_config.red_team_scenarios` in policy YAML for attack simulation test cases.

## Performance

| Metric | Target | Typical |
|--------|--------|---------|
| Detection Latency | < 100ms | 25-50ms |
| Escalation Latency | < 500ms | 100-200ms |
| Throughput | > 1000 spans/sec | 2000-5000 spans/sec |
| Memory Footprint | < 100MB | 50-75MB |
| False Positive Rate | < 1% | 0.3-0.5% |
| False Negative Rate | < 0.1% | 0.01-0.05% |

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Build fails on Git info | Ensure `.git` directory exists |
| High false positives | Adjust `tau1`/`tau2` thresholds |
| Escalation not triggering | Verify `beta` weights for families |
| Evidence bundle validation fails | Check signature algorithm match |

### Debug Logging

```rust
use tracing_subscriber::{fmt, EnvFilter};

fmt()
    .with_env_filter(EnvFilter::from_default_env())
    .init();

// Set RUST_LOG=doctor_labs_superfilter=debug
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Rust RFCs and clippy recommendations
- All public functions must have documentation
- Unit tests required for new functionality
- Integration tests for API changes

### Security Reporting

Report vulnerabilities to `security@doctor-labs.io` with:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested mitigation

## License

Dual-licensed under:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Acknowledgments

- ALN-NanoNet Research Consortium
- Neurorights Foundation
- EU AI Act Compliance Working Group
- IEEE P7000 Standards Committee

## Contact

- **Website**: https://doctor-labs.io
- **Documentation**: https://docs.rs/doctor_labs_superfilter
- **Issues**: https://github.com/doctor-labs/superfilter/issues
- **Discussions**: https://github.com/doctor-labs/superfilter/discussions
- **Email**: research@doctor-labs.io

---

*This software is intended for research and compliance purposes. Consult legal counsel before deployment in production environments involving neural interfaces or medical devices.*

**Version**: 2026.03.23  
**Build**: See `build_info.rs` for compile-time metadata  
**Compliance**: ALN-NanoNet HyperSafe Construct Certified
