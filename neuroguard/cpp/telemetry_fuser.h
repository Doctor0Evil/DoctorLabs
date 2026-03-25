// ============================================================================
// NeuroGuard Telemetry Fusion Engine - C++ Header
// Copyright (c) 2026 Doctor0Evil Research Labs
// ALN-NanoNet HyperSafe Construct Compliant
// ============================================================================
//
// This header defines the public interface for the Telemetry Fusion Engine,
// which aggregates multi-device BCI/XR telemetry streams for real-time
// quiet-violence pattern detection and evidence generation.
//
// Thread Safety: All public methods are thread-safe
// C Compatibility: C API provided for FFI with Rust, Python, and other languages
//
// Compliance: CRPD Article 13 | ECHR Article 3 | UNESCO Neuroethics 2026
// Version: 1.0.0
// Construct ID: ALN-NET-HYPER_SAFE_2026
// Corridor ID: NEUROGUARD_DEFENSE_001
// ============================================================================

#ifndef NEUROGUARD_TELEMETRY_FUSER_H
#define NEUROGUARD_TELEMETRY_FUSER_H

// ============================================================================
// Standard Library Includes
// ============================================================================

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// ============================================================================
// Platform-Specific Includes
// ============================================================================

#ifdef _WIN32
    #include <direct.h>
    #define NEUROGUARD_PLATFORM_WINDOWS
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #define NEUROGUARD_PLATFORM_UNIX
#endif

// ============================================================================
// API Export Macros
// ============================================================================

#ifdef NEUROGUARD_BUILD_SHARED
    #ifdef _WIN32
        #ifdef NEUROGUARD_EXPORTS
            #define NEUROGUARD_API __declspec(dllexport)
        #else
            #define NEUROGUARD_API __declspec(dllimport)
        #endif
    #else
        #define NEUROGUARD_API __attribute__((visibility("default")))
    #endif
#else
    #define NEUROGUARD_API
#endif

// ============================================================================
// Namespace Declaration
// ============================================================================

namespace neuroguard {

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * @brief Opaque handle for C API
 */
struct TelemetryFuserImpl;
using TelemetryFuserHandle = TelemetryFuserImpl*;

// ============================================================================
// Enumeration: Telemetry Event Types
// ============================================================================

/**
 * @brief Types of telemetry events that can be processed
 */
enum class TelemetryEventType : int32_t {
    UNKNOWN = 0,
    
    // Stimulus Events
    HAPTIC_STIMULUS = 1,
    VISUAL_STIMULUS = 2,
    AUDIO_STIMULUS = 3,
    NEURAL_STIMULUS = 4,
    
    // User Action Events
    USER_INPUT = 10,
    USER_REFUSAL = 11,
    USER_CONSENT = 12,
    USER_EXIT_ATTEMPT = 13,
    
    // System Events
    SYSTEM_PROMPT = 20,
    SYSTEM_NOTIFICATION = 21,
    CONFIGURATION_CHANGE = 22,
    ACCESS_REQUEST = 23,
    
    // Session Events
    SESSION_START = 30,
    SESSION_END = 31,
    SESSION_EXTENSION = 32,
    SESSION_TERMINATION = 33,
    
    // Guardian Events
    GUARDIAN_INTERVENTION = 40,
    GUARDIAN_BLOCK = 41,
    GUARDIAN_ALERT = 42,
    GUARDIAN_LOCK = 43,
};

// ============================================================================
// Enumeration: Pattern Families
// ============================================================================

/**
 * @brief Classification of detected abuse pattern families
 */
enum class PatternFamily : int32_t {
    UNKNOWN = 0,
    HAPTIC_TARGETING_ABUSE = 1,
    PROLONGED_SESSION_ABUSE = 2,
    NEURAL_HARASSMENT_SPIKE_PATTERNS = 3,
    NODE_INTERPRETER_HARASSMENT = 4,
    REFUSAL_EROSION_LOOPS = 5,
    IDENTITY_CROSSLINK_PATTERNS = 6,
};

// ============================================================================
// Enumeration: Severity Levels
// ============================================================================

/**
 * @brief Severity classification for detected violations
 */
enum class SeverityLevel : int32_t {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
    EMERGENCY = 5,
};

// ============================================================================
// Enumeration: Guardian Responses
// ============================================================================

/**
 * @brief Actions the Guardian Gateway can take when violations are detected
 */
enum class GuardianResponse : int32_t {
    LOG_ONLY = 0,
    ALERT_USER = 1,
    BLOCK_COMMAND = 2,
    ESCALATE_REVIEW = 3,
    EMERGENCY_LOCK = 4,
    EXPORT_AND_NOTIFY = 5,
};

// ============================================================================
// Structure: Stress Marker Snapshot
// ============================================================================

/**
 * @brief Physiological stress markers captured from BCI/biometric sensors
 * 
 * These markers are used to correlate sensory stimuli with user distress,
 * enabling detection of Neural-Harassment-Spike-Patterns (NHSP) and other
 * abuse patterns that target the user's nervous system.
 */
struct NEUROGUARD_API StressMarkerSnapshot {
    /// Heart Rate Variability in milliseconds (lower = higher stress)
    double hrv_ms;
    
    /// Galvanic Skin Response in microsiemens (higher = higher arousal)
    double gsr_microsiemens;
    
    /// Heart Rate in beats per minute
    double heart_rate_bpm;
    
    /// Respiration Rate in breaths per minute
    double respiration_rate;
    
    /// Pupil Dilation in millimeters (cognitive load indicator)
    double pupil_dilation_mm;
    
    /// Skin Temperature in Celsius
    double skin_temperature_c;
    
    /// Computed composite stress score (0.0 - 1.0)
    double stress_score;
    
    /// Capture timestamp in milliseconds since epoch
    int64_t capture_timestamp_ms;
    
    /// Validity flag
    bool is_valid;
    
    /**
     * @brief Default constructor
     */
    StressMarkerSnapshot();
    
    /**
     * @brief Compute composite stress score from all markers
     * @return Stress score between 0.0 and 1.0
     */
    double compute_stress_score() const;
    
    /**
     * @brief Check if markers indicate elevated stress
     * @return true if stress indicators exceed threshold
     */
    bool indicates_elevated_stress() const;
};

// ============================================================================
// Structure: Telemetry Event
// ============================================================================

/**
 * @brief Single telemetry event from a BCI/XR device
 * 
 * Each event represents a discrete occurrence in the user's digital/neural
 * environment, including stimuli, user actions, system prompts, and session
 * state changes. Events are fused across multiple devices for pattern detection.
 */
struct NEUROGUARD_API TelemetryEvent {
    /// Unique event identifier (UUID)
    std::string event_id;
    
    /// Timestamp in milliseconds since epoch
    int64_t timestamp_ms;
    
    /// Timestamp in ISO 8601 format
    std::string timestamp_iso;
    
    /// Source device identifier
    std::string device_id;
    
    /// Type of event
    TelemetryEventType event_type;
    
    /// Event channel (e.g., "haptic_left", "visual_center")
    std::string channel;
    
    /// Event intensity (0.0 - 1.0)
    double intensity;
    
    /// Event duration in milliseconds
    int64_t duration_ms;
    
    /// Associated user action (if applicable)
    std::string user_action;
    
    /// Stress markers at time of event
    StressMarkerSnapshot stress_markers;
    
    /// Sequence number in stream
    uint64_t sequence_number;
    
    /**
     * @brief Default constructor
     */
    TelemetryEvent();
    
    /**
     * @brief Construct telemetry event with all fields
     * @param type Event type
     * @param device Source device ID
     * @param channel Event channel
     * @param intensity Event intensity
     * @param dur_ms Event duration
     * @param markers Stress marker snapshot
     */
    TelemetryEvent(
        TelemetryEventType type,
        const std::string& device,
        const std::string& channel,
        double intensity,
        int64_t dur_ms,
        const StressMarkerSnapshot& markers);
};

// ============================================================================
// Structure: Detection Event
// ============================================================================

/**
 * @brief Detected abuse pattern with legal mapping
 * 
 * When the pattern detector identifies a potential violation, it creates a
 * DetectionEvent that includes the pattern classification, confidence score,
 * legal instrument citations, and recommended guardian response.
 */
struct NEUROGUARD_API DetectionEvent {
    /// Unique detection identifier (UUID)
    std::string event_id;
    
    /// Detection timestamp in ISO 8601 format
    std::string timestamp;
    
    /// Pattern family classification
    std::string pattern_family;
    
    /// Specific violation type within family
    std::string violation_type;
    
    /// Severity level
    SeverityLevel severity;
    
    /// Detection confidence (0.0 - 1.0)
    double confidence;
    
    /// Telemetry snapshot summary (hashed for privacy)
    std::string telemetry_snapshot;
    
    /// Legal instruments violated
    std::vector<std::string> legal_instruments;
    
    /// Pattern duration in milliseconds (if applicable)
    uint64_t pattern_duration_ms;
    
    /// Number of occurrences in detection window
    uint32_t occurrence_count;
    
    /// Recommended guardian response
    GuardianResponse guardian_response;
    
    /**
     * @brief Default constructor
     */
    DetectionEvent();
    
    /**
     * @brief Create detection event from pattern analysis
     * @param family Pattern family
     * @param violation_type Specific violation type
     * @param confidence Detection confidence
     * @param telemetry_snapshot Telemetry summary
     * @return New detection event
     */
    static DetectionEvent create(
        PatternFamily family,
        const std::string& violation_type,
        double confidence,
        const std::string& telemetry_snapshot);
    
    /**
     * @brief Compute severity from confidence and pattern weight
     * @param confidence Detection confidence
     * @param family Pattern family
     * @return Computed severity level
     */
    static SeverityLevel compute_severity(double confidence, PatternFamily family);
    
    /**
     * @brief Compute guardian response from severity and pattern
     * @param severity Severity level
     * @param family Pattern family
     * @return Recommended guardian response
     */
    static GuardianResponse compute_guardian_response(
        SeverityLevel severity, 
        PatternFamily family);
    
    /**
     * @brief Get pattern family weight for severity calculation
     * @param family Pattern family
     * @return Weight value (1.0 - 10.0)
     */
    static double get_pattern_family_weight(PatternFamily family);
    
    /**
     * @brief Convert pattern family to string
     * @param family Pattern family
     * @return String representation
     */
    static std::string pattern_family_to_string(PatternFamily family);
};

// ============================================================================
// Structure: Evidence Bundle
// ============================================================================

/**
 * @brief Court-admissible evidence bundle for legal submission
 * 
 * Evidence bundles contain all necessary information for legal proceedings,
 * including cryptographic hashes, lattice state transitions, and Organichain
 * notarization signatures.
 */
struct NEUROGUARD_API EvidenceBundle {
    /// Bundle timestamp in ISO 8601 format
    std::string timestamp;
    
    /// Associated detection event ID
    std::string event_id;
    
    /// Corridor identifier
    std::string corridor_id;
    
    /// Sovereign vault identifier
    std::string sovereign_vault_id;
    
    /// Pattern family
    std::string pattern_family;
    
    /// Violation type
    std::string violation_type;
    
    /// Severity level
    SeverityLevel severity;
    
    /// Detection confidence
    double confidence;
    
    /// Telemetry data hash (BLAKE3)
    std::string telemetry_hash;
    
    /// Lattice state before event
    int32_t lattice_state_before;
    
    /// Lattice state after event
    int32_t lattice_state_after;
    
    /// Whether policy was rejected
    bool policy_rejected;
    
    /// Organichain signature (Ed25519)
    std::string signature;
    
    /**
     * @brief Default constructor
     */
    EvidenceBundle();
    
    /**
     * @brief Create evidence bundle from detection event
     * @param detection Source detection event
     * @param corridor_id Corridor identifier
     * @param vault_id Sovereign vault identifier
     * @param lattice_before Lattice state before
     * @param lattice_after Lattice state after
     * @param rejected Whether policy was rejected
     * @return New evidence bundle
     */
    static EvidenceBundle from_detection(
        const DetectionEvent& detection,
        const std::string& corridor_id,
        const std::string& vault_id,
        int lattice_before,
        int lattice_after,
        bool rejected);
    
    /**
     * @brief Serialize bundle to JSON string
     * @return JSON representation
     */
    std::string to_json() const;
};

// ============================================================================
// Structure: Fuser Configuration
// ============================================================================

/**
 * @brief Configuration options for TelemetryFuser
 */
struct NEUROGUARD_API FuserConfig {
    /// Event buffer size (sliding window)
    size_t buffer_size;
    
    /// Maximum detection history size
    size_t max_history_size;
    
    /// Analysis window in milliseconds
    int64_t analysis_window_ms;
    
    /// Correlation threshold for pattern detection
    double correlation_threshold;
    
    /// Confidence threshold for detection
    double confidence_threshold;
    
    /// Minimum occurrences for pattern detection
    size_t min_occurrences;
    
    /// Evidence log file path
    std::string evidence_log_path;
    
    /// Corridor identifier
    std::string corridor_id;
    
    /// Sovereign vault identifier
    std::string sovereign_vault_id;
    
    /// Enable Organichain notarization
    bool enable_organichain;
    
    /// Enable cryptographic signing
    bool enable_crypto_signing;
    
    /**
     * @brief Default constructor with recommended values
     */
    FuserConfig()
        : buffer_size(10000)
        , max_history_size(100000)
        , analysis_window_ms(300000)
        , correlation_threshold(0.6)
        , confidence_threshold(0.7)
        , min_occurrences(3)
        , evidence_log_path("./evidence/evidence_bundles.jsonl")
        , corridor_id("NEUROGUARD_DEFENSE_001")
        , sovereign_vault_id("phoenix_district_001")
        , enable_organichain(true)
        , enable_crypto_signing(true)
    {}
};

// ============================================================================
// Structure: Device Stream Information
// ============================================================================

/**
 * @brief Information about a connected telemetry device stream
 */
struct NEUROGUARD_API DeviceStreamInfo {
    /// Device identifier
    std::string device_id;
    
    /// Device type (BCI, XR, biometric, etc.)
    std::string device_type;
    
    /// Last event timestamp
    int64_t last_event_time;
    
    /// Total event count
    uint64_t event_count;
    
    /// Stream active flag
    bool is_active;
};

// ============================================================================
// Structure: Fuser Statistics
// ============================================================================

/**
 * @brief Runtime statistics for TelemetryFuser
 */
struct NEUROGUARD_API FuserStatistics {
    /// Total events processed
    uint64_t total_events_processed;
    
    /// Total detections made
    uint64_t total_detections;
    
    /// Invariant violations detected
    uint64_t invariant_violations;
    
    /// Current buffer size
    size_t buffer_size;
    
    /// Current history size
    size_t history_size;
    
    /// Number of active device streams
    size_t active_device_count;
    
    /// Detections by pattern family
    std::unordered_map<std::string, uint64_t> detections_by_family;
    
    /**
     * @brief Default constructor
     */
    FuserStatistics()
        : total_events_processed(0)
        , total_detections(0)
        , invariant_violations(0)
        , buffer_size(0)
        , history_size(0)
        , active_device_count(0)
    {}
};

// ============================================================================
// Callback Type Definitions
// ============================================================================

/**
 * @brief Callback for detection events
 */
using DetectionCallback = std::function<void(const DetectionEvent&)>;

/**
 * @brief Callback for evidence bundles
 */
using EvidenceCallback = std::function<void(const EvidenceBundle&)>;

// ============================================================================
// Class: TelemetryFuser
// ============================================================================

/**
 * @brief Multi-device telemetry fusion engine for abuse pattern detection
 * 
 * The TelemetryFuser aggregates telemetry streams from multiple BCI/XR devices,
 * performs real-time pattern analysis for quiet-violence detection, and generates
 * court-admissible evidence bundles with cryptographic integrity.
 * 
 * Thread Safety: All public methods are thread-safe and can be called from
 * multiple threads concurrently.
 * 
 * Example Usage:
 * @code
 *   TelemetryFuser fuser;
 *   fuser.initialize();
 *   fuser.start();
 *   
 *   // Add telemetry events
 *   TelemetryEvent event(TelemetryEventType::HAPTIC_STIMULUS, ...);
 *   fuser.add_event(event);
 *   
 *   // Get statistics
 *   auto stats = fuser.get_statistics();
 *   
 *   // Export evidence
 *   fuser.export_evidence("./legal_export.json");
 *   
 *   fuser.stop();
 * @endcode
 */
class NEUROGUARD_API TelemetryFuser {
public:
    /**
     * @brief Default constructor
     */
    TelemetryFuser();
    
    /**
     * @brief Construct with custom configuration
     * @param config Fuser configuration
     */
    explicit TelemetryFuser(const FuserConfig& config);
    
    /**
     * @brief Destructor
     */
    ~TelemetryFuser();
    
    // Disable copy operations
    TelemetryFuser(const TelemetryFuser&) = delete;
    TelemetryFuser& operator=(const TelemetryFuser&) = delete;
    
    // Enable move operations
    TelemetryFuser(TelemetryFuser&&) noexcept;
    TelemetryFuser& operator=(TelemetryFuser&&) noexcept;
    
    // ========================================================================
    // Lifecycle Management
    // ========================================================================
    
    /**
     * @brief Initialize the fuser with current configuration
     * @return true on success, false on failure
     */
    bool initialize();
    
    /**
     * @brief Start the background worker thread
     */
    void start();
    
    /**
     * @brief Stop the background worker thread
     */
    void stop();
    
    /**
     * @brief Check if fuser is running
     * @return true if running
     */
    bool is_running() const { return is_running_.load(); }
    
    // ========================================================================
    // Event Processing
    // ========================================================================
    
    /**
     * @brief Add telemetry event to processing buffer
     * @param event Telemetry event to add
     */
    void add_event(const TelemetryEvent& event);
    
    /**
     * @brief Process current buffer for pattern detection
     * @return Vector of detected events
     */
    std::vector<DetectionEvent> process_buffer();
    
    // ========================================================================
    // Pattern Detection
    // ========================================================================
    
    /**
     * @brief Detect Haptic-Targeting-Abuse patterns
     * @return Vector of detection events
     */
    std::vector<DetectionEvent> detect_hta_pattern();
    
    /**
     * @brief Detect Neural-Harassment-Spike-Pattern patterns
     * @return Vector of detection events
     */
    std::vector<DetectionEvent> detect_nhsP_pattern();
    
    /**
     * @brief Detect Node-Interpreter-Harassment patterns
     * @return Vector of detection events
     */
    std::vector<DetectionEvent> detect_nih_pattern();
    
    /**
     * @brief Detect Prolonged-Session-Abuse patterns
     * @return Vector of detection events
     */
    std::vector<DetectionEvent> detect_psa_pattern();
    
    // ========================================================================
    // Evidence Management
    // ========================================================================
    
    /**
     * @brief Write evidence bundle to log file
     * @param bundle Evidence bundle to write
     */
    void write_evidence_bundle(const EvidenceBundle& bundle);
    
    /**
     * @brief Export all evidence for legal submission
     * @param output_path Output file path
     * @return true on success, false on failure
     */
    bool export_evidence(const std::string& output_path);
    
    /**
     * @brief Clear detection history
     */
    void clear_history();
    
    // ========================================================================
    // Statistics and Inspection
    // ========================================================================
    
    /**
     * @brief Get current fuser statistics
     * @return Statistics structure
     */
    FuserStatistics get_statistics() const;
    
    /**
     * @brief Get recent detection events
     * @param limit Maximum number of events to return
     * @return Vector of detection events
     */
    std::vector<DetectionEvent> get_recent_detections(size_t limit = 10) const;
    
    /**
     * @brief Get configuration
     * @return Current configuration
     */
    const FuserConfig& get_config() const { return config_; }
    
    // ========================================================================
    // Callbacks
    // ========================================================================
    
    /**
     * @brief Set detection event callback
     * @param callback Callback function
     */
    void set_detection_callback(DetectionCallback callback);
    
    /**
     * @brief Set evidence bundle callback
     * @param callback Callback function
     */
    void set_evidence_callback(EvidenceCallback callback);
    
private:
    // ========================================================================
    // Internal Methods
    // ========================================================================
    
    /**
     * @brief Background worker loop
     */
    void worker_loop();
    
    /**
     * @brief Create evidence directory if not exists
     */
    void create_evidence_directory();
    
    /**
     * @brief Log message with timestamp and severity
     * @param message Message to log
     * @param severity Severity level
     */
    void log_message(const std::string& message, const std::string& severity);
    
    // ========================================================================
    // Member Variables
    // ========================================================================
    
    /// Configuration
    FuserConfig config_;
    
    /// Event buffer (sliding window)
    std::deque<TelemetryEvent> event_buffer_;
    
    /// Detection history
    std::deque<DetectionEvent> detection_history_;
    
    /// Device stream information
    std::unordered_map<std::string, DeviceStreamInfo> device_streams_;
    
    /// Total events processed counter
    std::atomic<uint64_t> total_events_processed_;
    
    /// Total detections counter
    std::atomic<uint64_t> total_detections_;
    
    /// Invariant violations counter
    std::atomic<uint64_t> invariant_violations_;
    
    /// Running state flag
    std::atomic<bool> is_running_;
    
    /// Worker thread
    std::thread worker_thread_;
    
    /// Buffer mutex
    mutable std::mutex buffer_mutex_;
    
    /// History mutex
    mutable std::mutex history_mutex_;
    
    /// Stream mutex
    mutable std::mutex stream_mutex_;
    
    /// Detection callback
    DetectionCallback detection_callback_;
    
    /// Evidence callback
    EvidenceCallback evidence_callback_;
};

} // namespace neuroguard

// ============================================================================
// C API Declarations (for FFI)
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create new TelemetryFuser instance
 * @return Handle to fuser instance
 */
NEUROGUARD_API neuroguard::TelemetryFuserHandle telemetry_fuser_create(void);

/**
 * @brief Destroy TelemetryFuser instance
 * @param handle Fuser handle
 */
NEUROGUARD_API void telemetry_fuser_destroy(neuroguard::TelemetryFuserHandle handle);

/**
 * @brief Initialize fuser
 * @param handle Fuser handle
 * @return true on success
 */
NEUROGUARD_API bool telemetry_fuser_initialize(neuroguard::TelemetryFuserHandle handle);

/**
 * @brief Start fuser worker thread
 * @param handle Fuser handle
 */
NEUROGUARD_API void telemetry_fuser_start(neuroguard::TelemetryFuserHandle handle);

/**
 * @brief Stop fuser worker thread
 * @param handle Fuser handle
 */
NEUROGUARD_API void telemetry_fuser_stop(neuroguard::TelemetryFuserHandle handle);

/**
 * @brief Add telemetry event to fuser
 * @param handle Fuser handle
 * @param event_type Event type
 * @param device_id Device identifier
 * @param channel Event channel
 * @param intensity Event intensity
 * @param duration_ms Event duration
 * @param hrv Heart rate variability
 * @param gsr Galvanic skin response
 * @param heart_rate Heart rate
 */
NEUROGUARD_API void telemetry_fuser_add_event(
    neuroguard::TelemetryFuserHandle handle,
    int event_type,
    const char* device_id,
    const char* channel,
    double intensity,
    int64_t duration_ms,
    double hrv,
    double gsr,
    double heart_rate);

/**
 * @brief Export evidence to file
 * @param handle Fuser handle
 * @param output_path Output file path
 * @return true on success
 */
NEUROGUARD_API bool telemetry_fuser_export_evidence(
    neuroguard::TelemetryFuserHandle handle,
    const char* output_path);

/**
 * @brief Get fuser statistics
 * @param handle Fuser handle
 * @return Statistics structure
 */
NEUROGUARD_API neuroguard::FuserStatistics telemetry_fuser_get_statistics(
    neuroguard::TelemetryFuserHandle handle);

#ifdef __cplusplus
} // extern "C"
#endif

// ============================================================================
// End of Header - Telemetry Fusion Engine
// ============================================================================

#endif // NEUROGUARD_TELEMETRY_FUSER_H
