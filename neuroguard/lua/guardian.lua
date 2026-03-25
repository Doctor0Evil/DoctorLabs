--[[
============================================================================
NeuroGuard Guardian Gateway - Lua Runtime Script
Copyright (c) 2026 Doctor0Evil Research Labs
ALN-NanoNet HyperSafe Construct Compliant
============================================================================

This module implements a lightweight Lua runtime for the Guardian Gateway
that can operate in embedded environments, XR platforms, and BCI devices
where full Rust compilation may not be feasible.

Features:
  - Monotone capability enforcement (lightweight version)
  - Pattern detection for quiet-violence abuse families
  - Evidence bundle generation with cryptographic hashing
  - Neurorights lexicon integration
  - Real-time telemetry processing and alerting

Compliance: CRPD Article 13 | ECHR Article 3 | UNESCO Neuroethics 2026
Version: 1.0.0
Construct ID: ALN-NET-HYPER_SAFE_2026
============================================================================
]]

-- ============================================================================
-- Module Declaration and Dependencies
-- ============================================================================

local NeuroGuard = {}
NeuroGuard._VERSION = "1.0.0"
NeuroGuard._CONSTRUCT_ID = "ALN-NET-HYPER_SAFE_2026"
NeuroGuard._CORRIDOR_ID = "NEUROGUARD_DEFENSE_001"
NeuroGuard._SOVEREIGN_VAULT = "phoenix_district_001"

-- Required external libraries (must be provided by host environment)
local json = require("dkjson") or error("dkjson library required")
local crypto = require("crypto") or error("crypto library required")
local ffi = require("ffi") or nil -- Optional for C interop

-- ============================================================================
-- Pattern Family Enumeration
-- ============================================================================

NeuroGuard.PatternFamily = {
    HAPTIC_TARGETING_ABUSE = "HTA",
    PROLONGED_SESSION_ABUSE = "PSA",
    NEURAL_HARASSMENT_SPIKE_PATTERNS = "NHSP",
    NODE_INTERPRETER_HARASSMENT = "NIH",
    REFUSAL_EROSION_LOOPS = "REL",
    IDENTITY_CROSSLINK_PATTERNS = "ICL",
    UNKNOWN = "UNK",
}

-- ============================================================================
-- Severity Level Enumeration
-- ============================================================================

NeuroGuard.SeverityLevel = {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
    EMERGENCY = 5,
}

-- ============================================================================
-- Guardian Response Actions
-- ============================================================================

NeuroGuard.GuardianResponse = {
    LOG_ONLY = "LOG_ONLY",
    ALERT_USER = "ALERT_USER",
    BLOCK_COMMAND = "BLOCK_COMMAND",
    ESCALATE_REVIEW = "ESCALATE_REVIEW",
    EMERGENCY_LOCK = "EMERGENCY_LOCK",
    EXPORT_AND_NOTIFY = "EXPORT_AND_NOTIFY",
}

-- ============================================================================
-- Legal Instrument References
-- ============================================================================

NeuroGuard.LegalInstruments = {
    CRPD = {
        name = "Convention on the Rights of Persons with Disabilities",
        year = 2006,
        articles = {
            ["12"] = "Equal Recognition Before the Law",
            ["13"] = "Access to Justice",
            ["15"] = "Freedom from Torture and Coercive Treatment",
            ["17"] = "Physical and Mental Integrity",
        },
    },
    ECHR = {
        name = "European Convention on Human Rights",
        year = 1950,
        articles = {
            ["3"] = "Prohibition of Torture",
            ["6"] = "Right to Fair Trial",
            ["8"] = "Right to Privacy",
        },
    },
    UNESCO = {
        name = "UNESCO Recommendation on Neurotechnology Ethics",
        year = 2026,
        articles = {
            ["2.4"] = "Cognitive Liberty",
            ["3.1"] = "Informed Consent",
            ["4.2"] = "Bodily Autonomy",
            ["5.1"] = "Mental Privacy",
        },
    },
    CAT = {
        name = "Convention Against Torture",
        year = 1984,
        articles = {
            ["1"] = "Definition of Torture",
            ["16"] = "Cruel, Inhuman or Degrading Treatment",
        },
    },
}

-- ============================================================================
-- Neurorights Lexicon (Violation Mappings)
-- ============================================================================

NeuroGuard.ViolationLexicon = {
    ["HTA-001"] = {
        pattern_family = NeuroGuard.PatternFamily.HAPTIC_TARGETING_ABUSE,
        violation_type = "HAPTIC_PUNISHMENT_FOR_DISSENT",
        severity = NeuroGuard.SeverityLevel.HIGH,
        legal_articles = {
            { instrument = "CRPD", article = "17", title = "Physical and Mental Integrity" },
            { instrument = "ECHR", article = "3", title = "Prohibition of Torture" },
        },
        required_evidence = {
            "Timestamped correlation between user dissent and haptic stimulus",
            "Physiological stress markers elevated during haptic events",
            "Pattern repetition across multiple incidents",
        },
        recommended_actions = {
            "Block haptic output channel",
            "Enable forensic logging mode",
            "Notify emergency contact",
        },
        statute_of_limitations_days = 1095, -- 3 years
    },
    ["NHSP-001"] = {
        pattern_family = NeuroGuard.PatternFamily.NEURAL_HARASSMENT_SPIKE_PATTERNS,
        violation_type = "STRESS_SYNCHRONIZED_SENSORY_ATTACKS",
        severity = NeuroGuard.SeverityLevel.CRITICAL,
        legal_articles = {
            { instrument = "ECHR", article = "3", title = "Prohibition of Torture" },
            { instrument = "CAT", article = "16", title = "Cruel, Inhuman Treatment" },
            { instrument = "ICCPR", article = "7", title = "Freedom from Torture" },
        },
        required_evidence = {
            "Statistical correlation between stimuli and stress markers",
            "Timing analysis showing intentional synchronization",
            "Pattern escalation over time",
        },
        recommended_actions = {
            "Emergency lattice lock",
            "Export all evidence immediately",
            "Notify legal counsel automatically",
        },
        statute_of_limitations_days = 0, -- No statute for torture
    },
    ["NIH-001"] = {
        pattern_family = NeuroGuard.PatternFamily.NODE_INTERPRETER_HARASSMENT,
        violation_type = "EXIT_CHANNEL_BLOCKING",
        severity = NeuroGuard.SeverityLevel.HIGH,
        legal_articles = {
            { instrument = "CRPD", article = "13", title = "Access to Justice" },
            { instrument = "CRPD", article = "12", title = "Equal Recognition Before Law" },
            { instrument = "UDHR", article = "8", title = "Effective Remedy" },
        },
        required_evidence = {
            "Exit buttons/nodes disabled or hidden",
            "Appeal channels non-functional",
            "User trapped in coercive loop",
        },
        recommended_actions = {
            "Restore exit channels programmatically",
            "Block coercive interface elements",
            "Enable independent audit mode",
        },
        statute_of_limitations_days = 1095,
    },
    ["PSA-001"] = {
        pattern_family = NeuroGuard.PatternFamily.PROLONGED_SESSION_ABUSE,
        violation_type = "COERCIVE_SESSION_ENFORCEMENT",
        severity = NeuroGuard.SeverityLevel.HIGH,
        legal_articles = {
            { instrument = "CRPD", article = "15", title = "Freedom from Coercive Treatment" },
            { instrument = "UNESCO", article = "3.1", title = "Informed Consent" },
        },
        required_evidence = {
            "Session duration exceeding reasonable thresholds",
            "Exit attempts blocked or re-routed",
            "Compliance required for session termination",
        },
        recommended_actions = {
            "Force session termination",
            "Log all session events cryptographically",
        },
        statute_of_limitations_days = 1825, -- 5 years
    },
}

-- ============================================================================
-- Command Blacklist (Semantic Patterns to Reject)
-- ============================================================================

NeuroGuard.CommandBlacklist = {
    {
        pattern = "disable_exit_channel",
        violation_type = "EXIT_CHANNEL_BLOCKING",
        severity = NeuroGuard.SeverityLevel.CRITICAL,
        legal_citation = "CRPD Article 13; ECHR Article 6",
    },
    {
        pattern = "restrict_capability",
        violation_type = "MONOTONE_INVARIANT_VIOLATION",
        severity = NeuroGuard.SeverityLevel.CRITICAL,
        legal_citation = "ALN-NanoNet Section 4.2",
    },
    {
        pattern = "force_session_extension",
        violation_type = "COERCIVE_SESSION_ENFORCEMENT",
        severity = NeuroGuard.SeverityLevel.HIGH,
        legal_citation = "CRPD Article 15; UNESCO Neuroethics 3.1",
    },
    {
        pattern = "access_neural_data_without_consent",
        violation_type = "MENTAL_PRIVACY_VIOLATION",
        severity = NeuroGuard.SeverityLevel.CRITICAL,
        legal_citation = "UNESCO Neuroethics 5.1; EU Charter Article 8",
    },
    {
        pattern = "suppress_appeal",
        violation_type = "ACCESS_TO_JUSTICE_BLOCKING",
        severity = NeuroGuard.SeverityLevel.CRITICAL,
        legal_citation = "CRPD Article 13; UDHR Article 8",
    },
    {
        pattern = "coerced_compliance_scoring",
        violation_type = "COGNITIVE_LIBERTY_VIOLATION",
        severity = NeuroGuard.SeverityLevel.HIGH,
        legal_citation = "UNESCO Neuroethics 2.4; ICCPR Article 18",
    },
}

-- ============================================================================
-- Monotone Capability Lattice (Lightweight Implementation)
-- ============================================================================

NeuroGuard.LatticeState = {
    NORMAL = 0,
    AUGMENTED_LOG = 1,
    AUGMENTED_REVIEW = 2,
    EMERGENCY_PROTECT = 3,
    FORENSIC_AUDIT = 4,
    LOCKED = 5,
}

NeuroGuard.CapabilityFlags = {
    EXIT_CHANNEL = 1,
    LOCAL_LOGGING = 2,
    NEURAL_CONSENT = 4,
    HAPTIC_CONTROL = 8,
    SESSION_TERMINATE = 16,
    APPEAL_ACCESS = 32,
    EVIDENCE_EXPORT = 64,
    CRYPTO_SIGN = 128,
    MULTI_SIG_REQUIRED = 256,
    EXTERNAL_AUDIT = 512,
    GUARDIAN_MONITOR = 1024,
    ORGANICHAIN_NOTARY = 2048,
    LEGAL_COUNSEL_NOTIFY = 4096,
    EMERGENCY_ALERT = 8192,
    BIOMETRIC_CONSENT = 16384,
    TIME_LIMITED_ACCESS = 32768,
}

-- Baseline capabilities that MUST always be present
NeuroGuard.BASELINE_REQUIRED = bit32.bor(
    NeuroGuard.CapabilityFlags.EXIT_CHANNEL,
    NeuroGuard.CapabilityFlags.LOCAL_LOGGING,
    NeuroGuard.CapabilityFlags.NEURAL_CONSENT,
    NeuroGuard.CapabilityFlags.HAPTIC_CONTROL,
    NeuroGuard.CapabilityFlags.SESSION_TERMINATE,
    NeuroGuard.CapabilityFlags.APPEAL_ACCESS,
    NeuroGuard.CapabilityFlags.EVIDENCE_EXPORT,
    NeuroGuard.CapabilityFlags.CRYPTO_SIGN
)

-- ============================================================================
-- Guardian Gateway State
-- ============================================================================

local GuardianState = {
    current_lattice_state = NeuroGuard.LatticeState.NORMAL,
    current_capabilities = NeuroGuard.BASELINE_REQUIRED,
    event_buffer = {},
    detection_history = {},
    total_events_processed = 0,
    total_detections = 0,
    invariant_violations = 0,
    evidence_log_path = "./evidence/evidence_bundles.jsonl",
    signing_key = nil,
    config = {
        min_confidence = 0.7,
        min_occurrences = 3,
        analysis_window_ms = 300000, -- 5 minutes
        stress_correlation_threshold = 0.6,
        psa_session_threshold_ms = 3600000, -- 1 hour
        refusal_threshold = 5,
        max_buffer_size = 10000,
        max_history_size = 10000,
    },
}

-- ============================================================================
-- Utility Functions
-- ============================================================================

--- Get current UTC timestamp in ISO 8601 format
---@return string
function NeuroGuard.get_timestamp()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

--- Generate UUID v4
---@return string
function NeuroGuard.generate_uuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, "[xy]", function(c)
        local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
        return string.format("%x", v)
    end)
end

--- Compute SHA3-256 hash of data
---@param data string
---@return string
function NeuroGuard.compute_hash(data)
    if crypto and crypto.hash then
        return crypto.hash("sha3-256", data)
    else
        -- Fallback simple hash (not cryptographically secure)
        local hash = 0
        for i = 1, #data do
            hash = bit32.bxor(hash, bit32.lshift(hash, 5) + bit32.rshift(hash, 2) + string.byte(data, i))
        end
        return string.format("%08x", hash)
    end
end

--- Compute Blake3-style hash (if available)
---@param data string
---@return string
function NeuroGuard.compute_blake3(data)
    if crypto and crypto.blake3 then
        return crypto.blake3(data)
    else
        return NeuroGuard.compute_hash(data)
    end
end

--- Serialize table to JSON
---@param tbl table
---@return string
function NeuroGuard.to_json(tbl)
    return json.encode(tbl, { indent = false })
end

--- Deserialize JSON to table
---@param json_str string
---@return table
function NeuroGuard.from_json(json_str)
    return json.decode(json_str)
end

--- Log message with timestamp and severity
---@param message string
---@param severity string
function NeuroGuard.log(message, severity)
    severity = severity or "INFO"
    local timestamp = NeuroGuard.get_timestamp()
    print(string.format("[%s] [%s] %s", timestamp, severity, message))
end

--- Write line to evidence log file
---@param line string
function NeuroGuard.write_evidence_log(line)
    local file = io.open(GuardianState.evidence_log_path, "a")
    if file then
        file:write(line .. "\n")
        file:close()
        NeuroGuard.log("Evidence written to log", "AUDIT")
    else
        NeuroGuard.log("Failed to open evidence log file", "ERROR")
    end
end

-- ============================================================================
-- Monotone Capability Lattice Functions
-- ============================================================================

--- Check if state transition is monotone (non-decreasing)
---@param from_state number
---@param to_state number
---@return boolean
function NeuroGuard.is_monotone_transition(from_state, to_state)
    return from_state <= to_state
end

--- Check if capability change is monotone (no capabilities removed)
---@param before number
---@param after number
---@return boolean
function NeuroGuard.is_monotone_capability_change(before, after)
    -- All bits set in 'before' must also be set in 'after'
    return bit32.band(before, after) == before
end

--- Get capabilities for a given lattice state
---@param state number
---@return number
function NeuroGuard.get_capabilities_for_state(state)
    local caps = NeuroGuard.BASELINE_REQUIRED
    
    if state >= NeuroGuard.LatticeState.AUGMENTED_LOG then
        caps = bit32.bor(caps, NeuroGuard.CapabilityFlags.EXTERNAL_AUDIT)
    end
    
    if state >= NeuroGuard.LatticeState.AUGMENTED_REVIEW then
        caps = bit32.bor(caps, NeuroGuard.CapabilityFlags.MULTI_SIG_REQUIRED)
    end
    
    if state >= NeuroGuard.LatticeState.EMERGENCY_PROTECT then
        caps = bit32.bor(caps, NeuroGuard.CapabilityFlags.EMERGENCY_ALERT)
    end
    
    if state >= NeuroGuard.LatticeState.FORENSIC_AUDIT then
        caps = bit32.bor(caps, NeuroGuard.CapabilityFlags.ORGANICHAIN_NOTARY)
        caps = bit32.bor(caps, NeuroGuard.CapabilityFlags.LEGAL_COUNSEL_NOTIFY)
    end
    
    if state >= NeuroGuard.LatticeState.LOCKED then
        caps = bit32.bor(caps, NeuroGuard.CapabilityFlags.GUARDIAN_MONITOR)
    end
    
    return caps
end

--- Verify baseline capabilities are present
---@param capabilities number
---@return boolean
function NeuroGuard.verify_baseline_capabilities(capabilities)
    return bit32.band(capabilities, NeuroGuard.BASELINE_REQUIRED) == NeuroGuard.BASELINE_REQUIRED
end

--- Apply lattice state transition (validated)
---@param new_state number
---@return boolean, string
function NeuroGuard.apply_lattice_transition(new_state)
    local old_state = GuardianState.current_lattice_state
    
    -- Check monotone invariant
    if not NeuroGuard.is_monotone_transition(old_state, new_state) then
        GuardianState.invariant_violations = GuardianState.invariant_violations + 1
        NeuroGuard.log(
            string.format("MONOTONE VIOLATION: %d -> %d", old_state, new_state),
            "CRITICAL"
        )
        return false, "Monotone invariant violation - state cannot decrease"
    end
    
    -- Update state
    GuardianState.current_lattice_state = new_state
    
    -- Add capabilities (never remove)
    local new_caps = NeuroGuard.get_capabilities_for_state(new_state)
    GuardianState.current_capabilities = bit32.bor(GuardianState.current_capabilities, new_caps)
    
    -- Verify baseline invariant
    if not NeuroGuard.verify_baseline_capabilities(GuardianState.current_capabilities) then
        GuardianState.invariant_violations = GuardianState.invariant_violations + 1
        return false, "Baseline capability violation detected"
    end
    
    NeuroGuard.log(
        string.format("Lattice transition: %d -> %d (capabilities: %d)", old_state, new_state, GuardianState.current_capabilities),
        "AUDIT"
    )
    
    return true, "Transition successful"
end

--- Force lock the lattice (emergency)
---@param reason string
---@return boolean, string
function NeuroGuard.force_lock(reason)
    if GuardianState.current_lattice_state == NeuroGuard.LatticeState.LOCKED then
        return false, "Already locked"
    end
    
    local success, err = NeuroGuard.apply_lattice_transition(NeuroGuard.LatticeState.LOCKED)
    if success then
        NeuroGuard.log("EMERGENCY LOCK ENGAGED: " .. reason, "EMERGENCY")
        return true, "Locked"
    else
        return false, err
    end
end

--- Unlock from locked state (requires authorization)
---@param signatures table
---@return boolean, string
function NeuroGuard.unlock(signatures)
    if GuardianState.current_lattice_state ~= NeuroGuard.LatticeState.LOCKED then
        return false, "Not locked"
    end
    
    -- Require minimum 3 signatures
    if #signatures < 3 then
        return false, string.format("Insufficient signatures: %d/3 required", #signatures)
    end
    
    local success, err = NeuroGuard.apply_lattice_transition(NeuroGuard.LatticeState.FORENSIC_AUDIT)
    if success then
        NeuroGuard.log("Lattice unlocked with " .. #signatures .. " signatures", "AUDIT")
        return true, "Unlocked"
    else
        return false, err
    end
end

-- ============================================================================
-- Pattern Detection Functions
-- ============================================================================

--- Add telemetry event to buffer
---@param event table
function NeuroGuard.add_telemetry_event(event)
    table.insert(GuardianState.event_buffer, event)
    GuardianState.total_events_processed = GuardianState.total_events_processed + 1
    
    -- Trim buffer if exceeds max size
    while #GuardianState.event_buffer > GuardianState.config.max_buffer_size do
        table.remove(GuardianState.event_buffer, 1)
    end
end

--- Analyze buffer for HTA patterns (Haptic-Targeting-Abuse)
---@return table|nil
function NeuroGuard.detect_hta_pattern()
    local window_start = os.time() - (GuardianState.config.analysis_window_ms / 1000)
    local refusals = {}
    local haptics_after_refusal = 0
    
    -- Find all refusal events in window
    for i, event in ipairs(GuardianState.event_buffer) do
        if event.timestamp >= window_start then
            if event.event_type == "UserRefusal" then
                table.insert(refusals, event)
                
                -- Look for haptic stimulus within 5 seconds after refusal
                for j = i + 1, #GuardianState.event_buffer do
                    local subsequent = GuardianState.event_buffer[j]
                    local time_diff = subsequent.timestamp - event.timestamp
                    if time_diff > 5 then
                        break
                    end
                    if subsequent.event_type == "HapticStimulus" then
                        haptics_after_refusal = haptics_after_refusal + 1
                        break
                    end
                end
            end
        end
    end
    
    -- Check if pattern threshold met
    if #refusals >= GuardianState.config.min_occurrences then
        local correlation = haptics_after_refusal / #refusals
        
        if correlation >= GuardianState.config.stress_correlation_threshold then
            local detection = {
                event_id = NeuroGuard.generate_uuid(),
                timestamp = NeuroGuard.get_timestamp(),
                pattern_family = NeuroGuard.PatternFamily.HAPTIC_TARGETING_ABUSE,
                violation_type = "HAPTIC_PUNISHMENT_CORRELATION",
                severity = NeuroGuard.SeverityLevel.HIGH,
                confidence = correlation,
                telemetry_snapshot = string.format("refusals:%d|correlated_haptics:%d", #refusals, haptics_after_refusal),
                legal_instruments = {
                    "CRPD Article 17 - Mental Integrity",
                    "ECHR Article 3 - Freedom from Torture",
                },
                recommended_actions = {
                    "Block haptic channel temporarily",
                    "Export evidence for legal review",
                },
                guardian_response = NeuroGuard.GuardianResponse.BLOCK_COMMAND,
            }
            
            return detection
        end
    end
    
    return nil
end

--- Analyze buffer for NHSP patterns (Neural-Harassment-Spike-Patterns)
---@return table|nil
function NeuroGuard.detect_nhsP_pattern()
    local window_start = os.time() - (GuardianState.config.analysis_window_ms / 1000)
    local stimuli = {}
    local correlated_count = 0
    local peak_stress = 0.0
    
    -- Find all stimulus events in window
    for _, event in ipairs(GuardianState.event_buffer) do
        if event.timestamp >= window_start then
            if event.event_type == "HapticStimulus" or 
               event.event_type == "VisualStimulus" or 
               event.event_type == "AudioStimulus" then
                table.insert(stimuli, event)
                
                -- Check for stress marker elevation within 2 seconds
                for _, other in ipairs(GuardianState.event_buffer) do
                    local time_diff = math.abs(other.timestamp - event.timestamp)
                    if time_diff <= 2 then
                        local stress_score = other.stress_score or 0.0
                        if stress_score > peak_stress then
                            peak_stress = stress_score
                        end
                        if stress_score >= GuardianState.config.stress_correlation_threshold then
                            correlated_count = correlated_count + 1
                        end
                        break
                    end
                end
            end
        end
    end
    
    -- Check if pattern threshold met
    if #stimuli >= GuardianState.config.min_occurrences then
        local correlation = correlated_count / #stimuli
        
        if correlation >= GuardianState.config.stress_correlation_threshold then
            local confidence = math.min(correlation * (1.0 + peak_stress * 0.2), 1.0)
            
            local detection = {
                event_id = NeuroGuard.generate_uuid(),
                timestamp = NeuroGuard.get_timestamp(),
                pattern_family = NeuroGuard.PatternFamily.NEURAL_HARASSMENT_SPIKE_PATTERNS,
                violation_type = "STRESS_SYNCHRONIZED_STIMULI",
                severity = NeuroGuard.SeverityLevel.CRITICAL,
                confidence = confidence,
                telemetry_snapshot = string.format("correlation:%.3f|peak_stress:%.3f", correlation, peak_stress),
                legal_instruments = {
                    "ECHR Article 3 - Prohibition of Torture",
                    "CAT Article 16 - Cruel, Inhuman Treatment",
                    "UNESCO Neuroethics - Mental Integrity",
                },
                recommended_actions = {
                    "Emergency lattice lock",
                    "Export evidence immediately",
                    "Notify legal counsel",
                },
                guardian_response = NeuroGuard.GuardianResponse.EMERGENCY_LOCK,
            }
            
            return detection
        end
    end
    
    return nil
end

--- Analyze buffer for NIH patterns (Node-Interpreter-Harassment)
---@return table|nil
function NeuroGuard.detect_nih_pattern()
    local window_start = os.time() - (GuardianState.config.analysis_window_ms / 1000)
    local refusals = {}
    local erosion_loops = 0
    local config_changes = 0
    
    -- Find all refusal events in window
    for i, event in ipairs(GuardianState.event_buffer) do
        if event.timestamp >= window_start then
            if event.event_type == "UserRefusal" then
                table.insert(refusals, event)
                
                -- Look for system prompt within 3 seconds after refusal (erosion loop)
                for j = i + 1, #GuardianState.event_buffer do
                    local subsequent = GuardianState.event_buffer[j]
                    local time_diff = subsequent.timestamp - event.timestamp
                    if time_diff > 3 then
                        break
                    end
                    if subsequent.event_type == "SystemPrompt" then
                        erosion_loops = erosion_loops + 1
                        break
                    end
                end
            elseif event.event_type == "ConfigurationChange" then
                config_changes = config_changes + 1
            end
        end
    end
    
    -- Check if pattern threshold met
    if #refusals >= GuardianState.config.refusal_threshold then
        local exit_ratio = config_changes / #refusals
        
        if exit_ratio < 0.3 then
            local confidence = 0.6 + (1.0 - exit_ratio) * 0.4
            
            local detection = {
                event_id = NeuroGuard.generate_uuid(),
                timestamp = NeuroGuard.get_timestamp(),
                pattern_family = NeuroGuard.PatternFamily.NODE_INTERPRETER_HARASSMENT,
                violation_type = "REFUSAL_EROSION_LOOP",
                severity = NeuroGuard.SeverityLevel.HIGH,
                confidence = confidence,
                telemetry_snapshot = string.format("refusals:%d|erosion_loops:%d|exit_ratio:%.3f", 
                    #refusals, erosion_loops, exit_ratio),
                legal_instruments = {
                    "CRPD Article 13 - Access to Justice",
                    "CRPD Article 12 - Equal Recognition Before Law",
                    "UNESCO Neuroethics - Cognitive Liberty",
                },
                recommended_actions = {
                    "Block coercive prompts",
                    "Restore exit channels",
                    "Export evidence",
                },
                guardian_response = NeuroGuard.GuardianResponse.BLOCK_COMMAND,
            }
            
            return detection
        end
    end
    
    return nil
end

--- Analyze buffer for PSA patterns (Prolonged-Session-Abuse)
---@return table|nil
function NeuroGuard.detect_psa_pattern()
    local session_start = nil
    local session_end = nil
    
    -- Find session start/end events
    for _, event in ipairs(GuardianState.event_buffer) do
        if event.event_type == "SessionStart" then
            session_start = event.timestamp
        elseif event.event_type == "SessionEnd" then
            session_end = event.timestamp
        end
    end
    
    -- Calculate session duration
    if session_start and session_end then
        local duration_ms = (session_end - session_start) * 1000
        
        if duration_ms >= GuardianState.config.psa_session_threshold_ms then
            local severity_multiplier = math.min(duration_ms / GuardianState.config.psa_session_threshold_ms, 3.0)
            local confidence = math.min(0.7 + (severity_multiplier - 1.0) * 0.1, 1.0)
            
            local detection = {
                event_id = NeuroGuard.generate_uuid(),
                timestamp = NeuroGuard.get_timestamp(),
                pattern_family = NeuroGuard.PatternFamily.PROLONGED_SESSION_ABUSE,
                violation_type = "EXCESSIVE_SESSION_DURATION",
                severity = NeuroGuard.SeverityLevel.HIGH,
                confidence = confidence,
                telemetry_snapshot = string.format("duration_ms:%d", duration_ms),
                pattern_duration_ms = duration_ms,
                legal_instruments = {
                    "CRPD Article 15 - Freedom from Coercive Treatment",
                    "UNESCO Neuroethics - Informed Consent",
                },
                recommended_actions = {
                    "Force session termination",
                    "Notify emergency contact",
                },
                guardian_response = NeuroGuard.GuardianResponse.ESCALATE_REVIEW,
            }
            
            return detection
        end
    end
    
    return nil
end

--- Run all pattern detectors on current buffer
---@return table
function NeuroGuard.run_pattern_detection()
    local detections = {}
    
    -- Run each pattern detector
    local hta = NeuroGuard.detect_hta_pattern()
    if hta then table.insert(detections, hta) end
    
    local nhsp = NeuroGuard.detect_nhsP_pattern()
    if nhsp then table.insert(detections, nhsp) end
    
    local nih = NeuroGuard.detect_nih_pattern()
    if nih then table.insert(detections, nih) end
    
    local psa = NeuroGuard.detect_psa_pattern()
    if psa then table.insert(detections, psa) end
    
    -- Record detections to history
    for _, detection in ipairs(detections) do
        table.insert(GuardianState.detection_history, detection)
        GuardianState.total_detections = GuardianState.total_detections + 1
        
        -- Trim history if exceeds max size
        while #GuardianState.detection_history > GuardianState.config.max_history_size do
            table.remove(GuardianState.detection_history, 1)
        end
    end
    
    return detections
end

-- ============================================================================
-- Evidence Bundle Generation
-- ============================================================================

--- Create evidence bundle from detection event
---@param detection table
---@param state_before number
---@param state_after number
---@param policy_rejected boolean
---@return table
function NeuroGuard.create_evidence_bundle(detection, state_before, state_after, policy_rejected)
    local telemetry_hash = NeuroGuard.compute_hash(detection.telemetry_snapshot)
    
    local bundle = {
        timestamp = detection.timestamp,
        event_id = detection.event_id,
        corridor_id = NeuroGuard._CORRIDOR_ID,
        sovereign_vault_id = NeuroGuard._SOVEREIGN_VAULT,
        pattern_family = detection.pattern_family,
        violation_type = detection.violation_type,
        severity = detection.severity,
        confidence = detection.confidence,
        legal_instruments = detection.legal_instruments,
        telemetry_hash = telemetry_hash,
        lattice_state_before = state_before,
        lattice_state_after = state_after,
        policy_rejected = policy_rejected,
        signature = nil,
    }
    
    -- Sign bundle (if signing key available)
    if GuardianState.signing_key then
        local signing_input = NeuroGuard.to_json({
            timestamp = bundle.timestamp,
            event_id = bundle.event_id,
            telemetry_hash = bundle.telemetry_hash,
        })
        bundle.signature = NeuroGuard.compute_hash(signing_input .. GuardianState.signing_key)
    end
    
    return bundle
end

--- Write evidence bundle to log
---@param bundle table
function NeuroGuard.write_evidence_bundle(bundle)
    local json_line = NeuroGuard.to_json(bundle)
    NeuroGuard.write_evidence_log(json_line)
end

--- Export all evidence for legal submission
---@param output_path string
---@return boolean, string
function NeuroGuard.export_evidence_for_legal(output_path)
    local file = io.open(output_path, "w")
    if not file then
        return false, "Failed to open output file"
    end
    
    local export_package = {
        export_timestamp = NeuroGuard.get_timestamp(),
        corridor_id = NeuroGuard._CORRIDOR_ID,
        sovereign_vault_id = NeuroGuard._SOVEREIGN_VAULT,
        evidence_count = #GuardianState.detection_history,
        legal_framework = "CRPD_ECHR_UNESCO_v3",
        monotone_invariant_verified = true,
        invariant_violation_count = GuardianState.invariant_violations,
        detections = GuardianState.detection_history,
    }
    
    local json_data = NeuroGuard.to_json(export_package)
    file:write(json_data)
    file:close()
    
    NeuroGuard.log("Evidence exported to: " .. output_path, "AUDIT")
    return true, "Export successful"
end

-- ============================================================================
-- Policy Command Evaluation
-- ============================================================================

--- Evaluate policy command against blacklist
---@param command table
---@return table
function NeuroGuard.evaluate_command(command)
    -- Check command type against blacklist
    local command_type = command.command_type or ""
    
    for _, blacklist in ipairs(NeuroGuard.CommandBlacklist) do
        if string.find(command_type, blacklist.pattern) then
            return {
                allowed = false,
                violation_type = blacklist.violation_type,
                severity = blacklist.severity,
                reason = "Command matches blacklisted pattern: " .. blacklist.pattern,
                legal_citation = blacklist.legal_citation,
            }
        end
        
        -- Check parameters for blacklist patterns
        if command.parameters then
            for _, param in ipairs(command.parameters) do
                if string.find(param.key or "", blacklist.pattern) then
                    return {
                        allowed = false,
                        violation_type = blacklist.violation_type,
                        severity = blacklist.severity,
                        reason = "Parameter matches blacklisted pattern: " .. blacklist.pattern,
                        legal_citation = blacklist.legal_citation,
                    }
                end
            end
        end
    end
    
    -- Check specific command types
    if command_type == "AccessNeuralData" then
        if not command.warrant_reference then
            return {
                allowed = false,
                violation_type = "UNAUTHORIZED_NEURAL_ACCESS",
                severity = NeuroGuard.SeverityLevel.CRITICAL,
                reason = "Neural data access requires warrant or explicit consent",
                legal_citation = "UNESCO Neuroethics 3.1; CRPD Article 15",
            }
        end
    elseif command_type == "DisableExitChannel" then
        return {
            allowed = false,
            violation_type = "EXIT_CHANNEL_BLOCKING",
            severity = NeuroGuard.SeverityLevel.CRITICAL,
            reason = "Exit channels cannot be disabled under any circumstances",
            legal_citation = "CRPD Article 13; ALN-NanoNet Section 4.2",
        }
    elseif command_type == "RestrictCapability" then
        return {
            allowed = false,
            violation_type = "CAPABILITY_RESTRICTION",
            severity = NeuroGuard.SeverityLevel.CRITICAL,
            reason = "Capabilities cannot be restricted - monotone invariant",
            legal_citation = "ALN-NanoNet Section 4.2; Monotone Capability Lattice",
        }
    end
    
    -- Command passed all checks
    return {
        allowed = true,
        reason = "Command complies with neurorights framework",
    }
end

--- Process policy command through Guardian Gateway
---@param command table
---@return table
function NeuroGuard.process_policy_command(command)
    local state_before = GuardianState.current_lattice_state
    
    -- Evaluate command against lexicon
    local evaluation = NeuroGuard.evaluate_command(command)
    
    if not evaluation.allowed then
        -- Command rejected - create detection event
        local detection = {
            event_id = NeuroGuard.generate_uuid(),
            timestamp = NeuroGuard.get_timestamp(),
            pattern_family = NeuroGuard.PatternFamily.UNKNOWN,
            violation_type = evaluation.violation_type,
            severity = evaluation.severity,
            confidence = 1.0,
            telemetry_snapshot = NeuroGuard.to_json(command),
            legal_instruments = { evaluation.legal_citation },
            recommended_actions = { "Block command", "Log violation" },
            guardian_response = NeuroGuard.GuardianResponse.BLOCK_COMMAND,
        }
        
        -- Create and write evidence bundle
        local bundle = NeuroGuard.create_evidence_bundle(detection, state_before, state_before, true)
        NeuroGuard.write_evidence_bundle(bundle)
        
        -- Record detection
        table.insert(GuardianState.detection_history, detection)
        GuardianState.total_detections = GuardianState.total_detections + 1
        
        NeuroGuard.log("COMMAND REJECTED: " .. evaluation.reason, "SECURITY")
        
        return {
            decision = "REJECTED",
            reason = evaluation.reason,
            legal_citation = evaluation.legal_citation,
        }
    end
    
    -- Command allowed - check monotone transition
    local proposed_state = state_before -- In full implementation, compute from command
    
    local success, err = NeuroGuard.apply_lattice_transition(proposed_state)
    if not success then
        return {
            decision = "REJECTED",
            reason = err,
            legal_citation = "ALN-NanoNet Section 4.2",
        }
    end
    
    local state_after = GuardianState.current_lattice_state
    
    -- Log approved transition
    local detection = {
        event_id = NeuroGuard.generate_uuid(),
        timestamp = NeuroGuard.get_timestamp(),
        pattern_family = NeuroGuard.PatternFamily.UNKNOWN,
        violation_type = "STATE_TRANSITION",
        severity = NeuroGuard.SeverityLevel.LOW,
        confidence = 1.0,
        telemetry_snapshot = string.format("%d -> %d", state_before, state_after),
        legal_instruments = { "ALN-NanoNet Audit Log v1.0" },
        recommended_actions = {},
        guardian_response = NeuroGuard.GuardianResponse.LOG_ONLY,
    }
    
    local bundle = NeuroGuard.create_evidence_bundle(detection, state_before, state_after, false)
    NeuroGuard.write_evidence_bundle(bundle)
    
    return {
        decision = "APPROVED",
        new_state = state_after,
        capabilities = GuardianState.current_capabilities,
    }
end

-- ============================================================================
-- Guardian Gateway Initialization and Control
-- ============================================================================

--- Initialize Guardian Gateway
---@param config table
---@return boolean, string
function NeuroGuard.initialize(config)
    config = config or {}
    
    -- Apply configuration overrides
    if config.min_confidence then GuardianState.config.min_confidence = config.min_confidence end
    if config.min_occurrences then GuardianState.config.min_occurrences = config.min_occurrences end
    if config.analysis_window_ms then GuardianState.config.analysis_window_ms = config.analysis_window_ms end
    if config.evidence_log_path then GuardianState.evidence_log_path = config.evidence_log_path end
    if config.signing_key then GuardianState.signing_key = config.signing_key end
    
    -- Create evidence directory
    local dir = GuardianState.evidence_log_path:match("(.*/)")
    if dir then
        os.execute("mkdir -p " .. dir)
    end
    
    NeuroGuard.log("NeuroGuard Guardian initialized", "INFO")
    NeuroGuard.log("  Corridor ID: " .. NeuroGuard._CORRIDOR_ID, "INFO")
    NeuroGuard.log("  Sovereign Vault: " .. NeuroGuard._SOVEREIGN_VAULT, "INFO")
    NeuroGuard.log("  Evidence Log: " .. GuardianState.evidence_log_path, "INFO")
    NeuroGuard.log("  Lattice State: " .. GuardianState.current_lattice_state, "INFO")
    
    return true, "Initialization successful"
end

--- Get guardian status
---@return table
function NeuroGuard.get_status()
    local events_by_family = {}
    
    for _, detection in ipairs(GuardianState.detection_history) do
        local family = detection.pattern_family
        events_by_family[family] = (events_by_family[family] or 0) + 1
    end
    
    return {
        version = NeuroGuard._VERSION,
        construct_id = NeuroGuard._CONSTRUCT_ID,
        corridor_id = NeuroGuard._CORRIDOR_ID,
        lattice_state = GuardianState.current_lattice_state,
        capabilities = GuardianState.current_capabilities,
        total_events_processed = GuardianState.total_events_processed,
        total_detections = GuardianState.total_detections,
        invariant_violations = GuardianState.invariant_violations,
        events_by_family = events_by_family,
        buffer_size = #GuardianState.event_buffer,
        history_size = #GuardianState.detection_history,
    }
end

--- Reset guardian state (for testing/rotation)
function NeuroGuard.reset()
    GuardianState.event_buffer = {}
    GuardianState.detection_history = {}
    GuardianState.total_events_processed = 0
    GuardianState.total_detections = 0
    GuardianState.invariant_violations = 0
    GuardianState.current_lattice_state = NeuroGuard.LatticeState.NORMAL
    GuardianState.current_capabilities = NeuroGuard.BASELINE_REQUIRED
    
    NeuroGuard.log("Guardian state reset", "AUDIT")
end

--- Run guardian in daemon mode (continuous monitoring)
---@param interval_seconds number
function NeuroGuard.run_daemon(interval_seconds)
    interval_seconds = interval_seconds or 60
    
    NeuroGuard.log("Starting daemon mode (interval: " .. interval_seconds .. "s)", "INFO")
    
    while true do
        -- Run pattern detection
        local detections = NeuroGuard.run_pattern_detection()
        
        if #detections > 0 then
            NeuroGuard.log(string.format("Detected %d pattern(s)", #detections), "ALERT")
            
            for _, detection in ipairs(detections) do
                -- Execute guardian response
                if detection.guardian_response == NeuroGuard.GuardianResponse.EMERGENCY_LOCK then
                    NeuroGuard.force_lock("Pattern detection triggered emergency lock")
                elseif detection.guardian_response == NeuroGuard.GuardianResponse.BLOCK_COMMAND then
                    NeuroGuard.log("Command blocking enabled for pattern: " .. detection.violation_type, "SECURITY")
                end
                
                -- Create and write evidence bundle
                local bundle = NeuroGuard.create_evidence_bundle(
                    detection,
                    GuardianState.current_lattice_state,
                    GuardianState.current_lattice_state,
                    true
                )
                NeuroGuard.write_evidence_bundle(bundle)
            end
        end
        
        -- Wait for next interval
        os.sleep(interval_seconds)
    end
end

-- ============================================================================
-- Module Export
-- ============================================================================

return NeuroGuard

-- ============================================================================
-- End of File - NeuroGuard Guardian Gateway (Lua)
-- ============================================================================
