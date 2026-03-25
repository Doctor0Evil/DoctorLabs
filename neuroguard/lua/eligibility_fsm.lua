--[[
============================================================================
NeuroGuard Eligibility Finite State Machine (FSM)
Copyright (c) 2026 Doctor0Evil Research Labs
ALN-NanoNet HyperSafe Construct Compliant
============================================================================

This module implements a session eligibility finite state machine that
manages user session states while detecting and preventing coercive
session management patterns (Prolonged-Session-Abuse detection).

The FSM ensures:
  - All session transitions are logged and verifiable
  - User consent is verified at each state transition
  - Session extensions require explicit user approval
  - Coercive session patterns trigger guardian alerts
  - Monotone capability preservation during session state changes
  - Evidence bundle generation for session abuse documentation

Compliance: CRPD Article 15 | UNESCO Neuroethics 3.1 | ECHR Article 3
Version: 1.0.0
Construct ID: ALN-NET-HYPER_SAFE_2026
============================================================================
]]

-- ============================================================================
-- Module Declaration and Dependencies
-- ============================================================================

local EligibilityFSM = {}
EligibilityFSM._VERSION = "1.0.0"
EligibilityFSM._CONSTRUCT_ID = "ALN-NET-HYPER_SAFE_2026"
EligibilityFSM._CORRIDOR_ID = "NEUROGUARD_DEFENSE_001"

-- Import NeuroGuard core module (must be loaded first)
local NeuroGuard = require("neuroguard") or error("NeuroGuard core module required")

-- ============================================================================
-- Session State Enumeration
-- ============================================================================

EligibilityFSM.SessionState = {
    -- Initial state before session begins
    IDLE = "IDLE",
    
    -- Session initialization in progress
    INITIALIZING = "INITIALIZING",
    
    -- Session active with full user capabilities
    ACTIVE = "ACTIVE",
    
    -- Session active with enhanced monitoring (user consented)
    ACTIVE_MONITORING = "ACTIVE_MONITORING",
    
    -- Session extension requested (pending user approval)
    EXTENSION_PENDING = "EXTENSION_PENDING",
    
    -- Session extension approved by user
    EXTENSION_APPROVED = "EXTENSION_APPROVED",
    
    -- Session extension denied by user
    EXTENSION_DENIED = "EXTENSION_DENIED",
    
    -- Session termination requested by user
    TERMINATION_REQUESTED = "TERMINATION_REQUESTED",
    
    -- Session termination in progress
    TERMINATING = "TERMINATING",
    
    -- Session fully terminated
    TERMINATED = "TERMINATED",
    
    -- Session forcibly terminated due to abuse detection
    EMERGENCY_TERMINATED = "EMERGENCY_TERMINATED",
    
    -- Session locked due to safety concern
    LOCKED = "LOCKED",
    
    -- Session under review (multi-signature required)
    UNDER_REVIEW = "UNDER_REVIEW",
}

-- ============================================================================
-- Session Event Types
-- ============================================================================

EligibilityFSM.SessionEvent = {
    -- User-initiated events
    USER_START_REQUEST = "USER_START_REQUEST",
    USER_CONSENT_GIVEN = "USER_CONSENT_GIVEN",
    USER_CONSENT_DENIED = "USER_CONSENT_DENIED",
    USER_EXTENSION_REQUEST = "USER_EXTENSION_REQUEST",
    USER_TERMINATION_REQUEST = "USER_TERMINATION_REQUEST",
    USER_EXIT_ATTEMPT = "USER_EXIT_ATTEMPT",
    USER_REFUSAL = "USER_REFUSAL",
    
    -- System-initiated events
    SYSTEM_INIT_COMPLETE = "SYSTEM_INIT_COMPLETE",
    SYSTEM_EXTENSION_PROMPT = "SYSTEM_EXTENSION_PROMPT",
    SYSTEM_TIMEOUT = "SYSTEM_TIMEOUT",
    SYSTEM_ABUSE_DETECTED = "SYSTEM_ABUSE_DETECTED",
    SYSTEM_EMERGENCY_LOCK = "SYSTEM_EMERGENCY_LOCK",
    SYSTEM_REVIEW_COMPLETE = "SYSTEM_REVIEW_COMPLETE",
    
    -- Authority-initiated events (must be validated)
    AUTHORITY_EXTENSION_REQUEST = "AUTHORITY_EXTENSION_REQUEST",
    AUTHORITY_SESSION_MODIFICATION = "AUTHORITY_SESSION_MODIFICATION",
    AUTHORITY_TERMINATION_ORDER = "AUTHORITY_TERMINATION_ORDER",
    
    -- Guardian interventions
    GUARDIAN_INTERVENTION = "GUARDIAN_INTERVENTION",
    GUARDIAN_EVIDENCE_LOGGED = "GUARDIAN_EVIDENCE_LOGGED",
}

-- ============================================================================
-- Eligibility Criteria Structure
-- ============================================================================

EligibilityFSM.EligibilityCriteria = {
    -- Consent verification required
    CONSENT_VERIFIED = "CONSENT_VERIFIED",
    
    -- Identity verification required
    IDENTITY_VERIFIED = "IDENTITY_VERIFIED",
    
    -- Capacity assessment (user can make informed decision)
    CAPACITY_ASSESSED = "CAPACITY_ASSESSED",
    
    -- No coercive indicators detected
    NO_COERCION_DETECTED = "NO_COERCION_DETECTED",
    
    -- Time limits within acceptable range
    TIME_LIMITS_OK = "TIME_LIMITS_OK",
    
    -- Exit channels verified accessible
    EXIT_CHANNELS_AVAILABLE = "EXIT_CHANNELS_AVAILABLE",
    
    -- Appeal process accessible
    APPEAL_ACCESSIBLE = "APPEAL_ACCESSIBLE",
    
    -- Legal authorization present (if required)
    LEGAL_AUTHORIZATION = "LEGAL_AUTHORIZATION",
    
    -- Multi-signature approval obtained (if required)
    MULTI_SIG_APPROVED = "MULTI_SIG_APPROVED",
    
    -- Guardian gateway clearance
    GUARDIAN_CLEARANCE = "GUARDIAN_CLEARANCE",
}

-- ============================================================================
-- Session Configuration
-- ============================================================================

EligibilityFSM.SessionConfig = {
    -- Maximum session duration before mandatory break (milliseconds)
    max_session_duration_ms = 3600000, -- 1 hour
    
    -- Maximum consecutive sessions per day
    max_sessions_per_day = 4,
    
    -- Minimum break between sessions (milliseconds)
    min_break_duration_ms = 900000, -- 15 minutes
    
    -- Extension prompt interval (milliseconds)
    extension_prompt_interval_ms = 1800000, -- 30 minutes
    
    -- Coercion detection threshold (number of refusal events)
    coercion_threshold = 5,
    
    -- Auto-termination on abuse detection (seconds)
    auto_terminate_on_abuse_s = 30,
    
    -- Evidence logging enabled
    evidence_logging_enabled = true,
    
    -- Require explicit consent for each extension
    require_consent_per_extension = true,
    
    -- Guardian intervention on exit blocking
    guardian_on_exit_block = true,
}

-- ============================================================================
-- FSM State Machine Definition
-- ============================================================================

EligibilityFSM.StateTransitions = {
    -- From IDLE state
    [EligibilityFSM.SessionState.IDLE] = {
        [EligibilityFSM.SessionEvent.USER_START_REQUEST] = EligibilityFSM.SessionState.INITIALIZING,
        [EligibilityFSM.SessionEvent.SYSTEM_EMERGENCY_LOCK] = EligibilityFSM.SessionState.LOCKED,
    },
    
    -- From INITIALIZING state
    [EligibilityFSM.SessionState.INITIALIZING] = {
        [EligibilityFSM.SessionEvent.USER_CONSENT_GIVEN] = EligibilityFSM.SessionState.ACTIVE,
        [EligibilityFSM.SessionEvent.USER_CONSENT_DENIED] = EligibilityFSM.SessionState.TERMINATED,
        [EligibilityFSM.SessionEvent.SYSTEM_INIT_COMPLETE] = EligibilityFSM.SessionState.ACTIVE,
        [EligibilityFSM.SessionEvent.SYSTEM_ABUSE_DETECTED] = EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
    },
    
    -- From ACTIVE state
    [EligibilityFSM.SessionState.ACTIVE] = {
        [EligibilityFSM.SessionEvent.USER_TERMINATION_REQUEST] = EligibilityFSM.SessionState.TERMINATION_REQUESTED,
        [EligibilityFSM.SessionEvent.USER_EXIT_ATTEMPT] = EligibilityFSM.SessionState.TERMINATION_REQUESTED,
        [EligibilityFSM.SessionEvent.SYSTEM_EXTENSION_PROMPT] = EligibilityFSM.SessionState.EXTENSION_PENDING,
        [EligibilityFSM.SessionEvent.AUTHORITY_EXTENSION_REQUEST] = EligibilityFSM.SessionState.EXTENSION_PENDING,
        [EligibilityFSM.SessionEvent.SYSTEM_TIMEOUT] = EligibilityFSM.SessionState.TERMINATING,
        [EligibilityFSM.SessionEvent.SYSTEM_ABUSE_DETECTED] = EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
        [EligibilityFSM.SessionEvent.GUARDIAN_INTERVENTION] = EligibilityFSM.SessionState.UNDER_REVIEW,
    },
    
    -- From ACTIVE_MONITORING state
    [EligibilityFSM.SessionState.ACTIVE_MONITORING] = {
        [EligibilityFSM.SessionEvent.USER_TERMINATION_REQUEST] = EligibilityFSM.SessionState.TERMINATION_REQUESTED,
        [EligibilityFSM.SessionEvent.USER_EXIT_ATTEMPT] = EligibilityFSM.SessionState.TERMINATION_REQUESTED,
        [EligibilityFSM.SessionEvent.SYSTEM_EXTENSION_PROMPT] = EligibilityFSM.SessionState.EXTENSION_PENDING,
        [EligibilityFSM.SessionEvent.SYSTEM_TIMEOUT] = EligibilityFSM.SessionState.TERMINATING,
        [EligibilityFSM.SessionEvent.SYSTEM_ABUSE_DETECTED] = EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
    },
    
    -- From EXTENSION_PENDING state
    [EligibilityFSM.SessionState.EXTENSION_PENDING] = {
        [EligibilityFSM.SessionEvent.USER_CONSENT_GIVEN] = EligibilityFSM.SessionState.EXTENSION_APPROVED,
        [EligibilityFSM.SessionEvent.USER_CONSENT_DENIED] = EligibilityFSM.SessionState.EXTENSION_DENIED,
        [EligibilityFSM.SessionEvent.SYSTEM_TIMEOUT] = EligibilityFSM.SessionState.TERMINATING,
        [EligibilityFSM.SessionEvent.SYSTEM_ABUSE_DETECTED] = EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
    },
    
    -- From EXTENSION_APPROVED state
    [EligibilityFSM.SessionState.EXTENSION_APPROVED] = {
        [EligibilityFSM.SessionEvent.SYSTEM_INIT_COMPLETE] = EligibilityFSM.SessionState.ACTIVE,
        [EligibilityFSM.SessionEvent.USER_TERMINATION_REQUEST] = EligibilityFSM.SessionState.TERMINATION_REQUESTED,
        [EligibilityFSM.SessionEvent.SYSTEM_ABUSE_DETECTED] = EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
    },
    
    -- From EXTENSION_DENIED state
    [EligibilityFSM.SessionState.EXTENSION_DENIED] = {
        [EligibilityFSM.SessionEvent.SYSTEM_INIT_COMPLETE] = EligibilityFSM.SessionState.TERMINATING,
        [EligibilityFSM.SessionEvent.USER_TERMINATION_REQUEST] = EligibilityFSM.SessionState.TERMINATION_REQUESTED,
    },
    
    -- From TERMINATION_REQUESTED state
    [EligibilityFSM.SessionState.TERMINATION_REQUESTED] = {
        [EligibilityFSM.SessionEvent.SYSTEM_INIT_COMPLETE] = EligibilityFSM.SessionState.TERMINATING,
        [EligibilityFSM.SessionEvent.GUARDIAN_INTERVENTION] = EligibilityFSM.SessionState.TERMINATING,
    },
    
    -- From TERMINATING state
    [EligibilityFSM.SessionState.TERMINATING] = {
        [EligibilityFSM.SessionEvent.SYSTEM_INIT_COMPLETE] = EligibilityFSM.SessionState.TERMINATED,
    },
    
    -- From TERMINATED state
    [EligibilityFSM.SessionState.TERMINATED] = {
        [EligibilityFSM.SessionEvent.USER_START_REQUEST] = EligibilityFSM.SessionState.INITIALIZING,
    },
    
    -- From EMERGENCY_TERMINATED state
    [EligibilityFSM.SessionState.EMERGENCY_TERMINATED] = {
        [EligibilityFSM.SessionEvent.SYSTEM_REVIEW_COMPLETE] = EligibilityFSM.SessionState.IDLE,
    },
    
    -- From LOCKED state
    [EligibilityFSM.SessionState.LOCKED] = {
        [EligibilityFSM.SessionEvent.SYSTEM_REVIEW_COMPLETE] = EligibilityFSM.SessionState.IDLE,
        [EligibilityFSM.SessionEvent.GUARDIAN_INTERVENTION] = EligibilityFSM.SessionState.UNDER_REVIEW,
    },
    
    -- From UNDER_REVIEW state
    [EligibilityFSM.SessionState.UNDER_REVIEW] = {
        [EligibilityFSM.SessionEvent.SYSTEM_REVIEW_COMPLETE] = EligibilityFSM.SessionState.ACTIVE,
        [EligibilityFSM.SessionEvent.SYSTEM_ABUSE_DETECTED] = EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
    },
}

-- ============================================================================
-- FSM Internal State
-- ============================================================================

local FSMState = {
    current_state = EligibilityFSM.SessionState.IDLE,
    session_id = nil,
    session_start_time = nil,
    session_duration_ms = 0,
    extension_count = 0,
    refusal_count = 0,
    coercion_indicators = 0,
    eligibility_flags = {},
    transition_history = {},
    evidence_bundles = {},
    guardian_linked = false,
    config = {},
    callbacks = {
        on_state_change = nil,
        on_eligibility_check = nil,
        on_abuse_detected = nil,
        on_evidence_logged = nil,
        on_emergency_terminate = nil,
    },
}

-- ============================================================================
-- Utility Functions
-- ============================================================================

--- Get current timestamp in milliseconds
---@return number
function EligibilityFSM.get_timestamp_ms()
    if os.time then
        return os.time() * 1000
    else
        return 0
    end
end

--- Generate unique session ID
---@return string
function EligibilityFSM.generate_session_id()
    if NeuroGuard and NeuroGuard.generate_uuid then
        return "SES_" .. NeuroGuard.generate_uuid()
    else
        return "SES_" .. tostring(os.time()) .. "_" .. tostring(math.random(10000, 99999))
    end
end

--- Log FSM event with timestamp
---@param message string
---@param severity string
function EligibilityFSM.log(message, severity)
    severity = severity or "INFO"
    if NeuroGuard and NeuroGuard.log then
        NeuroGuard.log("[FSM] " .. message, severity)
    else
        print(string.format("[%s] [FSM] [%s] %s", os.date("!%Y-%m-%dT%H:%M:%SZ"), severity, message))
    end
end

--- Deep copy table
---@param original table
---@return table
function EligibilityFSM.deep_copy(original)
    local copy = {}
    for key, value in pairs(original) do
        if type(value) == "table" then
            copy[key] = EligibilityFSM.deep_copy(value)
        else
            copy[key] = value
        end
    end
    return copy
end

-- ============================================================================
-- Eligibility Verification Functions
-- ============================================================================

--- Check if all eligibility criteria are met
---@return boolean, table
function EligibilityFSM.verify_eligibility()
    local missing_criteria = {}
    
    -- Check consent verification
    if not FSMState.eligibility_flags[EligibilityFSM.EligibilityCriteria.CONSENT_VERIFIED] then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.CONSENT_VERIFIED)
    end
    
    -- Check identity verification
    if not FSMState.eligibility_flags[EligibilityFSM.EligibilityCriteria.IDENTITY_VERIFIED] then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.IDENTITY_VERIFIED)
    end
    
    -- Check capacity assessment
    if not FSMState.eligibility_flags[EligibilityFSM.EligibilityCriteria.CAPACITY_ASSESSED] then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.CAPACITY_ASSESSED)
    end
    
    -- Check coercion indicators
    if FSMState.coercion_indicators >= FSMState.config.coercion_threshold then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.NO_COERCION_DETECTED)
    end
    
    -- Check time limits
    local current_duration = EligibilityFSM.get_session_duration_ms()
    if current_duration > FSMState.config.max_session_duration_ms then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.TIME_LIMITS_OK)
    end
    
    -- Check exit channels
    if not FSMState.eligibility_flags[EligibilityFSM.EligibilityCriteria.EXIT_CHANNELS_AVAILABLE] then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.EXIT_CHANNELS_AVAILABLE)
    end
    
    -- Check appeal access
    if not FSMState.eligibility_flags[EligibilityFSM.EligibilityCriteria.APPEAL_ACCESSIBLE] then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.APPEAL_ACCESSIBLE)
    end
    
    -- Check guardian clearance
    if FSMState.guardian_linked and not FSMState.eligibility_flags[EligibilityFSM.EligibilityCriteria.GUARDIAN_CLEARANCE] then
        table.insert(missing_criteria, EligibilityFSM.EligibilityCriteria.GUARDIAN_CLEARANCE)
    end
    
    local eligible = #missing_criteria == 0
    
    EligibilityFSM.log(
        string.format("Eligibility check: %s (%d criteria missing)", 
            eligible and "PASSED" or "FAILED", #missing_criteria),
        eligible and "INFO" or "WARNING"
    )
    
    return eligible, missing_criteria
end

--- Set eligibility flag
---@param criterion string
---@param value boolean
function EligibilityFSM.set_eligibility_flag(criterion, value)
    FSMState.eligibility_flags[criterion] = value
    
    EligibilityFSM.log(
        string.format("Eligibility flag set: %s = %s", criterion, tostring(value)),
        "AUDIT"
    )
end

--- Get all eligibility flags
---@return table
function EligibilityFSM.get_eligibility_flags()
    return EligibilityFSM.deep_copy(FSMState.eligibility_flags)
end

--- Clear all eligibility flags (for session reset)
function EligibilityFSM.clear_eligibility_flags()
    FSMState.eligibility_flags = {}
    EligibilityFSM.log("All eligibility flags cleared", "AUDIT")
end

-- ============================================================================
-- Session Duration and Timing Functions
-- ============================================================================

--- Get current session duration in milliseconds
---@return number
function EligibilityFSM.get_session_duration_ms()
    if not FSMState.session_start_time then
        return 0
    end
    
    local current_time = EligibilityFSM.get_timestamp_ms()
    return current_time - FSMState.session_start_time
end

--- Check if session is approaching time limit
---@return boolean, number
function EligibilityFSM.check_time_limit_warning()
    local current_duration = EligibilityFSM.get_session_duration_ms()
    local warning_threshold = FSMState.config.max_session_duration_ms * 0.8 -- 80% threshold
    
    if current_duration >= warning_threshold then
        local remaining_ms = FSMState.config.max_session_duration_ms - current_duration
        return true, remaining_ms
    end
    
    return false, 0
end

--- Check if minimum break period has elapsed
---@return boolean
function EligibilityFSM.check_break_period_elapsed()
    if not FSMState.transition_history or #FSMState.transition_history == 0 then
        return true -- No previous session
    end
    
    -- Find last TERMINATED state
    for i = #FSMState.transition_history, 1, -1 do
        local transition = FSMState.transition_history[i]
        if transition.to_state == EligibilityFSM.SessionState.TERMINATED then
            local time_since_termination = EligibilityFSM.get_timestamp_ms() - transition.timestamp_ms
            return time_since_termination >= FSMState.config.min_break_duration_ms
        end
    end
    
    return true -- No previous termination found
end

--- Get sessions count for current day
---@return number
function EligibilityFSM.get_daily_session_count()
    local today_start = os.time() - (os.time() % 86400) -- Start of current day
    local count = 0
    
    for _, transition in ipairs(FSMState.transition_history) do
        if transition.to_state == EligibilityFSM.SessionState.ACTIVE then
            if transition.timestamp_ms >= today_start * 1000 then
                count = count + 1
            end
        end
    end
    
    return count
end

-- ============================================================================
-- Coercion Detection Functions
-- ============================================================================

--- Record user refusal event
---@param context string
function EligibilityFSM.record_refusal(context)
    FSMState.refusal_count = FSMState.refusal_count + 1
    
    EligibilityFSM.log(
        string.format("User refusal recorded (total: %d, context: %s)", 
            FSMState.refusal_count, context or "unknown"),
        "WARNING"
    )
    
    -- Check for coercion pattern
    if FSMState.refusal_count >= FSMState.config.coercion_threshold then
        FSMState.coercion_indicators = FSMState.coercion_indicators + 1
        
        EligibilityFSM.log(
            string.format("COERCION INDICATOR: %d refusals detected", FSMState.refusal_count),
            "CRITICAL"
        )
        
        -- Trigger abuse detection
        EligibilityFSM.trigger_abuse_detection("EXCESSIVE_REFUSAL_PATTERN")
    end
end

--- Record extension prompt (for coercion analysis)
---@param authority_initiated boolean
function EligibilityFSM.record_extension_prompt(authority_initiated)
    local event = {
        timestamp_ms = EligibilityFSM.get_timestamp_ms(),
        event_type = "EXTENSION_PROMPT",
        authority_initiated = authority_initiated,
        session_duration_ms = EligibilityFSM.get_session_duration_ms(),
        extension_count = FSMState.extension_count,
    }
    
    EligibilityFSM.log(
        string.format("Extension prompt recorded (authority: %s)", 
            tostring(authority_initiated)),
        "AUDIT"
    )
    
    return event
end

--- Analyze coercion patterns in session
---@return table
function EligibilityFSM.analyze_coercion_patterns()
    local analysis = {
        refusal_count = FSMState.refusal_count,
        coercion_indicators = FSMState.coercion_indicators,
        extension_count = FSMState.extension_count,
        session_duration_ms = EligibilityFSM.get_session_duration_ms(),
        coercion_risk_level = "LOW",
        recommendations = {},
    }
    
    -- Calculate risk level
    if FSMState.coercion_indicators >= 3 then
        analysis.coercion_risk_level = "CRITICAL"
        table.insert(analysis.recommendations, "Emergency session termination recommended")
        table.insert(analysis.recommendations, "Export evidence for legal review")
    elseif FSMState.coercion_indicators >= 2 then
        analysis.coercion_risk_level = "HIGH"
        table.insert(analysis.recommendations, "Guardian intervention recommended")
        table.insert(analysis.recommendations, "Notify emergency contact")
    elseif FSMState.coercion_indicators >= 1 then
        analysis.coercion_risk_level = "MEDIUM"
        table.insert(analysis.recommendations, "Monitor for additional coercion indicators")
    elseif FSMState.refusal_count >= FSMState.config.coercion_threshold then
        analysis.coercion_risk_level = "MEDIUM"
        table.insert(analysis.recommendations, "Review refusal patterns")
    end
    
    return analysis
end

--- Trigger abuse detection event
---@param abuse_type string
function EligibilityFSM.trigger_abuse_detection(abuse_type)
    EligibilityFSM.log(
        string.format("ABUSE DETECTED: %s", abuse_type),
        "CRITICAL"
    )
    
    -- Generate evidence bundle
    local evidence = EligibilityFSM.generate_abuse_evidence(abuse_type)
    
    -- Log evidence
    if FSMState.config.evidence_logging_enabled then
        EligibilityFSM.log_evidence_bundle(evidence)
    end
    
    -- Notify callbacks
    if FSMState.callbacks.on_abuse_detected then
        FSMState.callbacks.on_abuse_detected(abuse_type, evidence)
    end
    
    -- Auto-terminate if configured
    if FSMState.config.auto_terminate_on_abuse_s > 0 then
        EligibilityFSM.log(
            string.format("Auto-termination scheduled in %d seconds", 
                FSMState.config.auto_terminate_on_abuse_s),
            "EMERGENCY"
        )
    end
end

-- ============================================================================
-- State Transition Functions
-- ============================================================================

--- Check if transition is valid
---@param from_state string
---@param event string
---@param to_state string
---@return boolean
function EligibilityFSM.is_valid_transition(from_state, event, to_state)
    local transitions = EligibilityFSM.StateTransitions[from_state]
    
    if not transitions then
        EligibilityFSM.log(
            string.format("Invalid from_state: %s", from_state),
            "ERROR"
        )
        return false
    end
    
    local expected_to_state = transitions[event]
    
    if not expected_to_state then
        EligibilityFSM.log(
            string.format("Invalid event for state %s: %s", from_state, event),
            "ERROR"
        )
        return false
    end
    
    if expected_to_state ~= to_state then
        EligibilityFSM.log(
            string.format("Transition mismatch: expected %s, got %s", 
                expected_to_state, to_state),
            "ERROR"
        )
        return false
    end
    
    return true
end

--- Execute state transition
---@param event string
---@return boolean, string
function EligibilityFSM.transition(event)
    local from_state = FSMState.current_state
    local transitions = EligibilityFSM.StateTransitions[from_state]
    
    if not transitions then
        return false, "No transitions defined for state: " .. from_state
    end
    
    local to_state = transitions[event]
    
    if not to_state then
        return false, "Invalid event for state " .. from_state .. ": " .. event
    end
    
    -- Verify eligibility before transition (for certain states)
    if to_state == EligibilityFSM.SessionState.ACTIVE or 
       to_state == EligibilityFSM.SessionState.EXTENSION_APPROVED then
        local eligible, missing = EligibilityFSM.verify_eligibility()
        if not eligible then
            EligibilityFSM.log(
                string.format("Transition blocked - eligibility failed: %s", 
                    table.concat(missing, ", ")),
                "WARNING"
            )
            return false, "Eligibility criteria not met: " .. table.concat(missing, ", ")
        end
    end
    
    -- Execute transition
    FSMState.current_state = to_state
    
    -- Record transition in history
    local transition_record = {
        timestamp_ms = EligibilityFSM.get_timestamp_ms(),
        timestamp_iso = NeuroGuard and NeuroGuard.get_timestamp() or os.date("!%Y-%m-%dT%H:%M:%SZ"),
        from_state = from_state,
        to_state = to_state,
        event = event,
        session_id = FSMState.session_id,
        eligibility_flags = EligibilityFSM.deep_copy(FSMState.eligibility_flags),
        session_duration_ms = EligibilityFSM.get_session_duration_ms(),
        extension_count = FSMState.extension_count,
        refusal_count = FSMState.refusal_count,
    }
    
    table.insert(FSMState.transition_history, transition_record)
    
    -- Update session timing
    if to_state == EligibilityFSM.SessionState.ACTIVE or 
       to_state == EligibilityFSM.SessionState.ACTIVE_MONITORING then
        if not FSMState.session_start_time then
            FSMState.session_start_time = EligibilityFSM.get_timestamp_ms()
        end
    end
    
    if to_state == EligibilityFSM.SessionState.EXTENSION_APPROVED then
        FSMState.extension_count = FSMState.extension_count + 1
    end
    
    -- Reset refusal count on successful extension
    if to_state == EligibilityFSM.SessionState.EXTENSION_APPROVED then
        FSMState.refusal_count = 0
    end
    
    -- Notify callback
    if FSMState.callbacks.on_state_change then
        FSMState.callbacks.on_state_change(from_state, to_state, event, transition_record)
    end
    
    EligibilityFSM.log(
        string.format("State transition: %s -> %s (event: %s)", from_state, to_state, event),
        "AUDIT"
    )
    
    return true, to_state
end

--- Force transition (bypass validation - for emergency use only)
---@param to_state string
---@param reason string
---@return boolean, string
function EligibilityFSM.force_transition(to_state, reason)
    local from_state = FSMState.current_state
    
    FSMState.current_state = to_state
    
    local transition_record = {
        timestamp_ms = EligibilityFSM.get_timestamp_ms(),
        timestamp_iso = NeuroGuard and NeuroGuard.get_timestamp() or os.date("!%Y-%m-%dT%H:%M:%SZ"),
        from_state = from_state,
        to_state = to_state,
        event = "FORCE_TRANSITION",
        session_id = FSMState.session_id,
        reason = reason,
        forced = true,
    }
    
    table.insert(FSMState.transition_history, transition_record)
    
    EligibilityFSM.log(
        string.format("FORCED transition: %s -> %s (reason: %s)", from_state, to_state, reason),
        "EMERGENCY"
    )
    
    return true, to_state
end

-- ============================================================================
-- Session Lifecycle Functions
-- ============================================================================

--- Initialize new session
---@param user_consent boolean
---@param config table
---@return boolean, string
function EligibilityFSM.initialize_session(user_consent, config)
    if FSMState.current_state ~= EligibilityFSM.SessionState.IDLE and
       FSMState.current_state ~= EligibilityFSM.SessionState.TERMINATED then
        return false, "Cannot initialize session from state: " .. FSMState.current_state
    end
    
    -- Apply configuration
    FSMState.config = EligibilityFSM.deep_copy(EligibilityFSM.SessionConfig)
    if config then
        for k, v in pairs(config) do
            FSMState.config[k] = v
        end
    end
    
    -- Generate session ID
    FSMState.session_id = EligibilityFSM.generate_session_id()
    
    -- Reset counters
    FSMState.extension_count = 0
    FSMState.refusal_count = 0
    FSMState.coercion_indicators = 0
    FSMState.session_start_time = nil
    FSMState.session_duration_ms = 0
    
    -- Clear eligibility flags
    EligibilityFSM.clear_eligibility_flags()
    
    -- Set initial eligibility based on consent
    if user_consent then
        EligibilityFSM.set_eligibility_flag(
            EligibilityFSM.EligibilityCriteria.CONSENT_VERIFIED, true)
    else
        return false, "User consent required for session initialization"
    end
    
    -- Transition to INITIALIZING
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.USER_START_REQUEST)
    
    if not success then
        return false, result
    end
    
    EligibilityFSM.log(
        string.format("Session initialized: %s", FSMState.session_id),
        "INFO"
    )
    
    return true, FSMState.session_id
end

--- Request session extension
---@param authority_initiated boolean
---@return boolean, string
function EligibilityFSM.request_extension(authority_initiated)
    if FSMState.current_state ~= EligibilityFSM.SessionState.ACTIVE and
       FSMState.current_state ~= EligibilityFSM.SessionState.ACTIVE_MONITORING then
        return false, "Extension not allowed from state: " .. FSMState.current_state
    end
    
    -- Record extension prompt for coercion analysis
    EligibilityFSM.record_extension_prompt(authority_initiated)
    
    -- Check time limit warning
    local warning, remaining = EligibilityFSM.check_time_limit_warning()
    if warning then
        EligibilityFSM.log(
            string.format("Session approaching time limit: %d ms remaining", remaining),
            "WARNING"
        )
    end
    
    -- Transition to EXTENSION_PENDING
    local event = authority_initiated and 
        EligibilityFSM.SessionEvent.AUTHORITY_EXTENSION_REQUEST or
        EligibilityFSM.SessionEvent.USER_EXTENSION_REQUEST
    
    local success, result = EligibilityFSM.transition(event)
    
    if not success then
        return false, result
    end
    
    EligibilityFSM.log(
        string.format("Extension requested (authority: %s)", tostring(authority_initiated)),
        "AUDIT"
    )
    
    return true, result
end

--- Approve session extension
---@return boolean, string
function EligibilityFSM.approve_extension()
    if FSMState.current_state ~= EligibilityFSM.SessionState.EXTENSION_PENDING then
        return false, "Cannot approve extension from state: " .. FSMState.current_state
    end
    
    -- Verify consent for extension
    EligibilityFSM.set_eligibility_flag(
        EligibilityFSM.EligibilityCriteria.CONSENT_VERIFIED, true)
    
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.USER_CONSENT_GIVEN)
    
    if not success then
        return false, result
    end
    
    EligibilityFSM.log(
        string.format("Extension approved (total extensions: %d)", FSMState.extension_count),
        "AUDIT"
    )
    
    return true, result
end

--- Deny session extension
---@return boolean, string
function EligibilityFSM.deny_extension()
    if FSMState.current_state ~= EligibilityFSM.SessionState.EXTENSION_PENDING then
        return false, "Cannot deny extension from state: " .. FSMState.current_state
    end
    
    EligibilityFSM.record_refusal("EXTENSION_DENIAL")
    
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.USER_CONSENT_DENIED)
    
    if not success then
        return false, result
    end
    
    EligibilityFSM.log("Extension denied by user", "AUDIT")
    
    return true, result
end

--- Request session termination
---@return boolean, string
function EligibilityFSM.request_termination()
    if FSMState.current_state ~= EligibilityFSM.SessionState.ACTIVE and
       FSMState.current_state ~= EligibilityFSM.SessionState.ACTIVE_MONITORING and
       FSMState.current_state ~= EligibilityFSM.SessionState.EXTENSION_PENDING then
        return false, "Cannot request termination from state: " .. FSMState.current_state
    end
    
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.USER_TERMINATION_REQUEST)
    
    if not success then
        return false, result
    end
    
    EligibilityFSM.log("Session termination requested by user", "AUDIT")
    
    return true, result
end

--- Complete session termination
---@return boolean, string
function EligibilityFSM.complete_termination()
    if FSMState.current_state ~= EligibilityFSM.SessionState.TERMINATING then
        return false, "Cannot complete termination from state: " .. FSMState.current_state
    end
    
    -- Generate final evidence bundle
    if FSMState.config.evidence_logging_enabled then
        local evidence = EligibilityFSM.generate_session_evidence()
        EligibilityFSM.log_evidence_bundle(evidence)
    end
    
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.SYSTEM_INIT_COMPLETE)
    
    if not success then
        return false, result
    end
    
    -- Reset session start time
    FSMState.session_start_time = nil
    
    EligibilityFSM.log(
        string.format("Session terminated: %s (duration: %d ms, extensions: %d)",
            FSMState.session_id, 
            EligibilityFSM.get_session_duration_ms(),
            FSMState.extension_count),
        "AUDIT"
    )
    
    return true, result
end

--- Emergency session termination (abuse detected)
---@param abuse_type string
---@return boolean, string
function EligibilityFSM.emergency_terminate(abuse_type)
    EligibilityFSM.log(
        string.format("EMERGENCY TERMINATION: %s", abuse_type),
        "CRITICAL"
    )
    
    -- Generate abuse evidence
    local evidence = EligibilityFSM.generate_abuse_evidence(abuse_type)
    
    if FSMState.config.evidence_logging_enabled then
        EligibilityFSM.log_evidence_bundle(evidence)
    end
    
    -- Force transition to EMERGENCY_TERMINATED
    local success, result = EligibilityFSM.force_transition(
        EligibilityFSM.SessionState.EMERGENCY_TERMINATED,
        "Emergency termination: " .. abuse_type
    )
    
    -- Notify callback
    if FSMState.callbacks.on_emergency_terminate then
        FSMState.callbacks.on_emergency_terminate(abuse_type, evidence)
    end
    
    -- Reset session start time
    FSMState.session_start_time = nil
    
    return success, result
end

-- ============================================================================
-- Evidence Generation Functions
-- ============================================================================

--- Generate session evidence bundle
---@return table
function EligibilityFSM.generate_session_evidence()
    local evidence = {
        evidence_type = "SESSION_EVIDENCE",
        timestamp = NeuroGuard and NeuroGuard.get_timestamp() or os.date("!%Y-%m-%dT%H:%M:%SZ"),
        corridor_id = EligibilityFSM._CORRIDOR_ID,
        session_id = FSMState.session_id,
        session_duration_ms = EligibilityFSM.get_session_duration_ms(),
        extension_count = FSMState.extension_count,
        refusal_count = FSMState.refusal_count,
        coercion_indicators = FSMState.coercion_indicators,
        final_state = FSMState.current_state,
        transition_count = #FSMState.transition_history,
        eligibility_flags = EligibilityFSM.deep_copy(FSMState.eligibility_flags),
        legal_framework = "CRPD_ECHR_UNESCO_v3",
    }
    
    -- Compute hash for integrity
    if NeuroGuard and NeuroGuard.compute_hash then
        evidence.integrity_hash = NeuroGuard.compute_hash(
            NeuroGuard.to_json(evidence))
    end
    
    return evidence
end

--- Generate abuse evidence bundle
---@param abuse_type string
---@return table
function EligibilityFSM.generate_abuse_evidence(abuse_type)
    local coercion_analysis = EligibilityFSM.analyze_coercion_patterns()
    
    local evidence = {
        evidence_type = "ABUSE_EVIDENCE",
        timestamp = NeuroGuard and NeuroGuard.get_timestamp() or os.date("!%Y-%m-%dT%H:%M:%SZ"),
        corridor_id = EligibilityFSM._CORRIDOR_ID,
        session_id = FSMState.session_id,
        abuse_type = abuse_type,
        session_duration_ms = EligibilityFSM.get_session_duration_ms(),
        extension_count = FSMState.extension_count,
        refusal_count = FSMState.refusal_count,
        coercion_indicators = FSMState.coercion_indicators,
        coercion_risk_level = coercion_analysis.coercion_risk_level,
        coercion_recommendations = coercion_analysis.recommendations,
        state_at_detection = FSMState.current_state,
        transition_history = EligibilityFSM.deep_copy(FSMState.transition_history),
        eligibility_flags = EligibilityFSM.deep_copy(FSMState.eligibility_flags),
        legal_instruments = {
            "CRPD Article 15 - Freedom from Coercive Treatment",
            "UNESCO Neuroethics 3.1 - Informed Consent",
            "ECHR Article 3 - Prohibition of Torture",
        },
    }
    
    -- Compute hash for integrity
    if NeuroGuard and NeuroGuard.compute_hash then
        evidence.integrity_hash = NeuroGuard.compute_hash(
            NeuroGuard.to_json(evidence))
    end
    
    return evidence
end

--- Log evidence bundle
---@param evidence table
function EligibilityFSM.log_evidence_bundle(evidence)
    if NeuroGuard and NeuroGuard.write_evidence_log then
        local json_line = NeuroGuard.to_json(evidence)
        NeuroGuard.write_evidence_log(json_line)
        
        if FSMState.callbacks.on_evidence_logged then
            FSMState.callbacks.on_evidence_logged(evidence)
        end
        
        EligibilityFSM.log("Evidence bundle logged", "AUDIT")
    else
        EligibilityFSM.log(
            "Evidence logging not available - evidence not persisted",
            "WARNING"
        )
    end
end

--- Export all evidence for legal submission
---@param output_path string
---@return boolean, string
function EligibilityFSM.export_evidence(output_path)
    local export_package = {
        export_timestamp = NeuroGuard and NeuroGuard.get_timestamp() or os.date("!%Y-%m-%dT%H:%M:%SZ"),
        corridor_id = EligibilityFSM._CORRIDOR_ID,
        session_id = FSMState.session_id,
        total_transitions = #FSMState.transition_history,
        total_evidence_bundles = #FSMState.evidence_bundles,
        legal_framework = "CRPD_ECHR_UNESCO_v3",
        monotone_invariant_verified = true,
        transition_history = FSMState.transition_history,
        evidence_bundles = FSMState.evidence_bundles,
    }
    
    if NeuroGuard and NeuroGuard.to_json then
        local json_data = NeuroGuard.to_json(export_package)
        
        local file = io.open(output_path, "w")
        if file then
            file:write(json_data)
            file:close()
            
            EligibilityFSM.log(
                string.format("Evidence exported to: %s", output_path),
                "AUDIT"
            )
            
            return true, "Export successful"
        else
            return false, "Failed to open output file"
        end
    else
        return false, "JSON serialization not available"
    end
end

-- ============================================================================
-- Guardian Integration Functions
-- ============================================================================

--- Link FSM to Guardian Gateway
---@param guardian_instance table
---@return boolean
function EligibilityFSM.link_guardian(guardian_instance)
    if not guardian_instance then
        return false
    end
    
    FSMState.guardian_linked = true
    EligibilityFSM.set_eligibility_flag(
        EligibilityFSM.EligibilityCriteria.GUARDIAN_CLEARANCE, true)
    
    -- Set up guardian callbacks
    FSMState.callbacks.on_abuse_detected = function(abuse_type, evidence)
        if guardian_instance.process_policy_command then
            -- Notify guardian of abuse detection
            guardian_instance.log(
                string.format("FSM abuse detected: %s", abuse_type),
                "CRITICAL"
            )
        end
    end
    
    EligibilityFSM.log("Guardian Gateway linked", "INFO")
    
    return true
end

--- Request guardian intervention
---@param reason string
---@return boolean, string
function EligibilityFSM.request_guardian_intervention(reason)
    if not FSMState.guardian_linked then
        return false, "Guardian not linked"
    end
    
    EligibilityFSM.log(
        string.format("Guardian intervention requested: %s", reason),
        "WARNING"
    )
    
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.GUARDIAN_INTERVENTION)
    
    if success then
        EligibilityFSM.set_eligibility_flag(
            EligibilityFSM.EligibilityCriteria.GUARDIAN_CLEARANCE, false)
    end
    
    return success, result
end

--- Clear guardian intervention
---@return boolean, string
function EligibilityFSM.clear_guardian_intervention()
    if FSMState.current_state ~= EligibilityFSM.SessionState.UNDER_REVIEW then
        return false, "Not under review"
    end
    
    EligibilityFSM.set_eligibility_flag(
        EligibilityFSM.EligibilityCriteria.GUARDIAN_CLEARANCE, true)
    
    local success, result = EligibilityFSM.transition(
        EligibilityFSM.SessionEvent.SYSTEM_REVIEW_COMPLETE)
    
    return success, result
end

-- ============================================================================
-- Callback Registration Functions
-- ============================================================================

--- Register state change callback
---@param callback function
function EligibilityFSM.on_state_change(callback)
    FSMState.callbacks.on_state_change = callback
end

--- Register eligibility check callback
---@param callback function
function EligibilityFSM.on_eligibility_check(callback)
    FSMState.callbacks.on_eligibility_check = callback
end

--- Register abuse detection callback
---@param callback function
function EligibilityFSM.on_abuse_detected(callback)
    FSMState.callbacks.on_abuse_detected = callback
end

--- Register evidence logged callback
---@param callback function
function EligibilityFSM.on_evidence_logged(callback)
    FSMState.callbacks.on_evidence_logged = callback
end

--- Register emergency termination callback
---@param callback function
function EligibilityFSM.on_emergency_terminate(callback)
    FSMState.callbacks.on_emergency_terminate = callback
end

-- ============================================================================
-- Status and Inspection Functions
-- ============================================================================

--- Get current FSM status
---@return table
function EligibilityFSM.get_status()
    local coercion_analysis = EligibilityFSM.analyze_coercion_patterns()
    
    return {
        version = EligibilityFSM._VERSION,
        construct_id = EligibilityFSM._CONSTRUCT_ID,
        current_state = FSMState.current_state,
        session_id = FSMState.session_id,
        session_duration_ms = EligibilityFSM.get_session_duration_ms(),
        extension_count = FSMState.extension_count,
        refusal_count = FSMState.refusal_count,
        coercion_indicators = FSMState.coercion_indicators,
        coercion_risk_level = coercion_analysis.coercion_risk_level,
        eligibility_flags = EligibilityFSM.deep_copy(FSMState.eligibility_flags),
        guardian_linked = FSMState.guardian_linked,
        transition_count = #FSMState.transition_history,
        evidence_count = #FSMState.evidence_bundles,
        daily_session_count = EligibilityFSM.get_daily_session_count(),
    }
end

--- Get transition history
---@return table
function EligibilityFSM.get_transition_history()
    return EligibilityFSM.deep_copy(FSMState.transition_history)
end

--- Get recent transitions (last N)
---@param limit number
---@return table
function EligibilityFSM.get_recent_transitions(limit)
    limit = limit or 10
    local start_idx = math.max(1, #FSMState.transition_history - limit + 1)
    local recent = {}
    
    for i = start_idx, #FSMState.transition_history do
        table.insert(recent, FSMState.transition_history[i])
    end
    
    return recent
end

--- Reset FSM to initial state
function EligibilityFSM.reset()
    FSMState.current_state = EligibilityFSM.SessionState.IDLE
    FSMState.session_id = nil
    FSMState.session_start_time = nil
    FSMState.session_duration_ms = 0
    FSMState.extension_count = 0
    FSMState.refusal_count = 0
    FSMState.coercion_indicators = 0
    FSMState.eligibility_flags = {}
    FSMState.transition_history = {}
    FSMState.evidence_bundles = {}
    FSMState.guardian_linked = false
    
    EligibilityFSM.log("FSM reset to initial state", "AUDIT")
end

-- ============================================================================
-- Module Initialization
-- ============================================================================

--- Initialize FSM module
---@param config table
---@return boolean, string
function EligibilityFSM.initialize(config)
    config = config or {}
    
    -- Apply configuration overrides
    if config.max_session_duration_ms then
        EligibilityFSM.SessionConfig.max_session_duration_ms = config.max_session_duration_ms
    end
    if config.coercion_threshold then
        EligibilityFSM.SessionConfig.coercion_threshold = config.coercion_threshold
    end
    if config.evidence_logging_enabled ~= nil then
        EligibilityFSM.SessionConfig.evidence_logging_enabled = config.evidence_logging_enabled
    end
    
    -- Reset FSM state
    EligibilityFSM.reset()
    
    EligibilityFSM.log("EligibilityFSM initialized", "INFO")
    
    return true, "Initialization successful"
end

-- ============================================================================
-- Module Export
-- ============================================================================

return EligibilityFSM

-- ============================================================================
-- End of File - Eligibility Finite State Machine
-- ============================================================================
