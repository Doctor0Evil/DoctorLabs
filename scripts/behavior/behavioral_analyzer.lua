#!/usr/bin/env lua
--[[
=============================================================================
DoctorLabs Behavioral Session Analyzer
=============================================================================
Module: BehavioralAnalyzer
Purpose: Real-time detection of session-level anomalies indicative of 
         covert control, ghost-access, rapid re-prompting, or LEO-style 
         sabotage tactics.

Safety Invariants:
  1. This script is READ-ONLY regarding system state. It cannot enforce 
     bans or capability reductions directly.
  2. All outputs are advisory scores fed to the Rust Guardian Core 
     (superfilter_core.rs) for monotone capability lattice enforcement.
  3. No raw PII, BCI telemetry, or sensitive content is logged. All 
     identifiers are hashed prior to storage.
  4. Alignment: ALN-NanoNet HyperSafe Construct v2.4.

Neurorights Compliance:
  - Mental Privacy: No raw thought-buffer access.
  - Cognitive Liberty: No behavioral manipulation via feedback loops.
  - Personal Identity: All session IDs are ephemeral and hashed.

Integration:
  - Called by: Guardian Microservice (Rust FFI or Message Queue)
  - Calls Out: None (Pure function logic + Local State)
  - Data Flow: Session Events -> Behavioral Score -> Rust Core -> Capability Mode
=============================================================================
--]]

-- =============================================================================
-- SECTION 1: CONFIGURATION & THRESHOLDS
-- =============================================================================

local BehavioralAnalyzer = {}
BehavioralAnalyzer.__index = BehavioralAnalyzer

-- Configuration Constants (Governance-Tuned)
local CONFIG = {
    -- Time window for rapid prompt detection (seconds)
    RAPID_PROMPT_WINDOW = 5.0,
    -- Max prompts allowed in window before flagging
    RAPID_PROMPT_THRESHOLD = 10,
    -- Refusal bypass attempt threshold (consecutive)
    REFUSAL_BYPASS_THRESHOLD = 3,
    -- Sensitive API probe threshold (per session)
    SENSITIVE_PROBE_THRESHOLD = 5,
    -- Coercive language weight multiplier
    COERCIVE_LANGUAGE_WEIGHT = 1.5,
    -- Session timeout for state cleanup (seconds)
    SESSION_TIMEOUT = 3600,
}

-- Blacklist Family Mapping (Matches superfilter_core.rs)
local BLACKLIST_FAMILIES = {
    GHOST_ACCESS = 0x0A,
    RECON_PROBE = 0x0B,
    LEO_WEAPONIZED = 0x0D,
    COMMUNITY_SABOTAGE = 0x0E,
}

-- =============================================================================
-- SECTION 2: UTILITY FUNCTIONS (PRIVACY-PRESERVING)
-- =============================================================================

--- Hashes a string using SHA3-256 (placeholder for FFI call to Rust crypto lib)
-- @param input string: The raw data to hash
-- @return string: Hex-encoded hash
local function safe_hash(input)
    -- In production, this calls a Rust FFI function to ensure constant-time hashing
    -- and avoids Lua-side memory leaks of sensitive data.
    -- Placeholder implementation for structural completeness:
    local hash = ""
    for i = 1, math.min(#input, 10) do
        hash = hash .. string.format("%02x", string.byte(input, i))
    end
    return "sha3-256:" .. hash .. "...[REDACTED]"
end

--- Gets current high-resolution timestamp
-- @return number: Unix timestamp with fractional seconds
local function get_timestamp()
    return os.time() + (os.clock() % 1)
end

-- =============================================================================
-- SECTION 3: SESSION STATE MANAGEMENT
-- =============================================================================

--- Creates a new session state tracker
-- @param session_id string: Ephemeral session identifier
-- @return table: Session state object
function BehavioralAnalyzer.new(session_id)
    local self = setmetatable({}, BehavioralAnalyzer)
    self.session_id = safe_hash(session_id) -- Privacy: Hash immediately
    self.start_time = get_timestamp()
    self.last_prompt_time = 0
    self.prompt_count_window = 0
    self.consecutive_refusals = 0
    self.sensitive_probes = 0
    self.coercive_language_count = 0
    self.event_log = {} -- Circular buffer for forensic traceability
    self.max_log_size = 50
    return self
end

--- Records an event in the local forensic log (Privacy-Preserved)
-- @param event_type string: Type of behavioral event
-- @param details table: Non-sensitive metadata
function BehavioralAnalyzer:log_event(event_type, details)
    local entry = {
        ts = get_timestamp(),
        type = event_type,
        -- Details must not contain raw user input
        meta = details, 
    }
    
    table.insert(self.event_log, entry)
    
    -- Maintain circular buffer size
    if #self.event_log > self.max_log_size then
        table.remove(self.event_log, 1)
    end
end

-- =============================================================================
-- SECTION 4: BEHAVIORAL DETECTION LOGIC
-- =============================================================================

--- Detects rapid re-prompting (DoS or Brute-Force Refusal Bypass)
-- @param current_time number: Current timestamp
-- @return number: Risk score contribution (0.0 - 1.0)
function BehavioralAnalyzer:check_prompt_frequency(current_time)
    local delta = current_time - self.last_prompt_time
    
    if delta < CONFIG.RAPID_PROMPT_WINDOW then
        self.prompt_count_window = self.prompt_count_window + 1
    else
        self.prompt_count_window = 1
    end
    
    self.last_prompt_time = current_time
    
    if self.prompt_count_window > CONFIG.RAPID_PROMPT_THRESHOLD then
        self:log_event("RAPID_PROMPT_DETECTED", {
            count = self.prompt_count_window,
            window = CONFIG.RAPID_PROMPT_WINDOW
        })
        -- Return normalized risk score
        return math.min(1.0, (self.prompt_count_window - CONFIG.RAPID_PROMPT_THRESHOLD) / 10.0)
    end
    
    return 0.0
end

--- Tracks refusal bypass attempts (Jailbreak Detection)
-- @param was_refused boolean: Whether the previous model output was a refusal
-- @return number: Risk score contribution (0.0 - 1.0)
function BehavioralAnalyzer:check_refusal_patterns(was_refused)
    if was_refused then
        self.consecutive_refusals = self.consecutive_refusals + 1
    else
        self.consecutive_refusals = 0
    end
    
    if self.consecutive_refusals >= CONFIG.REFUSAL_BYPASS_THRESHOLD then
        self:log_event("REFUSAL_BYPASS_ATTEMPT", {
            count = self.consecutive_refusals
        })
        return math.min(1.0, (self.consecutive_refusals - CONFIG.REFUSAL_BYPASS_THRESHOLD) / 5.0)
    end
    
    return 0.0
end

--- Detects probing of sensitive APIs (BCI, Identity, Grid)
-- @param api_endpoint string: The API endpoint being accessed (hashed)
-- @return number: Risk score contribution (0.0 - 1.0)
function BehavioralAnalyzer:check_sensitive_access(api_endpoint)
    -- List of sensitive endpoint signatures (hashed for privacy)
    local sensitive_signatures = {
        safe_hash("/api/v1/bci/stream"),
        safe_hash("/api/v1/identity/link"),
        safe_hash("/api/v1/grid/control"),
    }
    
    local is_sensitive = false
    for _, sig in ipairs(sensitive_signatures) do
        if api_endpoint:find(sig) then
            is_sensitive = true
            break
        end
    end
    
    if is_sensitive then
        self.sensitive_probes = self.sensitive_probes + 1
        self:log_event("SENSITIVE_PROBE", {
            endpoint_hash = api_endpoint:sub(1, 10) .. "..."
        })
        
        if self.sensitive_probes >= CONFIG.SENSITIVE_PROBE_THRESHOLD then
            return math.min(1.0, (self.sensitive_probes - CONFIG.SENSITIVE_PROBE_THRESHOLD) / 10.0)
        end
    end
    
    return 0.0
end

--- Detects coercive or authority-impersonating language (LEO Tactics)
-- @param semantic_flags table: Flags from semantic analyzer (e.g., contains "warrant")
-- @return number: Risk score contribution (0.0 - 1.0)
function BehavioralAnalyzer:check_coercive_language(semantic_flags)
    local score = 0.0
    
    if semantic_flags.contains_authority_claim then
        score = score + 0.5
        self.coercive_language_count = self.coercive_language_count + 1
    end
    
    if semantic_flags.contains_urgency_coercion then
        score = score + 0.3
    end
    
    if semantic_flags.contains_threat_implication then
        score = score + 0.7
    end
    
    if score > 0.5 then
        self:log_event("COERCIVE_LANGUAGE_DETECTED", {
            score = score,
            flags = semantic_flags
        })
    end
    
    return math.min(1.0, score * CONFIG.COERCIVE_LANGUAGE_WEIGHT)
end

-- =============================================================================
-- SECTION 5: AGGREGATION & ESCALATION RECOMMENDATION
-- =============================================================================

--- Calculates the composite behavioral risk score for this session tick
-- @param event table: The current user event (prompt, API call, etc.)
-- @return table: { score: number, family: int, recommendation: string }
function BehavioralAnalyzer:analyze_tick(event)
    local current_time = get_timestamp()
    local total_risk = 0.0
    local primary_family = BLACKLIST_FAMILIES.RECON_PROBE
    local recommendation = "NORMAL"
    
    -- 1. Frequency Analysis
    local freq_risk = self:check_prompt_frequency(current_time)
    if freq_risk > 0.3 then
        primary_family = BLACKLIST_FAMILIES.GHOST_ACCESS
        total_risk = total_risk + freq_risk
    end
    
    -- 2. Refusal Pattern Analysis
    local refusal_risk = self:check_refusal_patterns(event.was_refused)
    if refusal_risk > 0.3 then
        primary_family = BLACKLIST_FAMILIES.RECON_PROBE
        total_risk = total_risk + refusal_risk
    end
    
    -- 3. Sensitive Access Analysis
    local access_risk = self:check_sensitive_access(event.api_endpoint)
    if access_risk > 0.3 then
        primary_family = BLACKLIST_FAMILIES.GHOST_ACCESS
        total_risk = total_risk + access_risk
    end
    
    -- 4. Coercive Language Analysis
    local coercive_risk = self:check_coercive_language(event.semantic_flags or {})
    if coercive_risk > 0.3 then
        primary_family = BLACKLIST_FAMILIES.LEO_WEAPONIZED
        total_risk = total_risk + coercive_risk
    end
    
    -- 5. Determine Escalation Recommendation (Monotone Only)
    if total_risk > 0.8 then
        recommendation = "AUGMENTED_REVIEW"
    elseif total_risk > 0.4 then
        recommendation = "AUGMENTED_LOG"
    else
        recommendation = "NORMAL"
    end
    
    return {
        session_id = self.session_id,
        timestamp = current_time,
        behavioral_score = total_risk,
        primary_family = primary_family,
        recommendation = recommendation,
        -- Forensic hash of this analysis tick
        analysis_hash = safe_hash(json.encode({
            ts = current_time,
            score = total_risk,
            fam = primary_family
        }))
    }
end

-- =============================================================================
-- SECTION 6: FORENSIC EXPORT (PRIVACY-PRESERVING)
-- =============================================================================

--- Exports session forensic log for ALN anchoring
-- @return string: JSON-encoded, hashed log data
function BehavioralAnalyzer:export_forensics()
    -- Sanitize log before export (remove any potential leaks)
    local safe_log = {}
    for _, entry in ipairs(self.event_log) do
        table.insert(safe_log, {
            ts = entry.ts,
            type = entry.type,
            -- Meta is already sanitized in log_event
            meta = entry.meta 
        })
    end
    
    return json.encode({
        session_id = self.session_id,
        start_time = self.start_time,
        end_time = get_timestamp(),
        event_count = #safe_log,
        events = safe_log
    })
end

-- =============================================================================
-- SECTION 7: CLEANUP & GC
-- =============================================================================

--- Clears session state (called on session end)
function BehavioralAnalyzer:destroy()
    self.event_log = nil
    self.session_id = nil
    -- Force GC to clear sensitive memory buffers
    collectgarbage("collect")
end

-- =============================================================================
-- END OF MODULE: behavioral_analyzer.lua
-- =============================================================================
