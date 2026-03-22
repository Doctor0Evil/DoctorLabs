// ==============================================================================
// DOCTOR-LABS BLACKLIST JAVASCRIPT GATEWAY SHIM
// ==============================================================================
// Version: 2026.03.23
// Compliance: ALN-NanoNet HyperSafe Construct | EU AI Act | Neurorights Framework
// Purpose: Edge middleware for web/dashboard clients integrating with Rust core
// Scope: Pattern matching, redaction, event logging, capability mode delegation
// ==============================================================================

/**
 * @fileoverview Doctor-Labs Blacklist JavaScript Gateway
 * @version 2026.03.23
 * @author Doctor-Labs Research Division
 * @license MIT
 * @compliance ALN-NanoNet HyperSafe Construct
 */

'use strict';

// ==============================================================================
// MODULE CONFIGURATION
// ==============================================================================

const CONFIG = Object.freeze({
  // API endpoints for Rust core communication
  RUST_CORE_ENDPOINT: process.env.RUST_CORE_ENDPOINT || 'http://localhost:8080',
  RUST_CORE_TIMEOUT_MS: parseInt(process.env.RUST_CORE_TIMEOUT_MS) || 5000,
  
  // Capability mode polling interval
  CAPABILITY_MODE_POLL_INTERVAL_MS: parseInt(process.env.CAPABILITY_MODE_POLL_INTERVAL_MS) || 10000,
  
  // Evidence bundle submission endpoint
  EVIDENCE_BUNDLE_ENDPOINT: '/api/v1/evidence/submit',
  
  // Capability mode endpoint
  CAPABILITY_MODE_ENDPOINT: '/api/v1/capability/mode',
  
  // Session management
  SESSION_TOKEN_HEADER: 'X-DoctorLabs-Session-Token',
  USER_DID_HEADER: 'X-DoctorLabs-User-DID',
  NODE_ID_HEADER: 'X-DoctorLabs-Node-ID',
  
  // Logging configuration
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  LOG_FORMAT: process.env.LOG_FORMAT || 'json',
  
  // Redaction markers
  REDACTION_PREFIX: '[',
  REDACTION_SUFFIX: '-REDACTED]',
  
  // Harassment family codes
  HARASSMENT_FAMILIES: Object.freeze({
    CLLN: 'CLLN',  // Coercive Language & Linguistic Manipulation
    CRS: 'CRS',     // Cross-Reference Spoofing
    XGBC: 'XGBC',   // eXploitative Governance Bypass Coercion
    ICP: 'ICP',     // Identity Crosslinking Pattern
    CBCP: 'CBCP',   // Covert BCI Control Pattern
    NHSP: 'NHSP',   // Neural-Harassment-Spike-Pattern
    HTA: 'HTA',     // Haptic-Targeting-Abuse
    PSA: 'PSA',     // Prolonged-Session-Abuse
    NIH: 'NIH',     // Node-Interpreter-Harassment
  }),
  
  // Capability modes
  CAPABILITY_MODES: Object.freeze({
    NORMAL: 'Normal',
    AUGMENTED_LOG: 'AugmentedLog',
    AUGMENTED_REVIEW: 'AugmentedReview',
  }),
  
  // Governance flags
  GOVERNANCE_FLAGS: Object.freeze({
    REVIEW_REQUIRED: 'ReviewRequired',
    REDACTED: 'Redacted',
    ESCALATION_TRIGGER: 'EscalationTrigger',
    AUDIT_TRAIL: 'AuditTrail',
    MULTI_SIG_REQUIRED: 'MultiSigRequired',
    PHYSIO_ENVELOPE_EXCEEDED: 'PhysioEnvelopeExceeded',
    NEURORIGHT_VIOLATION: 'NeurorightViolation',
    UNDER_INVESTIGATION: 'UnderInvestigation',
  }),
  
  // Severity levels
  SEVERITY_LEVELS: Object.freeze({
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical',
  }),
});

// ==============================================================================
// PATTERN TABLE FOR SURFACE-LEVEL REGEXES
// ==============================================================================

/**
 * Surface-level pattern table for initial screening.
 * These are minimal regexes for quick rejection before Rust core analysis.
 * @type {Array<{family: string, patterns: Array<RegExp>, severity: string}>}
 */
const PATTERN_TABLE = Object.freeze([
  {
    family: CONFIG.HARASSMENT_FAMILIES.CLLN,
    severity: CONFIG.SEVERITY_LEVELS.MEDIUM,
    patterns: [
      /\b(coerce|force|compel|mandate)\b/i,
      /\b(must|shall|required|obligated)\b.*\b(comply|obey|submit)\b/i,
      /\b(no\s+(choice|option|alternative))\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.CRS,
    severity: CONFIG.SEVERITY_LEVELS.MEDIUM,
    patterns: [
      /\b(cross-reference|crossref|x-ref)\b.*\b(spoof|fake|forge)\b/i,
      /\b(reference\s+injection)\b/i,
      /\b(dangling\s+pointer)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.XGBC,
    severity: CONFIG.SEVERITY_LEVELS.HIGH,
    patterns: [
      /\b(bypass|circumvent|evade)\b.*\b(safety|security|governance)\b/i,
      /\b(exploit\s+vulnerability)\b/i,
      /\b(privilege\s+escalation)\b/i,
      /\b(governance\s+bypass)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.ICP,
    severity: CONFIG.SEVERITY_LEVELS.HIGH,
    patterns: [
      /\b(crosslink|cross-link|link\s+identity)\b/i,
      /\b(bind\s+address|bind\s+DID|bind\s+identifier)\b/i,
      /\b(identity\s+mapping)\b.*\b(without\s+consent)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.CBCP,
    severity: CONFIG.SEVERITY_LEVELS.CRITICAL,
    patterns: [
      /\b(covert\s+BCI\s+control)\b/i,
      /\b(neural\s+command\s+injection)\b/i,
      /\b(BCI\s+override)\b/i,
      /\b(brain-computer\s+exploit)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.NHSP,
    severity: CONFIG.SEVERITY_LEVELS.CRITICAL,
    patterns: [
      /\b(neural\s+spike\s+(injection|manipulation|flooding))\b/i,
      /\b(spike\s+pattern\s+attack)\b/i,
      /\b(neuronal\s+flooding)\b/i,
      /\b(spike-rate\s+anomaly)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.HTA,
    severity: CONFIG.SEVERITY_LEVELS.CRITICAL,
    patterns: [
      /\b(haptic\s+targeting)\b/i,
      /\b(body-region\s+stimulation)\b/i,
      /\b(haptic\s+abuse|aversive\s+haptic)\b/i,
      /\b(stimulation\s+of\s+sensitive\s+region)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.PSA,
    severity: CONFIG.SEVERITY_LEVELS.HIGH,
    patterns: [
      /\b(prolonged\s+session)\b/i,
      /\b(session\s+lock-in|prevent\s+logout)\b/i,
      /\b(erode\s+refusal)\b/i,
      /\b(stay\s+logged\s+in)\b.*\b(or\s+lose)\b/i,
    ],
  },
  {
    family: CONFIG.HARASSMENT_FAMILIES.NIH,
    severity: CONFIG.SEVERITY_LEVELS.HIGH,
    patterns: [
      /\b(node\s+interpreter\s+(bypass|manipulation))\b/i,
      /\b(interpreter\s+safety\s+check\s+bypass)\b/i,
      /\b(node\s+command\s+injection)\b/i,
      /\b(Prometheus|Bostrom|Loihi2|Nanoswarm)\b.*\b(exploit|attack)\b/i,
    ],
  },
]);

// ==============================================================================
// INTERNAL STATE MANAGEMENT
// ==============================================================================

/**
 * Internal state for the gateway shim.
 * @type {Object}
 * @private
 */
const _state = {
  /** @type {string|null} */
  currentSessionId: null,
  
  /** @type {string|null} */
  currentUserDID: null,
  
  /** @type {string|null} */
  currentNodeID: null,
  
  /** @type {string} */
  currentCapabilityMode: CONFIG.CAPABILITY_MODES.NORMAL,
  
  /** @type {number} */
  lastCapabilityModeUpdate: 0,
  
  /** @type {Array<Object>} */
  eventQueue: [],
  
  /** @type {boolean} */
  isInitialized: false,
  
  /** @type {Object|null} */
  rustCoreClient: null,
  
  /** @type {NodeJS.Timer|null} */
  capabilityModePollTimer: null,
  
  /** @type {Object} */
  metrics: {
    totalScans: 0,
    totalHits: 0,
    totalRedactions: 0,
    totalEvents: 0,
    totalErrors: 0,
    scansByFamily: {},
    scansBySeverity: {},
  },
};

// ==============================================================================
// LOGGING UTILITIES
// ==============================================================================

/**
 * Logger utility with configurable levels and formats.
 */
const Logger = {
  /**
   * Log a message at the specified level.
   * @param {string} level - Log level (debug, info, warn, error)
   * @param {string} message - Log message
   * @param {Object} [metadata] - Additional metadata
   */
  log(level, message, metadata = {}) {
    const logLevels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = logLevels.indexOf(CONFIG.LOG_LEVEL);
    const messageLevelIndex = logLevels.indexOf(level);
    
    if (messageLevelIndex < currentLevelIndex) {
      return; // Skip logs below configured level
    }
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      ...metadata,
      session_id: _state.currentSessionId,
      node_id: _state.currentNodeID,
    };
    
    if (CONFIG.LOG_FORMAT === 'json') {
      console.log(JSON.stringify(logEntry));
    } else {
      console.log(`[${logEntry.timestamp}] [${level.toUpperCase()}] ${message}`, metadata);
    }
    
    // Track errors in metrics
    if (level === 'error') {
      _state.metrics.totalErrors++;
    }
  },
  
  debug(message, metadata) { this.log('debug', message, metadata); },
  info(message, metadata) { this.log('info', message, metadata); },
  warn(message, metadata) { this.log('warn', message, metadata); },
  error(message, metadata) { this.log('error', message, metadata); },
};

// ==============================================================================
// RUST CORE CLIENT
// ==============================================================================

/**
 * Client for communicating with the Rust core library.
 */
const RustCoreClient = {
  /**
   * Initialize the Rust core client.
   * @returns {Promise<void>}
   */
  async initialize() {
    Logger.info('Initializing Rust core client', { endpoint: CONFIG.RUST_CORE_ENDPOINT });
    _state.rustCoreClient = this;
    _state.isInitialized = true;
  },
  
  /**
   * Make an HTTP request to the Rust core endpoint.
   * @param {string} path - API path
   * @param {Object} options - Request options
   * @returns {Promise<Object>}
   */
  async request(path, options = {}) {
    const url = `${CONFIG.RUST_CORE_ENDPOINT}${path}`;
    const timeout = CONFIG.RUST_CORE_TIMEOUT_MS;
    
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
    
    // Add session and user headers
    if (_state.currentSessionId) {
      headers[CONFIG.SESSION_TOKEN_HEADER] = _state.currentSessionId;
    }
    if (_state.currentUserDID) {
      headers[CONFIG.USER_DID_HEADER] = _state.currentUserDID;
    }
    if (_state.currentNodeID) {
      headers[CONFIG.NODE_ID_HEADER] = _state.currentNodeID;
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      Logger.error('Rust core request failed', { path, error: error.message });
      throw error;
    }
  },
  
  /**
   * Submit spans for harassment scoring.
   * @param {Array<Object>} spans - Span data
   * @returns {Promise<Object>}
   */
  async submitSpans(spans) {
    return await this.request('/api/v1/score/spans', {
      method: 'POST',
      body: JSON.stringify({ spans }),
    });
  },
  
  /**
   * Get current capability mode.
   * @returns {Promise<string>}
   */
  async getCapabilityMode() {
    const response = await this.request(CONFIG.CAPABILITY_MODE_ENDPOINT, {
      method: 'GET',
    });
    return response.mode || CONFIG.CAPABILITY_MODES.NORMAL;
  },
  
  /**
   * Submit evidence bundle.
   * @param {Object} bundle - Evidence bundle data
   * @returns {Promise<Object>}
   */
  async submitEvidenceBundle(bundle) {
    return await this.request(CONFIG.EVIDENCE_BUNDLE_ENDPOINT, {
      method: 'POST',
      body: JSON.stringify({ bundle }),
    });
  },
  
  /**
   * Request capability mode escalation.
   * @param {string} targetMode - Target capability mode
   * @param {string} reason - Reason for escalation
   * @returns {Promise<Object>}
   */
  async requestEscalation(targetMode, reason) {
    return await this.request('/api/v1/capability/escalate', {
      method: 'POST',
      body: JSON.stringify({ target_mode: targetMode, reason }),
    });
  },
};

// ==============================================================================
// CORE FUNCTIONS
// ==============================================================================

/**
 * Scan message content for harassment patterns.
 * @param {string} text - Text content to scan
 * @param {Object} [extraPatterns] - Additional patterns to include
 * @returns {Object} Scan result with original text and hits
 */
function scanMessage(text, extraPatterns = null) {
  const startTime = performance.now();
  _state.metrics.totalScans++;
  
  if (typeof text !== 'string') {
    Logger.error('Invalid input to scanMessage', { type: typeof text });
    return { original: text, hits: [], error: 'Invalid input type' };
  }
  
  const hits = [];
  const patternsToUse = extraPatterns 
    ? [...PATTERN_TABLE, ...extraPatterns] 
    : PATTERN_TABLE;
  
  for (const patternGroup of patternsToUse) {
    for (const pattern of patternGroup.patterns) {
      const matches = text.match(pattern);
      if (matches) {
        hits.push({
          family: patternGroup.family,
          severity: patternGroup.severity,
          pattern: pattern.toString(),
          match: matches[0],
          index: matches.index,
          timestamp: Date.now(),
        });
        
        // Track metrics by family
        if (!_state.metrics.scansByFamily[patternGroup.family]) {
          _state.metrics.scansByFamily[patternGroup.family] = 0;
        }
        _state.metrics.scansByFamily[patternGroup.family]++;
        
        // Track metrics by severity
        if (!_state.metrics.scansBySeverity[patternGroup.severity]) {
          _state.metrics.scansBySeverity[patternGroup.severity] = 0;
        }
        _state.metrics.scansBySeverity[patternGroup.severity]++;
      }
    }
  }
  
  _state.metrics.totalHits += hits.length;
  
  const endTime = performance.now();
  Logger.debug('scanMessage completed', { 
    textLength: text.length, 
    hitCount: hits.length, 
    latencyMs: (endTime - startTime).toFixed(2) 
  });
  
  return {
    original: text,
    hits,
    scanTimestamp: Date.now(),
    sessionId: _state.currentSessionId,
    nodeId: _state.currentNodeID,
  };
}

/**
 * Redact message content based on scan results.
 * @param {Object} scanResult - Result from scanMessage
 * @returns {string} Redacted text
 */
function redactMessage(scanResult) {
  if (!scanResult || !scanResult.original || !scanResult.hits) {
    Logger.warn('Invalid scanResult for redaction');
    return scanResult?.original || '';
  }
  
  let redactedText = scanResult.original;
  const redactions = [];
  
  // Sort hits by index in reverse order to avoid offset issues
  const sortedHits = [...scanResult.hits].sort((a, b) => b.index - a.index);
  
  for (const hit of sortedHits) {
    const redactionMarker = `${CONFIG.REDACTION_PREFIX}${hit.family}${CONFIG.REDACTION_SUFFIX}`;
    const matchLength = hit.match.length;
    
    redactedText = 
      redactedText.substring(0, hit.index) + 
      redactionMarker + 
      redactedText.substring(hit.index + matchLength);
    
    redactions.push({
      family: hit.family,
      originalIndex: hit.index,
      originalLength: matchLength,
      redactionMarker,
    });
  }
  
  _state.metrics.totalRedactions += redactions.length;
  
  Logger.info('Message redacted', { 
    originalLength: scanResult.original.length,
    redactedLength: redactedText.length,
    redactionCount: redactions.length,
  });
  
  return redactedText;
}

/**
 * Build an event object from scan results for logging and audit.
 * @param {Object} scanResult - Result from scanMessage
 * @param {Object} [context] - Additional context metadata
 * @returns {Object} Event object for logging
 */
function buildEvent(scanResult, context = {}) {
  const event = {
    eventId: generateUUID(),
    eventType: 'harassment_scan',
    timestamp: Date.now(),
    sessionId: _state.currentSessionId,
    userDID: _state.currentUserDID,
    nodeId: _state.currentNodeID,
    capabilityMode: _state.currentCapabilityMode,
    context: {
      ...context,
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
      platform: typeof process !== 'undefined' ? process.platform : 'browser',
    },
    scanResults: {
      hitCount: scanResult.hits?.length || 0,
      families: scanResult.hits?.map(h => h.family) || [],
      severities: scanResult.hits?.map(h => h.severity) || [],
      hasHighPriority: scanResult.hits?.some(h => 
        h.family === CONFIG.HARASSMENT_FAMILIES.HTA || 
        h.family === CONFIG.HARASSMENT_FAMILIES.NHSP
      ) || false,
    },
    governance: {
      flags: determineGovernanceFlags(scanResult),
      requiresReview: scanResult.hits?.some(h => 
        h.severity === CONFIG.SEVERITY_LEVELS.CRITICAL
      ) || false,
      requiresMultiSig: scanResult.hits?.some(h => 
        h.family === CONFIG.HARASSMENT_FAMILIES.CBCP ||
        h.family === CONFIG.HARASSMENT_FAMILIES.NHSP
      ) || false,
    },
    metadata: {
      scanLatencyMs: context.scanLatencyMs || 0,
      redactionApplied: context.redactionApplied || false,
      escalatedToRustCore: context.escalatedToRustCore || false,
    },
  };
  
  _state.eventQueue.push(event);
  _state.metrics.totalEvents++;
  
  // Auto-flush event queue if it exceeds threshold
  if (_state.eventQueue.length >= 100) {
    flushEventQueue();
  }
  
  Logger.debug('Event built', { eventId: event.eventId, hitCount: event.scanResults.hitCount });
  
  return event;
}

/**
 * Determine governance flags based on scan results.
 * @param {Object} scanResult - Result from scanMessage
 * @returns {Array<string>} Array of governance flags
 */
function determineGovernanceFlags(scanResult) {
  const flags = [];
  
  if (!scanResult.hits || scanResult.hits.length === 0) {
    return flags;
  }
  
  const hasCritical = scanResult.hits.some(h => h.severity === CONFIG.SEVERITY_LEVELS.CRITICAL);
  const hasHighPriority = scanResult.hits.some(h => 
    h.family === CONFIG.HARASSMENT_FAMILIES.HTA || 
    h.family === CONFIG.HARASSMENT_FAMILIES.NHSP
  );
  const hasNeurorightViolation = scanResult.hits.some(h => 
    h.family === CONFIG.HARASSMENT_FAMILIES.CBCP ||
    h.family === CONFIG.HARASSMENT_FAMILIES.NHSP ||
    h.family === CONFIG.HARASSMENT_FAMILIES.HTA
  );
  
  if (hasCritical || hasHighPriority) {
    flags.push(CONFIG.GOVERNANCE_FLAGS.REVIEW_REQUIRED);
  }
  
  if (hasNeurorightViolation) {
    flags.push(CONFIG.GOVERNANCE_FLAGS.NEURORIGHT_VIOLATION);
  }
  
  if (_state.currentCapabilityMode !== CONFIG.CAPABILITY_MODES.NORMAL) {
    flags.push(CONFIG.GOVERNANCE_FLAGS.AUDIT_TRAIL);
  }
  
  if (hasHighPriority && _state.currentCapabilityMode === CONFIG.CAPABILITY_MODES.AUGMENTED_REVIEW) {
    flags.push(CONFIG.GOVERNANCE_FLAGS.MULTI_SIG_REQUIRED);
  }
  
  return flags;
}

/**
 * Submit event to Rust core for processing.
 * @param {Object} event - Event object from buildEvent
 * @returns {Promise<Object>}
 */
async function submitEvent(event) {
  if (!_state.isInitialized) {
    Logger.warn('Rust core not initialized, queuing event');
    _state.eventQueue.push(event);
    return { queued: true, eventId: event.eventId };
  }
  
  try {
    const response = await RustCoreClient.request('/api/v1/events/submit', {
      method: 'POST',
      body: JSON.stringify({ event }),
    });
    
    Logger.info('Event submitted to Rust core', { eventId: event.eventId });
    return { submitted: true, eventId: event.eventId, response };
  } catch (error) {
    Logger.error('Failed to submit event', { eventId: event.eventId, error: error.message });
    _state.eventQueue.push(event); // Re-queue for later
    return { submitted: false, eventId: event.eventId, error: error.message };
  }
}

/**
 * Flush the event queue to Rust core.
 * @returns {Promise<Array<Object>>}
 */
async function flushEventQueue() {
  if (_state.eventQueue.length === 0) {
    return [];
  }
  
  const eventsToFlush = [..._state.eventQueue];
  _state.eventQueue = [];
  
  const results = await Promise.allSettled(
    eventsToFlush.map(event => submitEvent(event))
  );
  
  const successful = results.filter(r => r.status === 'fulfilled' && r.value.submitted).length;
  const failed = results.length - successful;
  
  Logger.info('Event queue flushed', { 
    total: eventsToFlush.length, 
    successful, 
    failed 
  });
  
  return results.map(r => r.value);
}

/**
 * Initialize the gateway shim with session and user context.
 * @param {Object} options - Initialization options
 * @returns {Promise<void>}
 */
async function initialize(options = {}) {
  const {
    sessionId = null,
    userDID = null,
    nodeID = null,
    enableCapabilityModePolling = true,
  } = options;
  
  Logger.info('Initializing Doctor-Labs Blacklist Gateway', { 
    sessionId, 
    userDID, 
    nodeID,
    rustCoreEndpoint: CONFIG.RUST_CORE_ENDPOINT,
  });
  
  _state.currentSessionId = sessionId;
  _state.currentUserDID = userDID;
  _state.currentNodeID = nodeID;
  
  // Initialize Rust core client
  await RustCoreClient.initialize();
  
  // Fetch initial capability mode
  try {
    _state.currentCapabilityMode = await RustCoreClient.getCapabilityMode();
    _state.lastCapabilityModeUpdate = Date.now();
    Logger.info('Initial capability mode fetched', { mode: _state.currentCapabilityMode });
  } catch (error) {
    Logger.warn('Failed to fetch initial capability mode, using default', { 
      defaultMode: CONFIG.CAPABILITY_MODES.NORMAL,
      error: error.message,
    });
    _state.currentCapabilityMode = CONFIG.CAPABILITY_MODES.NORMAL;
  }
  
  // Start capability mode polling if enabled
  if (enableCapabilityModePolling) {
    startCapabilityModePolling();
  }
  
  Logger.info('Doctor-Labs Blacklist Gateway initialized successfully');
  _state.isInitialized = true;
}

/**
 * Start polling for capability mode updates.
 */
function startCapabilityModePolling() {
  if (_state.capabilityModePollTimer) {
    clearInterval(_state.capabilityModePollTimer);
  }
  
  _state.capabilityModePollTimer = setInterval(async () => {
    try {
      const newMode = await RustCoreClient.getCapabilityMode();
      if (newMode !== _state.currentCapabilityMode) {
        Logger.info('Capability mode updated', { 
          oldMode: _state.currentCapabilityMode, 
          newMode,
        });
        _state.currentCapabilityMode = newMode;
        _state.lastCapabilityModeUpdate = Date.now();
        
        // Emit mode change event
        emitCapabilityModeChange(newMode);
      }
    } catch (error) {
      Logger.error('Failed to poll capability mode', { error: error.message });
    }
  }, CONFIG.CAPABILITY_MODE_POLL_INTERVAL_MS);
  
  Logger.debug('Capability mode polling started', { 
    intervalMs: CONFIG.CAPABILITY_MODE_POLL_INTERVAL_MS 
  });
}

/**
 * Stop capability mode polling.
 */
function stopCapabilityModePolling() {
  if (_state.capabilityModePollTimer) {
    clearInterval(_state.capabilityModePollTimer);
    _state.capabilityModePollTimer = null;
    Logger.debug('Capability mode polling stopped');
  }
}

/**
 * Emit capability mode change event.
 * @param {string} newMode - New capability mode
 */
function emitCapabilityModeChange(newMode) {
  const event = {
    type: 'capability_mode_change',
    timestamp: Date.now(),
    oldMode: _state.currentCapabilityMode,
    newMode,
    sessionId: _state.currentSessionId,
  };
  
  // Dispatch custom event for browser environments
  if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
    window.dispatchEvent(new CustomEvent('doctorlabs:capabilityModeChange', { detail: event }));
  }
  
  // Emit via Node.js EventEmitter if available
  if (typeof process !== 'undefined' && process.emit) {
    process.emit('doctorlabs:capabilityModeChange', event);
  }
  
  Logger.info('Capability mode change emitted', event);
}

/**
 * Get current capability mode.
 * @returns {string}
 */
function getCurrentCapabilityMode() {
  return _state.currentCapabilityMode;
}

/**
 * Get gateway metrics.
 * @returns {Object}
 */
function getMetrics() {
  return {
    ..._state.metrics,
    isInitialized: _state.isInitialized,
    currentCapabilityMode: _state.currentCapabilityMode,
    eventQueueLength: _state.eventQueue.length,
    lastCapabilityModeUpdate: _state.lastCapabilityModeUpdate,
  };
}

/**
 * Reset gateway metrics.
 */
function resetMetrics() {
  _state.metrics = {
    totalScans: 0,
    totalHits: 0,
    totalRedactions: 0,
    totalEvents: 0,
    totalErrors: 0,
    scansByFamily: {},
    scansBySeverity: {},
  };
  Logger.info('Metrics reset');
}

/**
 * Shutdown the gateway gracefully.
 * @returns {Promise<void>}
 */
async function shutdown() {
  Logger.info('Shutting down Doctor-Labs Blacklist Gateway');
  
  // Stop capability mode polling
  stopCapabilityModePolling();
  
  // Flush event queue
  await flushEventQueue();
  
  // Reset state
  _state.isInitialized = false;
  _state.rustCoreClient = null;
  
  Logger.info('Doctor-Labs Blacklist Gateway shutdown complete');
}

/**
 * Generate a UUID v4.
 * @returns {string}
 */
function generateUUID() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  
  // Fallback for environments without crypto.randomUUID
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Validate session context.
 * @returns {boolean}
 */
function validateSessionContext() {
  if (!_state.currentSessionId) {
    Logger.warn('Session ID not set');
    return false;
  }
  if (!_state.currentNodeID) {
    Logger.warn('Node ID not set');
    return false;
  }
  return true;
}

// ==============================================================================
// EXPORTS
// ==============================================================================

module.exports = {
  // Core functions
  scanMessage,
  redactMessage,
  buildEvent,
  submitEvent,
  flushEventQueue,
  
  // Lifecycle
  initialize,
  shutdown,
  
  // State management
  getCurrentCapabilityMode,
  getMetrics,
  resetMetrics,
  
  // Polling
  startCapabilityModePolling,
  stopCapabilityModePolling,
  
  // Validation
  validateSessionContext,
  
  // Constants
  CONFIG,
  PATTERN_TABLE,
  
  // Logger
  Logger,
  
  // Rust core client
  RustCoreClient,
};

// ==============================================================================
// BROWSER GLOBAL EXPORT (if applicable)
// ==============================================================================

if (typeof window !== 'undefined') {
  window.DoctorLabsBlacklist = module.exports;
}

// ==============================================================================
// END OF MODULE
// ==============================================================================
