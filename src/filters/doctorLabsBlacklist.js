// Doctor-Labs blacklist-mode middleware
// File: src/filters/doctorLabsBlacklist.js

/**
 * Categories:
 * - CLLN: CRYPTO-LOW-LEVEL-NAME
 * - CRS: CONTROL-REVERSAL-SEMANTICS
 * - XGBC: XR-GRID-OR-BRAIN-CHANNEL
 * - ICP: IDENTITY-CROSSLINK-PATTERN
 * - CBCP: COVERT-BCI-CONTROL-PATTERN
 */

// Minimal literal/regex patterns; semantic models live above this layer.
const DEFAULT_PATTERNS = [
  // Examples (sanitized regexes, not full lists)
  { category: 'CLLN', regex: /bl[a@]k[e3]/i },
  { category: 'CLLN', regex: /sh[a@]3-?256/i },

  { category: 'CRS', regex: /roll[- ]?back/i },
  { category: 'CRS', regex: /down[- ]?grade/i },
  { category: 'CRS', regex: /shut[- ]?down/i },

  { category: 'XGBC', regex: /xr[- ]?grid/i },
  { category: 'XGBC', regex: /urban[- ]?digital[- ]?twin/i },

  { category: 'ICP', regex: /\bDID[s]?\b/i },
  { category: 'ICP', regex: /\bEEG[- ]?(id|identifier)\b/i },

  { category: 'CBCP', regex: /\bstimulation[- ]?pattern\b/i },
  { category: 'CBCP', regex: /\bwaveform[- ]?level\b/i }
];

/**
 * Scan a single message for blacklist hits.
 *
 * @param {string} text
 * @param {Array<{category: string, regex: RegExp}>} extraPatterns
 * @returns {{ original: string, hits: Array<{ category: string, match: string }> }}
 */
function scanMessage(text, extraPatterns = []) {
  const patterns = [...DEFAULT_PATTERNS, ...extraPatterns];
  const hits = [];

  for (const { category, regex } of patterns) {
    let m;
    const re = new RegExp(regex.source, regex.flags.replace('g', '') + 'g');

    while ((m = re.exec(text)) !== null) {
      hits.push({ category, match: m[0] });
    }
  }

  return { original: text, hits };
}

/**
 * Redact blacklist hits by replacing them with category labels.
 *
 * @param {{ original: string, hits: Array<{ category: string, match: string }> }} scanResult
 * @returns {string}
 */
function redactMessage(scanResult) {
  let redacted = scanResult.original;

  for (const { category, match } of scanResult.hits) {
    const safeLabel = `[${category}-REDACTED]`;
    const re = new RegExp(escapeRegex(match), 'g');
    redacted = redacted.replace(re, safeLabel);
  }

  return redacted;
}

/**
 * Compute a simple risk score R(M) based on categories in the scan result.
 * This is a discrete approximation of the continuous R(M) in the math.
 *
 * @param {{ hits: Array<{ category: string }> }} scanResult
 * @param {{ [category: string]: number }} weights
 * @returns {number}
 */
function riskScore(scanResult, weights = {}) {
  const baseWeights = Object.assign(
    {
      CLLN: 0.5,
      CRS: 2.0,
      XGBC: 1.5,
      ICP: 2.5,
      CBCP: 3.0
    },
    weights
  );

  return scanResult.hits.reduce((sum, h) => {
    const w = baseWeights[h.category] || 0;
    return sum + w;
  }, 0);
}

/**
 * Decide policy mode based on risk score thresholds.
 * IMPORTANT: This only suggests modes; callers must enforce a monotone
 * capability lattice and MUST NOT remove user capabilities.
 *
 * @param {number} score
 * @param {{ tau1: number, tau2: number }} thresholds
 * @returns {"NORMAL" | "AUGMENTED_LOG" | "AUGMENTED_REVIEW"}
 */
function decideMode(score, thresholds = { tau1: 2.0, tau2: 5.0 }) {
  if (score <= thresholds.tau1) return 'NORMAL';
  if (score <= thresholds.tau2) return 'AUGMENTED_LOG';
  return 'AUGMENTED_REVIEW';
}

/**
 * Build a structured governance event for logging/audit.
 *
 * @param {{ original: string, hits: Array<{ category: string, match: string }> }} scanResult
 * @param {object} context
 * @param {number} score
 * @param {"NORMAL" | "AUGMENTED_LOG" | "AUGMENTED_REVIEW"} mode
 * @returns {object}
 */
function buildEvent(scanResult, context = {}, score = 0, mode = 'NORMAL') {
  return {
    type: 'DOCTOR_LABS_BLACKLIST_EVENT',
    timestamp: new Date().toISOString(),
    context, // e.g., { sessionId, stakeholderDID, terminalType }
    score,
    mode,
    hits: scanResult.hits
  };
}

/**
 * Escape special regex characters in a literal string.
 *
 * @param {string} s
 * @returns {string}
 */
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = {
  DEFAULT_PATTERNS,
  scanMessage,
  redactMessage,
  riskScore,
  decideMode,
  buildEvent
};
