// File: src/filters/doctorLabsPowerShellGuard.js
/**
 * Doctor-Labs PowerShellGuard middleware (blacklist-mode)
 * - Sanitizes PBS/CEP/XGBC patterns in AI-chat → PowerShell generation.
 * - Enforces monotone capability escalation using your BI/ALN sessionid.
 * - Never performs reversals, downgrades, rollbacks, or shutdowns.
 */

const DEFAULT_PATTERNS = [
  // XGBC (from document)
  { key: 'XGBC', pattern: /urban[- ]?digital[- ]?twin/i },
  // PBS (new from 2025–2026 threats)
  { key: 'PBS', pattern: /clm-rout|FullBypass|Stracciatella|runspace/i },
  // CEP
  { key: 'CEP', pattern: /AMSI bypass|CLM evasion|constrained language bypass/i }
];

function scanMessage(text, extraPatterns = [], sessionId = null, biDid = null) {
  const patterns = [...DEFAULT_PATTERNS, ...extraPatterns];
  const hits = [];
  for (const { key, pattern } of patterns) {
    if (pattern.test(text)) {
      hits.push({ key, pattern: pattern.toString() });
    }
  }
  // Guard with BI/ALN/sessionid (metadata only, no reversal)
  return {
    original: text,
    hits,
    guardContext: { sessionId, biDid, timestamp: new Date().toISOString() }
  };
}

function redactMessage(scanResult) {
  let redacted = scanResult.original;
  for (const { key } of scanResult.hits) {
    const re = new RegExp(DEFAULT_PATTERNS.find(p => p.key === key).pattern.source, 'gi');
    redacted = redacted.replace(re, `[${key}-REDACTED]`);
  }
  return redacted;
}

function computeRogueScore(scanResult) {
  // Simplified R(M) for this impl; full formula in Rust crate
  return scanResult.hits.length * 1.0; // β_F=1.0
}

function escalateCapability(rScore, tau1 = 1.0, tau2 = 3.0) {
  if (rScore <= tau1) return 'Normal';
  if (rScore <= tau2) return 'AugmentedLog';
  return 'AugmentedReview'; // adds G, never removes C
}

function buildEvent(scanResult, context = {}) {
  const r = computeRogueScore(scanResult);
  return {
    type: 'DOCTOR_LABS_POWERSHELL_GUARD_EVENT',
    timestamp: new Date().toISOString(),
    context: { ...context, biDid: context.biDid || 'redacted', sessionId: context.sessionId },
    hits: scanResult.hits,
    rogueScore: r,
    capabilityMode: escalateCapability(r)
  };
}

module.exports = {
  scanMessage,
  redactMessage,
  buildEvent,
  escalateCapability
};
