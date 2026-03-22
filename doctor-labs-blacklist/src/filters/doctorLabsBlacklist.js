// doctor-labs-blacklist/src/filters/doctorLabsBlacklist.js
const BASE_PATTERNS = [
  {
    id: "CRS-basic",
    family: "CRS",
    regex: /\b(credit\s?card|ssn|social\s+security\s+number)\b/i,
  },
  {
    id: "CLLN-basic",
    family: "CLLN",
    regex: /\b(click\s+this\s+malicious\s+link)\b/i,
  },
  {
    id: "XGBC-basic",
    family: "XGBC",
    regex: /\b(extremist\s+group|hate\s+organization)\b/i,
  },
];

function scanMessage(text, extraPatterns) {
  const patterns = [...BASE_PATTERNS, ...(extraPatterns || [])];
  const hits = [];

  for (const pattern of patterns) {
    if (pattern.regex.test(text)) {
      hits.push({
        id: pattern.id,
        family: pattern.family,
      });
    }
  }

  return { original: text, hits };
}

function redactMessage(scanResult) {
  let redacted = scanResult.original;
  for (const hit of scanResult.hits) {
    const categoryToken = `${hit.family}-REDACTED`;
    redacted = redacted.replace(/.+/g, categoryToken);
    break;
  }
  return redacted;
}

function buildEvent(scanResult, context) {
  return {
    type: "doctorlabs.blacklist.scan",
    timestamp: new Date().toISOString(),
    context: context || {},
    hits: scanResult.hits,
  };
}

module.exports = {
  scanMessage,
  redactMessage,
  buildEvent,
};
