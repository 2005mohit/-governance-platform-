// src/exitcodes.js
//
// Exit-code policy lives here so the CLI and the tests share one definition
// of "at or above the threshold".
//
//   0  scan completed, no finding at or above --fail-on
//   1  scan completed, at least one finding at or above --fail-on
//   2  tool/config error (bad arguments, unreadable path, rule-pack failure,
//      consent declined, report-write failure, unexpected crash)
const SEVERITY_RANK = Object.freeze({
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
});

const FAIL_ON_LEVELS = Object.freeze(["critical", "high", "medium", "low", "none"]);

const FAIL_ON_RANK = Object.freeze({
  critical: SEVERITY_RANK.CRITICAL,
  high: SEVERITY_RANK.HIGH,
  medium: SEVERITY_RANK.MEDIUM,
  low: SEVERITY_RANK.LOW,
  none: Infinity
});

function normalizeFailOn(value) {
  return typeof value === "string" ? value.toLowerCase() : value;
}

function isValidFailOn(value) {
  return FAIL_ON_LEVELS.includes(normalizeFailOn(value));
}

// Returns the findings at or above the threshold. A finding with an unknown
// severity is ignored rather than treated as critical: a malformed record must
// not fail a build by itself.
function findingsAtOrAbove(findings, failOn) {
  const threshold = FAIL_ON_RANK[normalizeFailOn(failOn)];
  if (threshold === undefined) {
    throw new Error(`Unknown fail-on threshold: ${failOn}`);
  }
  if (threshold === Infinity) return [];
  return findings.filter((finding) => (SEVERITY_RANK[finding.severity] || 0) >= threshold);
}

function shouldFail(findings, failOn) {
  return findingsAtOrAbove(findings, failOn).length > 0;
}

module.exports = {
  SEVERITY_RANK,
  FAIL_ON_LEVELS,
  findingsAtOrAbove,
  shouldFail,
  isValidFailOn
};
