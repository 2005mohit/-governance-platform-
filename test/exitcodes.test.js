// Unit tests for the --fail-on threshold logic.
//
// The shipped rule pack has no LOW-severity rule, so a LOW *finding* cannot be
// produced by a repository fixture. These synthetic findings cover that branch
// directly; the CLI integration test covers every threshold value end-to-end.
const assert = require("assert");
const {
  FAIL_ON_LEVELS,
  findingsAtOrAbove,
  shouldFail,
  isValidFailOn
} = require("../src/exitcodes");

const finding = (severity, id) => ({ id: id || severity, severity });
const allSeverities = [
  finding("CRITICAL", "c"),
  finding("HIGH", "h"),
  finding("MEDIUM", "m"),
  finding("LOW", "l")
];

function ids(findings) {
  return findings.map((f) => f.id).join(",");
}

let checks = 0;

for (const level of FAIL_ON_LEVELS) {
  assert.ok(isValidFailOn(level), `${level} should be valid`);
  checks++;
}
assert.ok(!isValidFailOn("severe"), "severe should be invalid");
assert.ok(!isValidFailOn(""), "empty should be invalid");
checks += 2;

assert.strictEqual(ids(findingsAtOrAbove(allSeverities, "critical")), "c");
assert.strictEqual(ids(findingsAtOrAbove(allSeverities, "high")), "c,h");
assert.strictEqual(ids(findingsAtOrAbove(allSeverities, "medium")), "c,h,m");
assert.strictEqual(ids(findingsAtOrAbove(allSeverities, "low")), "c,h,m,l");
assert.strictEqual(ids(findingsAtOrAbove(allSeverities, "none")), "");
checks += 5;

assert.strictEqual(shouldFail(allSeverities, "critical"), true);
assert.strictEqual(shouldFail([finding("HIGH")], "critical"), false);
assert.strictEqual(shouldFail([finding("MEDIUM")], "low"), true);
assert.strictEqual(shouldFail([finding("LOW")], "medium"), false);
assert.strictEqual(shouldFail([finding("LOW")], "low"), true);
assert.strictEqual(shouldFail(allSeverities, "none"), false);
assert.strictEqual(shouldFail([], "low"), false);
assert.strictEqual(shouldFail([finding("UNKNOWN")], "low"), false);
checks += 8;

assert.throws(() => findingsAtOrAbove(allSeverities, "severe"), /Unknown fail-on threshold/);
checks++;

console.log(`ok - ${checks} exit-code threshold assertions passed`);
