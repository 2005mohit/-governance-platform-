// JS/TS definition filtering.
//
// Definitions (function, class method, object method, TS signature) name an
// action but never perform it, so they must not fire the action-verb rules.
// Real calls must keep firing, including `this.delete`, bracket-string calls,
// calls passed as arguments, and calls sharing a line with a definition.
//
// Expected values are totals across both action rules: a positive fixture
// expects exactly one NO_HUMAN_LOOP and exactly one NO_LOGGING finding.
const assert = require("assert");
const path = require("path");
const Scanner = require("../src/scanner");

const RULES_PATH = path.join(__dirname, "..", "rules", "eu_ai_act.yaml");
const FIXTURE_ROOT = path.join(__dirname, "..", "test-rules", "js-definitions");
const ACTION_RULES = ["NO_HUMAN_LOOP", "NO_LOGGING"];

// Relative path -> expected count for each action rule.
const EXPECTED = {
  "negative/negative-functions.js": 0,
  "negative/negative-class.js": 0,
  "negative/negative-object.js": 0,
  "negative/negative-export.js": 0,
  "negative/negative-typescript.ts": 0,
  "negative/negative-comments.js": 0,
  "positive/positive-db-delete.js": 2,
  "positive/positive-await-terminate.js": 2,
  "positive/positive-this-delete.js": 2,
  "positive/positive-bracket-call.js": 2,
  "positive/positive-call-argument.js": 2,
  "positive/positive-same-line.js": 2,
  // Documented taxonomy gap: `send` is not in high_risk_actions.yaml. This is
  // a real call, not a definition, so it must stay at zero until the pack
  // gains that verb. Do not widen detection here.
  "documented/taxonomy-send.js": 0
};

function relative(file) {
  return file.replace(/\\/g, "/");
}

async function main() {
  const scanner = new Scanner(RULES_PATH, FIXTURE_ROOT);
  const originalLog = console.log;
  const originalStderrWrite = process.stderr.write;
  console.log = () => {};
  process.stderr.write = () => true;
  let findings;
  try {
    findings = await scanner.scan();
  } finally {
    console.log = originalLog;
    process.stderr.write = originalStderrWrite;
  }

  const actual = {};
  for (const key of Object.keys(EXPECTED)) actual[key] = 0;
  for (const finding of findings) {
    if (!ACTION_RULES.includes(finding.id)) continue;
    const key = relative(finding.file);
    actual[key] = (actual[key] || 0) + 1;
  }

  let checks = 0;
  for (const [file, expected] of Object.entries(EXPECTED)) {
    assert.strictEqual(
      actual[file] || 0,
      expected,
      `${file}: expected ${expected} action findings ` +
        `(${ACTION_RULES.join(" + ")}), got ${actual[file] || 0}`
    );
    checks++;
  }

  const unexpected = Object.keys(actual).filter((file) => !(file in EXPECTED));
  assert.deepStrictEqual(unexpected, [], `unexpected fixture files produced findings: ${unexpected.join(", ")}`);
  checks++;

  console.log(`ok - ${checks} JS/TS definition-filtering assertions passed`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
