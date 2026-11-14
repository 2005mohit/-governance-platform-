// JS/TS definition filtering.
//
// Definitions (function, class method, object method, TS signature) name an
// action but never perform it, so they must not fire the action-verb rules.
// Real calls must keep firing, including `this.delete`, bracket-string calls,
// calls passed as arguments, and calls sharing a line with a definition.
//
// Each file expects exactly one NO_HUMAN_LOOP and one NO_LOGGING finding, or
// zero for a negative fixture.
const assert = require("assert");
const path = require("path");
const Scanner = require("../src/scanner");

const RULES_PATH = path.join(__dirname, "..", "rules", "eu_ai_act.yaml");
const FIXTURE_ROOT = path.join(__dirname, "..", "test-rules", "js-definitions");
const ACTION_RULES = ["NO_HUMAN_LOOP", "NO_LOGGING"];

const ZERO = { NO_HUMAN_LOOP: 0, NO_LOGGING: 0 };
const ONE_EACH = { NO_HUMAN_LOOP: 1, NO_LOGGING: 1 };

// Relative path -> exact count per action rule.
const EXPECTED = {
  "negative/negative-functions.js": ZERO,
  "negative/negative-class.js": ZERO,
  "negative/negative-object.js": ZERO,
  "negative/negative-export.js": ZERO,
  "negative/negative-typescript.ts": ZERO,
  "negative/negative-comments.js": ZERO,
  "positive/positive-db-delete.js": ONE_EACH,
  "positive/positive-await-terminate.js": ONE_EACH,
  "positive/positive-this-delete.js": ONE_EACH,
  "positive/positive-bracket-call.js": ONE_EACH,
  "positive/positive-call-argument.js": ONE_EACH,
  "positive/positive-same-line.js": ONE_EACH,
  // Documented taxonomy gap: `send` is not in high_risk_actions.yaml. This is
  // a real call, not a definition, so it must stay at zero until the pack
  // gains that verb. Do not widen detection here.
  "documented/taxonomy-send.js": ZERO
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
  for (const file of Object.keys(EXPECTED)) {
    actual[file] = { NO_HUMAN_LOOP: 0, NO_LOGGING: 0 };
  }
  for (const finding of findings) {
    if (!ACTION_RULES.includes(finding.id)) continue;
    const key = relative(finding.file);
    if (!actual[key]) actual[key] = { NO_HUMAN_LOOP: 0, NO_LOGGING: 0 };
    actual[key][finding.id]++;
  }

  let checks = 0;
  for (const [file, expected] of Object.entries(EXPECTED)) {
    for (const rule of ACTION_RULES) {
      assert.strictEqual(
        actual[file][rule],
        expected[rule],
        `${file}: expected ${expected[rule]} ${rule} finding(s), got ${actual[file][rule]}`
      );
      checks++;
    }
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
