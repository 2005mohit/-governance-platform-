// Rule-pack validation tests.
//
// Every bad pack under test/fixtures/packs/ must be rejected before scanning
// with an actionable message: pack path, rule id (when known), field, problem,
// and fix. The CLI must exit 2 and write no report files.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const Scanner = require("../src/scanner");
const { validateRulePack, RulePackError } = require("../src/rulepack");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "src", "cli.js");
const PACKS = path.join(__dirname, "fixtures", "packs");
const AUDIT_SCHEMA = path.join(ROOT, "audit", "scratch", "schema");
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "ai-risk-pack-"));
let checks = 0;

function pack(name) {
  return path.join(PACKS, name);
}

function assertRejected(file, expected, label) {
  const absolute = path.resolve(file);
  let caught = null;
  try {
    validateRulePack(absolute);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, `${label}: expected validation to fail`);
  assert.ok(caught instanceof RulePackError, `${label}: expected RulePackError, got ${caught && caught.name}`);
  assert.ok(
    caught.message.includes(absolute),
    `${label}: message must include the pack path ${absolute}\n${caught.message}`
  );
  for (const text of expected) {
    assert.ok(
      caught.message.includes(text),
      `${label}: message must include ${JSON.stringify(text)}\n${caught.message}`
    );
  }
  checks++;
  return caught;
}

function runCli(args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 120000,
    env: { ...process.env, ...env }
  });
}

function copyProject(prefix) {
  const dest = path.join(TMP_ROOT, prefix);
  fs.mkdirSync(dest, { recursive: true });
  fs.cpSync(path.join(ROOT, "src"), path.join(dest, "src"), { recursive: true });
  fs.cpSync(path.join(ROOT, "rules"), path.join(dest, "rules"), { recursive: true });
  fs.copyFileSync(path.join(ROOT, "package.json"), path.join(dest, "package.json"));
  return dest;
}

function assertNoReports(outputDir, label) {
  for (const name of ["report.json", "report.html", "report.sarif"]) {
    assert.ok(
      !fs.existsSync(path.join(outputDir, name)),
      `${label}: ${name} must not be written when the pack is invalid`
    );
  }
  checks++;
}

function main() {
  // Valid packs pass, including the shipped pack and a pack with actionsRef.
  {
    const shipped = validateRulePack(path.join(ROOT, "rules", "eu_ai_act.yaml"));
    assert.strictEqual(shipped.rules.length, 12, "shipped pack should contain 12 rules");
    assert.ok(
      shipped.rules.every((rule) => Array.isArray(rule.actions) && rule.actions.length > 0
        || !rule.logic || !["high_risk_action_without_approval", "high_risk_action_without_logging", "bypass_flag_near_action"].includes(rule.logic)),
      "proximity rules should have resolved actions"
    );
    checks++;

    const valid = validateRulePack(pack("valid/pack.yaml"));
    assert.strictEqual(valid.rules.length, 2, "valid pack should contain 2 rules");
    const actionRule = valid.rules.find((rule) => rule.id === "VALID_ACTION");
    assert.deepStrictEqual(actionRule.actions, ["delete"], "actionsRef should resolve to action names");
    checks++;
  }

  assertRejected(pack("invalid-regex.yaml"), [
    'rule "BAD_REGEX"',
    'field "patterns[0]"',
    "does not compile",
    "Fix:"
  ], "invalid regex");

  assertRejected(pack("unknown-severity.yaml"), [
    'rule "ODD_SEVERITY"',
    'field "severity"',
    "SUPER",
    "CRITICAL, HIGH, MEDIUM, LOW",
    "Fix:"
  ], "unknown severity");

  assertRejected(pack("empty-rules.yaml"), [
    'field "rules"',
    "at least one rule",
    "Fix:"
  ], "empty rule list");

  assertRejected(pack("empty-patterns.yaml"), [
    'rule "EMPTY_PATTERNS"',
    'field "patterns"',
    "empty",
    "Fix:"
  ], "empty patterns");

  assertRejected(pack("missing-field.yaml"), [
    'field "id"',
    'rule "NO_DETECTION"',
    'field "patterns/logic"',
    "Fix:"
  ], "missing required field");

  assertRejected(pack("duplicate-ids.yaml"), [
    'rule "DUPLICATE"',
    "duplicate",
    "Fix:"
  ], "duplicate rule ids");

  assertRejected(pack("wrong-types.yaml"), [
    'rule "WRONG_TYPES"',
    'field "fileTypes"',
    'field "patterns"',
    "expected a list",
    "Fix:"
  ], "wrong field types");

  assertRejected(pack("dangling-ref.yaml"), [
    'rule "DANGLING"',
    'field "actionsRef"',
    "missing_taxonomy",
    "could not be loaded",
    "Fix:"
  ], "dangling actionsRef");

  assertRejected(pack("alias-bomb.yaml"), [
    'rule "ALIAS_BOMB"',
    "alias",
    "expansion",
    "Fix:"
  ], "alias bomb");

  assertRejected(pack("oversized.yaml"), [
    "exceeds",
    "byte",
    "Fix:"
  ], "oversized pack");

  assertRejected(pack("unknown-top-level.yaml"), [
    "unknown top-level key",
    '"version"',
    "Fix:"
  ], "unknown top-level key");

  assertRejected(pack("catastrophic-regex.yaml"), [
    'rule "REDOS"',
    'field "patterns[0]"',
    "catastrophic",
    "nested quantifier",
    "Fix:"
  ], "catastrophic regex");

  assertRejected(pack("non-list-rules.yaml"), [
    'field "rules"',
    "expected a list",
    "Fix:"
  ], "non-list rules");

  assertRejected(pack("unknown-rule-field.yaml"), [
    'rule "UNKNOWN_RULE_FIELD"',
    "unknown field",
    '"pattern"',
    "Fix:"
  ], "unknown rule field");

  // Scanner validates at construction, so direct callers cannot bypass it.
  {
    assert.throws(
      () => new Scanner(pack("invalid-regex.yaml"), path.join(ROOT, "test-baseline-commented")),
      RulePackError,
      "Scanner construction must validate the pack"
    );
    checks++;
  }

  // The audit's own schema probes are test inputs when present locally.
  if (fs.existsSync(AUDIT_SCHEMA)) {
    for (const name of fs.readdirSync(AUDIT_SCHEMA).filter((n) => n.endsWith(".yaml"))) {
      assertRejected(
        path.join(AUDIT_SCHEMA, name),
        [],
        `audit schema case ${name}`
      );
    }
  }

  // End-to-end: a bad pack exits 2, explains the problem, and writes no report.
  for (const [fixture, expected] of [
    ["invalid-regex.yaml", ['rule "BAD_REGEX"', "does not compile"]],
    ["alias-bomb.yaml", ["alias", "expansion"]]
  ]) {
    const copied = copyProject(`cli-${path.basename(fixture, ".yaml")}`);
    const packPath = path.join(copied, "rules", "eu_ai_act.yaml");
    fs.copyFileSync(pack(fixture), packPath);
    const out = path.join(copied, "out");
    const result = spawnSync(
      process.execPath,
      [path.join(copied, "src", "cli.js"), path.join(ROOT, "test-baseline-commented"), "--yes", "--format", "json", "-o", out],
      {
        cwd: copied,
        encoding: "utf8",
        timeout: 120000,
        env: { ...process.env, NODE_PATH: path.join(ROOT, "node_modules") }
      }
    );
    assert.strictEqual(result.status, 2, `${fixture}: expected exit 2, got ${result.status}\n${result.stderr}`);
    assert.ok(
      result.stderr.includes("Rule pack validation failed"),
      `${fixture}: stderr must label the failure\n${result.stderr}`
    );
    assert.ok(result.stderr.includes(packPath), `${fixture}: stderr must include the pack path`);
    for (const text of expected) {
      assert.ok(result.stderr.includes(text), `${fixture}: stderr must include ${JSON.stringify(text)}\n${result.stderr}`);
    }
    assertNoReports(out, `${fixture} CLI`);
    checks += 3;
  }

  console.log(`ok - ${checks} rule-pack validation assertions passed`);
}

try {
  main();
} finally {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
}
