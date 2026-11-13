// End-to-end exit-code tests.
//
// Every case runs the real CLI in a child process so the assertions cover
// stdout, stderr, the process status, and the fact that report files exist
// before a non-zero gate exit.
const assert = require("assert");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const yaml = require("js-yaml");
const { FAIL_ON_LEVELS } = require("../src/exitcodes");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "src", "cli.js");
const FIXTURES = {
  clean: path.join(ROOT, "test-baseline-commented"),
  medium: path.join(ROOT, "test-exitcodes", "medium"),
  high: path.join(ROOT, "test-exitcodes", "high"),
  critical: path.join(ROOT, "test-exitcodes", "critical")
};

const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "ai-risk-exit-"));
let counter = 0;
let checks = 0;

function uniquePath(prefix) {
  counter++;
  return path.join(TMP_ROOT, `${prefix}-${counter}`);
}

function runCli(args, options = {}) {
  const result = spawnSync(process.execPath, [options.cli || CLI, ...args], {
    cwd: options.cwd || ROOT,
    encoding: "utf8",
    env: { ...process.env, ...(options.env || {}) },
    stdio: options.stdio || "pipe",
    timeout: 120000
  });
  return {
    status: result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || ""
  };
}

function assertExit(result, expected, label) {
  assert.strictEqual(
    result.status,
    expected,
    `${label}: expected exit ${expected}, got ${result.status}\n` +
    `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`
  );
  checks++;
}

function scan(fixture, failOn, extraArgs = []) {
  const outputDir = uniquePath("scan");
  const result = runCli([fixture, "--yes", "--fail-on", failOn, "-o", outputDir, ...extraArgs]);
  return { ...result, outputDir };
}

// Copies just enough of the project to run the CLI against a modified rule
// pack. Used for cases the shipped pack cannot express (a LOW finding and a
// deliberately broken pack). The real rules/ directory is never touched.
function copyProject(prefix) {
  const dest = uniquePath(prefix);
  fs.cpSync(path.join(ROOT, "src"), path.join(dest, "src"), { recursive: true });
  fs.cpSync(path.join(ROOT, "rules"), path.join(dest, "rules"), { recursive: true });
  fs.copyFileSync(path.join(ROOT, "package.json"), path.join(dest, "package.json"));
  return dest;
}

function runCopiedProject(root, args) {
  return runCli(args, {
    cwd: root,
    cli: path.join(root, "src", "cli.js"),
    env: { NODE_PATH: path.join(ROOT, "node_modules") }
  });
}

function assertReportsWritten(result, label) {
  assert.ok(fs.existsSync(path.join(result.outputDir, "report.json")), `${label}: report.json missing`);
  assert.ok(fs.existsSync(path.join(result.outputDir, "report.html")), `${label}: report.html missing`);
  checks++;
}

function main() {
  // 1. none never fails, even when the highest severity is present.
  {
    const result = scan(FIXTURES.critical, "none");
    assertExit(result, 0, "none threshold on critical fixture");
    assertReportsWritten(result, "none threshold on critical fixture");
    assert.ok(!/Fail threshold/.test(result.stderr), "none threshold must not print a gate message");
  }

  // 2. Every threshold that the fixture can meet exits 1 and writes reports.
  {
    const result = scan(FIXTURES.medium, "low");
    assertExit(result, 1, "low threshold on medium fixture");
    assertReportsWritten(result, "low threshold on medium fixture");
    assert.match(result.stderr, /Fail threshold "low" reached/);
  }
  {
    const result = scan(FIXTURES.medium, "medium");
    assertExit(result, 1, "medium threshold on medium fixture");
    assertReportsWritten(result, "medium threshold on medium fixture");
  }
  {
    const result = scan(FIXTURES.high, "high");
    assertExit(result, 1, "high threshold on high fixture");
    assertReportsWritten(result, "high threshold on high fixture");
  }
  {
    const result = scan(FIXTURES.critical, "critical");
    assertExit(result, 1, "critical threshold on critical fixture");
    assertReportsWritten(result, "critical threshold on critical fixture");
  }

  // 3. A threshold above the highest finding exits 0.
  assertExit(scan(FIXTURES.medium, "high"), 0, "high threshold above medium findings");
  assertExit(scan(FIXTURES.high, "critical"), 0, "critical threshold above high findings");

  // 4. The clean fixture exits 0 at every threshold.
  for (const level of FAIL_ON_LEVELS) {
    assertExit(scan(FIXTURES.clean, level), 0, `clean fixture at ${level}`);
  }

  // 5. Invalid --fail-on is a config error, not a finding gate.
  {
    const result = runCli([FIXTURES.clean, "--yes", "--fail-on", "severe", "-o", uniquePath("bad-level")]);
    assertExit(result, 2, "invalid --fail-on value");
    assert.match(result.stderr, /Invalid --fail-on value "severe"/);
  }

  // 6. Missing option value is a bad-argument error.
  {
    const result = runCli([FIXTURES.clean, "--yes", "--fail-on", "-o", uniquePath("no-value")]);
    assertExit(result, 2, "missing --fail-on value");
    assert.match(result.stderr, /--fail-on requires one of/);
  }

  // 7. Unknown option is a bad-argument error.
  {
    const result = runCli([FIXTURES.clean, "--yes", "--wat", "-o", uniquePath("unknown")]);
    assertExit(result, 2, "unknown option");
    assert.match(result.stderr, /Unknown option: --wat/);
  }

  // 8. Nonexistent scan path is a config error.
  {
    const result = runCli([path.join(TMP_ROOT, "does-not-exist"), "--yes", "-o", uniquePath("missing")]);
    assertExit(result, 2, "nonexistent scan path");
    assert.match(result.stderr, /Cannot scan .*directory not found/);
  }

  // 9. A file is not a scannable directory.
  {
    const filePath = path.join(TMP_ROOT, "not-a-directory.txt");
    fs.writeFileSync(filePath, "not a directory\n");
    const result = runCli([filePath, "--yes", "-o", uniquePath("file-path")]);
    assertExit(result, 2, "file as scan path");
    assert.match(result.stderr, /Cannot scan .*not a directory/);
  }

  // 10. Declining consent in a non-interactive run exits 2, never 0.
  {
    const result = runCli([FIXTURES.clean, "-o", uniquePath("declined")]);
    assertExit(result, 2, "consent declined without --yes");
    assert.match(result.stdout, /No interactive terminal detected/);
    assert.match(result.stderr, /Consent was not given/);
  }

  // 11. A rule-pack failure is a tool error, not a clean scan. Build a small
  //     copy of the project so the shipped pack is never touched.
  {
    const brokenRoot = copyProject("broken-pack");
    fs.writeFileSync(path.join(brokenRoot, "rules", "eu_ai_act.yaml"), "rules: [\n");
    const result = runCopiedProject(
      brokenRoot,
      [FIXTURES.clean, "--yes", "-o", path.join(brokenRoot, "out")]
    );
    assertExit(result, 2, "rule-pack failure");
    assert.match(result.stderr, /Scan failed:/);
    assert.ok(!fs.existsSync(path.join(brokenRoot, "out", "report.json")), "no report on a failed scan");
  }

  // 12. The shipped pack has no LOW rule, so make one in a copied pack. This
  //     proves the lowest threshold end-to-end without changing the product's
  //     12-rule pack.
  {
    const lowRoot = copyProject("low-pack");
    const lowPackPath = path.join(lowRoot, "rules", "eu_ai_act.yaml");
    const pack = yaml.load(fs.readFileSync(lowPackPath, "utf8"));
    const corsRule = pack.rules.find((rule) => rule.id === "CORS_WILDCARD");
    assert.ok(corsRule, "CORS_WILDCARD should exist in the copied pack");
    corsRule.severity = "LOW";
    fs.writeFileSync(lowPackPath, yaml.dump(pack));

    const lowOut = path.join(lowRoot, "out-low");
    const lowResult = runCopiedProject(
      lowRoot,
      [FIXTURES.medium, "--yes", "--fail-on", "low", "-o", lowOut]
    );
    assertExit(lowResult, 1, "low threshold on LOW-severity fixture");
    assertReportsWritten({ outputDir: lowOut }, "low threshold on LOW-severity fixture");

    const mediumOut = path.join(lowRoot, "out-medium");
    const mediumResult = runCopiedProject(
      lowRoot,
      [FIXTURES.medium, "--yes", "--fail-on", "medium", "-o", mediumOut]
    );
    assertExit(mediumResult, 0, "medium threshold above LOW-severity finding");
  }

  console.log(`ok - ${checks} CLI exit-code assertions passed`);
}

try {
  main();
} catch (error) {
  console.error(error.message || error);
  process.exitCode = 1;
} finally {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
}
