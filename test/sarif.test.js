// SARIF 2.1.0 tests.
//
// The official schema is vendored under test/fixtures/sarif/ so this runs
// offline. Ajv is a devDependency only; the scanner itself has no new runtime
// dependency and makes no network calls.
const assert = require("assert");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Ajv = require("ajv");
const { buildSARIF } = require("../src/reporter");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "src", "cli.js");
const SCHEMA_PATH = path.join(__dirname, "fixtures", "sarif", "sarif-schema-2.1.0.json");
const FIXTURES = {
  baseline: path.join(ROOT, "test-baseline"),
  agent: path.join(ROOT, "test-baseline-agent"),
  commented: path.join(ROOT, "test-baseline-commented"),
  decisions: path.join(ROOT, "test-baseline-decisions")
};

const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "ai-risk-sarif-"));
let counter = 0;
let checks = 0;

const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
const ajv = new Ajv({ schemaId: "id", allErrors: true, strict: false, logger: false });
ajv.addMetaSchema(require("ajv/lib/refs/json-schema-draft-04.json"));
const validateSarif = ajv.compile(schema);

function uniquePath(prefix) {
  counter++;
  return path.join(TMP_ROOT, `${prefix}-${counter}`);
}

function runCli(args) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 120000
  });
  return {
    status: result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || ""
  };
}

function scan(fixture, extraArgs = []) {
  const outputDir = uniquePath("out");
  const result = runCli([fixture, "--yes", "-o", outputDir, ...extraArgs]);
  assert.strictEqual(result.status, 0, `scan failed:\n${result.stdout}\n${result.stderr}`);
  checks++;
  return { ...result, outputDir };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function assertValidSarif(sarif, label) {
  const valid = validateSarif(sarif);
  assert.ok(
    valid,
    `${label}: invalid SARIF\n${JSON.stringify(validateSarif.errors, null, 2)}`
  );
  checks++;
}

function assertNoAbsolutePaths(sarif, label) {
  const text = JSON.stringify(sarif);
  const escapedRoot = ROOT.replace(/\\/g, "\\\\");
  const escapedTmp = TMP_ROOT.replace(/\\/g, "\\\\");
  assert.ok(!text.includes(escapedRoot), `${label}: SARIF contains the repository root`);
  assert.ok(!text.includes(ROOT.replace(/\\/g, "/")), `${label}: SARIF contains the repository root`);
  assert.ok(!text.includes(escapedTmp), `${label}: SARIF contains the temp root`);
  assert.ok(!text.includes(TMP_ROOT.replace(/\\/g, "/")), `${label}: SARIF contains the temp root`);
  // A Windows drive path starts a token (quote, whitespace, or the start of the
  // string). URL schemes such as https:// have a letter before the colon and
  // must not be mistaken for one.
  assert.ok(!/(^|["'\s])[A-Za-z]:[\\/]/.test(text), `${label}: SARIF contains a Windows absolute path`);
  assert.ok(!text.includes("file:///"), `${label}: SARIF contains a file:// URI`);
  checks++;
}

function fingerprints(sarif) {
  return sarif.runs[0].results.map((result) => result.partialFingerprints["aiRiskSnapshot/v1"]);
}

function main() {
  // 1. Every baseline fixture produces schema-valid SARIF and the same result
  //    count as report.json.
  const produced = {};
  for (const [name, fixture] of Object.entries(FIXTURES)) {
    const scanResult = scan(fixture);
    const json = readJson(path.join(scanResult.outputDir, "report.json"));
    const sarif = readJson(path.join(scanResult.outputDir, "report.sarif"));
    produced[name] = sarif;

    assertValidSarif(sarif, `${name} SARIF`);
    assert.strictEqual(sarif.version, "2.1.0", `${name}: SARIF version`);
    assert.strictEqual(
      sarif.runs[0].results.length,
      json.findings.length,
      `${name}: SARIF result count should equal report.json finding count`
    );
    checks++;

    assertNoAbsolutePaths(sarif, `${name} SARIF`);

    const driver = sarif.runs[0].tool.driver;
    assert.strictEqual(driver.name, "ai-risk-snapshot");
    assert.ok(driver.rules.length > 0, `${name}: driver.rules should not be empty`);
    assert.ok(!("informationUri" in driver), `${name}: informationUri must be omitted when package.json has no repository URL`);
    for (const rule of driver.rules) {
      assert.ok(rule.id && rule.name && rule.shortDescription.text);
      assert.ok(["error", "warning", "note"].includes(rule.defaultConfiguration.level));
      assert.ok(rule.properties.article && rule.properties.severity);
      assert.ok(!("providerOrDeployer" in rule.properties), "pack has no providerOrDeployer");
      assert.ok(!("highRiskOnly" in rule.properties), "pack has no highRiskOnly");
    }
    checks++;

    const runProperties = sarif.runs[0].properties;
    assert.deepStrictEqual(runProperties.applicability, json.applicability);
    assert.strictEqual(
      runProperties.indicatorsNotComplianceDetermination,
      json.applicability.articleReferencesNote
    );
    checks++;
  }

  // 2. Zero findings -> valid SARIF with an empty results array.
  assert.strictEqual(produced.commented.runs[0].results.length, 0, "commented fixture should have zero results");
  assertValidSarif(produced.commented, "zero-finding SARIF");
  checks++;

  // 3. Fingerprints are identical across three runs.
  const fingerprintRuns = [0, 1, 2].map(() => {
    const result = scan(FIXTURES.baseline);
    return fingerprints(readJson(path.join(result.outputDir, "report.sarif")));
  });
  assert.deepStrictEqual(fingerprintRuns[1], fingerprintRuns[0], "fingerprints changed on run 2");
  assert.deepStrictEqual(fingerprintRuns[2], fingerprintRuns[0], "fingerprints changed on run 3");
  checks += 2;

  // 4. A blank line above a finding shifts the line number but not the hash.
  {
    const copyRoot = uniquePath("blank-line");
    fs.cpSync(FIXTURES.baseline, copyRoot, { recursive: true });
    const target = path.join(copyRoot, "src", "agent.py");
    const original = fs.readFileSync(target, "utf8");
    fs.writeFileSync(target, "\n" + original);

    const before = scan(FIXTURES.baseline);
    const after = scan(copyRoot);
    const beforeFingerprints = fingerprints(readJson(path.join(before.outputDir, "report.sarif"))).sort();
    const afterFingerprints = fingerprints(readJson(path.join(after.outputDir, "report.sarif"))).sort();
    assert.deepStrictEqual(afterFingerprints, beforeFingerprints, "fingerprints changed when a blank line was inserted");
    checks++;
  }

  // 5. Duplicate snippets in one file get distinct hashes, and line numbers do
  //    not participate in the hash.
  {
    const rule = { id: "DUP", title: "Duplicate", article: "Article X", severity: "HIGH" };
    const makeFinding = (line, snippet) => ({
      id: "DUP",
      title: "Duplicate",
      article: "Article X",
      severity: "HIGH",
      file: "src/a.py",
      line,
      snippet,
      method: "proximity-heuristic"
    });
    const sarif = buildSARIF(
      [makeFinding(1, "db.delete(x)"), makeFinding(2, "  db.delete(x)  ")],
      { scannedDirectory: ROOT, rules: [rule] }
    );
    const values = fingerprints(sarif);
    assert.strictEqual(values.length, 2);
    assert.notStrictEqual(values[0], values[1], "duplicate snippets must not share a fingerprint");
    const moved = buildSARIF([makeFinding(99, "db.delete(x)")], { scannedDirectory: ROOT, rules: [rule] });
    assert.strictEqual(
      fingerprints(moved)[0],
      values[0],
      "changing only the line number must not change the fingerprint"
    );
    assert.strictEqual(sarif.runs[0].results[1].level, "error", "HIGH should map to error");
    checks += 3;
  }

  // 6. Level mapping, including LOW -> note via a synthetic finding.
  {
    const rule = { id: "LOWRULE", title: "Low", article: "Article X", severity: "LOW" };
    const sarif = buildSARIF(
      [{
        id: "LOWRULE",
        title: "Low",
        article: "Article X",
        severity: "LOW",
        file: "src/low.py",
        line: 3,
        snippet: "low",
        method: null
      }],
      { scannedDirectory: ROOT, rules: [rule] }
    );
    assert.strictEqual(sarif.runs[0].results[0].level, "note");
    checks++;
  }

  // 7. --format sarif writes only report.sarif.
  {
    const result = scan(FIXTURES.baseline, ["--format", "sarif"]);
    assert.ok(fs.existsSync(path.join(result.outputDir, "report.sarif")));
    assert.ok(!fs.existsSync(path.join(result.outputDir, "report.json")));
    assert.ok(!fs.existsSync(path.join(result.outputDir, "report.html")));
    checks += 3;
  }

  // 8. JSON and HTML selections write only their own artefact.
  {
    const jsonOnly = scan(FIXTURES.baseline, ["--format", "json"]);
    assert.ok(fs.existsSync(path.join(jsonOnly.outputDir, "report.json")));
    assert.ok(!fs.existsSync(path.join(jsonOnly.outputDir, "report.html")));
    assert.ok(!fs.existsSync(path.join(jsonOnly.outputDir, "report.sarif")));
    const htmlOnly = scan(FIXTURES.baseline, ["--format", "html"]);
    assert.ok(fs.existsSync(path.join(htmlOnly.outputDir, "report.html")));
    assert.ok(!fs.existsSync(path.join(htmlOnly.outputDir, "report.json")));
    assert.ok(!fs.existsSync(path.join(htmlOnly.outputDir, "report.sarif")));
    checks += 6;
  }

  // 9. Invalid --format is a config error and exits 2.
  {
    const outputDir = uniquePath("bad-format");
    const result = runCli([FIXTURES.baseline, "--yes", "--format", "xml", "-o", outputDir]);
    assert.strictEqual(result.status, 2);
    assert.match(result.stderr, /Invalid --format value "xml"/);
    checks += 2;
  }

  // 10. Exit codes from item 1 are unchanged with --format sarif.
  {
    const outputDir = uniquePath("gate-fail");
    const result = runCli([FIXTURES.baseline, "--yes", "--format", "sarif", "--fail-on", "high", "-o", outputDir]);
    assert.strictEqual(result.status, 1, "failing gate with --format sarif must still exit 1");
    assert.ok(fs.existsSync(path.join(outputDir, "report.sarif")));
    checks += 2;
  }
  {
    const outputDir = uniquePath("gate-pass");
    const result = runCli([FIXTURES.commented, "--yes", "--format", "sarif", "--fail-on", "high", "-o", outputDir]);
    assert.strictEqual(result.status, 0, "clean fixture with --format sarif must exit 0");
    checks++;
  }

  // 11. A planted secret appears in neither report.json nor report.sarif.
  {
    const secret = "sk-TESTONLY1234567890abcdef";
    const secretRoot = uniquePath("secret");
    fs.mkdirSync(secretRoot, { recursive: true });
    fs.writeFileSync(path.join(secretRoot, ".env"), `SERVICE_KEY=${secret}\n`);
    const outputDir = uniquePath("secret-out");
    const result = runCli([secretRoot, "--yes", "-o", outputDir]);
    assert.strictEqual(result.status, 0, "secret fixture scan failed");
    const jsonText = fs.readFileSync(path.join(outputDir, "report.json"), "utf8");
    const sarifText = fs.readFileSync(path.join(outputDir, "report.sarif"), "utf8");
    assert.ok(!jsonText.includes(secret), "secret leaked into report.json");
    assert.ok(!sarifText.includes(secret), "secret leaked into report.sarif");
    assert.match(jsonText, /IDENTITY_KEY/);
    assert.match(sarifText, /IDENTITY_KEY/);
    checks += 4;
  }

  console.log(`ok - ${checks} SARIF assertions passed`);
}

try {
  main();
} catch (error) {
  console.error(error.message || error);
  process.exitCode = 1;
} finally {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
}
