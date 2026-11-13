// SARIF 2.1.0 tests.
//
// The official schema is vendored under test/fixtures/sarif/ so this runs
// offline. Ajv is a devDependency only; the scanner itself has no new runtime
// dependency and makes no network calls.
const assert = require("assert");
const { spawnSync } = require("child_process");
const crypto = require("crypto");
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
      const expectedName = rule.id
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join("");
      assert.strictEqual(rule.name, expectedName, `${name}: rule name must be a stable identifier derived from the id`);
      assert.ok(rule.id && rule.name && rule.shortDescription.text);
      assert.ok(["error", "warning", "note"].includes(rule.defaultConfiguration.level));
      assert.ok(rule.properties.article && rule.properties.severity);
      assert.ok(!("providerOrDeployer" in rule.properties), "pack has no providerOrDeployer");
      assert.ok(!("highRiskOnly" in rule.properties), "pack has no highRiskOnly");
    }
    assert.strictEqual(
      driver.rules.find((rule) => rule.id === "IDENTITY_KEY").name,
      "IdentityKey",
      `${name}: IDENTITY_KEY should map to IdentityKey`
    );
    checks++;

    // report.json carries confidence and confidenceWeight on every finding;
    // SARIF properties.confidence must equal the JSON numeric value.
    assert.strictEqual(sarif.runs[0].results.length, json.findings.length);
    for (let i = 0; i < json.findings.length; i++) {
      const finding = json.findings[i];
      const result = sarif.runs[0].results[i];
      assert.ok(["high", "medium"].includes(finding.confidence), `${name}: finding confidence label`);
      assert.strictEqual(
        finding.confidence,
        finding.confidenceWeight >= 1 ? "high" : "medium",
        `${name}: confidence label should match confidenceWeight`
      );
      assert.strictEqual(
        result.properties.confidence,
        finding.confidence,
        `${name}: SARIF confidence label must equal report.json confidence`
      );
      assert.strictEqual(
        result.properties.confidenceWeight,
        finding.confidenceWeight,
        `${name}: SARIF confidenceWeight must equal report.json confidenceWeight`
      );
      assert.ok(
        !result.locations[0].physicalLocation.artifactLocation.uri.includes("\\"),
        `${name}: SARIF uri must use forward slashes`
      );
      if (finding.method) {
        assert.strictEqual(result.properties.method, finding.method, `${name}: SARIF method`);
      } else {
        assert.ok(!("method" in result.properties), `${name}: method must be omitted when the finding has none`);
      }
    }
    checks += 2;

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

  // 5b. Shuffling the input order must not change any finding's fingerprint.
  {
    const rule = { id: "SHUF", title: "Shuffle", article: "Article X", severity: "MEDIUM" };
    const makeFinding = (line, snippet) => ({
      id: "SHUF",
      title: "Shuffle",
      article: "Article X",
      severity: "MEDIUM",
      file: "src/shuffle.py",
      line,
      snippet,
      method: "proximity-heuristic"
    });
    const original = [makeFinding(10, "alpha()"), makeFinding(20, "beta()"), makeFinding(30, "gamma()")];
    const byMessage = (sarif) =>
      Object.fromEntries(
        sarif.runs[0].results.map((result) => [
          result.message.text,
          result.partialFingerprints["aiRiskSnapshot/v1"]
        ])
      );
    const canonical = byMessage(buildSARIF(original, { scannedDirectory: ROOT, rules: [rule] }));
    const shuffled = byMessage(
      buildSARIF([original[2], original[0], original[1]], { scannedDirectory: ROOT, rules: [rule] })
    );
    assert.deepStrictEqual(shuffled, canonical, "fingerprints changed when input order was shuffled");
    checks++;
  }

  // 5c. Nested paths use forward slashes in the URI, and the fingerprint is
  //     computed from that forward-slash URI. report.json is left OS-native.
  {
    const nestedRoot = uniquePath("nested");
    fs.mkdirSync(path.join(nestedRoot, "a", "b"), { recursive: true });
    fs.writeFileSync(path.join(nestedRoot, "a", "b", "c.py"), "pickle.loads(data)\n");
    const outputDir = uniquePath("nested-out");
    const result = runCli([nestedRoot, "--yes", "--format", "all", "-o", outputDir]);
    assert.strictEqual(result.status, 0, `nested scan failed:\n${result.stdout}\n${result.stderr}`);
    const sarif = readJson(path.join(outputDir, "report.sarif"));
    const json = readJson(path.join(outputDir, "report.json"));

    const nestedResult = sarif.runs[0].results.find((r) => r.ruleId === "UNSAFE_DESERIALIZE");
    assert.ok(nestedResult, "nested fixture should fire UNSAFE_DESERIALIZE");
    assert.strictEqual(
      nestedResult.locations[0].physicalLocation.artifactLocation.uri,
      "a/b/c.py",
      "nested URI must be relative and forward-slash separated"
    );
    for (const nested of sarif.runs[0].results) {
      const uri = nested.locations[0].physicalLocation.artifactLocation.uri;
      assert.ok(!uri.includes("\\"), `SARIF uri must not contain a backslash: ${uri}`);
    }
    const expectedFingerprint = crypto
      .createHash("sha256")
      .update(
        `UNSAFE_DESERIALIZE\u0000a/b/c.py\u0000pickle.loads(data)\u00000`
      )
      .digest("hex");
    assert.strictEqual(
      nestedResult.partialFingerprints["aiRiskSnapshot/v1"],
      expectedFingerprint,
      "fingerprint input must use the forward-slash URI"
    );
    if (process.platform === "win32") {
      assert.ok(
        json.findings[0].file.includes("\\"),
        "report.json keeps OS-native separators (documented, not changed here)"
      );
    }
    checks += 3;
  }

  // 6. Level mapping, including LOW -> note via a synthetic finding.
  {
    const rule = { id: "LOW_RULE", title: "Low", article: "Article X", severity: "LOW" };
    const sarif = buildSARIF(
      [{
        id: "LOW_RULE",
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
    assert.ok(!("method" in sarif.runs[0].results[0].properties), "method must be omitted when absent");
    assert.strictEqual(sarif.runs[0].tool.driver.rules[0].name, "LowRule");
    checks += 2;
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
