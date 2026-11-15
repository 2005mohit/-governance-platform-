#!/usr/bin/env node
// Tests for audit/verify/V7_TRIAGE/build_triage.js.
//
// The important assertions are (a) the triage key is exactly the SARIF
// fingerprint, (b) human fields survive a re-run, and (c) a finding that is
// absent from the new report is retained, not deleted.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const SCRIPT = path.join(REPO_ROOT, "audit", "verify", "V7_TRIAGE", "build_triage.js");
const { buildSARIF } = require(path.join(REPO_ROOT, "src", "reporter"));
const Ajv = require("ajv");

function run(dir, extra = []) {
  execFileSync(
    "node",
    [SCRIPT, path.join(dir, "report.json"), "--out", path.join(dir, "triage.json"), ...extra],
    { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  return JSON.parse(fs.readFileSync(path.join(dir, "triage.json"), "utf8"));
}

function writeReport(dir, findings) {
  fs.writeFileSync(
    path.join(dir, "report.json"),
    JSON.stringify(
      {
        tool: "ai-risk-snapshot",
        version: require(path.join(REPO_ROOT, "package.json")).version,
        generatedAt: "2026-11-15T00:00:00.000Z",
        scannedDirectory: dir,
        filesScanned: 1,
        findings
      },
      null,
      2
    )
  );
}

const baseFindings = [
  {
    id: "NO_HUMAN_LOOP",
    title: "Missing Human-in-the-Loop",
    article: "Article 14 (Human Oversight)",
    severity: "CRITICAL",
    confidence: "high",
    method: "proximity-heuristic",
    file: "src\\app.py",
    line: 10,
    snippet: "delete(user_id)",
    extraFiles: []
  },
  {
    id: "NO_HUMAN_LOOP",
    title: "Missing Human-in-the-Loop",
    article: "Article 14 (Human Oversight)",
    severity: "CRITICAL",
    confidence: "high",
    method: "proximity-heuristic",
    file: "src\\app.py",
    line: 10,
    snippet: "delete(user_id)",
    extraFiles: []
  },
  {
    id: "NO_LOGGING",
    title: "Missing Audit Log",
    article: "Article 12 (Record-Keeping / Logging)",
    severity: "HIGH",
    confidence: "high",
    method: "proximity-heuristic",
    file: "src\\app.py",
    line: 20,
    snippet: "transfer(amount)",
    extraFiles: []
  }
];

function testFingerprintsAndSarf() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "build-triage-"));
  try {
    writeReport(dir, baseFindings);
    const triage = run(dir);

    assert.strictEqual(triage.findings.length, 3);
    assert.strictEqual(triage.fingerprintScheme, "sarif:aiRiskSnapshot/v1");
    assert.strictEqual(triage.findings[0].file, "src/app.py", "file should be forward-slashed");

    const expected = buildSARIF(baseFindings, { scannedDirectory: dir }).runs[0].results.map(
      (r) => r.partialFingerprints["aiRiskSnapshot/v1"]
    );
    assert.deepStrictEqual(
      triage.findings.map((f) => f.fingerprint),
      expected,
      "triage fingerprints must equal the SARIF fingerprints in the same order"
    );
    assert.strictEqual(new Set(expected).size, 3, "identical snippets need distinct duplicate indices");
    for (const f of triage.findings) assert.match(f.fingerprint, /^[a-f0-9]{64}$/);

    assert.strictEqual(triage.summary.byStatus.unreviewed, 3);
    console.log("ok - build_triage: fingerprints match SARIF and duplicate indices stay distinct");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testMergePreservesHumanFields() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "build-triage-"));
  try {
    writeReport(dir, baseFindings);
    const first = run(dir);
    first.findings[0].status = "true_positive";
    first.findings[0].owner = "labeller-a";
    first.findings[0].notes = "Confirmed by reading the call site.";
    fs.writeFileSync(path.join(dir, "triage.json"), JSON.stringify(first, null, 2));

    // Second report: same two findings, the third is gone.
    writeReport(dir, baseFindings.slice(0, 2));
    const second = run(dir, ["--existing", path.join(dir, "triage.json")]);

    assert.strictEqual(second.findings.length, 3, "absent findings must be retained");
    const kept = second.findings.find((f) => f.fingerprint === first.findings[0].fingerprint);
    assert.strictEqual(kept.status, "true_positive");
    assert.strictEqual(kept.owner, "labeller-a");
    assert.strictEqual(kept.notes, "Confirmed by reading the call site.");
    assert.strictEqual(kept.seenCount, 2);
    assert.strictEqual(second.summary.notSeenInLatest, 1);
    assert.strictEqual(second.summary.byStatus.true_positive, 1);
    console.log("ok - build_triage: re-run preserves status, owner and notes; absent row retained");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testFileLevelLine() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "build-triage-"));
  try {
    writeReport(dir, [
      {
        id: "SENSITIVE_DATA",
        title: "Sensitive Personal Documents",
        article: "Article 10",
        severity: "HIGH",
        file: "docs\\passport_scan.pdf",
        line: "N/A",
        snippet: "passport_scan.pdf",
        extraFiles: []
      }
    ]);
    const triage = run(dir);
    assert.strictEqual(triage.findings[0].line, null);
    assert.strictEqual(triage.findings[0].lineRaw, "N/A");
    console.log("ok - build_triage: file-level finding keeps line null and records lineRaw");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testSchema() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "build-triage-"));
  try {
    writeReport(dir, baseFindings);
    const triage = run(dir);
    const schema = require(path.join(REPO_ROOT, "audit", "verify", "V7_TRIAGE", "triage.schema.json"));
    const ajv = new Ajv({ allErrors: true, schemaId: "auto" });
    const valid = ajv.validate(schema, triage);
    assert.ok(valid, ajv.errorsText());
    console.log("ok - build_triage: output validates against triage.schema.json");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

testFingerprintsAndSarf();
testMergePreservesHumanFields();
testFileLevelLine();
testSchema();
console.log("ok - build_triage tests passed");
