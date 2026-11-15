#!/usr/bin/env node
// Tests for audit/verify/V6_VERIFY/verify_report.js.
//
// The tests build throwaway scan trees and report.json files in the OS temp
// directory, run the verifier as a child process, and assert on the JSON it
// writes. Nothing in src/ or rules/ is touched.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const SCRIPT = path.join(REPO_ROOT, "audit", "verify", "V6_VERIFY", "verify_report.js");

function runVerifier(dir) {
  const out = path.join(dir, "verification.json");
  let code = 0;
  try {
    execFileSync("node", [SCRIPT, path.join(dir, "report.json"), "--out", out, "--quiet"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    code = error.status === undefined ? 1 : error.status;
  }
  return { code, result: JSON.parse(fs.readFileSync(out, "utf8")) };
}

function writeReport(dir, findings) {
  const report = {
    tool: "ai-risk-snapshot",
    version: require(path.join(REPO_ROOT, "package.json")).version,
    generatedAt: "2026-11-15T00:00:00.000Z",
    scannedDirectory: dir,
    filesScanned: 1,
    findings
  };
  fs.writeFileSync(path.join(dir, "report.json"), JSON.stringify(report, null, 2));
}

function makeDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "verify-report-"));
}

function testPassing() {
  const dir = makeDir();
  try {
    fs.writeFileSync(path.join(dir, "sample.py"), 'def hello():\n    print("hello")\n');
    fs.writeFileSync(
      path.join(dir, "secrets.py"),
      'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwx"\n'
    );
    fs.mkdirSync(path.join(dir, "docs"));
    fs.writeFileSync(path.join(dir, "docs", "passport_scan.pdf"), "not a real document\n");

    writeReport(dir, [
      {
        id: "NO_LOGGING",
        file: "sample.py",
        line: 2,
        snippet: '    print("hello")',
        extraFiles: []
      },
      {
        id: "IDENTITY_KEY",
        file: "secrets.py",
        line: 1,
        snippet: "(value withheld — a secret-shaped pattern was matched on this line)",
        extraFiles: []
      },
      {
        id: "SENSITIVE_DATA",
        file: "docs/passport_scan.pdf",
        line: "N/A",
        snippet: "passport_scan.pdf",
        extraFiles: []
      }
    ]);

    const { code, result } = runVerifier(dir);
    assert.strictEqual(code, 0, "passing fixture should exit 0");
    assert.strictEqual(result.totals.findings, 3);
    assert.strictEqual(result.totals.passed, 3);
    assert.strictEqual(result.totals.failed, 0);
    assert.strictEqual(result.totals.snippetMatch, 1);
    assert.strictEqual(result.totals.redactedConfirmed, 1);
    assert.strictEqual(result.totals.noLineSentinelString, 1);
    assert.strictEqual(result.schemaWarnings.length, 1);
    assert.match(result.schemaWarnings[0].warning, /instead of null/);
    assert.match(result.findings[0].fingerprint, /^[a-f0-9]{64}$/);
    console.log("ok - verify_report: passing, redacted and file-level citations");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testFailing() {
  const dir = makeDir();
  try {
    fs.writeFileSync(path.join(dir, "sample.py"), 'def hello():\n    print("hello")\n');

    writeReport(dir, [
      {
        id: "NO_LOGGING",
        file: "sample.py",
        line: 1,
        snippet: '    print("hello")',
        extraFiles: []
      },
      {
        id: "NO_LOGGING",
        file: "missing.py",
        line: 1,
        snippet: 'print("gone")',
        extraFiles: []
      },
      {
        id: "HTTP_NO_AUTH",
        file: "sample.py",
        line: 2,
        snippet: '    print("hello")',
        extraFiles: ["nope.txt"]
      }
    ]);

    const { code, result } = runVerifier(dir);
    assert.strictEqual(code, 1, "failing fixture should exit 1");
    assert.strictEqual(result.totals.failed, 3);
    assert.strictEqual(result.totals.fileMissing, 1);
    assert.strictEqual(result.totals.snippetOffset, 1);
    assert.strictEqual(result.totals.extraFilesMissing, 1);
    const offset = result.findings.find((f) => f.snippetStatus === "offset");
    assert.strictEqual(offset.snippetFoundAtLine, 2);
    assert.strictEqual(offset.ok, false);
    console.log("ok - verify_report: missing file, line offset and missing extraFile");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

testPassing();
testFailing();
console.log("ok - verify_report tests passed");
