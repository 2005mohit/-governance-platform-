#!/usr/bin/env node
// Baseline gate for the batch run.
//
// Runs `npm test`, then scans the four baseline fixtures and compares the
// result with the committed expectation snapshot in test/expected/. The
// comparison covers finding id, file, line, snippet, severity, method,
// tool exposure, confidence label/weight, plus the score and band. Generated
// timestamps are deliberately excluded.
//
// Usage:
//   node scripts/gate.js            # verify; exit 1 on any diff
//   node scripts/gate.js --update   # rewrite the expectation snapshot
//
// This file is not shipped in the npm package: package.json `files` lists only
// src/, rules/, README.md and LICENSE.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "src", "cli.js");
const EXPECTED_PATH = path.join(ROOT, "test", "expected", "baselines.json");
const BASELINES = [
  "test-baseline",
  "test-baseline-agent",
  "test-baseline-commented",
  "test-baseline-decisions"
];

const UPDATE = process.argv.includes("--update");
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "ai-risk-gate-"));

function runNpmTest() {
  const isWindows = process.platform === "win32";
  const command = isWindows ? process.env.ComSpec || "cmd.exe" : "npm";
  const args = isWindows ? ["/d", "/s", "/c", "npm test"] : ["test"];
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 600000
  });
  if (result.status !== 0) {
    console.error("gate: npm test failed");
    if (result.stdout) console.error(result.stdout.trim());
    if (result.stderr) console.error(result.stderr.trim());
    process.exit(1);
  }
  console.log("gate: npm test passed");
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 180000
  });
}

function normalizeFinding(finding) {
  return {
    id: finding.id,
    file: String(finding.file || "").replace(/\\/g, "/"),
    line: finding.line,
    snippet: finding.snippet,
    severity: finding.severity,
    method: finding.method || null,
    toolExposure: finding.toolExposure || null,
    confidence: finding.confidence,
    confidenceWeight: finding.confidenceWeight
  };
}

function snapshot(fixture) {
  const outputDir = path.join(TMP_ROOT, fixture);
  const result = runCli([fixture, "--yes", "--format", "json", "-o", outputDir]);
  if (result.status !== 0) {
    throw new Error(
      `scan of ${fixture} exited ${result.status}\n` +
      `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`
    );
  }
  const reportPath = path.join(outputDir, "report.json");
  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  const findings = (report.findings || [])
    .map(normalizeFinding)
    .sort((a, b) => {
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      const la = Number(a.line) || 0;
      const lb = Number(b.line) || 0;
      if (la !== lb) return la - lb;
      if (a.id !== b.id) return a.id < b.id ? -1 : 1;
      const sa = String(a.snippet || "");
      const sb = String(b.snippet || "");
      return sa < sb ? -1 : sa > sb ? 1 : 0;
    });
  return {
    score: report.score,
    band: report.riskRating,
    findings
  };
}

function diffSnapshots(expected, actual) {
  const lines = [];
  if (expected.score !== actual.score) {
    lines.push(`  score: expected ${expected.score}, got ${actual.score}`);
  }
  if (expected.band !== actual.band) {
    lines.push(`  band: expected ${expected.band}, got ${actual.band}`);
  }
  const key = (f) =>
    `${f.id}|${f.file}|${f.line}|${f.snippet}|${f.severity}|${f.method}|${f.toolExposure}|${f.confidence}|${f.confidenceWeight}`;
  const expectedKeys = new Set(expected.findings.map(key));
  const actualKeys = new Set(actual.findings.map(key));
  for (const f of expected.findings) {
    if (!actualKeys.has(key(f))) lines.push(`  removed: ${key(f)}`);
  }
  for (const f of actual.findings) {
    if (!expectedKeys.has(key(f))) lines.push(`  added:   ${key(f)}`);
  }
  return lines;
}

function main() {
  if (!UPDATE) runNpmTest();

  const actual = {};
  for (const fixture of BASELINES) {
    actual[fixture] = snapshot(fixture);
  }

  if (UPDATE) {
    fs.mkdirSync(path.dirname(EXPECTED_PATH), { recursive: true });
    fs.writeFileSync(EXPECTED_PATH, JSON.stringify(actual, null, 2) + "\n");
    console.log(`gate: wrote ${path.relative(ROOT, EXPECTED_PATH)}`);
    return;
  }

  const expected = JSON.parse(fs.readFileSync(EXPECTED_PATH, "utf8"));
  let failed = false;
  for (const fixture of BASELINES) {
    const diff = diffSnapshots(expected[fixture], actual[fixture]);
    if (diff.length) {
      failed = true;
      console.error(`gate: ${fixture} changed`);
      for (const line of diff) console.error(line);
    } else {
      console.log(
        `gate: ${fixture} unchanged ` +
        `(${actual[fixture].findings.length} findings, score ${actual[fixture].score}, ${actual[fixture].band})`
      );
    }
  }
  if (failed) {
    console.error("gate: baseline diff detected — stop condition (a)");
    process.exitCode = 1;
  } else {
    console.log("gate: all baselines match the committed expectation");
  }
}

try {
  main();
} finally {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
}
