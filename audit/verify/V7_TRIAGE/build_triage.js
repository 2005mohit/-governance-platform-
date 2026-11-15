#!/usr/bin/env node
// V7: build a triage file from a report.json.
//
// The triage key is the SARIF fingerprint, not file:line. The fingerprint is
// obtained by calling the project's own buildSARIF() and reading
// partialFingerprints["aiRiskSnapshot/v1"], so this file cannot drift from the
// SARIF output. Line numbers are presentation only.
//
// Human-owned fields (status, owner, notes, labels, duplicateOf,
// acceptedRiskExpiry) are preserved when an existing triage file is supplied.
//
// Usage:
//   node build_triage.js <report.json> [--verification <verification.json>]
//                        [--existing <triage.json>] [--out <triage.json>]
//                        [--csv <triage.csv>]
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { buildSARIF } = require(path.join(REPO_ROOT, "src", "reporter"));
const pkg = require(path.join(REPO_ROOT, "package.json"));

const STATUSES = [
  "unreviewed",
  "true_positive",
  "false_positive",
  "context",
  "accepted_risk",
  "fixed",
  "wont_fix",
  "duplicate"
];

function parseArgs(argv) {
  const opts = {
    report: null,
    verification: null,
    existing: null,
    out: null,
    csv: null
  };
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (["--verification", "--existing", "--out", "--csv"].includes(arg)) {
      const v = args[i + 1];
      if (!v || v.startsWith("-")) return { error: `${arg} requires a value.` };
      opts[arg.slice(2)] = path.resolve(v);
      i++;
    } else if (arg.startsWith("-")) {
      return { error: `Unknown option: ${arg}` };
    } else if (!opts.report) {
      opts.report = path.resolve(arg);
    } else {
      return { error: `Unexpected extra argument: ${arg}` };
    }
  }
  if (!opts.report) return { error: "A report.json path is required." };
  return { opts };
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function rulePackHash() {
  const files = ["eu_ai_act.yaml", "high_risk_actions.yaml"]
    .map((n) => path.join(REPO_ROOT, "rules", n))
    .filter((f) => fs.existsSync(f));
  return crypto
    .createHash("sha256")
    .update(files.map((f) => fs.readFileSync(f)).reduce((a, b) => Buffer.concat([a, Buffer.from("\n"), b])))
    .digest("hex");
}

function normSlash(p) {
  return String(p || "").replace(/\\/g, "/");
}

function lineOf(finding) {
  const n = Number(finding.line);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function csvCell(value) {
  const s = value == null ? "" : String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function loadVerification(file) {
  if (!file) return null;
  if (!fs.existsSync(file)) throw new Error(`verification file not found: ${file}`);
  const v = JSON.parse(fs.readFileSync(file, "utf8"));
  const byFingerprint = new Map();
  for (const f of v.findings || []) {
    if (f && f.fingerprint) byFingerprint.set(f.fingerprint, f);
  }
  return byFingerprint;
}

function loadExisting(file) {
  if (!file) return new Map();
  if (!fs.existsSync(file)) throw new Error(`existing triage file not found: ${file}`);
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  const map = new Map();
  for (const row of doc.findings || []) {
    if (row && row.fingerprint) map.set(row.fingerprint, row);
  }
  return map;
}

function main() {
  const parsed = parseArgs(process.argv);
  if (parsed.error) {
    console.error(parsed.error);
    process.exitCode = 2;
    return;
  }
  const opts = parsed.opts;

  const report = JSON.parse(fs.readFileSync(opts.report, "utf8"));
  if (!Array.isArray(report.findings)) throw new Error("report.json has no findings array");

  const verification = loadVerification(opts.verification);
  const existing = loadExisting(opts.existing);

  // Reuse the SARIF fingerprint implementation rather than re-deriving it.
  const sarif = buildSARIF(report.findings, {
    scannedDirectory: report.scannedDirectory
  });
  const fingerprintByIndex = sarif.runs[0].results.map(
    (r) => r.partialFingerprints["aiRiskSnapshot/v1"]
  );

  const reportHash = sha256File(opts.report);
  const now = new Date().toISOString();
  const seen = new Set();

  const rows = report.findings.map((f, index) => {
    const fingerprint = fingerprintByIndex[index];
    seen.add(fingerprint);
    const prior = existing.get(fingerprint) || {};
    const v = verification ? verification.get(fingerprint) : null;
    const history = Array.isArray(prior.history) ? prior.history.slice() : [];
    history.push({
      reportSha256: reportHash,
      reportGeneratedAt: report.generatedAt || null,
      present: true
    });

    return {
      fingerprint,
      ruleId: f.id,
      file: normSlash(f.file),
      line: lineOf(f),
      lineRaw: f.line == null ? null : f.line,
      severity: f.severity || null,
      article: f.article || null,
      title: f.title || null,
      confidence: f.confidence || null,
      method: f.method || null,
      toolExposure: f.toolExposure || null,
      snippet: f.snippet || "",
      status: STATUSES.includes(prior.status) ? prior.status : "unreviewed",
      owner: prior.owner == null ? null : prior.owner,
      notes: prior.notes == null ? "" : prior.notes,
      labels: Array.isArray(prior.labels) ? prior.labels : [],
      duplicateOf: prior.duplicateOf == null ? null : prior.duplicateOf,
      acceptedRiskExpiry: prior.acceptedRiskExpiry == null ? null : prior.acceptedRiskExpiry,
      firstSeen: prior.firstSeen || report.generatedAt || now,
      lastSeen: report.generatedAt || now,
      seenCount: Number.isInteger(prior.seenCount) ? prior.seenCount + 1 : 1,
      notSeenInLatest: false,
      verification: v
        ? {
            citationVerified: !!v.ok,
            lineStatus: v.lineStatus,
            snippetStatus: v.snippetStatus,
            snippetFoundAtLine: v.snippetFoundAtLine,
            fingerprint: v.fingerprint
          }
        : null,
      history
    };
  });

  // Keep rows that are absent from this report. A finding can disappear
  // because it was fixed, because the file moved, or because the rule changed.
  // None of those is safe to infer automatically, so the row is retained and
  // marked as not seen.
  const absent = [];
  for (const [fingerprint, prior] of existing) {
    if (seen.has(fingerprint)) continue;
    const history = Array.isArray(prior.history) ? prior.history.slice() : [];
    history.push({
      reportSha256: reportHash,
      reportGeneratedAt: report.generatedAt || null,
      present: false
    });
    absent.push({ ...prior, notSeenInLatest: true, history });
  }

  const all = [...rows, ...absent];
  const byStatus = {};
  for (const s of STATUSES) byStatus[s] = 0;
  for (const r of all) byStatus[r.status] = (byStatus[r.status] || 0) + 1;

  const doc = {
    schemaVersion: "1.0",
    generatedBy: "audit/verify/V7_TRIAGE/build_triage.js",
    generatedAt: now,
    tool: report.tool || null,
    reportVersion: report.version || null,
    lastReportGeneratedAt: report.generatedAt || null,
    reportSha256: reportHash,
    rulePackSha256: rulePackHash(),
    fingerprintScheme: "sarif:aiRiskSnapshot/v1",
    summary: {
      total: all.length,
      presentInLatest: rows.length,
      notSeenInLatest: absent.length,
      byStatus
    },
    findings: all
  };

  const outFile = opts.out || path.join(path.dirname(opts.report), "triage.json");
  fs.writeFileSync(outFile, JSON.stringify(doc, null, 2) + "\n");

  if (opts.csv) {
    const header = [
      "fingerprint",
      "rule",
      "file",
      "line",
      "severity",
      "status",
      "owner",
      "confidence",
      "method",
      "article",
      "notes"
    ];
    const lines = [header.join(",")];
    for (const r of all) {
      lines.push(
        [
          r.fingerprint,
          r.ruleId,
          r.file,
          r.line == null ? "" : r.line,
          r.severity,
          r.status,
          r.owner,
          r.confidence,
          r.method,
          r.article,
          r.notes
        ].map(csvCell).join(",")
      );
    }
    fs.writeFileSync(opts.csv, lines.join("\n") + "\n");
  }

  console.log(
    `build_triage: ${all.length} rows (${rows.length} present, ${absent.length} not seen); ` +
      `${byStatus.unreviewed} unreviewed`
  );
  console.log(`build_triage: wrote ${outFile}`);
}

try {
  main();
} catch (error) {
  console.error(`build_triage: ${error.message}`);
  process.exitCode = 2;
}
