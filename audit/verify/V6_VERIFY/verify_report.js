#!/usr/bin/env node
// V6: verify a report.json against the files it cites.
//
// For every finding this reopens the cited file and line, compares the
// snippet, checks every extraFiles entry, recomputes the SARIF fingerprint
// (same algorithm as src/reporter.js), and records provenance: tool version,
// rule-pack hash, report hash and two file-list hashes.
//
// It does not change the scan. It only says whether the report's citations
// still resolve on disk.
//
// Usage:
//   node audit/verify/V6_VERIFY/verify_report.js <report.json> [options]
//
// Options:
//   --root <dir>          scan root; defaults to report.scannedDirectory
//   --rules <dir>         rule directory; defaults to <repo>/rules
//   --include-tests       mirror a scan that included test directories
//   --out <file>          write JSON here; defaults to <report dir>/verification.json
//   --quiet               suppress the per-finding lines
//
// Exit codes: 0 = all citations verified, 1 = at least one citation failed,
// 2 = usage or input error.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const yaml = require("js-yaml");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const Scanner = require(path.join(REPO_ROOT, "src", "scanner"));
const pkg = require(path.join(REPO_ROOT, "package.json"));

const USAGE =
  "Usage: node verify_report.js <report.json> [--root <dir>] [--rules <dir>]\n" +
  "                              [--include-tests] [--out <file>] [--quiet]";

function parseArgs(argv) {
  const opts = { report: null, root: null, rules: null, includeTests: false, out: null, quiet: false };
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--root" || arg === "--rules" || arg === "--out") {
      const v = args[i + 1];
      if (!v || v.startsWith("-")) return { error: `${arg} requires a value.` };
      if (arg === "--root") opts.root = path.resolve(v);
      if (arg === "--rules") opts.rules = path.resolve(v);
      if (arg === "--out") opts.out = path.resolve(v);
      i++;
    } else if (arg === "--include-tests") {
      opts.includeTests = true;
    } else if (arg === "--quiet") {
      opts.quiet = true;
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

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function sha256File(file) {
  return sha256(fs.readFileSync(file));
}

function normSlash(p) {
  return String(p || "").replace(/\\/g, "/");
}

function normalizeSnippet(snippet) {
  return String(snippet || "").trim().replace(/\s+/g, " ");
}

function isRedacted(snippet) {
  return /value withheld/i.test(String(snippet || ""));
}

// Same escaping rule as src/reporter.js relativeArtifactUri.
function relativeArtifactUri(file, root) {
  let rel = normSlash(file);
  if (path.isAbsolute(file)) {
    rel = root ? normSlash(path.relative(root, file)) : path.basename(file);
  }
  const encoded = rel
    .split("/")
    .filter((s) => s !== "")
    .map((s) => encodeURIComponent(s))
    .join("/");
  return encoded || "unknown";
}

// Same fingerprint and duplicate-index algorithm as buildSARIF.
function computeFingerprints(findings, root) {
  const ordered = findings.map((finding, index) => ({ finding, index }));
  ordered.sort((a, b) => {
    const fa = String(a.finding.file || "");
    const fb = String(b.finding.file || "");
    if (fa !== fb) return fa < fb ? -1 : 1;
    const la = Number(a.finding.line) || 0;
    const lb = Number(b.finding.line) || 0;
    if (la !== lb) return la - lb;
    const ia = String(a.finding.id || "");
    const ib = String(b.finding.id || "");
    if (ia !== ib) return ia < ib ? -1 : 1;
    const sa = normalizeSnippet(a.finding.snippet);
    const sb = normalizeSnippet(b.finding.snippet);
    if (sa !== sb) return sa < sb ? -1 : 1;
    return a.index - b.index;
  });

  const counts = new Map();
  const byIndex = new Map();
  for (const { finding, index } of ordered) {
    const uri = relativeArtifactUri(finding.file, root);
    const snippet = normalizeSnippet(finding.snippet);
    const key = `${finding.id}\u0000${uri}\u0000${snippet}`;
    const duplicateIndex = counts.get(key) || 0;
    counts.set(key, duplicateIndex + 1);
    byIndex.set(
      index,
      sha256(`${finding.id}\u0000${uri}\u0000${snippet}\u0000${duplicateIndex}`)
    );
  }
  return byIndex;
}

function loadRulePack(rulesDir) {
  const files = ["eu_ai_act.yaml", "high_risk_actions.yaml"]
    .map((n) => path.join(rulesDir, n))
    .filter((f) => fs.existsSync(f));
  if (!files.length) throw new Error(`no rule pack found in ${rulesDir}`);
  const byId = new Map();
  for (const f of files) {
    const doc = yaml.load(fs.readFileSync(f, "utf8"));
    for (const r of doc.rules || []) byId.set(r.id, r);
  }
  const packHash = sha256(
    files.map((f) => fs.readFileSync(f)).reduce((a, b) => Buffer.concat([a, Buffer.from("\n"), b]))
  );
  return { files, byId, packHash };
}

async function computeInventory(root, rulesPath, includeTests) {
  const scanner = new Scanner(rulesPath, root, { includeTests });
  const codeFiles = await scanner.walkDir(root);
  const sensitive = scanner.sensitiveFiles || [];
  const all = [...new Set([...codeFiles, ...sensitive].map((f) => normSlash(path.relative(root, f))))].sort();
  return {
    codeFiles: codeFiles.length,
    sensitiveFiles: sensitive.length,
    relativePaths: all,
    sha256: sha256(all.join("\n"))
  };
}

function resolveCitedPath(file, root) {
  if (!file) return null;
  return path.isAbsolute(file) ? file : path.join(root, file);
}

function checkFinding(finding, index, root, rules, fingerprint) {
  const out = {
    index,
    rule: finding.id,
    file: finding.file,
    line: null,
    fingerprint,
    fileExists: false,
    lineStatus: "not-checked",
    snippetStatus: "not-checked",
    snippetFoundAtLine: null,
    redactedPatternConfirmed: null,
    extraFiles: [],
    ok: false
  };

  const resolved = resolveCitedPath(finding.file, root);
  if (!resolved || !fs.existsSync(resolved)) {
    out.lineStatus = "file-missing";
    return out;
  }
  out.fileExists = true;

  const raw = fs.readFileSync(resolved, "utf8");
  const lines = raw.split(/\r?\n/);
  const snippet = String(finding.snippet || "");

  // Project-level findings (SENSITIVE_DATA) have no line. The cited file
  // itself is the evidence, so there is nothing to match on a line.
  //
  // The scanner currently writes the string "N/A" rather than null. That is
  // a report-schema defect, not a citation failure: the file is still the
  // evidence. It is recorded as a warning so the schema issue is not hidden.
  const lineValue = finding.line;
  const fileLevel =
    lineValue == null ||
    lineValue === "" ||
    (typeof lineValue === "string" && /^n\/?a$/i.test(lineValue.trim()));
  if (fileLevel) {
    out.line = null;
    out.lineStatus =
      typeof lineValue === "string" && /^n\/?a$/i.test(lineValue.trim())
        ? "no-line-sentinel"
        : "no-line";
    out.snippetStatus = "no-line";
    if (out.lineStatus === "no-line-sentinel") {
      out.schemaWarning = `line is the string ${JSON.stringify(lineValue)} instead of null`;
    }
  } else {
    const n = Number(finding.line);
    if (!Number.isInteger(n) || n < 1) {
      out.lineStatus = "invalid-line";
    } else if (n > lines.length) {
      out.lineStatus = "out-of-range";
      out.lineTotal = lines.length;
    } else {
      out.line = n;
      out.lineStatus = "ok";
      const cited = normalizeSnippet(lines[n - 1]);
      const wanted = normalizeSnippet(snippet);

      if (!wanted) {
        out.snippetStatus = "empty-snippet";
      } else if (isRedacted(snippet)) {
        const rule = rules.byId.get(finding.id);
        const patterns = (rule && rule.patterns) || [];
        const hit = patterns.some((p) => {
          try {
            return new RegExp(p).test(lines[n - 1]);
          } catch {
            return false;
          }
        });
        out.redactedPatternConfirmed = hit;
        out.snippetStatus = hit ? "redacted-pattern-confirmed" : "redacted-pattern-not-found";
      } else if (cited.includes(wanted)) {
        out.snippetStatus = "match";
      } else {
        // A wrong line number is a citation defect, but a snippet a few lines
        // away tells the reader something useful, so record both.
        for (let d = 1; d <= 3; d++) {
          for (const candidate of [n - 1 - d, n - 1 + d]) {
            if (candidate < 0 || candidate >= lines.length) continue;
            if (normalizeSnippet(lines[candidate]).includes(wanted)) {
              out.snippetStatus = "offset";
              out.snippetFoundAtLine = candidate + 1;
              break;
            }
          }
          if (out.snippetFoundAtLine) break;
        }
        if (!out.snippetFoundAtLine) out.snippetStatus = "mismatch";
      }
    }
  }

  for (const extra of finding.extraFiles || []) {
    const p = path.isAbsolute(extra) ? extra : path.join(root, extra);
    out.extraFiles.push({ path: normSlash(extra), exists: fs.existsSync(p) });
  }

  const extraOk = out.extraFiles.every((e) => e.exists);
  out.ok =
    out.fileExists &&
    extraOk &&
    ["ok", "no-line", "no-line-sentinel"].includes(out.lineStatus) &&
    ["match", "no-line", "redacted-pattern-confirmed"].includes(out.snippetStatus);
  return out;
}

async function main() {
  const parsed = parseArgs(process.argv);
  if (parsed.error) {
    console.error(parsed.error);
    console.error(USAGE);
    process.exitCode = 2;
    return;
  }
  const opts = parsed.opts;

  if (!fs.existsSync(opts.report)) {
    console.error(`verify_report: report not found: ${opts.report}`);
    process.exitCode = 2;
    return;
  }

  const report = JSON.parse(fs.readFileSync(opts.report, "utf8"));
  if (!report || !Array.isArray(report.findings)) {
    console.error("verify_report: report.json has no findings array");
    process.exitCode = 2;
    return;
  }

  const root = opts.root || report.scannedDirectory;
  if (!root || !fs.existsSync(root)) {
    console.error(`verify_report: scan root not found: ${root || "(none)"}`);
    process.exitCode = 2;
    return;
  }

  const rulesDir = opts.rules || path.join(REPO_ROOT, "rules");
  const rules = loadRulePack(rulesDir);
  const inventory = await computeInventory(root, path.join(rulesDir, "eu_ai_act.yaml"), opts.includeTests);
  const fingerprints = computeFingerprints(report.findings, root);

  const results = report.findings.map((f, i) =>
    checkFinding(f, i, root, rules, fingerprints.get(i))
  );

  const citedPaths = [...new Set(report.findings.map((f) => normSlash(f.file)))].sort();
  const totals = {
    findings: results.length,
    passed: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok).length,
    fileMissing: results.filter((r) => r.lineStatus === "file-missing").length,
    lineOutOfRange: results.filter((r) => ["out-of-range", "invalid-line"].includes(r.lineStatus)).length,
    snippetMatch: results.filter((r) => r.snippetStatus === "match").length,
    snippetOffset: results.filter((r) => r.snippetStatus === "offset").length,
    snippetMismatch: results.filter((r) => r.snippetStatus === "mismatch").length,
    redactedConfirmed: results.filter((r) => r.snippetStatus === "redacted-pattern-confirmed").length,
    redactedUnconfirmed: results.filter((r) => r.snippetStatus === "redacted-pattern-not-found").length,
    noLine: results.filter((r) => r.snippetStatus === "no-line").length,
    noLineSentinelString: results.filter((r) => r.lineStatus === "no-line-sentinel").length,
    extraFileRefs: results.reduce((n, r) => n + r.extraFiles.length, 0),
    extraFilesMissing: results.reduce((n, r) => n + r.extraFiles.filter((e) => !e.exists).length, 0)
  };

  const out = {
    generatedBy: "audit/verify/V6_VERIFY/verify_report.js",
    generatedAt: new Date().toISOString(),
    reportPath: opts.report,
    root,
    verified: totals.failed === 0,
    provenance: {
      tool: {
        reportTool: report.tool || null,
        reportVersion: report.version || null,
        packageVersion: pkg.version,
        match: String(report.version) === String(pkg.version)
      },
      report: {
        sha256: sha256File(opts.report),
        generatedAt: report.generatedAt || null,
        scannedDirectory: report.scannedDirectory || null,
        filesScanned: report.filesScanned ?? null
      },
      rulePack: {
        files: rules.files.map((f) => normSlash(path.relative(REPO_ROOT, f))),
        sha256: rules.packHash
      },
      citedFileList: {
        uniqueFiles: citedPaths.length,
        sha256: sha256(citedPaths.join("\n"))
      },
      recomputedInventory: {
        includeTests: opts.includeTests,
        codeFiles: inventory.codeFiles,
        sensitiveFiles: inventory.sensitiveFiles,
        totalPaths: inventory.relativePaths.length,
        sha256: inventory.sha256,
        note:
          "Recomputed at verification time with the scanner's own walkDir. The report does not " +
          "embed a file list, so this cannot prove the original scan saw the same set."
      }
    },
    totals,
    schemaWarnings: results
      .filter((r) => r.schemaWarning)
      .map((r) => ({ index: r.index, rule: r.rule, file: normSlash(r.file), warning: r.schemaWarning })),
    findings: results.map((r) => ({
      index: r.index,
      rule: r.rule,
      file: normSlash(r.file),
      line: r.line,
      fileExists: r.fileExists,
      lineStatus: r.lineStatus,
      lineStatus: r.lineStatus,
      snippetStatus: r.snippetStatus,
      snippetFoundAtLine: r.snippetFoundAtLine,
      redactedPatternConfirmed: r.redactedPatternConfirmed,
      schemaWarning: r.schemaWarning || null,
      extraFiles: r.extraFiles,
      fingerprint: r.fingerprint,
      ok: r.ok
    }))
  };

  const outFile = opts.out || path.join(path.dirname(opts.report), "verification.json");
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2) + "\n");

  if (!opts.quiet) {
    for (const r of out.findings) {
      if (r.ok) continue;
      const why = !r.fileExists
        ? "file missing"
        : r.lineStatus !== "ok" && r.lineStatus !== "no-line"
          ? `line ${r.lineStatus}`
          : r.snippetStatus === "offset"
            ? `snippet found at line ${r.snippetFoundAtLine}, not ${r.line}`
            : r.snippetStatus;
      console.log(`FAIL ${r.rule} ${r.file}:${r.line} - ${why}`);
    }
  }

  console.log(
    `verify_report: ${totals.passed}/${totals.findings} citations verified ` +
      `(${totals.fileMissing} missing files, ${totals.snippetMismatch} snippet mismatches, ` +
      `${totals.snippetOffset} line offsets, ${totals.redactedUnconfirmed} unconfirmed redactions)`
  );
  console.log(`verify_report: wrote ${outFile}`);
  if (!out.verified) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`verify_report: ${error.message}`);
  process.exitCode = 2;
});
