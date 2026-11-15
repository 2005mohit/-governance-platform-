#!/usr/bin/env node
// V6 runner: re-scan each verification target, then verify every citation.
//
// Targets are the four V1 repositories and the V3 seeded copy. Reports and
// verification JSON stay in the OS temp directory; only the combined summary
// is written here.
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const TEMP = process.env.TEMP || "/tmp";
const OUT = __dirname;
const REPORTS = path.join(TEMP, "opencode", "v6-reports");

const REUSE = process.argv.includes("--reuse");

const TARGETS = [
  { alias: "crewAI", root: path.join(TEMP, "opencode", "verify-repos", "crewAI"), source: "V1" },
  { alias: "autogen", root: path.join(TEMP, "opencode", "verify-repos", "autogen"), source: "V1" },
  { alias: "mcp-servers", root: path.join(TEMP, "opencode", "verify-repos", "servers"), source: "V1" },
  { alias: "mcp-python-sdk", root: path.join(TEMP, "opencode", "verify-repos", "python-sdk"), source: "V1" },
  { alias: "v3-seeded", root: path.join(TEMP, "opencode", "v3-seeded"), source: "V3" }
];

function runNode(args, label) {
  return execFileSync("node", args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024
  });
}

function main() {
  fs.mkdirSync(REPORTS, { recursive: true });
  const results = [];

  for (const target of TARGETS) {
    if (!fs.existsSync(target.root)) {
      throw new Error(`target root missing: ${target.root} (${target.alias})`);
    }
    const dir = path.join(REPORTS, target.alias);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });

    const report = path.join(dir, "report.json");
    if (!(REUSE && fs.existsSync(report))) {
      runNode(
        [
          path.join(REPO_ROOT, "src", "cli.js"),
          target.root,
          "--yes",
          "--format",
          "json",
          "--output",
          dir
        ],
        target.alias
      );
    }
    const verification = path.join(dir, "verification.json");
    let verifyExit = 0;
    try {
      runNode(
        [path.join(OUT, "verify_report.js"), report, "--out", verification, "--quiet"],
        target.alias
      );
    } catch (error) {
      verifyExit = error.status === undefined ? 1 : error.status;
      if (!fs.existsSync(verification)) throw error;
    }

    const v = JSON.parse(fs.readFileSync(verification, "utf8"));
    results.push({
      alias: target.alias,
      source: target.source,
      root: target.root,
      reportSha256: v.provenance.report.sha256,
      toolVersion: v.provenance.tool.reportVersion,
      rulePackSha256: v.provenance.rulePack.sha256,
      citedFileListSha256: v.provenance.citedFileList.sha256,
      recomputedInventorySha256: v.provenance.recomputedInventory.sha256,
      filesScanned: v.provenance.report.filesScanned,
      findings: v.totals.findings,
      passed: v.totals.passed,
      failed: v.totals.failed,
      fileMissing: v.totals.fileMissing,
      lineOutOfRange: v.totals.lineOutOfRange,
      snippetMatch: v.totals.snippetMatch,
      snippetOffset: v.totals.snippetOffset,
      snippetMismatch: v.totals.snippetMismatch,
      redactedConfirmed: v.totals.redactedConfirmed,
      redactedUnconfirmed: v.totals.redactedUnconfirmed,
      noLine: v.totals.noLine,
      noLineSentinelString: v.totals.noLineSentinelString,
      schemaWarnings: v.schemaWarnings || [],
      extraFileRefs: v.totals.extraFileRefs,
      extraFilesMissing: v.totals.extraFilesMissing,
      verified: v.verified,
      verifyExit,
      citations: v.findings.map((f) => ({
        index: f.index,
        rule: f.rule,
        file: f.file,
        line: f.line,
        lineStatus: f.lineStatus,
        snippetStatus: f.snippetStatus,
        snippetFoundAtLine: f.snippetFoundAtLine,
        ok: f.ok,
        fingerprint: f.fingerprint
      }))
    });
  }

  const totalFindings = results.reduce((n, r) => n + r.findings, 0);
  const totalPassed = results.reduce((n, r) => n + r.passed, 0);
  const combined = {
    generatedBy: "audit/verify/V6_VERIFY/run_verification.js",
    generatedAt: new Date().toISOString(),
    toolVersion: require(path.join(REPO_ROOT, "package.json")).version,
    note:
      "Reports were regenerated from the pinned repositories and the V3 seeded copy, then every " +
      "citation was reopened. A pass means the cited file and line exist and the snippet matches; " +
      "it says nothing about whether the finding is a true positive.",
    totals: {
      targets: results.length,
      findings: totalFindings,
      passed: totalPassed,
      failed: totalFindings - totalPassed
    },
    citations: results.flatMap((r) =>
      r.citations.map((c) => ({ target: r.alias, ...c }))
    ),
    targets: results.map(({ citations, ...rest }) => rest)
  };

  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(combined, null, 2) + "\n");

  const md = [];
  md.push("# V6 — citation verification");
  md.push("");
  md.push("Every row below was produced by re-running the scanner on the pinned tree, then");
  md.push("reopening each cited file:line with `verify_report.js`. A pass means the citation");
  md.push("resolves; it is **not** a judgment that the finding is correct.");
  md.push("");
  md.push(`- Tool version: ${combined.toolVersion}`);
  md.push(`- Targets: ${results.length}`);
  md.push(`- Findings reopened: ${totalFindings}`);
  md.push(`- Citations verified: **${totalPassed}/${totalFindings}**`);
  md.push("");
  md.push("| Target | Source | Findings | Verified | Missing file | Line out of range | Snippet match | Offset | Mismatch | Redacted confirmed | Evaluated redaction | No-line | No-line sentinel | Extra files | Extra missing |");
  md.push("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
  for (const r of results) {
    md.push(
      `| ${r.alias} | ${r.source} | ${r.findings} | ${r.passed} | ${r.fileMissing} | ${r.lineOutOfRange} | ${r.snippetMatch} | ${r.snippetOffset} | ${r.snippetMismatch} | ${r.redactedConfirmed} | ${r.redactedUnconfirmed} | ${r.noLine} | ${r.noLineSentinelString} | ${r.extraFileRefs} | ${r.extraFilesMissing} |`
    );
  }
  md.push("");
  md.push("## Schema warnings");
  md.push("");
  const warnings = results.flatMap((r) =>
    (r.schemaWarnings || []).map((w) => ({ ...w, target: r.alias }))
  );
  if (!warnings.length) {
    md.push("- None.");
  } else {
    for (const w of warnings) {
      md.push(`- ${w.target}: ${w.rule} \`${w.file}\` — ${w.warning}`);
    }
    md.push("");
    md.push("  These are treated as file-level citations (the file is the evidence), not as");
    md.push("  citation failures. The defect is in the report schema, not in the line content.");
  }
  md.push("");
  md.push("## Provenance per target");
  md.push("");
  md.push("| Target | Tool | Rule pack SHA-256 | Report SHA-256 | Cited file-list SHA-256 | Recomputed inventory SHA-256 |");
  md.push("|---|---|---|---|---|---|");
  for (const r of results) {
    md.push(
      `| ${r.alias} | ${r.toolVersion} | \`${r.rulePackSha256.slice(0, 16)}…\` | \`${r.reportSha256.slice(0, 16)}…\` | \`${r.citedFileListSha256.slice(0, 16)}…\` | \`${r.recomputedInventorySha256.slice(0, 16)}…\` |`
    );
  }
  md.push("");
  md.push("Full hashes are in `results.json`.");
  md.push("");
  md.push("## What this does and does not establish");
  md.push("");
  md.push("- It establishes that the report is internally traceable: every cited path exists, the");
  md.push("  line is in range, and the snippet is on that line (or, for redacted secrets, a");
  md.push("  secret-shaped pattern is on the line).");
  md.push("- It does not establish that the finding is a true positive, that the rule is legally");
  md.push("  correct, or that the scan was complete.");
  md.push("- `recomputedInventorySha256` is recomputed with the scanner's own `walkDir` at");
  md.push("  verification time. The report does not embed a file list, so the original inventory");
  md.push("  cannot be proven from the report alone. That is the gap V7 proposes to close.");
  md.push("- Redacted `IDENTITY_KEY` snippets cannot be matched literally. They are verified by");
  md.push("  applying the rule's own patterns to the cited line; that confirms the shape, not the");
  md.push("  original value.");
  md.push("");
  fs.writeFileSync(path.join(OUT, "RESULTS.md"), md.join("\n"));

  console.log(`ok - ${totalPassed}/${totalFindings} citations verified across ${results.length} targets`);
  for (const r of results) {
    console.log(`  ${r.alias}: ${r.passed}/${r.findings}${r.failed ? ` (${r.failed} failed)` : ""}`);
  }
  if (totalPassed !== totalFindings) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  console.error(`run_verification: ${error.message}`);
  process.exitCode = 1;
}
