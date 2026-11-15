#!/usr/bin/env node
// V1b: run our matching rules against third-party labelled fixtures.
//
// Nothing from the third-party repositories is copied into this repository.
// The fixtures stay in the temp clone roots; this script reads them, runs the
// scanner and the third-party tool from their own locations, and writes only
// counts, line numbers and short snippets.
//
// Suites:
//   Bandit examples      -> UNSAFE_DESERIALIZE (pickle / yaml / eval / exec)
//   Semgrep rule tests   -> CORS_WILDCARD (FastAPI wildcard fixture)
//                           IAM_WILDCARD (Terraform admin-policy fixture)
//   Gitleaks testdata    -> no per-file expected labels; reference only
//
// Usage: node audit/verify/V1B_THIRD_PARTY/run.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const yaml = require("js-yaml");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const TEMP = process.env.TEMP || "/tmp";
const REPOS = path.join(TEMP, "opencode", "verify-repos");
const OUT = __dirname;
const Scanner = require(path.join(ROOT, "src", "scanner"));

const PINS = {
  bandit: {
    repo: "https://github.com/PyCQA/bandit",
    sha: "2d5467c45c3189f4d7d07e8022276bc73a478abd",
    license: "Apache-2.0",
    licenseFile: "LICENSE"
  },
  semgrep: {
    repo: "https://github.com/semgrep/semgrep-rules",
    sha: "a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2",
    license: "Semgrep Rules License v1.0 (LICENSE is a one-line reference)",
    licenseFile: "LICENSE"
  },
  gitleaks: {
    repo: "https://github.com/gitleaks/gitleaks",
    sha: "5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c",
    license: "MIT",
    licenseFile: "LICENSE"
  }
};

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function rulePackHash() {
  return sha256(
    ["rules/eu_ai_act.yaml", "rules/high_risk_actions.yaml"]
      .map((p) => fs.readFileSync(path.join(ROOT, p)))
      .reduce((a, b) => Buffer.concat([a, Buffer.from("\n"), b]))
  );
}

function loadRules() {
  const doc = yaml.load(fs.readFileSync(path.join(ROOT, "rules", "eu_ai_act.yaml"), "utf8"));
  return new Map(doc.rules.map((r) => [r.id, r]));
}

// Build a temp rule pack with only the rules under test. The original pack is
// never written to.
function buildFilteredPack(ruleIds, rules) {
  const dir = path.join(TEMP, "opencode", "v1b-pack");
  fs.mkdirSync(dir, { recursive: true });
  const doc = yaml.load(fs.readFileSync(path.join(ROOT, "rules", "eu_ai_act.yaml"), "utf8"));
  doc.rules = doc.rules.filter((r) => ruleIds.includes(r.id));
  const file = path.join(dir, "pack.yaml");
  fs.writeFileSync(file, yaml.dump(doc));
  return file;
}

async function scanWith(packPath, targetDir, includeTests = true) {
  const scanner = new Scanner(packPath, targetDir, { includeTests });
  // The scanner prints one line per file. Keep this report readable by
  // silencing that progress output for the duration of the scan only.
  const log = console.log;
  console.log = () => {};
  let findings;
  try {
    findings = await scanner.scan();
  } finally {
    console.log = log;
  }
  return findings.map((f) => ({
    id: f.id,
    file: String(f.file).replace(/\\/g, "/"),
    line: f.line,
    snippet: f.snippet
  }));
}

// Apply the rule's regex patterns line by line. This is NOT scanner output:
// the scanner reports at most one finding per rule per file, so this second
// view is needed to count instances. Comment/string masking is not applied.
function patternMatchLines(rule, filePath) {
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    for (const pattern of rule.patterns || []) {
      if (new RegExp(pattern).test(lines[i])) {
        hits.push({ line: i + 1, pattern, snippet: lines[i].trim().slice(0, 160) });
        break;
      }
    }
  }
  return hits;
}

// Bandit's functional tests assert an issue count per example. Parse them so
// the third-party expectation is read from the pinned source, not hardcoded.
function banditExpectedCounts(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  const out = new Map();
  const blockRe = /expect\s*=\s*\{([\s\S]*?)\}\s*\n\s*self\.check_example\("([^"]+)"\s*,\s*expect\)/g;
  let m;
  while ((m = blockRe.exec(text))) {
    const body = m[1];
    const sev = /"SEVERITY"\s*:\s*\{([^}]*)\}/.exec(body);
    if (!sev) continue;
    let total = 0;
    for (const n of sev[1].match(/\d+/g) || []) total += Number(n);
    out.set(m[2], total);
  }
  return out;
}

function runBandit(files) {
  const env = { ...process.env, PYTHONPATH: path.join(TEMP, "opencode", "v1b-py") };
  const outFile = path.join(TEMP, "opencode", "v1b-bandit.json");
  try {
    execFileSync(
      "python",
      ["-m", "bandit", "-f", "json", "-o", outFile, ...files],
      { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
  } catch (error) {
    // Bandit exits 1 when it finds issues; that is expected.
    if (!fs.existsSync(outFile)) throw error;
  }
  const json = JSON.parse(fs.readFileSync(outFile, "utf8"));
  return json.results.map((r) => ({
    file: path.basename(r.filename),
    line: r.line_number,
    testId: r.test_id,
    testName: r.test_name,
    text: r.issue_text
  }));
}

// Semgrep rule tests annotate the expected target: `# ruleid: <id>` or
// `# ok: <id>` on the line above the construct. Return the next code line.
function semgrepAnnotationTargets(filePath) {
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  const positives = [];
  const negatives = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:\/\/|#)\s*(ruleid|ok):\s*(\S+)/.exec(lines[i]);
    if (!m) continue;
    let j = i + 1;
    while (j < lines.length && (/^\s*$/.test(lines[j]) || /^\s*(?:\/\/|#)/.test(lines[j]))) j++;
    if (j >= lines.length) continue;
    const target = { line: j + 1, text: lines[j].trim().slice(0, 160), annotationLine: i + 1 };
    (m[1] === "ruleid" ? positives : negatives).push(target);
  }
  return { positives, negatives };
}

// Terraform fixture is block-structured: the annotation precedes a heredoc
// policy, not one code line. Group by `resource` block and record whether the
// block carries a ruleid/ok annotation.
function terraformBlocks(filePath) {
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  const blocks = [];
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    if (/^resource\s+"/.test(lines[i])) {
      current = { start: i + 1, end: null, annotation: null, lines: [] };
      blocks.push(current);
    }
    if (!current) continue;
    const ann = /^\s*#\s*(ruleid|ok):/.exec(lines[i]);
    if (ann) current.annotation = ann[1];
    current.lines.push({ line: i + 1, text: lines[i] });
    if (/^\}\s*$/.test(lines[i])) {
      current.end = i + 1;
      current = null;
    }
  }
  return blocks;
}

function hitsInBlock(hits, block) {
  return hits.filter((h) => h.line >= block.start && h.line <= block.end);
}

function pct(num, den) {
  return den ? `${num}/${den} (${((num / den) * 100).toFixed(1)}%)` : "n/a";
}

async function main() {
  const rules = loadRules();
  const packPath = buildFilteredPack(
    ["UNSAFE_DESERIALIZE", "CORS_WILDCARD", "IAM_WILDCARD"],
    rules
  );

  const results = {
    generatedBy: "audit/verify/V1B_THIRD_PARTY/run.js",
    generatedAt: new Date().toISOString(),
    toolVersion: require(path.join(ROOT, "package.json")).version,
    rulePackSha256: rulePackHash(),
    note:
      "Third-party suites only. Results are reported separately from the project corpus and " +
      "are not a measure of general precision or recall.",
    suites: {}
  };

  // ---------- Bandit ----------
  const banditDir = path.join(REPOS, "bandit");
  const banditExamples = path.join(banditDir, "examples");
  const banditFiles = ["pickle_deserialize.py", "yaml_load.py", "eval.py", "exec.py"];
  const banditFindingsAll = await scanWith(packPath, banditExamples, true);
  const banditFindings = banditFindingsAll.filter((f) =>
    banditFiles.includes(path.basename(f.file))
  );
  const banditActual = runBandit(banditFiles.map((f) => path.join(banditExamples, f)));
  const banditExpected = banditExpectedCounts(
    path.join(banditDir, "tests", "functional", "test_functional.py")
  );

  const banditCases = banditFiles.map((file) => {
    const filePath = path.join(banditExamples, file);
    const hits = patternMatchLines(rules.get("UNSAFE_DESERIALIZE"), filePath);
    const scanner = banditFindings.filter((f) => path.basename(f.file) === file);
    const thirdParty = banditActual.filter((r) => r.file === file);
    const expectedTests = [...new Set(thirdParty.map((r) => r.testId))];
    // Match at the line level, but only for constructs our rule claims to
    // cover. B307/B102 are listed for context, not counted as our misses.
    const coveredTests = expectedTests.filter((id) => ["B301", "B506"].includes(id));
    const covered = thirdParty.filter((r) => coveredTests.includes(r.testId));
    const matched = covered.filter((r) => hits.some((h) => h.line === r.line));
    return {
      file,
      banditExpectedIssuesFromFunctionalTest: banditExpected.get(file) ?? null,
      banditIssuesAtRuntime: thirdParty.map((r) => ({
        line: r.line,
        testId: r.testId,
        text: r.text
      })),
      scannerFinding: scanner.length ? scanner[0] : null,
      scannerFlaggedFile: scanner.length > 0,
      patternMatchLines: hits.map((h) => h.line),
      coveredConstructs: {
        tests: coveredTests,
        expected: covered.length,
        matched: matched.length,
        missed: covered
          .filter((r) => !hits.some((h) => h.line === r.line))
          .map((r) => ({ line: r.line, testId: r.testId, text: r.text }))
      },
      outOfScopeConstructs: thirdParty
        .filter((r) => !coveredTests.includes(r.testId))
        .map((r) => ({ line: r.line, testId: r.testId, text: r.text }))
    };
  });

  const coveredExpected = banditCases.reduce((n, c) => n + c.coveredConstructs.expected, 0);
  const coveredMatched = banditCases.reduce((n, c) => n + c.coveredConstructs.matched, 0);

  results.suites.bandit = {
    ...PINS.bandit,
    rule: "UNSAFE_DESERIALIZE",
    scanner: {
      filesScannedInExamplesDir: banditFindingsAll.length,
      findingsInTestFiles: banditFindings
    },
    banditVersion: "1.9.4",
    cases: banditCases,
    totals: {
      testFiles: banditFiles.length,
      filesFlaggedByScanner: banditCases.filter((c) => c.scannerFlaggedFile).length,
      coveredInstancesExpected: coveredExpected,
      coveredInstancesMatched: coveredMatched,
      coverage: pct(coveredMatched, coveredExpected),
      outOfScopeInstances: banditCases.reduce((n, c) => n + c.outOfScopeConstructs.length, 0)
    },
    scopeNote:
      "B301 (pickle) and B506 (unsafe yaml) are counted: both tools claim these constructs. " +
      "B307 (eval) and B102 (exec) are shown but not counted as our misses, because our rule " +
      "only claims eval/exec over external input and these fixtures use literals. Bandit's own " +
      "functional-test count is parsed from the pinned test file; runtime lines come from Bandit 1.9.4."
  };

  // ---------- Semgrep: CORS ----------
  const semgrepDir = path.join(REPOS, "semgrep-rules");
  const corsFixture = path.join(semgrepDir, "python", "fastapi", "security", "wildcard-cors.py");
  const corsFindingsAll = await scanWith(packPath, path.dirname(corsFixture), true);
  const corsFindings = corsFindingsAll.filter((f) => path.basename(f.file) === "wildcard-cors.py");
  const corsHits = patternMatchLines(rules.get("CORS_WILDCARD"), corsFixture);
  const corsAnn = semgrepAnnotationTargets(corsFixture);
  const corsPositiveLines = corsAnn.positives.map((p) => p.line);
  const corsNegativeLines = corsAnn.negatives.map((p) => p.line);
  const corsMatched = corsPositiveLines.filter((l) => corsHits.some((h) => h.line === l));
  const corsFalsePositives = corsNegativeLines.filter((l) => corsHits.some((h) => h.line === l));

  results.suites.semgrepCors = {
    ...PINS.semgrep,
    rule: "CORS_WILDCARD",
    fixture:
      "python/fastapi/security/wildcard-cors.py (Semgrep rule: wildcard-cors, taint mode)",
    scannerFinding: corsFindings.length ? corsFindings[0] : null,
    expectedPositiveLines: corsAnn.positives,
    expectedNegativeLines: corsAnn.negatives,
    patternMatchLines: corsHits,
    instanceCoverage: {
      expected: corsPositiveLines.length,
      matched: corsMatched.length,
      missed: corsPositiveLines.filter((l) => !corsMatched.includes(l)),
      value: pct(corsMatched.length, corsPositiveLines.length)
    },
    falsePositivesOnAnnotatedOkLines: {
      expected: corsNegativeLines.length,
      count: corsFalsePositives.length,
      lines: corsFalsePositives
    },
    scopeNote:
      "Semgrep's rule is taint-mode and flags a wildcard reached through a variable; our regex " +
      "only sees a literal ['*']. The miss at the variable line is a real coverage gap, not a harness artefact."
  };

  // ---------- Semgrep: IAM ----------
  const iamFixture = path.join(
    semgrepDir,
    "terraform",
    "aws",
    "security",
    "aws-iam-admin-policy.tf"
  );
  const iamFindingsAll = await scanWith(packPath, path.dirname(iamFixture), true);
  const iamFindings = iamFindingsAll.filter(
    (f) => path.basename(f.file) === "aws-iam-admin-policy.tf"
  );
  const iamHits = patternMatchLines(rules.get("IAM_WILDCARD"), iamFixture);
  const blocks = terraformBlocks(iamFixture);
  const positiveBlocks = blocks.filter((b) => b.annotation === "ruleid");
  const positiveDetected = positiveBlocks.filter((b) => hitsInBlock(iamHits, b).length > 0);
  const unannotatedFlagged = blocks
    .filter((b) => !b.annotation && hitsInBlock(iamHits, b).length > 0)
    .map((b) => ({
      start: b.start,
      end: b.end,
      matchedLines: hitsInBlock(iamHits, b).map((h) => h.line),
      snippets: hitsInBlock(iamHits, b).map((h) => h.snippet)
    }));

  results.suites.semgrepIam = {
    ...PINS.semgrep,
    rule: "IAM_WILDCARD",
    fixture:
      "terraform/aws/security/aws-iam-admin-policy.tf (Semgrep rule: aws-iam-admin-policy)",
    scannerFinding: iamFindings.length ? iamFindings[0] : null,
    positiveBlocks: positiveBlocks.map((b) => ({ start: b.start, end: b.end })),
    patternMatchLines: iamHits.map((h) => h.line),
    blockCoverage: {
      expected: positiveBlocks.length,
      detected: positiveDetected.length,
      missed: positiveBlocks
        .filter((b) => !positiveDetected.includes(b))
        .map((b) => ({ start: b.start, end: b.end })),
      value: pct(positiveDetected.length, positiveBlocks.length)
    },
    unannotatedBlocksFlagged: unannotatedFlagged,
    scopeNote:
      "Only four blocks carry a ruleid annotation; two are arrays (no scalar wildcard) and two " +
      "are scalar Action/Resource '*'. Our regex matches the scalar blocks only. The unannotated " +
      "deny-only block (Effect: Deny, Action/Resource '*') is also matched; Semgrep's Allow-only " +
      "rule does not flag it. It is reported as an extra match, not counted as a Semgrep negative."
  };

  // ---------- Gitleaks ----------
  results.suites.gitleaks = {
    ...PINS.gitleaks,
    status: "REFERENCE-ONLY — NOT MEASURED",
    reason:
      "At the pinned commit, testdata/expected contains formatter-output fixtures and a " +
      "concatenated git fixture, not a per-file expected-findings corpus. No third-party " +
      "per-file labels exist to score against, so no number is produced.",
    observedFiles: fs
      .readdirSync(path.join(REPOS, "gitleaks", "testdata", "expected"), { recursive: true })
      .map((p) => String(p).replace(/\\/g, "/"))
      .slice(0, 20)
  };

  results.limitations = [
    "Bandit and Semgrep rules are not our rules. The comparison measures coverage of third-party labelled constructs, not our own precision or recall.",
    "The scanner reports at most one finding per rule per file; instance counts come from applying the rule regex to the fixture lines and are labelled as pattern-level, not scanner output.",
    "Semgrep fixtures are read in place. Nothing from semgrep-rules is copied into this repository; only aggregate counts and line numbers are published.",
    "These fixtures are small, hand-written tests. No generalisation to real repositories is claimed."
  ];

  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(results, null, 2) + "\n");

  const md = [];
  md.push("# V1b — third-party labelled suites (run 2026-11-15)");
  md.push("");
  md.push("Status: **third-party evidence only**, kept separate from the project corpus. These are");
  md.push("not measurements of this tool's real-world precision or recall.");
  md.push("");
  md.push(`- Tool version: ${results.toolVersion}`);
  md.push(`- Rule-pack SHA-256: \`${results.rulePackSha256}\``);
  md.push(`- Bandit runtime version: 1.9.4`);
  md.push("");
  md.push("## Licence check");
  md.push("");
  md.push("| Suite | Repository | Commit | Licence | What was copied |");
  md.push("|---|---|---|---|---|");
  md.push(`| Bandit | ${PINS.bandit.repo} | \`${PINS.bandit.sha}\` | Apache-2.0 (LICENSE read) | Nothing |`);
  md.push(`| Semgrep rules | ${PINS.semgrep.repo} | \`${PINS.semgrep.sha}\` | \`LICENSE\` is a one-line reference to Semgrep Rules License v1.0; redistribution terms not relied on | Nothing; fixtures read in place, aggregate results only |`);
  md.push(`| Gitleaks | ${PINS.gitleaks.repo} | \`${PINS.gitleaks.sha}\` | MIT (LICENSE read) | Nothing |`);
  md.push("");
  md.push("## Bandit examples — UNSAFE_DESERIALIZE");
  md.push("");
  md.push("| File | Bandit expected (functional test) | Bandit issues at runtime | Scanner flags file | Rule-pattern lines | Covered B301/B506 matched |");
  md.push("|---|---:|---:|---|---|---|");
  for (const c of banditCases) {
    md.push(
      `| ${c.file} | ${c.banditExpectedIssuesFromFunctionalTest ?? "n/a"} | ${c.banditIssuesAtRuntime.length} | ${
        c.scannerFlaggedFile ? "yes" : "no"
      } | ${c.patternMatchLines.join(", ") || "none"} | ${c.coveredConstructs.matched}/${c.coveredConstructs.expected} |`
    );
  }
  md.push("");
  md.push(
    `Covered-construct coverage: **${results.suites.bandit.totals.coverage}** (n=${coveredExpected} B301/B506 instances across 4 files). ` +
      `Out-of-scope Bandit instances (B307/B102, literal eval/exec): ${results.suites.bandit.totals.outOfScopeInstances}.`
  );
  md.push("");
  for (const c of banditCases) {
    if (c.coveredConstructs.missed.length || c.outOfScopeConstructs.length) {
      md.push(`- \`${c.file}\``);
      for (const m of c.coveredConstructs.missed) md.push(`  - MISS (covered construct) line ${m.line}: ${m.testId} — ${m.text}`);
      for (const m of c.outOfScopeConstructs) md.push(`  - out of scope line ${m.line}: ${m.testId} — ${m.text}`);
    }
  }
  md.push("");
  md.push("## Semgrep rule tests");
  md.push("");
  md.push("### CORS_WILDCARD — FastAPI wildcard fixture");
  md.push("");
  md.push(`- Annotated positives: ${corsPositiveLines.length} lines (${corsPositiveLines.join(", ")})`);
  md.push(`- Annotated negatives: ${corsNegativeLines.length} lines (${corsNegativeLines.join(", ")})`);
  md.push(`- Rule-pattern matches: ${corsHits.map((h) => h.line).join(", ") || "none"}`);
  md.push(`- Instance coverage: **${results.suites.semgrepCors.instanceCoverage.value}**`);
  md.push(`- False positives on annotated ok lines: ${corsFalsePositives.length}/${corsNegativeLines.length}`);
  md.push("");
  md.push("### IAM_WILDCARD — Terraform admin-policy fixture");
  md.push("");
  md.push(`- Annotated positive blocks: ${positiveBlocks.length} (${positiveBlocks.map((b) => `${b.start}-${b.end}`).join(", ")})`);
  md.push(`- Blocks with at least one rule-pattern match: ${results.suites.semgrepIam.blockCoverage.value}`);
  md.push(`- Rule-pattern lines: ${iamHits.map((h) => h.line).join(", ") || "none"}`);
  md.push(`- Unannotated blocks also flagged: ${unannotatedFlagged.length}${unannotatedFlagged.length ? ` (lines ${unannotatedFlagged.flatMap((b) => b.matchedLines).join(", ")})` : ""}`);
  md.push("");
  md.push("## Gitleaks");
  md.push("");
  md.push("**REFERENCE-ONLY — NOT MEASURED.** No per-file expected-findings labels at the pinned");
  md.push("commit; the `testdata/expected` tree holds formatter fixtures, not a labelled corpus.");
  md.push("");
  md.push("## Limitations");
  md.push("");
  for (const l of results.limitations) md.push(`- ${l}`);
  md.push("");
  fs.writeFileSync(path.join(OUT, "SUMMARY.md"), md.join("\n"));

  console.log(`ok - bandit coverage ${results.suites.bandit.totals.coverage}`);
  console.log(`ok - cors coverage ${results.suites.semgrepCors.instanceCoverage.value}`);
  console.log(`ok - iam block coverage ${results.suites.semgrepIam.blockCoverage.value}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
