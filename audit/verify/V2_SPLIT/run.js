#!/usr/bin/env node
// V2: split corpus reporting. Plain, evasion/stress and framework results are
// reported as separate claims. There is deliberately no pooled headline.
//
// The corpus test is re-run first. If it fails, this script stops: a changed
// baseline is a stop condition, not something to paper over.
//
// Outputs: results.json, REPORT.md (next to this script).
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const OUT = __dirname;
const MANIFEST = path.join(ROOT, "test", "corpus", "manifest.json");
const EXPECTED = path.join(ROOT, "test", "corpus", "expected.json");
const POOL = path.join(ROOT, "audit", "verify", "V1_LABELLING", "findings_pool.json");

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function sha256Buffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function groupOf(c) {
  if (c.type === "framework") return "framework";
  if (c.kind === "evasion") return "evasion";
  if (c.kind === "stress") return "stress";
  return "plain";
}

function runCorpusTest() {
  try {
    const stdout = execFileSync("node", [path.join(ROOT, "test", "corpus.test.js")], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
    return { exitCode: 0, stdout: stdout.trim() };
  } catch (error) {
    return {
      exitCode: error.status === undefined ? 1 : error.status,
      stdout: String(error.stdout || "").trim(),
      stderr: String(error.stderr || "").trim()
    };
  }
}

function pct(n, d) {
  return d ? `${n}/${d} (${((n / d) * 100).toFixed(1)}%)` : "0/0 (n/a)";
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  const expected = JSON.parse(fs.readFileSync(EXPECTED, "utf8"));
  const pool = JSON.parse(fs.readFileSync(POOL, "utf8"));

  const test = runCorpusTest();
  if (test.exitCode !== 0) {
    throw new Error(
      `corpus test failed (exit ${test.exitCode}); stopping because a baseline changed\n` +
        `${test.stdout}\n${test.stderr || ""}`
    );
  }

  const groups = { plain: [], evasion: [], stress: [], framework: [] };
  for (const c of manifest) groups[groupOf(c)].push(c);

  const report = {
    generatedBy: "audit/verify/V2_SPLIT/run.js",
    generatedAt: new Date().toISOString(),
    toolVersion: require(path.join(ROOT, "package.json")).version,
    headline: null,
    headlineReason:
      "No single number. Plain and evasion/stress cases measure different claims; " +
      "pooling them would hide the evasion result. The smallest reported unit is group x rule.",
    provenance: {
      manifestSha256: sha256File(MANIFEST),
      expectedSnapshotSha256: sha256File(EXPECTED),
      rulePackSha256: sha256Buffer(
        ["rules/eu_ai_act.yaml", "rules/high_risk_actions.yaml"]
          .map((p) => fs.readFileSync(path.join(ROOT, p)))
          .reduce((a, b) => Buffer.concat([a, Buffer.from("\n"), b]))
      ),
      corpusTest: {
        command: "node test/corpus.test.js",
        exitCode: test.exitCode,
        output: test.stdout.split(/\r?\n/)
      }
    },
    groups: {}
  };

  for (const [group, cases] of Object.entries(groups)) {
    if (group === "framework") {
      const exposed = cases.filter((c) => expected.cases[c.name].agentTool);
      report.groups.framework = {
        cases: cases.length,
        agentToolExposed: exposed.length,
        agentToolNotExposed: cases.length - exposed.length,
        exposedRate: pct(exposed.length, cases.length),
        notExposed: cases.filter((c) => !expected.cases[c.name].agentTool).map((c) => c.name),
        note:
          "Framework cases assert only whether an agent-tool surface is exposed, not a rule outcome."
      };
      continue;
    }

    const rows = cases.map((c) => {
      const observed = expected.cases[c.name].rules || [];
      const targetHit = observed.includes(c.target);
      return {
        name: c.name,
        target: c.target,
        expect: Boolean(c.expect),
        observedRules: observed,
        targetHit,
        correct: targetHit === Boolean(c.expect),
        extraRules: c.expect ? [] : observed.filter((r) => r !== c.target)
      };
    });

    const positive = rows.filter((r) => r.expect);
    const negative = rows.filter((r) => !r.expect);
    const misses = positive.filter((r) => !r.targetHit);
    const falsePositives = negative.filter((r) => r.targetHit);
    const negativeWithExtraRules = negative.filter((r) => r.extraRules.length > 0);

    report.groups[group] = {
      cases: rows.length,
      positiveCases: positive.length,
      negativeCases: negative.length,
      targetCorrect: rows.filter((r) => r.correct).length,
      targetCorrectRate: pct(rows.filter((r) => r.correct).length, rows.length),
      misses: misses.map((r) => ({
        case: r.name,
        target: r.target,
        observedRules: r.observedRules
      })),
      falsePositives: falsePositives.map((r) => ({
        case: r.name,
        target: r.target,
        observedRules: r.observedRules
      })),
      negativeCasesWithOtherRulesFiring: negativeWithExtraRules.length,
      negativeCasesWithOtherRulesFiringList: negativeWithExtraRules.map((r) => ({
        case: r.name,
        extraRules: r.extraRules
      })),
      kindBreakdown: cases.reduce((acc, c) => {
        const key = `${c.kind}/${c.expect ? "expect-hit" : "expect-clean"}`;
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {}),
      note:
        group === "stress"
          ? "No stress cases exist in the manifest at this commit; no stress number is invented."
          : "Case-level target-rule outcome only. Other rules firing on a negative case are listed separately and are not counted as false positives."
    };
  }

  // Per-rule, per-group outcomes. Never averaged across groups.
  const perRule = {};
  for (const group of ["plain", "evasion"]) {
    for (const c of groups[group]) {
      const observed = expected.cases[c.name].rules || [];
      const hit = observed.includes(c.target);
      if (!perRule[c.target]) perRule[c.target] = { plain: null, evasion: null };
      if (!perRule[c.target][group]) {
        perRule[c.target][group] = { cases: 0, correct: 0, positives: 0, negatives: 0, misses: [], falsePositives: [] };
      }
      const b = perRule[c.target][group];
      b.cases++;
      if (hit === Boolean(c.expect)) b.correct++;
      if (c.expect) b.positives++;
      else b.negatives++;
      if (c.expect && !hit) b.misses.push(c.name);
      if (!c.expect && hit) b.falsePositives.push(c.name);
    }
  }
  for (const [rule, g] of Object.entries(perRule)) {
    for (const group of ["plain", "evasion"]) {
      const b = g[group];
      if (!b) continue;
      g[group] = { ...b, rate: pct(b.correct, b.cases) };
    }
  }
  report.perRule = perRule;

  // V1 real-repository counts: raw, unlabelled, and kept out of the corpus
  // numbers above.
  const repoCounts = {};
  const ruleCounts = {};
  for (const f of pool.pool) {
    repoCounts[f.repo] = (repoCounts[f.repo] || 0) + 1;
    ruleCounts[f.rule] = (ruleCounts[f.rule] || 0) + 1;
  }
  report.realRepoRawCounts = {
    note:
      "Raw scanner finding counts from V1. No human labels exist yet, so these are not precision " +
      "or recall. They are not pooled with the corpus numbers.",
    repositories: pool.repos.map((r) => ({ alias: r.alias, name: r.name, url: r.url, sha: r.sha, license: r.license })),
    totalFindings: pool.pool.length,
    byRepository: repoCounts,
    byRule: ruleCounts
  };

  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(report, null, 2) + "\n");

  const md = [];
  md.push("# V2 - split corpus report (plain vs evasion/stress)");
  md.push("");
  md.push("**No pooled headline.** Plain and evasion cases measure different claims, so they are");
  md.push("reported separately. The corpus test was re-run before this report and exited 0.");
  md.push("");
  md.push(`- Tool version: ${report.toolVersion}`);
  md.push(`- Rule-pack SHA-256: \`${report.provenance.rulePackSha256}\``);
  md.push(`- Corpus manifest SHA-256: \`${report.provenance.manifestSha256}\``);
  md.push(`- Pinned snapshot SHA-256: \`${report.provenance.expectedSnapshotSha256}\``);
  md.push("");
  md.push("## Group summary");
  md.push("");
  md.push("| Group | Cases (n) | Positive cases | Negative cases | Target-rule correct | Misses | Target false positives |");
  md.push("|---|---:|---:|---:|---:|---:|---:|");
  for (const group of ["plain", "evasion"]) {
    const g = report.groups[group];
    md.push(
      `| ${group} | ${g.cases} | ${g.positiveCases} | ${g.negativeCases} | ${g.targetCorrectRate} | ${g.misses.length} | ${g.falsePositives.length} |`
    );
  }
  md.push(`| stress | 0 | 0 | 0 | n/a | 0 | 0 |`);
  md.push("");
  md.push(
    `Framework surface: **${report.groups.framework.exposedRate}** cases expose an agent-tool surface (n=${report.groups.framework.cases}).`
  );
  md.push("");
  md.push("## Per-rule, split by group");
  md.push("");
  md.push("| Rule | Plain correct | Plain misses | Plain FPs | Evasion correct | Evasion misses | Evasion FPs |");
  md.push("|---|---:|---|---:|---:|---|---:|");
  for (const rule of Object.keys(perRule).sort()) {
    const p = perRule[rule].plain || { rate: "n/a", misses: [], falsePositives: [] };
    const e = perRule[rule].evasion || { rate: "n/a", misses: [], falsePositives: [] };
    md.push(
      `| ${rule} | ${p.rate} | ${p.misses.join(", ") || "-"} | ${p.falsePositives.join(", ") || "-"} | ${e.rate} | ${e.misses.join(", ") || "-"} | ${e.falsePositives.join(", ") || "-"} |`
    );
  }
  md.push("");
  md.push("## Miss lists (every miss, case level)");
  md.push("");
  for (const group of ["plain", "evasion"]) {
    md.push(`### ${group}`);
    md.push("");
    if (!report.groups[group].misses.length) md.push("- No positive-case misses.");
    for (const m of report.groups[group].misses) {
      md.push(`- MISS ${m.case} (target ${m.target}); observed rules: ${m.observedRules.join(", ") || "none"}`);
    }
    if (!report.groups[group].falsePositives.length) md.push("- No target-rule false positives.");
    for (const fp of report.groups[group].falsePositives) {
      md.push(`- FP ${fp.case} (target ${fp.target}); observed rules: ${fp.observedRules.join(", ") || "none"}`);
    }
    md.push("");
  }
  md.push("## Negative cases where other rules fired");
  md.push("");
  md.push("Listed for context only. These are not counted as false positives: the target rule did not fire.");
  md.push("");
  for (const group of ["plain", "evasion"]) {
    const g = report.groups[group];
    md.push(`- ${group}: ${g.negativeCasesWithOtherRulesFiring}/${g.negativeCases} negative cases had another rule fire.`);
    for (const x of g.negativeCasesWithOtherRulesFiringList) {
      md.push(`  - ${x.case}: ${x.extraRules.join(", ")}`);
    }
  }
  md.push("");
  md.push("## Real-repository counts (V1) — unlabelled, kept separate");
  md.push("");
  md.push(
    `Raw findings: ${report.realRepoRawCounts.totalFindings} across ${report.realRepoRawCounts.repositories.length} pinned repositories. ` +
      "No human labels exist yet, so these are counts only, not precision or recall."
  );
  md.push("");
  md.push("| Repository | Findings |");
  md.push("|---|---:|");
  for (const [repo, n] of Object.entries(report.realRepoRawCounts.byRepository)) md.push(`| ${repo} | ${n} |`);
  md.push("");
  md.push("| Rule | Findings |");
  md.push("|---|---:|");
  for (const [rule, n] of Object.entries(report.realRepoRawCounts.byRule).sort()) md.push(`| ${rule} | ${n} |`);
  md.push("");
  md.push("## How to read this");
  md.push("");
  md.push("- A plain miss and an evasion miss are different claims; neither is extrapolated to real repositories.");
  md.push("- The corpus test asserts the pinned per-case rule set, not the stated intent. It passes even where stated intent is not met; those gaps are what this report exposes.");
  md.push("- Nothing here was changed to improve a number.");
  md.push("");
  fs.writeFileSync(path.join(OUT, "REPORT.md"), md.join("\n"));

  console.log(`ok - plain ${report.groups.plain.targetCorrectRate}`);
  console.log(`ok - evasion ${report.groups.evasion.targetCorrectRate}`);
  console.log(`ok - framework ${report.groups.framework.exposedRate}`);
  console.log(`ok - real-repo findings ${report.realRepoRawCounts.totalFindings}`);
}

try {
  main();
} catch (error) {
  console.error(`V2: ${error.message}`);
  process.exit(2);
}
