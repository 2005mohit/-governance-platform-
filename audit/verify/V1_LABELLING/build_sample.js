#!/usr/bin/env node
// Build the V1 blind-labelling sheets from scanner reports of pinned repos.
//
// Deterministic: the pool is sorted by a hash of repo/path/line/snippet before
// capping at five per rule, then globally shuffled with a recorded seed. No
// labels are produced. Re-running with the same reports yields the same IDs.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const OUT = __dirname;
const REPORTS = process.env.V1_REPORTS || path.join(process.env.TEMP || "/tmp", "opencode", "v1-scans");
const SEED = 20261114;

const REPOS = [
  { alias: "repoA", name: "crewAI", url: "https://github.com/crewAIInc/crewAI", sha: "d7dfa0ef5ade793bd48ff7357c6eb45a45294371", license: "MIT", dir: "crewAI", report: "crewAI/report.json" },
  { alias: "repoB", name: "autogen", url: "https://github.com/microsoft/autogen", sha: "8390985108cb1e3881f5f7297765758d8ad2540c", license: "MIT (code; docs CC-BY-4.0)", dir: "autogen", report: "autogen/report.json" },
  { alias: "repoC", name: "mcp-servers", url: "https://github.com/modelcontextprotocol/servers", sha: "e1dc4b18dbb948921da37f3d4224a628730b43b0", license: "MIT/Apache-2.0 transition (see LICENSE)", dir: "servers", report: "servers/report.json" },
  { alias: "repoD", name: "mcp-python-sdk", url: "https://github.com/modelcontextprotocol/python-sdk", sha: "77001c96f9507be0f4d009b83210a384a5e08bda", license: "MIT", dir: "python-sdk", report: "python-sdk/report.json" }
];

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

// Mulberry32: small deterministic PRNG, seed recorded in the summary.
function mulberry32(seed) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle(items, seed) {
  const rand = mulberry32(seed);
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function csvCell(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function readPool() {
  const pool = [];
  const skipped = [];
  for (const repo of REPOS) {
    const reportPath = path.join(REPORTS, repo.report);
    if (!fs.existsSync(reportPath)) throw new Error(`missing report: ${reportPath}`);
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    for (const f of report.findings || []) {
      if (!f.line || !f.file) {
        skipped.push({ repo: repo.name, rule: f.id, file: f.file, line: f.line });
        continue;
      }
      pool.push({
        repo: repo.name,
        alias: repo.alias,
        url: repo.url,
        sha: repo.sha,
        rule: f.id,
        file: String(f.file).replace(/\\/g, "/"),
        line: f.line,
        snippet: f.snippet || "",
        method: f.method || null,
        confidence: f.confidence || null,
        confidenceWeight: f.confidenceWeight === undefined ? null : f.confidenceWeight,
        toolExposure: f.toolExposure || null
      });
    }
  }

  // De-duplicate identical findings (same repo/rule/path/line/snippet).
  const seen = new Set();
  return {
    pool: pool.filter((f) => {
      const key = [f.repo, f.rule, f.file, f.line, f.snippet].join("\u0000");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
    skipped
  };
}

function main() {
  const { pool, skipped } = readPool();

  const byRule = new Map();
  for (const f of pool) {
    if (!byRule.has(f.rule)) byRule.set(f.rule, []);
    byRule.get(f.rule).push(f);
  }

  const available = {};
  const selected = [];
  for (const [rule, list] of [...byRule.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const sorted = list.slice().sort((a, b) => {
      const ha = sha256([a.repo, a.file, a.line, a.snippet].join("\u0000"));
      const hb = sha256([b.repo, b.file, b.line, b.snippet].join("\u0000"));
      return ha < hb ? -1 : ha > hb ? 1 : 0;
    });
    available[rule] = sorted.length;
    selected.push(...sorted.slice(0, 5));
  }

  const shuffled = shuffle(selected, SEED);
  const rows = shuffled.map((f, i) => ({
    finding_id: `F${String(i + 1).padStart(3, "0")}`,
    ...f
  }));

  const header = "finding_id,file,line,snippet,label,notes";
  const sheet = (r) =>
    [r.finding_id, `${r.alias}/${r.file}`, r.line, r.snippet].map(csvCell).join(",") + ",,";
  fs.writeFileSync(path.join(OUT, "labeller_A.csv"), header + "\n" + rows.map(sheet).join("\n") + "\n");
  fs.writeFileSync(path.join(OUT, "labeller_B.csv"), header + "\n" + rows.map(sheet).join("\n") + "\n");
  fs.writeFileSync(
    path.join(OUT, "labeller_AI.csv"),
    "# AI-assisted, not independent (agent helped build the tool). Intentionally unfilled.\n" +
    header + "\n" + rows.map(sheet).join("\n") + "\n"
  );

  const findingMap = {
    generatedBy: "audit/verify/V1_LABELLING/build_sample.js",
    note: "For kappa only. Must not be shown to human labellers.",
    seed: SEED,
    toolVersion: require(path.join(ROOT, "package.json")).version,
    rulePackSha256: sha256(
      ["rules/eu_ai_act.yaml", "rules/high_risk_actions.yaml"]
        .map((p) => fs.readFileSync(path.join(ROOT, p)))
        .reduce((a, b) => Buffer.concat([a, Buffer.from("\n"), b]))
    ),
    sampleSize: rows.length,
    rulesWithFindings: available,
    findings: rows.map((r) => ({
      finding_id: r.finding_id,
      rule: r.rule,
      repo: r.repo,
      url: r.url,
      sha: r.sha,
      file: r.file,
      line: r.line,
      method: r.method,
      confidence: r.confidence,
      confidenceWeight: r.confidenceWeight,
      toolExposure: r.toolExposure
    }))
  };
  fs.writeFileSync(path.join(OUT, "finding_map.json"), JSON.stringify(findingMap, null, 2) + "\n");

  fs.writeFileSync(
    path.join(OUT, "findings_pool.json"),
    JSON.stringify({
      generatedBy: "audit/verify/V1_LABELLING/build_sample.js",
      note: "All findings from the four pinned scans, before capping. No labels.",
      repos: REPOS.map(({ alias, name, url, sha, license, report }) => ({ alias, name, url, sha, license, report })),
      pool,
      skipped
    }, null, 2) + "\n"
  );

  const repoPins = [
    "# Repository pins (V1)",
    "",
    "Labellers may open these at the recorded commit. The alias is the prefix used in the CSV `file` column.",
    "",
    "| Alias | Repository | Commit | Licence |",
    "|---|---|---|---|",
    ...REPOS.map((r) => `| ${r.alias} | ${r.url} | \`${r.sha}\` | ${r.license} |`),
    "",
    "Scan date: 2026-11-14. Scans were read-only and local.",
    ""
  ].join("\n");
  fs.writeFileSync(path.join(OUT, "REPO_PINS.md"), repoPins);

  const lines = [
    "# V1 sample summary",
    "",
    `- Tool version: ${findingMap.toolVersion}`,
    `- Rule-pack SHA-256: \`${findingMap.rulePackSha256}\``,
    `- Pooled findings: ${pool.length} across ${REPOS.length} repositories`,
    `- Selected for labelling: ${rows.length} (up to 5 per rule)`,
    `- Shuffle seed: ${SEED}`,
    `- Skipped for no line/file: ${skipped.length}`,
    "",
    "| Rule | Findings in pool | Selected |",
    "|---|---:|---:|",
    ...Object.entries(available).sort().map(([rule, n]) => `| ${rule} | ${n} | ${Math.min(5, n)} |`),
    "",
    "Rules with no real-repository findings in this frame (not back-filled): " +
      ["IDENTITY_KEY", "IAM_WILDCARD", "AUTO_DECISION", "SENSITIVE_DATA", "SAFETY_BYPASS"]
        .filter((r) => !available[r]).join(", ") + ".",
    "",
    "`labeller_A.csv` and `labeller_B.csv` contain no labels. `labeller_AI.csv` is",
    "intentionally unfilled and marked AI-assisted if anyone ever fills it.",
    ""
  ];
  fs.writeFileSync(path.join(OUT, "SAMPLE_SUMMARY.md"), lines.join("\n"));
  console.log(`ok - ${rows.length} rows from ${pool.length} pooled findings; ${skipped.length} skipped`);
}

main();
