#!/usr/bin/env node
// Cohen's kappa for the two blind V1 sheets.
//
// Reads labeller_A.csv, labeller_B.csv and finding_map.json. Blank label cells
// are treated as "not yet labelled" and excluded; the tool never invents a
// label. Outputs observed/expected agreement, kappa, per-rule agreement and
// the disagreement list. No pooled precision is produced here.
//
// Usage:
//   node kappa.js [--a A.csv] [--b B.csv] [--map finding_map.json]
//                 [--json out.json] [--md out.md]
const fs = require("fs");
const path = require("path");

const HERE = __dirname;
const ALLOWED = new Set(["TP", "FP", "CONTEXT"]);

function parseArgs(argv) {
  const opts = {
    a: path.join(HERE, "labeller_A.csv"),
    b: path.join(HERE, "labeller_B.csv"),
    map: path.join(HERE, "finding_map.json"),
    json: null,
    md: null
  };
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === "--a") opts.a = argv[++i];
    else if (key === "--b") opts.b = argv[++i];
    else if (key === "--map") opts.map = argv[++i];
    else if (key === "--json") opts.json = argv[++i];
    else if (key === "--md") opts.md = argv[++i];
    else if (key === "--help" || key === "-h") {
      console.log("node kappa.js [--a A.csv] [--b B.csv] [--map finding_map.json] [--json out.json] [--md out.md]");
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${key}`);
    }
  }
  return opts;
}

// Minimal RFC-4180 parser: quoted cells, escaped quotes, embedded newlines.
function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') {
        quoted = false;
      } else {
        cell += ch;
      }
      continue;
    }
    if (ch === '"') {
      quoted = true;
    } else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\n") {
      row.push(cell.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += ch;
    }
  }
  if (cell.length || row.length) {
    row.push(cell.replace(/\r$/, ""));
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c.trim() !== "") && !r[0].startsWith("#"));
}

function readSheet(file) {
  const rows = parseCsv(fs.readFileSync(file, "utf8"));
  if (!rows.length) throw new Error(`${file}: empty CSV`);
  const header = rows[0].map((h) => h.trim());
  for (const required of ["finding_id", "label"]) {
    if (!header.includes(required)) throw new Error(`${file}: missing column ${required}`);
  }
  const idIndex = header.indexOf("finding_id");
  const labelIndex = header.indexOf("label");
  const notesIndex = header.indexOf("notes");
  const out = new Map();
  for (let i = 1; i < rows.length; i++) {
    const id = (rows[i][idIndex] || "").trim();
    if (!id) continue;
    if (out.has(id)) throw new Error(`${file}: duplicate finding_id ${id}`);
    const raw = (rows[i][labelIndex] || "").trim().toUpperCase();
    if (raw && !ALLOWED.has(raw)) {
      throw new Error(`${file}: finding ${id} has invalid label "${raw}" (allowed: TP, FP, CONTEXT)`);
    }
    out.set(id, {
      label: raw || null,
      notes: notesIndex === -1 ? "" : (rows[i][notesIndex] || "").trim(),
      row: i + 1
    });
  }
  return out;
}

function kappa(pairs) {
  const categories = [...ALLOWED];
  const n = pairs.length;
  if (!n) return { n: 0, observed: null, expected: null, kappa: null };
  let agree = 0;
  const aCounts = Object.fromEntries(categories.map((c) => [c, 0]));
  const bCounts = Object.fromEntries(categories.map((c) => [c, 0]));
  for (const [a, b] of pairs) {
    aCounts[a]++;
    bCounts[b]++;
    if (a === b) agree++;
  }
  const observed = agree / n;
  let expected = 0;
  for (const c of categories) expected += (aCounts[c] / n) * (bCounts[c] / n);
  const value = expected === 1 ? null : (observed - expected) / (1 - expected);
  return { n, observed, expected, kappa: value, aCounts, bCounts };
}

function pct(x) {
  return x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(1)}%`;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const a = readSheet(opts.a);
  const b = readSheet(opts.b);
  const map = JSON.parse(fs.readFileSync(opts.map, "utf8"));
  const ruleByFinding = new Map((map.findings || []).map((f) => [f.finding_id, f]));

  const ids = new Set([...a.keys(), ...b.keys()]);
  const pairs = [];
  const disagreements = [];
  const perRule = new Map();
  let unlabelled = 0;
  let labelledBoth = 0;

  for (const id of [...ids].sort()) {
    const av = a.get(id);
    const bv = b.get(id);
    const meta = ruleByFinding.get(id);
    if (!av || !bv) throw new Error(`finding ${id} is missing from one sheet`);
    if (!av.label || !bv.label) {
      unlabelled++;
      continue;
    }
    labelledBoth++;
    pairs.push([av.label, bv.label]);
    const rule = meta ? meta.rule : "UNKNOWN";
    if (!perRule.has(rule)) perRule.set(rule, { n: 0, agree: 0, disagreements: 0 });
    const bucket = perRule.get(rule);
    bucket.n++;
    if (av.label === bv.label) bucket.agree++;
    else {
      bucket.disagreements++;
      disagreements.push({
        finding_id: id,
        rule,
        repo: meta ? meta.repo : null,
        file: meta ? meta.file : null,
        line: meta ? meta.line : null,
        labeller_A: av.label,
        labeller_B: bv.label,
        notes_A: av.notes,
        notes_B: bv.notes
      });
    }
  }

  const stats = kappa(pairs);
  const result = {
    generatedBy: "audit/verify/V1_LABELLING/kappa.js",
    sheets: { a: path.basename(opts.a), b: path.basename(opts.b) },
    rows: ids.size,
    labelledBoth,
    unlabelled,
    categories: [...ALLOWED],
    agreement: {
      observed: stats.observed,
      expected: stats.expected,
      cohensKappa: stats.kappa
    },
    labelCounts: { A: stats.aCounts || null, B: stats.bCounts || null },
    perRule: Object.fromEntries(
      [...perRule.entries()].sort((x, y) => x[0].localeCompare(y[0])).map(([rule, v]) => [
        rule,
        { n: v.n, agree: v.agree, agreement: v.n ? v.agree / v.n : null, disagreements: v.disagreements }
      ])
    ),
    disagreements,
    note: labelledBoth
      ? "Human labels only. AI-assisted labels are never merged here."
      : "No rows have both human labels yet; kappa is not defined. Sheets are blank by design."
  };

  if (opts.json) fs.writeFileSync(opts.json, JSON.stringify(result, null, 2) + "\n");

  const lines = [
    "# Cohen's kappa — V1 human sheets",
    "",
    `Rows: ${result.rows}; labelled by both: ${labelledBoth}; unlabelled: ${unlabelled}`,
    "",
    labelledBoth
      ? `Observed agreement: ${pct(stats.observed)}; expected: ${pct(stats.expected)}; ` +
        `Cohen's kappa: ${stats.kappa === null ? "undefined" : stats.kappa.toFixed(3)}`
      : "No rows have both human labels yet, so kappa is undefined. This is expected before the labellers submit.",
    "",
    "| Rule | n | agree | agreement |",
    "|---|---:|---:|---:|",
    ...[...perRule.entries()]
      .sort((x, y) => x[0].localeCompare(y[0]))
      .map(([rule, v]) => `| ${rule} | ${v.n} | ${v.agree} | ${v.n ? pct(v.agree / v.n) : "n/a"} |`),
    "",
    `Disagreements: ${disagreements.length}`,
    ...disagreements.map(
      (d) => `- ${d.finding_id} (${d.rule}) ${d.file}:${d.line} — A=${d.labeller_A}, B=${d.labeller_B}`
    ),
    ""
  ];
  const md = lines.join("\n");
  if (opts.md) fs.writeFileSync(opts.md, md);
  else console.log(md);
}

try {
  main();
} catch (error) {
  console.error(`kappa: ${error.message}`);
  process.exit(2);
}
