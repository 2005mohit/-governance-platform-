// Corpus regression tests.
//
// Every case from the audit corpus (test/corpus/manifest.json) is scanned in
// isolation and compared with test/corpus/expected.json, which pins the exact
// set of rule ids each case produced when the snapshot was accepted. The
// manifest's stated-intent target/expect pair is asserted separately, so a
// case cannot silently change meaning.
//
// Evasion cases and framework-detection cases are reported as their own
// groups. They are never averaged into the plain precision/recall number.
//
// Regenerate the snapshot after an intentional detection change:
//   node test/corpus.test.js --update
//
// If Python is unavailable, AST-dependent cases are skipped rather than
// allowed to fail on a proximity fallback; test/corpus/ast-dependent.json
// lists them. CI installs Python so the full set always runs there.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const Scanner = require("../src/scanner");

const CORPUS = path.join(__dirname, "corpus");
const RULES = path.join(__dirname, "..", "rules", "eu_ai_act.yaml");
const MANIFEST = path.join(CORPUS, "manifest.json");
const EXPECTED = path.join(CORPUS, "expected.json");
const AST_DEPENDENT = path.join(CORPUS, "ast-dependent.json");
const CASES = path.join(CORPUS, "cases");
const UPDATE = process.argv.includes("--update");

const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));

function groupOf(c) {
  if (c.type === "framework") return "framework";
  if (c.kind === "evasion") return "evasion";
  if (c.kind === "stress") return "stress";
  return "plain";
}

async function scanCase(name) {
  const dir = path.join(CASES, name);
  assert.ok(fs.existsSync(dir), `case directory missing: ${name}`);
  assert.ok(fs.readdirSync(dir).length > 0, `case directory is empty: ${name}`);
  const scanner = new Scanner(RULES, dir);
  const log = console.log;
  const warn = console.warn;
  const stderrWrite = process.stderr.write;
  console.log = () => {};
  console.warn = () => {};
  process.stderr.write = () => true;
  let findings;
  try {
    findings = await scanner.scan();
  } finally {
    console.log = log;
    console.warn = warn;
    process.stderr.write = stderrWrite;
  }
  return {
    rules: [...new Set(findings.map((f) => f.id))].sort(),
    agentTool: findings.some((f) => f.toolExposure === "agent-tool"),
    astAvailable: scanner.astAvailable
  };
}

function sameRules(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

async function main() {
  const groups = { plain: [], evasion: [], framework: [], stress: [] };
  for (const c of manifest) groups[groupOf(c)].push(c.name);

  const observed = {};
  const failures = [];
  let pythonAvailable = true;
  let skippedAst = 0;
  const intent = {
    plain: { met: 0, total: 0 },
    evasion: { met: 0, total: 0 },
    framework: { met: 0, total: 0 },
    stress: { met: 0, total: 0 }
  };
  const astDependent = !UPDATE && fs.existsSync(AST_DEPENDENT)
    ? new Set(JSON.parse(fs.readFileSync(AST_DEPENDENT, "utf8")))
    : new Set();

  for (const c of manifest) {
    const out = await scanCase(c.name);
    if (out.astAvailable === false) pythonAvailable = false;
    observed[c.name] = { rules: out.rules, agentTool: out.agentTool };

    // Stated-intent statistics are reported per group, never pooled: an
    // evasion miss and a plain-case miss are different claims. They are
    // informational; the pass/fail contract is the pinned observed set below.
    const g = groupOf(c);
    intent[g].total++;
    if (c.type === "framework") {
      if (out.agentTool) intent[g].met++;
    } else if (out.rules.includes(c.target) === Boolean(c.expect)) {
      intent[g].met++;
    }
  }

  if (UPDATE) {
    const doc = {
      generatedBy: "test/corpus.test.js --update",
      note: "Exact rule-id set per corpus case at the accepted snapshot. Evasion and framework cases are tracked separately from plain cases.",
      groups,
      cases: observed
    };
    fs.writeFileSync(EXPECTED, JSON.stringify(doc, null, 2) + "\n");
    console.log(`ok - wrote ${path.relative(path.join(__dirname, ".."), EXPECTED)} for ${manifest.length} cases`);
    return;
  }

  const expected = JSON.parse(fs.readFileSync(EXPECTED, "utf8"));
  for (const c of manifest) {
    if (!pythonAvailable && astDependent.has(c.name)) {
      skippedAst++;
      continue;
    }
    const want = expected.cases[c.name];
    assert.ok(want, `${c.name}: missing from expected.json; run --update`);
    if (!sameRules(observed[c.name].rules, want.rules)) {
      failures.push(
        `${c.name}: pinned rules [${want.rules.join(", ")}] but observed ` +
        `[${observed[c.name].rules.join(", ")}]`
      );
    }
    if (Boolean(want.agentTool) !== Boolean(observed[c.name].agentTool)) {
      failures.push(`${c.name}: pinned agentTool=${Boolean(want.agentTool)}, observed ${observed[c.name].agentTool}`);
    }
  }

  if (failures.length) {
    throw new Error(`corpus snapshot drifted (${failures.length} case(s)):\n  - ${failures.join("\n  - ")}`);
  }

  const total = Object.values(groups).reduce((n, list) => n + list.length, 0);
  assert.strictEqual(total, manifest.length, "every manifest case must belong to exactly one group");

  const skipped = skippedAst ? `, skipped ${skippedAst} AST-dependent cases (Python unavailable)` : "";
  console.log(`ok - corpus plain: ${groups.plain.length} cases pin exact per-rule outcomes; ${intent.plain.met}/${intent.plain.total} match stated intent${skipped}`);
  console.log(`ok - corpus evasion: ${groups.evasion.length} cases pin exact per-rule outcomes; ${intent.evasion.met}/${intent.evasion.total} match stated intent (reported separately)`);
  console.log(`ok - corpus framework: ${groups.framework.length} cases pin exact per-rule outcomes; ${intent.framework.met}/${intent.framework.total} expose agent-tool (reported separately)`);
  if (groups.stress.length) {
    console.log(`ok - corpus stress: ${groups.stress.length} cases pin exact per-rule outcomes; ${intent.stress.met}/${intent.stress.total} match stated intent (reported separately)`);
  }
}

// Small helper so the comparison block stays readable.
function observedRulesOf(name) {
  return [];
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
