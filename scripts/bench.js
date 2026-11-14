#!/usr/bin/env node
// Reproducible performance benchmark for the scan path.
//
// Usage:
//   node scripts/bench.js                 # 20k db.delete() case from audit/
//   node scripts/bench.js <dir>           # scan any directory
//   node scripts/bench.js --out <file>    # also write the finding signature
//
// Reports wall time, peak RSS (process.resourceUsage().maxRSS) and a stable
// hash of the finding set, so "before" and "after" runs can be diffed as well
// as timed. Not shipped in the npm package.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const Scanner = require("../src/scanner");

const ROOT = path.join(__dirname, "..");
const RULES = path.join(ROOT, "rules", "eu_ai_act.yaml");

const argv = process.argv.slice(2);
const outIndex = argv.indexOf("--out");
const outPath = outIndex === -1 ? null : argv[outIndex + 1];
const dirIndex = argv.findIndex((a, i) => !a.startsWith("--") && (outIndex === -1 || i !== outIndex + 1));
const dir = path.resolve(dirIndex === -1 ? path.join(os.tmpdir(), "opencode", "manydel") : argv[dirIndex]);

if (!fs.existsSync(path.join(dir, "many.py")) && !fs.readdirSync(dir).length) {
  const gen = spawnSync(process.execPath, [path.join(ROOT, "audit", "make_manydel.js")], { encoding: "utf8" });
  if (gen.status !== 0) {
    console.error(gen.stderr || "failed to generate the 20k fixture");
    process.exit(1);
  }
}

function signature(findings) {
  return findings
    .map((f) => ({
      id: f.id,
      file: String(f.file || "").replace(/\\/g, "/"),
      line: f.line,
      snippet: f.snippet,
      severity: f.severity,
      method: f.method || null,
      toolExposure: f.toolExposure || null,
      confidence: f.confidence,
      confidenceWeight: f.confidenceWeight
    }))
    .sort((a, b) => {
      const ka = JSON.stringify(a);
      const kb = JSON.stringify(b);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
}

async function main() {
  const scanner = new Scanner(RULES, dir);
  const started = process.hrtime.bigint();
  const findings = await scanner.scan();
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  const peaks = process.resourceUsage();
  const sig = signature(findings);
  const hash = crypto.createHash("sha256").update(JSON.stringify(sig)).digest("hex");

  const result = {
    dir,
    elapsedMs: Number(elapsedMs.toFixed(1)),
    peakRssMB: Number((peaks.maxRSS / 1024).toFixed(1)),
    filesScanned: scanner.filesScanned,
    findings: findings.length,
    signature: hash
  };
  if (outPath) {
    fs.writeFileSync(path.resolve(outPath), JSON.stringify({ ...result, findingSet: sig }, null, 2) + "\n");
  }
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
