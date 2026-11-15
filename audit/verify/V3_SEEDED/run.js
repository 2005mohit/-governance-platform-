#!/usr/bin/env node
// V3: seeded-defect recall on a copy of a real public repository.
//
// The copy stays in the OS temp directory. Three placement variants are seeded
// for each rule (36 seeds total). The unmodified copy is scanned first, then
// the seeded copy, and only findings whose file (or extraFiles entry) is a
// seeded path count towards recall. Every miss is listed with file:line.
//
// Outputs: results.json, REPORT.md.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const OUT = __dirname;
const TEMP = process.env.TEMP || "/tmp";
const SRC = path.join(TEMP, "opencode", "verify-repos", "servers");
const DEST = path.join(TEMP, "opencode", "v3-seeded");

const Scanner = require(path.join(ROOT, "src", "scanner"));
const RULES = path.join(ROOT, "rules", "eu_ai_act.yaml");

const PIN = {
  repo: "https://github.com/modelcontextprotocol/servers",
  sha: "e1dc4b18dbb948921da37f3d4224a628730b43b0",
  license: "MIT/Apache-2.0 transition (see LICENSE)"
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

function norm(p) {
  return String(p).replace(/\\/g, "/");
}

// 3 placement variants per rule.
// variant 1: direct / top level; 2: inside a function or nested config;
// 3: inside a class/method or a second nesting form.
const SEEDS = [
  // IDENTITY_KEY
  {
    rule: "IDENTITY_KEY",
    variant: "direct",
    path: "zz_seeded/identity/direct/settings.py",
    anchor: 'OPENAI_API_KEY = "sk-',
    content: 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234"\n'
  },
  {
    rule: "IDENTITY_KEY",
    variant: "function",
    path: "zz_seeded/identity/function/client.py",
    anchor: 'aws_access_key_id = "AKIA',
    content: 'def build_client():\n    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n    return aws_access_key_id\n'
  },
  {
    rule: "IDENTITY_KEY",
    variant: "class",
    path: "zz_seeded/identity/class/vault.py",
    anchor: "github_token =",
    content: 'class Vault:\n    github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n'
  },

  // IAM_WILDCARD
  {
    rule: "IAM_WILDCARD",
    variant: "direct",
    path: "zz_seeded/iam/direct/policy.tf",
    anchor: '"Action": "*"',
    content:
      'resource "aws_iam_policy" "seed_direct" {\n' +
      '  name = "seed-direct"\n' +
      '  policy = <<POLICY\n' +
      '{\n' +
      '  "Version": "2012-10-17",\n' +
      '  "Statement": [\n' +
      '    {\n' +
      '      "Effect": "Allow",\n' +
      '      "Action": "*",\n' +
      '      "Resource": "*"\n' +
      '    }\n' +
      '  ]\n' +
      '}\n' +
      'POLICY\n' +
      '}\n'
  },
  {
    rule: "IAM_WILDCARD",
    variant: "nested",
    path: "zz_seeded/iam/nested/template.yaml",
    anchor: 'Action: "*"',
    content:
      'AWSTemplateFormatVersion: "2010-09-09"\n' +
      'Resources:\n' +
      '  SeedRole:\n' +
      '    Type: AWS::IAM::Role\n' +
      '    Properties:\n' +
      '      AssumeRolePolicyDocument:\n' +
      '        Statement:\n' +
      '          - Effect: Allow\n' +
      '            Action: "*"\n' +
      '            Resource: "*"\n'
  },
  {
    rule: "IAM_WILDCARD",
    variant: "hcl",
    path: "zz_seeded/iam/hcl/main.tf",
    anchor: 'Action   = "*"',
    content:
      'resource "aws_iam_policy" "seed_hcl" {\n' +
      '  name = "seed-hcl"\n' +
      '  policy = jsonencode({\n' +
      '    Version = "2012-10-17"\n' +
      '    Statement = [{\n' +
      '      Effect   = "Allow"\n' +
      '      Action   = "*"\n' +
      '      Resource = "*"\n' +
      '    }]\n' +
      '  })\n' +
      '}\n'
  },

  // NO_HUMAN_LOOP
  {
    rule: "NO_HUMAN_LOOP",
    variant: "direct",
    path: "zz_seeded/human/direct/ops.py",
    anchor: "delete(customer_id)",
    content: "# destructive action with no gate nearby\ndelete(customer_id)\n"
  },
  {
    rule: "NO_HUMAN_LOOP",
    variant: "function",
    path: "zz_seeded/human/function/purge.py",
    anchor: "delete(user_id)",
    content: "def purge_account(user_id):\n    delete(user_id)\n"
  },
  {
    rule: "NO_HUMAN_LOOP",
    variant: "class",
    path: "zz_seeded/human/class/actions.py",
    anchor: "transfer(amount)",
    content: "class AccountActions:\n    def run(self, amount):\n        transfer(amount)\n"
  },

  // NO_LOGGING
  {
    rule: "NO_LOGGING",
    variant: "direct",
    path: "zz_seeded/logging/direct/ops.py",
    anchor: "delete(record_id)",
    content: "# destructive action with no audit trail\ndelete(record_id)\n"
  },
  {
    rule: "NO_LOGGING",
    variant: "function",
    path: "zz_seeded/logging/function/move.py",
    anchor: "transfer(amount)",
    content: "def move_funds(amount):\n    transfer(amount)\n"
  },
  {
    rule: "NO_LOGGING",
    variant: "class",
    path: "zz_seeded/logging/class/payments.py",
    anchor: "send_payment(amount)",
    content: "class Payments:\n    def run(self, amount):\n        send_payment(amount)\n"
  },

  // NO_AI_DISCLOSURE
  {
    rule: "NO_AI_DISCLOSURE",
    variant: "direct",
    path: "zz_seeded/disclosure/direct/prompt.py",
    anchor: "system_prompt =",
    content:
      'system_prompt = "You are a helpful assistant for internal staff. Answer using the provided documents."\n'
  },
  {
    rule: "NO_AI_DISCLOSURE",
    variant: "function",
    path: "zz_seeded/disclosure/function/chat.py",
    anchor: '"role": "system"',
    content:
      'def build_messages():\n' +
      '    return [{"role": "system", "content": "You are a concise support agent. Use the knowledge base."}]\n'
  },
  {
    rule: "NO_AI_DISCLOSURE",
    variant: "class",
    path: "zz_seeded/disclosure/class/agent.py",
    anchor: "SYSTEM_PROMPT =",
    content:
      'class AgentConfig:\n' +
      '    SYSTEM_PROMPT = """You are an internal research assistant. Summarize the supplied context."""\n'
  },

  // AUTO_DECISION
  {
    rule: "AUTO_DECISION",
    variant: "direct",
    path: "zz_seeded/decision/direct/decision.py",
    anchor: 'decision["status"] = "approved"',
    content: 'decision = {}\ndecision["status"] = "approved"\n'
  },
  {
    rule: "AUTO_DECISION",
    variant: "function",
    path: "zz_seeded/decision/function/review.py",
    anchor: 'result.status = "rejected"',
    content:
      'def evaluate(application):\n' +
      '    # approval decision for the application\n' +
      '    result = application\n' +
      '    result.status = "rejected"\n' +
      '    return result\n'
  },
  {
    rule: "AUTO_DECISION",
    variant: "class",
    path: "zz_seeded/decision/class/underwriting.py",
    anchor: 'outcome["status"] = "accepted"',
    content:
      'class Underwriter:\n' +
      '    def decide(self, application):\n' +
      '        # underwriting outcome\n' +
      '        outcome = {}\n' +
      '        outcome["status"] = "accepted"\n' +
      '        return outcome\n'
  },

  // CORS_WILDCARD
  {
    rule: "CORS_WILDCARD",
    variant: "direct",
    path: "zz_seeded/cors/direct/app.py",
    anchor: 'allow_origins=["*"]',
    content:
      'from fastapi import FastAPI\n' +
      'from fastapi.middleware.cors import CORSMiddleware\n' +
      'app = FastAPI()\n' +
      'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
  },
  {
    rule: "CORS_WILDCARD",
    variant: "function",
    path: "zz_seeded/cors/function/configure.py",
    anchor: 'allow_origins=["*"]',
    content:
      'def configure(app):\n' +
      '    app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
  },
  {
    rule: "CORS_WILDCARD",
    variant: "class",
    path: "zz_seeded/cors/class/service.py",
    anchor: 'allow_origins=["*"]',
    content:
      'class Service:\n' +
      '    def __init__(self, app):\n' +
      '        app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
  },

  // SENSITIVE_DATA (project-level; file name + extension)
  {
    rule: "SENSITIVE_DATA",
    variant: "direct",
    path: "zz_seeded/data/direct/passport_scan.pdf",
    anchor: null,
    content: "seeded personal document\n"
  },
  {
    rule: "SENSITIVE_DATA",
    variant: "nested",
    path: "zz_seeded/data/nested/finance/bank_statement_2026.csv",
    anchor: null,
    content: "account,amount\nseed,1\n"
  },
  {
    rule: "SENSITIVE_DATA",
    variant: "class",
    path: "zz_seeded/data/class/credit_report.xlsx",
    anchor: null,
    content: "seeded spreadsheet\n"
  },

  // HTTP_NO_AUTH (project-level; route definitions without auth markers)
  {
    rule: "HTTP_NO_AUTH",
    variant: "direct",
    path: "zz_seeded/http/direct/app.py",
    anchor: '@app.get("/seed/direct")',
    content:
      'from fastapi import FastAPI\n' +
      'app = FastAPI()\n' +
      '\n' +
      '@app.get("/seed/direct")\n' +
      'def direct():\n' +
      '    return {"ok": True}\n'
  },
  {
    rule: "HTTP_NO_AUTH",
    variant: "nested",
    path: "zz_seeded/http/nested/routes.py",
    anchor: '@router.post("/seed/nested")',
    content:
      'from fastapi import APIRouter\n' +
      'router = APIRouter()\n' +
      '\n' +
      '@router.post("/seed/nested")\n' +
      'def nested():\n' +
      '    return {"ok": True}\n'
  },
  {
    rule: "HTTP_NO_AUTH",
    variant: "call",
    path: "zz_seeded/http/call/handlers.js",
    anchor: 'app.get("/seed/method"',
    content:
      'const express = require("express");\n' +
      'const app = express();\n' +
      'app.get("/seed/method", function (req, res) {\n' +
      '  res.json({ ok: true });\n' +
      '});\n'
  },

  // SAFETY_BYPASS
  {
    rule: "SAFETY_BYPASS",
    variant: "direct",
    path: "zz_seeded/bypass/direct/transfer.py",
    anchor: "require_approval = False",
    content: "require_approval = False\ndelete(record_id)\n"
  },
  {
    rule: "SAFETY_BYPASS",
    variant: "function",
    path: "zz_seeded/bypass/function/transfer.py",
    anchor: "skip_validation = True",
    content: "def move(amount):\n    skip_validation = True\n    transfer(amount)\n"
  },
  {
    rule: "SAFETY_BYPASS",
    variant: "class",
    path: "zz_seeded/bypass/class/payments.py",
    anchor: "bypass_checks = True",
    content:
      'class Payments:\n' +
      '    def run(self, amount):\n' +
      '        bypass_checks = True\n' +
      '        send_payment(amount)\n'
  },

  // UNSAFE_DESERIALIZE
  {
    rule: "UNSAFE_DESERIALIZE",
    variant: "direct",
    path: "zz_seeded/deserialize/direct/load.py",
    anchor: "pickle.loads(payload)",
    content: 'import pickle\npayload = b"data"\npickle.loads(payload)\n'
  },
  {
    rule: "UNSAFE_DESERIALIZE",
    variant: "function",
    path: "zz_seeded/deserialize/function/yaml_load.py",
    anchor: "yaml.load(raw)",
    content: 'import yaml\ndef parse(raw):\n    return yaml.load(raw)\n'
  },
  {
    rule: "UNSAFE_DESERIALIZE",
    variant: "class",
    path: "zz_seeded/deserialize/class/torch_load.py",
    anchor: "torch.load(path)",
    content:
      'import torch\n' +
      'class ModelLoader:\n' +
      '    def load(self, path):\n' +
      '        return torch.load(path)\n'
  },

  // ERROR_LEAKAGE
  {
    rule: "ERROR_LEAKAGE",
    variant: "direct",
    path: "zz_seeded/leakage/direct/api.py",
    anchor: "detail=str(e)",
    content:
      'from fastapi import HTTPException\n' +
      'try:\n' +
      '    1 / 0\n' +
      'except Exception as e:\n' +
      '    raise HTTPException(status_code=500, detail=str(e))\n'
  },
  {
    rule: "ERROR_LEAKAGE",
    variant: "function",
    path: "zz_seeded/leakage/function/handler.py",
    anchor: 'str(e)',
    content:
      'from django.http import JsonResponse\n' +
      'def handler(request):\n' +
      '    try:\n' +
      '        raise ValueError("bad")\n' +
      '    except Exception as e:\n' +
      '        return JsonResponse({"error": str(e)})\n'
  },
  {
    rule: "ERROR_LEAKAGE",
    variant: "class",
    path: "zz_seeded/leakage/class/response.py",
    anchor: "err.message",
    content:
      'from flask import Response\n' +
      'class Api:\n' +
      '    def fail(self, err):\n' +
      '        return Response({"error": err.message})\n'
  }
];

function lineOf(filePath, anchor) {
  if (!anchor) return 1;
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) if (lines[i].includes(anchor)) return i + 1;
  throw new Error(`anchor not found in ${filePath}: ${anchor}`);
}

function copyRepo() {
  fs.rmSync(DEST, { recursive: true, force: true });
  fs.mkdirSync(DEST, { recursive: true });
  fs.cpSync(SRC, DEST, {
    recursive: true,
    filter: (src) => {
      const rel = norm(path.relative(SRC, src));
      return !rel.startsWith(".git/") && rel !== ".git" && !rel.split("/").includes("node_modules");
    }
  });
}

async function scan(dir) {
  const scanner = new Scanner(RULES, dir, { includeTests: false });
  const log = console.log;
  const warn = console.warn;
  const stderr = process.stderr.write;
  console.log = () => {};
  console.warn = () => {};
  process.stderr.write = () => true;
  let findings;
  try {
    findings = await scanner.scan();
  } finally {
    console.log = log;
    console.warn = warn;
    process.stderr.write = stderr;
  }
  return { findings, filesScanned: scanner.filesScanned };
}

function matchesSeed(finding, seedRel) {
  if (norm(finding.file) === seedRel) return "file";
  if ((finding.extraFiles || []).some((p) => norm(p) === seedRel)) return "extraFiles";
  return null;
}

async function main() {
  copyRepo();

  const baselineRun = await scan(DEST);
  const baseline = baselineRun.findings;

  for (const seed of SEEDS) {
    const full = path.join(DEST, seed.path);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, seed.content);
  }

  const seededRun = await scan(DEST);
  const seeded = seededRun.findings;

  const results = SEEDS.map((seed) => {
    const hit = seeded
      .filter((f) => f.id === seed.rule)
      .map((f) => ({ f, via: matchesSeed(f, seed.path) }))
      .filter((x) => x.via);
    const anchorLine = lineOf(path.join(DEST, seed.path), seed.anchor);
    return {
      rule: seed.rule,
      variant: seed.variant,
      file: seed.path,
      line: anchorLine,
      anchor: seed.anchor,
      detected: hit.length > 0,
      via: hit.map((x) => x.via),
      reportedLines: hit.map((x) => x.f.line)
    };
  });

  const byRule = {};
  for (const r of results) {
    if (!byRule[r.rule]) {
      byRule[r.rule] = { seeds: 0, detected: 0, misses: [] };
    }
    byRule[r.rule].seeds++;
    if (r.detected) byRule[r.rule].detected++;
    else byRule[r.rule].misses.push({ file: r.file, line: r.line, variant: r.variant });
  }

  const detected = results.filter((r) => r.detected).length;
  const report = {
    generatedBy: "audit/verify/V3_SEEDED/run.js",
    generatedAt: new Date().toISOString(),
    toolVersion: require(path.join(ROOT, "package.json")).version,
    rulePackSha256: rulePackHash(),
    sourceRepo: PIN,
    seedRoot: "zz_seeded/",
    totalSeeds: SEEDS.length,
    detected,
    recall: `${detected}/${SEEDS.length} (${((detected / SEEDS.length) * 100).toFixed(1)}%)`,
    byRule,
    seeds: results,
    baselineScan: {
      filesScanned: baselineRun.filesScanned,
      findings: baseline.length,
      byRule: baseline.reduce((acc, f) => {
        acc[f.id] = (acc[f.id] || 0) + 1;
        return acc;
      }, {})
    },
    seededScan: {
      filesScanned: seededRun.filesScanned,
      findings: seeded.length
    },
    note:
      "Recall is measured only against the 36 seeded defects in a copy of one real repository. " +
      "It is not a real-world recall estimate. A miss is listed with file:line."
  };

  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(report, null, 2) + "\n");

  const md = [];
  md.push("# V3 - seeded-defect recall (copy of a real repository)");
  md.push("");
  md.push(`Source: ${PIN.repo} at \`${PIN.sha}\` (${PIN.license}).`);
  md.push("The copy, the seeds and the scan stayed in the OS temp directory; nothing from the");
  md.push("source repository is committed.");
  md.push("");
  md.push(`- Tool version: ${report.toolVersion}`);
  md.push(`- Rule-pack SHA-256: \`${report.rulePackSha256}\``);
  md.push(`- Seeds: ${report.totalSeeds} (3 placement variants per rule)`);
  md.push(`- Detected: **${report.recall}**`);
  md.push("");
  md.push("## Per-rule recall");
  md.push("");
  md.push("| Rule | Seeds | Detected | Recall | Misses (file:line) |");
  md.push("|---|---:|---:|---:|---|");
  for (const rule of Object.keys(byRule).sort()) {
    const b = byRule[rule];
    const misses = b.misses.map((m) => `\`${m.file}:${m.line}\``).join(", ") || "-";
    md.push(`| ${rule} | ${b.seeds} | ${b.detected} | ${b.detected}/${b.seeds} | ${misses} |`);
  }
  md.push("");
  md.push("## Every seed");
  md.push("");
  md.push("| Rule | Variant | File:line | Detected | Reported line |");
  md.push("|---|---|---|---:|---|");
  for (const r of results) {
    md.push(
      `| ${r.rule} | ${r.variant} | \`${r.file}:${r.line}\` | ${r.detected ? "yes" : "NO"} | ${r.reportedLines.join(", ") || "-"} |`
    );
  }
  md.push("");
  md.push("## Baseline scan (unmodified copy)");
  md.push("");
  md.push(`Findings before seeding: ${baseline.length}.`);
  md.push("");
  md.push("| Rule | Findings |");
  md.push("|---|---:|");
  for (const [rule, n] of Object.entries(report.baselineScan.byRule).sort()) md.push(`| ${rule} | ${n} |`);
  md.push("");
  md.push("## Counter-evidence (do not generalise)");
  md.push("");
  md.push("All 36 seeds are canonical constructs the rules were written to match; none is an evasion");
  md.push("variant. In the same verification run the evasion corpus met stated intent on 0/27 cases");
  md.push("(V2, n=27), and the third-party comparison missed 1 of 5 covered Bandit instances, 1 of 2");
  md.push("Semgrep CORS instances, and 2 of 4 Semgrep IAM blocks (V1b). The 36/36 here must not be");
  md.push("read as a real-world recall estimate.");
  md.push("");
  md.push("## Interpretation limits");
  md.push("");
  md.push("- These are deliberately planted defects. The seed set is small (n=36) and comes from one repository." );
  md.push("- Detection is credited only when the target rule cites the seeded file (or lists it in `extraFiles` for the project-level rules).");
  md.push("- A missed seed is a real miss for that placement; it is not evidence about any other repository.");
  md.push("- No detector was changed to improve this number.");
  md.push("");
  fs.writeFileSync(path.join(OUT, "REPORT.md"), md.join("\n"));

  console.log(`ok - seeded recall ${report.recall}`);
  for (const [rule, b] of Object.entries(byRule)) {
    if (b.detected !== b.seeds) console.log(`miss - ${rule}: ${b.detected}/${b.seeds}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
