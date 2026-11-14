#!/usr/bin/env node
// src/cli.js
const path = require("path");
const fs = require("fs");
const os = require("os");
const { promptAgreement } = require("./agreement");
const Scanner = require("./scanner");
const { RulePackError } = require("./rulepack");
const { generateReport, getBand } = require("./reporter");
const { FAIL_ON_LEVELS, findingsAtOrAbove, isValidFailOn } = require("./exitcodes");

const pkg = require("../package.json");

const USAGE =
  "Usage: ai-risk-snapshot [path] [--yes] [--include-tests] [--output <dir>]\n" +
  "                        [--fail-on <critical|high|medium|low|none>]\n" +
  "                        [--format <json|html|sarif|all>]";

const FORMATS = ["json", "html", "sarif", "all"];

function parseArgs(argv) {
  const opts = {
    rootDir: process.cwd(),
    outputDir: null,
    yes: false,
    includeTests: false,
    failOn: "none",
    format: "all"
  };

  let positionalSeen = false;
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--yes" || arg === "-y") {
      opts.yes = true;
    } else if (arg === "--include-tests") {
      opts.includeTests = true;
    } else if (arg === "--scan") {
      // accepted no-op for backwards-compatible docs; scanning is the default action
      continue;
    } else if (arg === "--output" || arg === "-o") {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("-")) {
        return { error: `${arg} requires a directory path.` };
      }
      opts.outputDir = value;
      i++;
    } else if (arg === "--fail-on") {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("-")) {
        return { error: `--fail-on requires one of: ${FAIL_ON_LEVELS.join(", ")}.` };
      }
      if (!isValidFailOn(value)) {
        return {
          error: `Invalid --fail-on value "${value}". Use one of: ${FAIL_ON_LEVELS.join(", ")}.`
        };
      }
      opts.failOn = value.toLowerCase();
      i++;
    } else if (arg === "--format") {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("-")) {
        return { error: `--format requires one of: ${FORMATS.join(", ")}.` };
      }
      const normalized = value.toLowerCase();
      if (!FORMATS.includes(normalized)) {
        return {
          error: `Invalid --format value "${value}". Use one of: ${FORMATS.join(", ")}.`
        };
      }
      opts.format = normalized;
      i++;
    } else if (arg.startsWith("-")) {
      return { error: `Unknown option: ${arg}` };
    } else if (positionalSeen) {
      return { error: `Unexpected extra argument: ${arg}` };
    } else {
      opts.rootDir = path.resolve(arg);
      positionalSeen = true;
    }
  }
  return { opts };
}

function plainError(err) {
  if (err && (err.code === "EACCES" || err.code === "EPERM")) {
    return "you don't have write permission for that location";
  }
  if (err && err.code === "ENOSPC") {
    return "the disk is full";
  }
  return err && err.code ? `an error occurred (${err.code})` : "an unknown error occurred";
}

function scanPathError(err) {
  if (err && err.code === "ENOENT") return "directory not found";
  if (err && err.code === "ENOTDIR") return "path is not a directory";
  if (err && (err.code === "EACCES" || err.code === "EPERM")) return "permission denied";
  return plainError(err);
}

// Figures out where the report should go, and makes sure it's actually
// writable BEFORE the scan starts. Failing late — after a full scan — would
// lose the results for no reason. If the chosen location can't be written,
// fall back to the OS temp folder with a clear, plain-language message.
function resolveOutputDir(opts) {
  const requested = opts.outputDir
    ? path.resolve(opts.outputDir)
    : path.join(process.cwd(), "ai-risk-snapshot-report");

  try {
    fs.mkdirSync(requested, { recursive: true });
    // A probe write catches an existing-but-not-writable folder, not just a
    // folder that fails to be created. Cleanup is best-effort.
    const probe = path.join(requested, ".write-probe");
    fs.writeFileSync(probe, "ok");
    try {
      fs.rmSync(probe);
    } catch { /* not important */ }
    return { outputDir: requested, fellBack: false };
  } catch (err) {
    const fallback = path.join(os.tmpdir(), "ai-risk-snapshot-report");
    try {
      fs.mkdirSync(fallback, { recursive: true });
      const probe = path.join(fallback, ".write-probe");
      fs.writeFileSync(probe, "ok");
      try {
        fs.rmSync(probe);
      } catch { /* not important */ }
      console.log(
        "\nThe report folder you chose isn't writable, so the report can't be saved there:\n" +
        `  ${requested}\n` +
        `Reason: ${plainError(err)}.\n` +
        "\nYour scan will still run. The report will be written to a temporary folder instead:\n" +
        `  ${fallback}\n` +
        "Copy it somewhere safe when you're done — the system may clean up temporary folders.\n"
      );
      return { outputDir: fallback, fellBack: true };
    } catch (fallbackErr) {
      throw new Error(
        "Couldn't create a writable folder for the report anywhere — not even your system's\n" +
        "temporary folder. This is unusual. Check disk space and permissions, then try again."
      );
    }
  }
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

  try {
    const stat = await fs.promises.stat(opts.rootDir);
    if (!stat.isDirectory()) {
      const notDir = new Error("not a directory");
      notDir.code = "ENOTDIR";
      throw notDir;
    }
    await fs.promises.access(opts.rootDir, fs.constants.R_OK);
  } catch (err) {
    console.error(`Cannot scan "${opts.rootDir}": ${scanPathError(err)}.`);
    process.exitCode = 2;
    return;
  }

  // Output goes in a dedicated folder, separate from the scanned project,
  // so the report isn't dropped inside a client's repo where it could get
  // committed and pushed by accident.
  let outputDir;
  let outputFellBack = false;
  try {
    const resolved = resolveOutputDir(opts);
    outputDir = resolved.outputDir;
    outputFellBack = resolved.fellBack;
  } catch (err) {
    console.error(err.message);
    process.exitCode = 2;
    return;
  }

  const agreed = await promptAgreement(opts.yes, outputDir);
  if (!agreed) {
    console.error("Consent was not given; no scan was run.");
    process.exitCode = 2;
    return;
  }

  try {
    const rulesPath = path.join(__dirname, "../rules/eu_ai_act.yaml");
    let scanner;
    try {
      scanner = new Scanner(rulesPath, opts.rootDir, { includeTests: opts.includeTests });
    } catch (error) {
      if (error instanceof RulePackError) {
        console.error(`Rule pack validation failed:\n${error.message}`);
        process.exitCode = 2;
        return;
      }
      throw error;
    }
    const findings = await scanner.scan();

    const formats = opts.format === "all" ? ["json", "html", "sarif"] : [opts.format];
    const { score, jsonPath, htmlPath, sarifPath } = generateReport(findings, outputDir, {
      version: pkg.version,
      scannedDirectory: opts.rootDir,
      filesScanned: scanner.filesScanned,
      filesSkipped: scanner.skippedFiles,
      astAvailable: scanner.astAvailable,
      rules: scanner.rules
    }, { formats });

    const band = getBand(score, findings);

    console.log("\nScan complete.");
    console.log(`  Files scanned: ${scanner.filesScanned}`);
    if (scanner.skippedFiles > 0) {
      console.log(`  Files skipped: ${scanner.skippedFiles} (see warnings above)`);
    }
    console.log(`  Findings:      ${findings.length}`);
    console.log(`  Score:         ${score}/100 (${band.label})`);
    console.log("");
    if (htmlPath) console.log(`  Report: ${htmlPath}`);
    if (jsonPath) console.log(`  Data:   ${jsonPath}`);
    if (sarifPath) console.log(`  SARIF:  ${sarifPath}`);

    if (findings.length > 0) {
      const serious = findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length;
      if (serious > 0) {
        console.log(`\nThis scan found ${findings.length} ${findings.length === 1 ? "finding" : "findings"}, ${serious} of them at CRITICAL or HIGH severity.`);
      } else {
        console.log(`\nThis scan found ${findings.length} ${findings.length === 1 ? "finding" : "findings"} worth a closer look.`);
      }
      console.log("Open report.html for details, and reach out with report.json if you'd like a full audit.");
    } else {
      console.log("\nNo pattern-based findings in the code this scan looked through.");
      console.log("Scope note: this covers static patterns in code only — not live behaviour, cloud IAM, or process/documentation checks.");
    }

    if (!outputFellBack) {
      console.log(
        `\nReminder: add "${path.relative(process.cwd(), outputDir) || "ai-risk-snapshot-report"}/" ` +
        "to your .gitignore so this report doesn't end up committed to version control."
      );
    }
    console.log("Nothing from this scan was sent anywhere. It stayed on this machine.");

    // The report is written above, so a failing gate still leaves both files
    // behind. Exit 1 means "scan completed, threshold met" — never "the scan
    // broke". Tool/config failures use exit 2 below.
    const thresholdHits = findingsAtOrAbove(findings, opts.failOn);
    if (thresholdHits.length > 0) {
      console.error(
        `\nFail threshold "${opts.failOn}" reached: ` +
        `${thresholdHits.length} finding${thresholdHits.length === 1 ? "" : "s"} ` +
        `at or above ${opts.failOn.toUpperCase()}.`
      );
      process.exitCode = 1;
    } else {
      process.exitCode = 0;
    }
  } catch (error) {
    console.error("Scan failed:", error.message);
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error("Unexpected failure:", error && error.message ? error.message : error);
  process.exitCode = 2;
});
