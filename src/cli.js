#!/usr/bin/env node
// src/cli.js
const path = require("path");
const fs = require("fs");
const os = require("os");
const { promptAgreement } = require("./agreement");
const Scanner = require("./scanner");
const { generateReport, getBand } = require("./reporter");

const pkg = require("../package.json");

function parseArgs(argv) {
  const opts = {
    rootDir: process.cwd(),
    outputDir: null,
    yes: false,
    includeTests: false
  };

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
      opts.outputDir = args[i + 1];
      i++;
    } else if (!arg.startsWith("-")) {
      opts.rootDir = path.resolve(arg);
    }
  }
  return opts;
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
  const opts = parseArgs(process.argv);

  try {
    await fs.promises.access(opts.rootDir);
  } catch {
    console.log(`Directory not found: ${opts.rootDir}`);
    process.exit(1);
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
    console.log(err.message);
    process.exit(1);
  }

  const agreed = await promptAgreement(opts.yes, outputDir);
  if (!agreed) return;

  try {
    const rulesPath = path.join(__dirname, "../rules/eu_ai_act.yaml");
    const scanner = new Scanner(rulesPath, opts.rootDir, { includeTests: opts.includeTests });
    const findings = await scanner.scan();

    const { score, jsonPath, htmlPath } = generateReport(findings, outputDir, {
      version: pkg.version,
      scannedDirectory: opts.rootDir,
      filesScanned: scanner.filesScanned,
      filesSkipped: scanner.skippedFiles
    });

    const band = getBand(score, findings);

    console.log("\nScan complete.");
    console.log(`  Files scanned: ${scanner.filesScanned}`);
    if (scanner.skippedFiles > 0) {
      console.log(`  Files skipped: ${scanner.skippedFiles} (see warnings above)`);
    }
    console.log(`  Findings:      ${findings.length}`);
    console.log(`  Score:         ${score}/100 (${band.label})`);
    console.log(`\n  Report: ${htmlPath}`);
    console.log(`  Data:   ${jsonPath}`);

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
  } catch (error) {
    console.error("Scan failed:", error.message);
    process.exit(1);
  }
}

main();
