// src/agreement.js
const readline = require("readline");
const fs = require("fs");
const path = require("path");

const TERMS_VERSION = "1.1.0";

const TERMS_TEXT =
  "\nAI Risk Snapshot — Terms Before You Proceed\n" +
  "============================================\n\n" +
  "1. Read-only. This tool only reads files on your computer. It does not\n" +
  "   execute your code, modify any file, or install anything beyond its own\n" +
  "   dependencies.\n\n" +
  "2. Local-only. All scanning happens on this machine. Nothing is sent to\n" +
  "   us, or anywhere else, unless you personally choose to send the report\n" +
  "   afterward.\n\n" +
  "3. Not a certified audit. This is a preliminary, automated scan. It is\n" +
  "   NOT a certified compliance audit, a legal opinion, or legal advice,\n" +
  "   and no result from this tool should be described as a 'certificate'\n" +
  "   of compliance with the EU AI Act or any other law.\n\n" +
  "4. Provided as-is. The scan is heuristic-based and can miss real issues\n" +
  "   or flag things that aren't actually problems. It's a starting point,\n" +
  "   not a guarantee.\n\n" +
  "5. Liability. To the extent permitted by law, our liability arising from\n" +
  "   this free tool is limited to the fees you paid for it ($0).\n\n" +
  "6. PII handling. The report redacts common personal-data patterns\n" +
  "   (emails, ID-like numbers, card-like numbers, phone numbers) before\n" +
  "   they're written to any output file.\n\n" +
  "7. Confidentiality. If you choose to send us a report, we treat its\n" +
  "   contents as confidential. We may reuse anonymised, non-identifying\n" +
  "   *patterns* (e.g. 'X% of scans find missing logging') for our own\n" +
  "   research and marketing, never anything that identifies you or your\n" +
  "   codebase.\n";

function writeConsentLog(outputDir, accepted, method) {
  try {
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    const entry = {
      timestamp: new Date().toISOString(),
      termsVersion: TERMS_VERSION,
      accepted,
      method // "interactive" | "flag"
    };
    const logPath = path.join(outputDir, ".consent-log.json");
    fs.writeFileSync(logPath, JSON.stringify(entry, null, 2));
  } catch (err) {
    // Never block the scan over a logging failure — just warn.
    console.warn("  (could not write local consent log — continuing anyway)");
  }
}

/**
 * @param {boolean} autoYes - true if the user passed --yes on the command
 *   line (needed for non-interactive contexts like CI). This is still an
 *   explicit, deliberate act of agreement — not a default.
 * @param {string} outputDir - where to write the local consent record.
 */
async function promptAgreement(autoYes, outputDir) {
  console.log(TERMS_TEXT);

  if (autoYes) {
    console.log("--yes flag detected: terms accepted non-interactively.\n");
    writeConsentLog(outputDir, true, "flag");
    return true;
  }

  if (!process.stdin.isTTY) {
    console.log(
      "No interactive terminal detected, and no --yes flag was passed.\n" +
      "Re-run with --yes if you've read the terms above and agree, e.g.:\n" +
      "  npx ai-risk-snapshot --yes\n" +
      "In CI you normally need both --yes and --fail-on.\n"
    );
    return false;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  return new Promise((resolve) => {
    rl.question("Do you agree to these terms? (yes/no): ", (answer) => {
      rl.close();
      const accepted = answer.toLowerCase().trim() === "yes";
      writeConsentLog(outputDir, accepted, "interactive");
      if (accepted) {
        resolve(true);
      } else {
        console.log("You must agree to proceed. Exiting.");
        resolve(false);
      }
    });
  });
}

module.exports = { promptAgreement, TERMS_VERSION };
