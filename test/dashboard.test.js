// Dashboard report test: static checks on the generated HTML.
// It cannot run the page's JavaScript, so it covers what must always hold:
// untrusted text is escaped, headline numbers are consistent, and the
// "not a verdict" framing is present.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { generateReport } = require("../src/reporter");

const HOSTILE_FILE = "src/<img src=x onerror=alert(1)>.py";
const HOSTILE_SNIPPET = "delete(\"<script>alert(2)</script>\")";

function finding(over) {
  return Object.assign({
    id: "NO_HUMAN_LOOP", article: "Article 14 (Human Oversight)", title: "Missing Human-in-the-Loop",
    severity: "CRITICAL", toolExposure: "agent-tool", method: "ast-same-function",
    file: HOSTILE_FILE, line: 4, snippet: HOSTILE_SNIPPET, extraFiles: [],
    consequence: "An irreversible action can run with no person able to stop it.",
    fix: "Add a human approval step before the action executes.", type: "Logic"
  }, over || {});
}

function render(findings, meta) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dash-"));
  generateReport(findings, dir, Object.assign({ version: "test", scannedDirectory: "/x/<b>proj</b>", filesScanned: 3, filesSkipped: 0, astAvailable: true }, meta || {}));
  return fs.readFileSync(path.join(dir, "report.html"), "utf8");
}

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n += 1; };

// 1. Hostile file names, snippets and folder names never appear as live markup.
const html = render([
  finding(),
  finding({ id: "IDENTITY_KEY", article: "Article 15 (Cybersecurity)", title: "Hardcoded key", method: null, toolExposure: null, file: ".env", line: 1, snippet: "(value withheld)" }),
  finding({ id: "NO_LOGGING", severity: "HIGH", method: "proximity-heuristic" })
]);
ok(!html.includes("<img src=x"), "raw <img> from file name must be escaped");
ok(!html.includes("<script>alert"), "raw <script> from snippet must be escaped");
ok(!html.includes("<b>proj</b>"), "folder name must be escaped");
ok(html.includes("&lt;img src=x"), "escaped file name should be visible as text");

// 2. Headline counts use issue types and agree with the card list.
ok(html.includes("Issues found"), "issues tile missing");
ok((html.match(/<details class="card /g) || []).length === 3, "expected 3 finding cards (3 issue types)");
ok(/class="big">3<\/div><div class="small">in 3 places/.test(html), "tile should say 3 issues in 3 places");

// 3. Framing and honesty labels.
ok(html.includes("EU AI Act review checklist"), "framing banner missing");
ok(html.includes("not a legal determination"), "short legal-determination caveat missing");
ok(html.includes("What was checked"), "checks panel missing");
ok((html.match(/<div class=\"check (hit|clear)\">/g) || []).length === 12, "expected 12 check chips");
ok((html.match(/<div class=\"check hit\">/g) || []).length === 3, "3 flagged check chips expected");
ok(html.includes("Needs a human check"), "heuristic label missing");
ok(html.includes("Pattern match"), "pattern label missing");
ok(!html.includes("Direct match"), "old label must be gone");

// 4. Full path is not shown in the visible page (only folder name).
ok(!html.includes("/x/&lt;b&gt;proj"), "visible page should show folder name only");

// 5. Python-missing note appears only when astAvailable is false.
ok(!html.includes("Python was not found"), "no note expected when astAvailable");
ok(render([finding()], { astAvailable: false }).includes("Python was not found"), "note expected when astAvailable is false");

// 6. Empty report: neutral wording, no false reassurance.
const empty = render([]);
ok(empty.includes("not a clean bill of health"), "empty state must not over-reassure");
ok(!empty.includes("<details class=\"card "), "no cards expected");

console.log(`ok - ${n} dashboard report assertions passed`);
