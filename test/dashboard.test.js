// Dashboard report test: static checks on the generated HTML.
// It cannot run the page's JavaScript, so it covers what must always hold:
// untrusted text is escaped, headline numbers are consistent, and the
// "not a verdict" framing is present.
//
// The assertions use data-* hooks rather than CSS class names so a visual
// restyle cannot break them. The hooks are part of the report contract:
//   data-finding        one per issue type in the list
//   data-severity       lowercase severity on list rows
//   data-check          one per scan check in "What was checked"
//   data-flagged        "true" / "false" on each check row
//   data-headline       the headline sentence
//   data-issues/critical/high  counts the headline was derived from
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

// 2. Headline counts use issue types and agree with the finding list.
const issueRows = (html.match(/data-finding(?=[\s>])/g) || []).length;
const headlineIssues = Number((html.match(/data-issues="(\d+)"/) || [])[1]);
const headlineCritical = Number((html.match(/data-critical="(\d+)"/) || [])[1]);
const headlineHigh = Number((html.match(/data-high="(\d+)"/) || [])[1]);
ok(issueRows === 3, `expected 3 finding rows (3 issue types), got ${issueRows}`);
ok(headlineIssues === issueRows, `headline issues (${headlineIssues}) must equal finding rows (${issueRows})`);
ok(headlineCritical === 2 && headlineHigh === 1, "headline severity counts must match the findings");
ok((html.match(/data-finding[^>]*data-severity="critical"/g) || []).length >= 1, "critical severity hook missing");
ok((html.match(/data-finding[^>]*data-severity="high"/g) || []).length >= 1, "high severity hook missing");

// 3. Framing and honesty labels.
ok(html.includes("EU AI Act review checklist"), "framing line missing");
ok(html.includes("not a legal determination"), "short legal-determination caveat missing");
ok(html.includes("What was checked"), "checks panel missing");
const checkRows = (html.match(/data-check="/g) || []).length;
ok(checkRows === 12, `expected 12 check rows, got ${checkRows}`);
const flaggedRows = (html.match(/data-check="[^"]+" data-flagged="true"/g) || []).length;
ok(flaggedRows === 3, `3 flagged check rows expected, got ${flaggedRows}`);
ok(html.includes("Needs a human check"), "heuristic label missing");
ok(html.includes("Pattern match"), "pattern label missing");
ok(!html.includes("Direct match"), "old label must be gone");

// 4. One priority list: no separate "Do these first", first three rows open.
ok(!html.includes("Do these first"), "the separate priority section must be gone");
ok(html.includes("The first three are the best place to start."), "priority hint missing");
ok((html.match(/data-finding[^>]*\sopen>/g) || []).length === 3, "the first three findings should be open");

// 5. Zero counts are hidden; the header keeps the local note on its own line.
ok(!html.includes('<span class="word medium">'), "zero medium count should be hidden");
ok(!html.includes('<span class="word low">'), "zero low count should be hidden");
ok(html.includes('<span class="word critical">'), "critical count missing");
ok(html.includes('<div class="local">Ran on your computer. Nothing was uploaded.</div>'), "local header note should be its own line");

// 6. Visible paths use forward slashes; the report data is untouched.
const pathHtml = render([finding({ file: "infra\\policy.tf", line: 12 })]);
ok(pathHtml.includes("infra/policy.tf:12"), "visible paths should use forward slashes");

// 7. Rows that share a title get a qualifier for the real difference.
const duplicateTitles = render([
  finding({ toolExposure: "agent-tool", method: "ast-same-function" }),
  finding({ toolExposure: "general-code", method: "ast-same-function" })
]);
ok(duplicateTitles.includes("(in an AI agent tool file)"), "agent-tool qualifier missing");
ok(duplicateTitles.includes("(in general code)"), "general-code qualifier missing");
const duplicateMethods = render([
  finding({ toolExposure: "general-code", method: "proximity-heuristic" }),
  finding({ toolExposure: "general-code", method: "ast-same-function" })
]);
ok(duplicateMethods.includes("(in general code, nearby words)"), "method qualifier missing for nearby words");
ok(duplicateMethods.includes("(in general code, structural check)"), "method qualifier missing for structural check");

// 8. Full path is not shown in the visible page (only folder name).
ok(!html.includes("/x/&lt;b&gt;proj"), "visible page should show folder name only");

// 9. Python-missing note appears only when astAvailable is false.
ok(!html.includes("Python was not found"), "no note expected when astAvailable");
ok(render([finding()], { astAvailable: false }).includes("Python was not found"), "note expected when astAvailable is false");

// 10. Empty report: no findings section or severity bar, but keep the caveat.
const empty = render([]);
ok(empty.includes("Nothing was flagged"), "empty headline missing");
ok(empty.includes("That only means no pattern matched"), "empty headline caveat missing");
ok(empty.includes("not that it passed"), "checks caveat must remain");
ok(!empty.includes("All findings"), "no findings heading expected");
ok(!empty.includes('<div class="sevbar'), "no severity bar expected");
ok(!/data-finding(?=[\s>])/.test(empty), "no finding rows expected");
ok(/data-issues="0"/.test(empty), "headline should report zero issues");
ok(empty.includes("What was checked"), "checks panel missing from a clean report");
ok((empty.match(/data-check="/g) || []).length === 12, "all 12 checks should still be listed");
ok(!empty.includes("Python was not found"), "no Python note in a clean report with astAvailable");

console.log(`ok - ${n} dashboard report assertions passed`);
