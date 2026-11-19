"use strict";

// Dashboard-style HTML report. Presentation only: it reads findings that the
// scanner already produced and never changes detection, scoring, JSON or SARIF.
//
// Design rules for this file:
//  - One plain headline says what needs attention first. Details stay closed
//    until a reader opens them.
//  - Structure is information: ruled rows, no cards, no shadows, no pills.
//  - Every value that came from scanned code or file names goes through esc().
//  - No external resources (fonts, scripts, images). Works offline and prints.

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };

// Plain-language wording per rule. These describe what the pattern MEANS in
// everyday terms and deliberately use "may" / "might": a finding is a pointer
// for review, not proof of a breach.
const PLAIN = {
  IDENTITY_KEY: {
    title: "A secret key is stored in the code",
    why: "Anyone who can read the code could use this key to act as your service."
  },
  IAM_WILDCARD: {
    title: "Cloud permissions are very broad",
    why: "One mistake or leaked key could reach every resource in the account."
  },
  NO_HUMAN_LOOP: {
    title: "A risky action may run without a person approving it",
    why: "An action that cannot be undone might run with nobody able to stop it."
  },
  NO_LOGGING: {
    title: "A risky action may leave no record",
    why: "If something goes wrong, there might be no trail showing what happened."
  },
  HTTP_NO_AUTH: {
    title: "Web endpoints without a visible login check",
    why: "Anyone who can reach the server might be able to call these endpoints."
  },
  AUTO_DECISION: {
    title: "The software may decide an outcome automatically",
    why: "A person could be approved or rejected with no human review."
  },
  SENSITIVE_DATA: {
    title: "A file that looks like personal data is in the project",
    why: "Personal documents inside a code repository can be shared by accident."
  },
  NO_AI_DISCLOSURE: {
    title: "A chatbot prompt does not say it is an AI",
    why: "Users might not be told they are talking to an AI."
  },
  CORS_WILDCARD: {
    title: "Any website may be allowed to call this API",
    why: "Other websites might be able to read responses from this API."
  },
  UNSAFE_DESERIALIZE: {
    title: "Loading untrusted data could run attacker code",
    why: "Crafted input could make the program run code the attacker chose."
  },
  ERROR_LEAKAGE: {
    title: "Error details may be shown to users",
    why: "Internal error text can help an attacker learn how the system works."
  },
  SAFETY_BYPASS: {
    title: "A safety check appears to be switched off",
    why: "A protection looks disabled next to a high-impact action."
  }
};

// Short labels for the "What was checked" panel. Article text mirrors the rule pack.
const CHECKS = [
  { id: "IDENTITY_KEY", name: "Secret keys in code", art: "Art. 15" },
  { id: "IAM_WILDCARD", name: "Broad cloud permissions", art: "Art. 15" },
  { id: "HTTP_NO_AUTH", name: "Endpoint login checks", art: "Art. 15" },
  { id: "CORS_WILDCARD", name: "Open API access (CORS)", art: "Art. 15" },
  { id: "UNSAFE_DESERIALIZE", name: "Unsafe data loading", art: "Art. 15" },
  { id: "ERROR_LEAKAGE", name: "Error detail exposure", art: "Art. 15" },
  { id: "SENSITIVE_DATA", name: "Personal-data files", art: "Art. 10 / GDPR" },
  { id: "NO_HUMAN_LOOP", name: "Human approval", art: "Art. 14" },
  { id: "AUTO_DECISION", name: "Automatic decisions", art: "Art. 14" },
  { id: "SAFETY_BYPASS", name: "Safety switches", art: "Art. 14" },
  { id: "NO_LOGGING", name: "Action logging", art: "Art. 12" },
  { id: "NO_AI_DISCLOSURE", name: "AI disclosure", art: "Art. 50" }
];

// Rules that match a literal, specific pattern. Everything else relies on a
// heuristic (nearby words, file names, structure) and needs a human to confirm.
// This is a statement about HOW the rule detects, not a measured accuracy.
const DIRECT_RULES = new Set(["IDENTITY_KEY", "IAM_WILDCARD", "CORS_WILDCARD", "UNSAFE_DESERIALIZE"]);

const STATUS_PLAIN = {
  "Severe gap": "Needs urgent attention",
  "Elevated gap": "Needs attention soon",
  "Moderate gap": "A few things to review",
  "Good readiness": "No issues flagged"
};

function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function firstSentence(text) {
  const t = String(text || "").trim().replace(/\s+/g, " ");
  if (!t) return "";
  const m = t.match(/^(.+?[.!?])(\s|$)/);
  return m ? m[1] : t;
}

function clip(text, max) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const lastSpace = cut.lastIndexOf(" ");
  return (lastSpace > max * 0.6 ? cut.slice(0, lastSpace) : cut) + "…";
}

function baseName(p) {
  const s = String(p || "").replace(/[\\/]+$/, "");
  const parts = s.split(/[\\/]/);
  return parts[parts.length - 1] || s;
}

function displayPath(p) {
  if (p === null || p === undefined) return "";
  return String(p).replace(/\\/g, "/");
}

function formatScore(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return "—";
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}

function plainFor(group) {
  const p = PLAIN[group.id];
  if (p) return p;
  return { title: group.title || group.id, why: firstSentence(group.consequence) };
}

function methodQualifier(group) {
  if (group.method === "ast-same-function") return "structural check";
  if (group.method === "proximity-heuristic") return "nearby words";
  return "pattern match";
}

function titleQualifier(group, groups) {
  const title = plainFor(group).title;
  const sameTitle = groups.filter((g) => plainFor(g).title === title);
  if (sameTitle.length < 2) return "";
  const exposures = new Set(sameTitle.map((g) => g.toolExposure || "general-code"));
  const methods = new Set(sameTitle.map((g) => g.method || "pattern"));
  const exposure = group.toolExposure === "agent-tool" ? "in an AI agent tool file" : "in general code";
  const method = methodQualifier(group);
  if (exposures.size > 1) {
    return methods.size > 1 ? ` (${exposure}, ${method})` : ` (${exposure})`;
  }
  if (methods.size > 1) return ` (${exposure}, ${method})`;
  return "";
}

function tierFor(group) {
  // An agent-tool-exposed oversight finding is still heuristic. A finding
  // reported as general code is explicitly weaker (no agent tool detected).
  if (DIRECT_RULES.has(group.id)) return "direct";
  return "review";
}

function groupFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = [f.id || f.title, f.toolExposure || "-", f.method || "-"].join("|");
    if (!groups.has(key)) {
      groups.set(key, {
        id: f.id,
        article: f.article,
        title: f.title,
        severity: f.severity,
        toolExposure: f.toolExposure || null,
        method: f.method || null,
        consequence: f.consequence,
        fix: f.fix,
        files: []
      });
    }
    const g = groups.get(key);
    g.files.push({ file: f.file, line: f.line, snippet: f.snippet });
    if (Array.isArray(f.extraFiles)) {
      for (const extra of f.extraFiles) g.files.push({ file: extra, line: "N/A", snippet: "" });
    }
  }
  return [...groups.values()].sort((a, b) => {
    const s = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    if (s) return s;
    const t = (tierFor(a) === "direct" ? 0 : 1) - (tierFor(b) === "direct" ? 0 : 1);
    if (t) return t;
    return b.files.length - a.files.length;
  });
}

function where(file, line) {
  return `${esc(displayPath(file))}${line !== undefined && line !== null && line !== "N/A" ? ":" + esc(line) : ""}`;
}

function methodText(group) {
  if (group.method === "ast-same-function") return "Checked the structure of the surrounding function";
  if (group.method === "proximity-heuristic") return "Looked for related words nearby";
  return "Matched a specific pattern or file name";
}

function exposureText(group) {
  if (group.toolExposure === "agent-tool") return "In a file that registers an AI agent tool";
  if (group.toolExposure === "general-code") return "No agent tool found in this file, so treat it as general code";
  return "";
}

function severityCounts(groups) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const g of groups) if (counts[g.severity] !== undefined) counts[g.severity] += 1;
  return counts;
}

function bandKey(counts) {
  if (counts.CRITICAL) return "critical";
  if (counts.HIGH) return "high";
  if (counts.MEDIUM) return "medium";
  if (counts.LOW) return "low";
  return "clear";
}

function renderHeadline(issues, critical, high) {
  let first;
  let second = "";
  if (!issues) {
    first = "Nothing was flagged.";
    second = "That only means no pattern matched.";
  } else {
    first = `${issues} ${issues === 1 ? "issue needs" : "issues need"} a look.`;
    if (critical) second = `${critical} ${critical === 1 ? "is" : "are"} critical.`;
    else if (high) second = `${high} ${high === 1 ? "is" : "are"} high.`;
    else second = "None are critical or high.";
  }
  return `<h1 data-headline data-issues="${issues}" data-critical="${critical}" data-high="${high}">${esc(first)}${second ? ` <span class="second">${esc(second)}</span>` : ""}</h1>`;
}

function renderScore(score, counts, band) {
  const n = Number(score);
  const safe = Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - safe / 100);
  const label = band.label || "";
  const plain = STATUS_PLAIN[label] || "";
  return `<aside class="score" data-band="${bandKey(counts)}" aria-label="Readiness summary">
      <div class="ring">
        <svg viewBox="0 0 80 80" role="img" aria-label="Readiness score ${esc(formatScore(score))} out of 100">
          <circle class="ring-track" cx="40" cy="40" r="${radius}"></circle>
          <circle class="ring-arc" cx="40" cy="40" r="${radius}" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"></circle>
        </svg>
        <span class="ring-center"><span class="ring-num">${esc(formatScore(score))}</span><span class="ring-max">/ 100</span></span>
      </div>
      <div class="score-copy">
        <span class="score-kicker">Readiness score</span>
        <strong class="score-band">${esc(label)}</strong>
        ${plain ? `<span class="score-plain">${esc(plain)}</span>` : ""}
      </div>
    </aside>`;
}

function renderSeverity(groups, counts, reviewCount) {
  const total = groups.length;
  const keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const shown = keys.filter((k) => counts[k] > 0);
  const segs = shown
    .map((k) => `<span class="seg ${k.toLowerCase()}" style="width:${((counts[k] / total) * 100).toFixed(2)}%"></span>`)
    .join("");
  const items = shown
    .map((k) => `<span class="sev-item"><span class="word ${k.toLowerCase()}">${esc(SEV_LABEL[k])}</span> <b>${counts[k]}</b></span>`)
    .join("");
  const label = shown.map((k) => `${counts[k]} ${SEV_LABEL[k]}`).join(", ");
  const reviewNote = reviewCount
    ? `<p class="review-note">${reviewCount} of ${total} ${reviewCount === 1 ? "uses" : "use"} a heuristic and ${reviewCount === 1 ? "needs" : "need"} a human check.</p>`
    : "";
  return `<div class="sevbar${total ? "" : " empty"}" role="img" aria-label="${esc(total ? label : "No findings")}">${segs}</div>
    <div class="sevcounts">${items}</div>${reviewNote}`;
}

function renderFindings(groups) {
  return groups.map((g, index) => {
    const p = plainFor(g);
    const qualifier = titleQualifier(g, groups);
    const title = p.title + qualifier;
    const tier = tierFor(g);
    const loc = g.files[0] || {};
    const shown = g.files.slice(0, 10);
    const hidden = g.files.length - shown.length;
    const fix = firstSentence(g.fix);
    const exposure = exposureText(g);
    const sev = g.severity.toLowerCase();
    const sure = tier === "direct"
      ? `<span class="f-mark"><span class="mark mark-direct" aria-hidden="true"></span>Pattern match</span>`
      : `<span class="f-mark"><span class="mark mark-review" aria-hidden="true"></span>Needs a human check</span>`;
    const searchText = [title, g.id, g.article, ...g.files.map((f) => displayPath(f.file))].join(" ").toLowerCase();
    return `
      <details class="finding" id="finding-${index + 1}" data-finding data-severity="${esc(sev)}" data-tier="${tier}" data-text="${esc(searchText)}"${index < 3 ? " open" : ""}>
        <summary>
          <span class="f-main">
            <span class="f-title"><span class="word ${esc(sev)}">${esc(SEV_LABEL[g.severity] || g.severity)}</span> <span class="f-name">${esc(title)}</span></span>
            <span class="f-why">${esc(p.why)}</span>
          </span>
          <span class="f-side">
            ${sure}
            <code>${where(loc.file, loc.line)}${g.files.length > 1 ? ` <span class="more">+${g.files.length - 1}</span>` : ""}</code>
          </span>
        </summary>
        <div class="f-body">
          ${fix ? `<p class="fix"><strong>What to do:</strong> ${esc(fix)}</p>` : ""}
          ${tier === "review" ? `<p class="note">This one uses a heuristic and can be wrong. Confirm it in the code before acting. The control may exist somewhere this scan cannot see, such as a gateway, a queue or another service.</p>` : ""}
          <h3 class="body-h">Where it was found</h3>
          <ul class="locs">
            ${shown.map((f) => `<li><code>${where(f.file, f.line)}</code>${f.snippet ? `<span class="snip">${esc(clip(f.snippet, 120))}</span>` : ""}</li>`).join("")}
          </ul>
          ${hidden > 0 ? `<p class="more">+${hidden} more locations are listed in report.json.</p>` : ""}
          <details class="tech">
            <summary>Technical details</summary>
            <dl>
              <dt>Related EU AI Act provision</dt><dd>${esc(g.article)}<br><em>A prompt for review, not a finding of non-compliance.</em></dd>
              <dt>How it was detected</dt><dd>${esc(methodText(g))}</dd>
              ${exposure ? `<dt>Agent context</dt><dd>${esc(exposure)}</dd>` : ""}
              <dt>Rule ID</dt><dd><code>${esc(g.id)}</code></dd>
            </dl>
          </details>
        </div>
      </details>`;
  }).join("");
}

function renderChecks(groups) {
  const flagged = new Map();
  for (const g of groups) flagged.set(g.id, (flagged.get(g.id) || 0) + 1);
  const known = new Set(CHECKS.map((c) => c.id));
  const extra = [...flagged.keys()].filter((id) => !known.has(id)).map((id) => ({ id, name: id, art: "" }));
  return CHECKS.concat(extra).map((c) => {
    const n = flagged.get(c.id) || 0;
    return `
      <div class="check-row" data-check="${esc(c.id)}" data-flagged="${n ? "true" : "false"}">
        <span class="check-mark" aria-hidden="true"></span>
        <span class="check-main"><span class="check-name">${esc(c.name)}</span>${c.art ? `<span class="check-art">${esc(c.art)}</span>` : ""}</span>
        <span class="check-result">${n ? `${n} flagged` : "nothing flagged"}</span>
      </div>`;
  }).join("");
}

function renderControls(groups, counts, reviewCount) {
  if (!groups.length) return "";
  const tabCount = {
    all: groups.length,
    critical: counts.CRITICAL,
    high: counts.HIGH,
    other: counts.MEDIUM + counts.LOW,
    review: reviewCount
  };
  const tab = (filter, label) => {
    const n = tabCount[filter];
    return `<button class="tab" data-filter="${filter}" aria-pressed="${filter === "all" ? "true" : "false"}">${label}${n ? ` <span class="tab-n">${n}</span>` : ""}</button>`;
  };
  return `
        <div class="controls" id="tools">
          <div class="tabs" role="group" aria-label="Filter findings">
            ${tab("all", "All")}
            ${tab("critical", "Critical")}
            ${tab("high", "High")}
            ${tab("other", "Medium and low")}
            ${tab("review", "Needs a human check")}
          </div>
          <div class="controls-tools">
            <div class="search-wrap">
              <svg class="search-icon" viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.5"></circle><path d="M10.5 10.5 14 14"></path></svg>
              <input class="search" id="q" type="search" placeholder="Search by file or topic" aria-label="Search findings">
              <kbd class="search-kbd" aria-hidden="true">/</kbd>
            </div>
            <span class="count" id="count" aria-live="polite"></span>
          </div>
        </div>`;
}

function renderAbout(app) {
  return `
    <section class="about" aria-labelledby="h-about">
      <details>
        <summary id="h-about">About this scan and what it cannot tell you</summary>
        <ul>
          <li>${esc(app.articleReferencesNote || "Article references are review prompts, not compliance findings.")}</li>
          <li>${esc(app.highRiskOnlyNote || "Some EU AI Act duties apply only to systems classified as high-risk. This scan does not perform that classification.")}</li>
          <li>${esc(app.roleNote || "Provider and deployer duties differ. This scan does not determine which role applies.")}</li>
          <li><strong>Pattern match</strong> means the rule looks for a specific pattern in the text. It can still be a harmless test value, so check the context. <strong>Needs a human check</strong> means the rule uses a heuristic, such as nearby words or file names, and can be wrong in either direction.</li>
          <li>The readiness score starts at 100 and subtracts points for each finding. It is a rough ranking of the gaps visible in code, not a probability of compliance.</li>
          <li>It reads files only. It does not run your code, test live behaviour, or review policies, training data or people and process.</li>
          <li>Not legal advice and not a certified audit.</li>
        </ul>
      </details>
    </section>`;
}

function buildDashboardHTML(findings, score, meta, reportData, helpers) {
  const band = (helpers && helpers.band) || {};
  const groups = groupFindings(findings);
  const places = findings.length;
  const issues = groups.length;
  const counts = severityCounts(groups);
  const reviewCount = groups.filter((g) => tierFor(g) === "review").length;
  const flaggedCheckIds = new Set(groups.map((g) => g.id));
  const extraCheckCount = [...flaggedCheckIds].filter((id) => !CHECKS.some((c) => c.id === id)).length;
  const checkTotal = CHECKS.length + extraCheckCount;
  const folder = baseName((reportData && reportData.scannedDirectory) || meta.scannedDirectory || "project");
  const when = (reportData && reportData.generatedAt) ? new Date(reportData.generatedAt) : new Date();
  const whenText = isNaN(when.getTime()) ? "" : when.toISOString().slice(0, 16).replace("T", " ") + " UTC";
  const app = (reportData && reportData.applicability) || {};
  const safeJson = JSON.stringify(reportData || { findings, score }).replace(/</g, "\\u003c");
  const filesScanned = Number(meta.filesScanned);
  const filesText = Number.isFinite(filesScanned) ? `${filesScanned} ${filesScanned === 1 ? "file" : "files"}` : "";
  const astNote = meta.astAvailable === false
    ? `<p class="note python-note">Python was not found on this computer, so some checks used a simpler method. Results may be less precise.</p>`
    : "";
  const metaFacts = [
    `<span>Scanned <b>${esc(folder)}</b></span>`,
    filesText ? `<span>${filesText}</span>` : "",
    `<span>${esc(places)} ${places === 1 ? "location" : "locations"}</span>`,
    whenText ? `<span>${esc(whenText)}</span>` : ""
  ].filter(Boolean).join("");
  const startHint = groups.length >= 3
    ? "The first three are the best place to start."
    : groups.length === 2
      ? "Both are the best place to start."
      : "This is the best place to start.";
  const severitySection = groups.length
    ? `<section class="severity" aria-labelledby="h-sev">
      <div class="sev-head">
        <h2 id="h-sev">By severity</h2>
        <span class="sev-total">${esc(issues)} ${issues === 1 ? "issue" : "issues"} across ${esc(places)} ${places === 1 ? "location" : "locations"}</span>
      </div>
      ${renderSeverity(groups, counts, reviewCount)}
    </section>`
    : "";
  const findingsSection = groups.length
    ? `<section class="findings" id="findings" aria-labelledby="h-all">
      <div class="findings-head">
        <div>
          <h2 id="h-all">All findings</h2>
          <p class="section-note">${startHint}</p>
        </div>
        <div class="head-tools">
          <button class="tool-btn" data-expand="true">Expand all</button>
          <button class="tool-btn" data-expand="false">Collapse all</button>
        </div>
      </div>
      ${renderControls(groups, counts, reviewCount)}
      <noscript><style>.controls, .actions, .head-tools { display: none !important; }</style></noscript>
      <div id="finding-list">${renderFindings(groups)}</div>
      <p class="no-results" id="no-results" hidden>No findings match that search. Try a file name, a rule ID, or a severity.</p>
    </section>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Risk Snapshot: ${esc(band.label)} (${esc(folder)})</title>
<style>
  :root {
    color-scheme: light;
    --page: #F5F7F4;
    --surface: #FFFFFF;
    --ink: #17211E;
    --muted: #5B6864;
    --rule: #D9DFDB;
    --control: #7C8A85;
    --accent: #0E6B5E;
    --accent-soft: #E3EEEB;
    --critical: #B3261E;
    --high: #A94E0B;
    --medium: #856000;
    --low: #566B7D;
    --good: #1D6F45;
    --hover: #EDF1EE;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      color-scheme: dark;
      --page: #0F1513;
      --surface: #151D1A;
      --ink: #E8EEEC;
      --muted: #A2B0AC;
      --rule: #293532;
      --control: #6F837D;
      --accent: #6AC8BA;
      --accent-soft: #172A26;
      --critical: #F08A82;
      --high: #EDA363;
      --medium: #D9BC6A;
      --low: #A9B8C6;
      --good: #72D3A1;
      --hover: #1A2421;
    }
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; scroll-behavior: smooth; }
  @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
  body {
    margin: 0;
    background: var(--page);
    color: var(--ink);
    font: 400 15px/1.55 var(--sans);
    font-variant-numeric: tabular-nums;
  }
  code { font-family: var(--mono); font-size: 0.82rem; }
  a { color: var(--accent); text-underline-offset: 2px; }
  a:hover { text-decoration-thickness: 2px; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 2px; }
  .skip {
    position: absolute; left: -9999px; top: 0; z-index: 10;
    background: var(--surface); color: var(--ink); padding: 8px 12px; border-radius: 4px;
  }
  .skip:focus { left: 12px; top: 12px; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 0 28px; }
  .masthead { border-bottom: 1px solid var(--rule); }
  .masthead-in {
    display: flex; flex-wrap: wrap; gap: 10px 24px;
    align-items: baseline; justify-content: space-between;
    padding-top: 18px; padding-bottom: 18px;
  }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 650; font-size: 0.95rem; letter-spacing: -0.01em; }
  .brand-mark { width: 9px; height: 9px; display: inline-block; background: var(--accent); }
  .brand .ver { font-weight: 500; color: var(--muted); font-size: 0.8rem; }
  .meta { display: grid; gap: 4px; color: var(--muted); font-size: 0.8rem; }
  .meta-facts { display: flex; flex-wrap: wrap; gap: 6px 0; align-items: baseline; }
  .meta-facts > span { padding: 0 12px; border-left: 1px solid var(--rule); }
  .meta-facts > span:first-child { border-left: 0; padding-left: 0; }
  .meta-facts > span:last-child { padding-right: 0; }
  .meta b { color: var(--ink); font-weight: 600; }
  .meta .local { color: var(--muted); }
  .lede {
    display: grid; grid-template-columns: minmax(0, 1fr) auto;
    gap: 28px 48px; align-items: start;
    padding-top: 46px;
  }
  .eyebrow {
    margin: 0 0 14px; color: var(--accent);
    font-size: 0.7rem; font-weight: 650; letter-spacing: 0.13em; text-transform: uppercase;
  }
  .lede h1 {
    margin: 0; max-width: 22ch;
    font-size: clamp(2rem, 5.2vw, 2.9rem);
    line-height: 1.03; letter-spacing: -0.035em; font-weight: 700;
    text-wrap: balance;
  }
  .lede h1 .second { display: block; }
  .quiet { color: var(--muted); max-width: 64ch; margin: 16px 0 0; }
  .lede .quiet { font-size: 1rem; line-height: 1.55; }
  .note {
    margin: 18px 0 0; padding: 11px 14px;
    background: var(--surface); border-left: 2px solid var(--medium);
    color: var(--muted); font-size: 0.86rem; max-width: 64ch;
  }
  .score {
    display: flex; align-items: center; gap: 16px;
    border-left: 1px solid var(--rule); padding: 2px 0 2px 30px;
    min-width: 230px;
  }
  .ring { position: relative; width: 92px; height: 92px; flex: 0 0 92px; }
  .ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .ring-track { fill: none; stroke: var(--rule); stroke-width: 6; }
  .ring-arc { fill: none; stroke: var(--accent); stroke-width: 6; stroke-linecap: butt; }
  .score[data-band="critical"] .ring-arc { stroke: var(--critical); }
  .score[data-band="high"] .ring-arc { stroke: var(--high); }
  .score[data-band="medium"] .ring-arc { stroke: var(--medium); }
  .score[data-band="low"] .ring-arc { stroke: var(--low); }
  .score[data-band="clear"] .ring-arc { stroke: var(--good); }
  .ring-center {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center; line-height: 1;
  }
  .ring-num { font-size: 1.45rem; font-weight: 700; letter-spacing: -0.04em; }
  .ring-max { margin-top: 3px; color: var(--muted); font-size: 0.62rem; letter-spacing: 0.02em; }
  .score-copy { display: grid; gap: 3px; }
  .score-kicker { color: var(--muted); font-size: 0.7rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; }
  .score-band { font-size: 1.05rem; font-weight: 700; letter-spacing: -0.015em; }
  .score[data-band="critical"] .score-band { color: var(--critical); }
  .score[data-band="high"] .score-band { color: var(--high); }
  .score[data-band="medium"] .score-band { color: var(--medium); }
  .score[data-band="low"] .score-band { color: var(--low); }
  .score[data-band="clear"] .score-band { color: var(--good); }
  .score-plain { color: var(--muted); font-size: 0.82rem; }
  @media (prefers-reduced-motion: no-preference) {
    .ring-arc { transition: stroke-dashoffset 0.7s ease; }
  }
  section { margin-top: 46px; }
  h2 { margin: 0 0 4px; font-size: 1.05rem; font-weight: 650; letter-spacing: -0.015em; }
  .section-note { color: var(--muted); font-size: 0.88rem; margin: 0; max-width: 66ch; }
  .severity { margin-top: 38px; }
  .sev-head { display: flex; flex-wrap: wrap; gap: 4px 24px; align-items: baseline; justify-content: space-between; margin-bottom: 12px; }
  .sev-head h2 { margin: 0; }
  .sev-total { color: var(--muted); font-size: 0.8rem; }
  .sevbar { display: flex; gap: 2px; height: 10px; background: var(--rule); }
  .sevbar .seg { display: block; height: 100%; }
  .seg.critical { background: var(--critical); }
  .seg.high { background: var(--high); }
  .seg.medium { background: var(--medium); }
  .seg.low { background: var(--low); }
  .sevcounts { display: flex; flex-wrap: wrap; gap: 8px 30px; margin-top: 12px; font-size: 0.84rem; color: var(--muted); }
  .sev-item { display: inline-flex; align-items: baseline; gap: 6px; }
  .sevcounts b { color: var(--ink); font-weight: 700; }
  .word { font-size: 0.84rem; font-weight: 650; }
  .word.critical { color: var(--critical); }
  .word.high { color: var(--high); }
  .word.medium { color: var(--medium); }
  .word.low { color: var(--low); }
  .review-note { color: var(--muted); font-size: 0.8rem; margin: 10px 0 0; }
  .more { color: var(--muted); font-size: 0.8rem; }
  .findings-head {
    display: flex; flex-wrap: wrap; gap: 8px 24px;
    align-items: flex-end; justify-content: space-between; margin-bottom: 16px;
  }
  .findings-head h2 { margin-bottom: 4px; }
  .head-tools { display: flex; gap: 14px; }
  .controls {
    position: sticky; top: 0; z-index: 20;
    display: grid; gap: 8px;
    padding: 10px 0;
    background: var(--page);
    border-top: 1px solid var(--rule);
    border-bottom: 1px solid var(--rule);
  }
  .tabs { display: flex; flex-wrap: wrap; gap: 0 2px; }
  .tab {
    appearance: none; background: none; border: 0;
    border-bottom: 2px solid transparent; color: var(--muted);
    font: inherit; font-size: 0.85rem; padding: 7px 7px 6px; cursor: pointer;
    display: inline-flex; align-items: baseline; gap: 6px;
  }
  .tab:hover { color: var(--ink); }
  .tab[aria-pressed="true"] { color: var(--ink); border-bottom-color: var(--accent); font-weight: 650; }
  .tab-n { color: var(--muted); font-size: 0.7rem; font-variant-numeric: tabular-nums; }
  .tab[aria-pressed="true"] .tab-n { color: var(--accent); }
  .controls-tools { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; }
  .search-wrap { position: relative; display: flex; align-items: center; flex: 1 1 260px; min-width: 200px; max-width: 420px; }
  .search-icon {
    position: absolute; left: 10px; width: 14px; height: 14px;
    fill: none; stroke: var(--muted); stroke-width: 1.6; pointer-events: none;
  }
  .search {
    width: 100%; border: 1px solid var(--control); background: var(--surface); color: var(--ink);
    border-radius: 3px; padding: 8px 32px 8px 31px; font: inherit; font-size: 0.85rem;
  }
  .search:focus { border-color: var(--accent); outline: none; box-shadow: 0 0 0 1px var(--accent); }
  .search-kbd {
    position: absolute; right: 8px; border: 1px solid var(--rule); border-radius: 3px;
    padding: 0 5px; color: var(--muted); font-family: var(--mono); font-size: 0.66rem; line-height: 1.5;
  }
  .count { color: var(--muted); font-size: 0.78rem; white-space: nowrap; margin-left: auto; }
  .tool-btn {
    appearance: none; background: none; border: 0; color: var(--muted);
    font: inherit; font-size: 0.78rem; padding: 5px 2px; cursor: pointer;
    text-decoration: underline; text-underline-offset: 2px;
  }
  .tool-btn:hover { color: var(--ink); }
  #finding-list { border-top: 0; }
  .finding {
    border-bottom: 1px solid var(--rule); border-left: 3px solid var(--rule);
    padding-left: 16px;
  }
  .finding[data-severity="critical"] { border-left-color: var(--critical); }
  .finding[data-severity="high"] { border-left-color: var(--high); }
  .finding[data-severity="medium"] { border-left-color: var(--medium); }
  .finding[data-severity="low"] { border-left-color: var(--low); }
  .finding > summary {
    list-style: none; cursor: pointer;
    display: grid; grid-template-columns: minmax(0, 1fr) auto 18px;
    gap: 0 20px; align-items: start;
    margin-left: -16px; padding: 16px 8px 16px 16px;
  }
  .finding > summary::-webkit-details-marker { display: none; }
  .finding > summary::after {
    content: ""; width: 7px; height: 7px; margin-top: 7px; justify-self: end;
    border-right: 1.5px solid var(--muted); border-bottom: 1.5px solid var(--muted);
    transform: rotate(45deg);
  }
  .finding[open] > summary::after { transform: rotate(-135deg); }
  @media (prefers-reduced-motion: no-preference) {
    .finding > summary { transition: background 0.14s ease; }
    .finding > summary::after { transition: transform 0.16s ease; }
  }
  .finding > summary:hover { background: var(--hover); }
  .f-main { display: grid; gap: 3px; min-width: 0; }
  .f-title { font-weight: 650; font-size: 1rem; line-height: 1.35; }
  .f-title .word { margin-right: 4px; }
  .f-why { color: var(--muted); font-size: 0.89rem; max-width: 70ch; }
  .f-side { display: grid; gap: 6px; justify-items: end; text-align: right; font-size: 0.78rem; color: var(--muted); }
  .f-side code { color: var(--ink); white-space: nowrap; }
  .f-mark { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
  .mark { width: 6px; height: 6px; display: inline-block; flex: 0 0 6px; }
  .mark-direct { background: var(--ink); }
  .mark-review { border: 1px solid var(--muted); }
  .f-body { padding: 2px 0 22px; }
  .f-body p { max-width: 74ch; }
  .fix { margin: 8px 0 0; font-size: 0.95rem; }
  .fix strong { font-weight: 650; }
  .body-h {
    margin: 24px 0 8px; font-size: 0.72rem; font-weight: 650;
    letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted);
  }
  .locs { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--rule); }
  .locs li {
    display: grid; grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.6fr);
    gap: 4px 20px; padding: 9px 0; border-bottom: 1px solid var(--rule); align-items: baseline;
  }
  .locs code { word-break: break-all; color: var(--ink); }
  .snip { color: var(--muted); font-family: var(--mono); font-size: 0.78rem; word-break: break-word; }
  .tech { margin-top: 20px; }
  .tech > summary { cursor: pointer; color: var(--muted); font-size: 0.82rem; font-weight: 600; }
  .tech > summary:hover { color: var(--ink); }
  .tech dl {
    display: grid; grid-template-columns: 190px minmax(0, 1fr);
    gap: 8px 20px; margin: 12px 0 0; font-size: 0.84rem;
  }
  .tech dt { color: var(--muted); }
  .tech dd { margin: 0; }
  .tech em { color: var(--muted); }
  .checked-head { display: flex; flex-wrap: wrap; gap: 6px 24px; align-items: baseline; justify-content: space-between; margin-bottom: 16px; }
  .checked-head h2 { margin: 0 0 4px; }
  .checked-sum { color: var(--muted); font-size: 0.8rem; white-space: nowrap; }
  .check-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 36px; border-top: 1px solid var(--rule); }
  .check-row {
    display: grid; grid-template-columns: 12px minmax(0, 1fr) auto;
    gap: 0 10px; padding: 10px 0; border-bottom: 1px solid var(--rule); align-items: baseline;
  }
  .check-mark { width: 6px; height: 6px; display: inline-block; border: 1px solid var(--control); margin-top: 5px; }
  .check-row[data-flagged="true"] .check-mark { background: var(--ink); border-color: var(--ink); }
  .check-main { display: flex; flex-wrap: wrap; gap: 2px 10px; align-items: baseline; min-width: 0; }
  .check-name { font-size: 0.88rem; }
  .check-art { color: var(--muted); font-size: 0.73rem; white-space: nowrap; }
  .check-art::before { content: "·"; margin-right: 6px; color: var(--control); }
  .check-result { text-align: right; color: var(--muted); font-size: 0.76rem; white-space: nowrap; }
  .check-row[data-flagged="true"] .check-result { color: var(--ink); font-weight: 650; }
  .no-results { margin: 24px 0 0; color: var(--muted); font-size: 0.9rem; }
  .about { border-top: 1px solid var(--rule); padding-top: 20px; }
  .about summary { cursor: pointer; font-weight: 650; font-size: 0.98rem; }
  .about summary:hover { color: var(--accent); }
  .about ul { margin: 14px 0 0; padding-left: 20px; color: var(--muted); max-width: 74ch; font-size: 0.88rem; }
  .about li { margin: 8px 0; }
  .about strong { color: var(--ink); font-weight: 650; }
  .next-review { border-top: 1px solid var(--rule); padding-top: 20px; }
  .next-review h2 { margin-bottom: 6px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
  .btn {
    appearance: none; font: inherit; font-size: 0.85rem; padding: 9px 16px;
    border-radius: 3px; border: 1px solid var(--control); background: transparent;
    color: var(--ink); cursor: pointer;
  }
  .btn:hover { border-color: var(--ink); }
  .btn.primary { background: var(--ink); border-color: var(--ink); color: var(--page); }
  .btn.primary:hover { background: var(--accent); border-color: var(--accent); }
  footer {
    margin-top: 44px; padding: 18px 0 40px; border-top: 1px solid var(--rule);
    color: var(--muted); font-size: 0.78rem;
    display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: baseline; justify-content: space-between;
  }
  footer p { margin: 0; max-width: 72ch; }
  .top-link { white-space: nowrap; }
  @media (max-width: 760px) {
    .lede { grid-template-columns: 1fr; gap: 24px; padding-top: 34px; }
    .score { border-left: 0; border-top: 1px solid var(--rule); padding: 18px 0 0; }
  }
  @media (max-width: 700px) {
    .controls { position: static; }
    .controls-tools { width: 100%; }
    .search-wrap { max-width: none; flex-basis: 100%; }
    .finding > summary { grid-template-columns: minmax(0, 1fr) 18px; padding-right: 0; }
    .f-side {
      grid-column: 1; grid-row: 2; justify-items: start; text-align: left;
      display: flex; flex-wrap: wrap; gap: 4px 12px; margin-top: 8px;
    }
    .f-side code { white-space: normal; overflow-wrap: anywhere; }
    .finding > summary::after { grid-column: 2; grid-row: 1; }
  }
  @media (max-width: 640px) {
    .wrap { padding: 0 18px; }
    .meta-facts > span { border-left: 0; padding: 0 14px 0 0; }
    .lede { padding-top: 28px; }
    .lede h1 { font-size: clamp(1.85rem, 9vw, 2.3rem); }
    .sev-head, .checked-head { gap: 2px 16px; }
    .check-grid { grid-template-columns: 1fr; }
    .locs li { grid-template-columns: 1fr; }
    .tech dl { grid-template-columns: 1fr; gap: 2px; }
    .tech dd { margin-bottom: 10px; }
    .search { min-width: 0; }
    .search-kbd { display: none; }
    .tabs { gap: 0; }
    .tab { padding-left: 6px; padding-right: 6px; }
    .head-tools { margin-left: auto; }
  }
  @media print {
    @page { margin: 16mm 14mm; }
    :root {
      color-scheme: light;
      --page: #FFFFFF; --surface: #FFFFFF; --ink: #000000; --muted: #333333;
      --rule: #BBBBBB; --control: #777777; --accent: #000000;
      --critical: #000000; --high: #000000; --medium: #000000; --low: #000000;
      --good: #000000; --hover: transparent;
    }
    body { background: #FFFFFF; color: #000000; font-size: 10.5pt; }
    .wrap { max-width: none; padding: 0; }
    .masthead { border-bottom: 1px solid #000000; }
    .meta-facts > span { border-left: 0; padding: 0 12px 0 0; }
    .skip, .controls, .actions, .count, .head-tools, .f-side .f-mark, .top-link { display: none !important; }
    .finding > summary::after { display: none !important; }
    .finding > summary:hover { background: transparent; }
    .lede { padding-top: 0; grid-template-columns: 1fr auto; }
    .lede h1 { font-size: 20pt; max-width: none; }
    .score { border-left: 1px solid #000000; }
    .ring-track { stroke: #DDDDDD; }
    section { margin-top: 20pt; }
    .findings { break-before: page; }
    .finding { break-inside: avoid; page-break-inside: avoid; }
    .finding > summary { grid-template-columns: 1fr auto; }
    .f-side { grid-column: 2; grid-row: 1; }
    .f-body { display: block !important; padding-bottom: 10pt; }
    details > summary ~ * { display: block !important; }
    details::details-content { content-visibility: visible !important; }
    .check-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .check-row, .locs li { break-inside: avoid; page-break-inside: avoid; }
    .note { background: #FFFFFF; border-left: 2px solid #000000; }
    a { color: #000000; }
  }
</style>
</head>
<body id="top">
  <a class="skip" href="#findings">Skip to findings</a>
  <header class="masthead">
    <div class="wrap masthead-in">
      <div class="brand"><span class="brand-mark" aria-hidden="true"></span>AI Risk Snapshot <span class="ver">v${esc(meta.version || "")}</span></div>
      <div class="meta">
        <div class="meta-facts">${metaFacts}</div>
        <div class="local">Ran on your computer. Nothing was uploaded.</div>
      </div>
    </div>
  </header>

  <main class="wrap">
    <section class="lede">
      <div class="lede-copy">
        <p class="eyebrow">EU AI Act review checklist</p>
        ${renderHeadline(issues, counts.CRITICAL, counts.HIGH)}
        <p class="quiet">Code-level indicators for your team to review, not a legal determination.</p>
        ${astNote}
      </div>
      ${renderScore(score, counts, band)}
    </section>

    ${severitySection}

    ${findingsSection}

    <section class="checked" aria-labelledby="h-checked">
      <div class="checked-head">
        <div>
          <h2 id="h-checked">What was checked</h2>
          <p class="section-note">Each check relates to an EU AI Act review question. “Nothing flagged” means no pattern matched, not that it passed.</p>
        </div>
        <span class="checked-sum">${esc(flaggedCheckIds.size)} of ${esc(checkTotal)} checks flagged</span>
      </div>
      <div class="check-grid">${renderChecks(groups)}</div>
    </section>

    ${renderAbout(app)}

    <section class="next-review">
      <h2>Want a deeper review?</h2>
      <p class="section-note">A full audit tests how these controls behave live and covers what a code scan cannot see. Save report.json and get in touch when you are ready.</p>
      <div class="actions">
        <button class="btn primary" id="copyBtn">Copy report.json</button>
        <button class="btn" id="printBtn">Print or save as PDF</button>
      </div>
    </section>

    <footer>
      <p>Generated locally by ai-risk-snapshot v${esc(meta.version || "")}. You decide if and when to share this report. It can contain short code excerpts.</p>
      <a class="top-link" href="#top">Back to top ↑</a>
    </footer>
  </main>

  <script>
    const REPORT_DATA = ${safeJson};
    function copyReport() {
      const text = JSON.stringify(REPORT_DATA, null, 2);
      const done = () => {
        const b = document.getElementById("copyBtn");
        const old = b.textContent;
        b.textContent = "Copied";
        setTimeout(() => { b.textContent = old; }, 1500);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
      } else { fallbackCopy(text, done); }
    }
    function fallbackCopy(text, done) {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) {}
      document.body.removeChild(ta);
    }
    function expandAll(open) {
      document.querySelectorAll("[data-finding]").forEach((d) => { d.open = open; });
    }
    (function () {
      const findings = Array.from(document.querySelectorAll("[data-finding]"));
      const buttons = Array.from(document.querySelectorAll("[data-filter]"));
      const q = document.getElementById("q");
      const count = document.getElementById("count");
      const noResults = document.getElementById("no-results");
      let mode = "all";
      function matches(el) {
        const sev = el.dataset.severity, tier = el.dataset.tier;
        if (mode === "critical" && sev !== "critical") return false;
        if (mode === "high" && sev !== "high") return false;
        if (mode === "other" && !(sev === "medium" || sev === "low")) return false;
        if (mode === "review" && tier !== "review") return false;
        const term = (q && q.value || "").trim().toLowerCase();
        return !term || (el.dataset.text || "").indexOf(term) !== -1;
      }
      function apply() {
        let shown = 0;
        findings.forEach((el) => { const ok = matches(el); el.hidden = !ok; if (ok) shown += 1; });
        if (count) count.textContent = findings.length ? "Showing " + shown + " of " + findings.length : "";
        if (noResults) noResults.hidden = !(findings.length && shown === 0);
      }
      buttons.forEach((b) => b.addEventListener("click", () => {
        mode = b.dataset.filter;
        buttons.forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false"));
        apply();
      }));
      if (q) {
        q.addEventListener("input", apply);
        document.addEventListener("keydown", (e) => {
          const tag = (document.activeElement && document.activeElement.tagName) || "";
          if (e.key === "/" && document.activeElement !== q && !/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) {
            e.preventDefault();
            q.focus();
          }
          if (e.key === "Escape" && document.activeElement === q) {
            q.value = "";
            apply();
            q.blur();
          }
        });
      }
      document.querySelectorAll("[data-expand]").forEach((b) => {
        b.addEventListener("click", () => expandAll(b.dataset.expand === "true"));
      });
      const copyBtn = document.getElementById("copyBtn");
      if (copyBtn) copyBtn.addEventListener("click", copyReport);
      const printBtn = document.getElementById("printBtn");
      if (printBtn) printBtn.addEventListener("click", () => window.print());
      apply();
    })();
    window.addEventListener("beforeprint", () => {
      document.querySelectorAll("details").forEach((d) => {
        d.dataset.wasOpen = d.open ? "1" : "0";
        d.open = true;
      });
    });
    window.addEventListener("afterprint", () => {
      document.querySelectorAll("details").forEach((d) => {
        if (d.dataset.wasOpen === "0") d.open = false;
        delete d.dataset.wasOpen;
      });
    });
  </script>
</body>
</html>`;
}

module.exports = { buildDashboardHTML };
