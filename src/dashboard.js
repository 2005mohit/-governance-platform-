"use strict";

// Dashboard-style HTML report. Presentation only: it reads findings that the
// scanner already produced and never changes detection, scoring, JSON or SARIF.
//
// Design rules for this file:
//  - Plain language first; technical detail (article, method, snippets) sits
//    inside collapsed sections.
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

const AREAS = [
  { name: "Access & data", ids: ["IDENTITY_KEY", "IAM_WILDCARD", "HTTP_NO_AUTH", "CORS_WILDCARD", "SENSITIVE_DATA", "UNSAFE_DESERIALIZE", "ERROR_LEAKAGE"] },
  { name: "Human oversight", ids: ["NO_HUMAN_LOOP", "AUTO_DECISION", "SAFETY_BYPASS"] },
  { name: "Records & logging", ids: ["NO_LOGGING"] },
  { name: "Transparency", ids: ["NO_AI_DISCLOSURE"] }
];

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

function plainFor(group) {
  const p = PLAIN[group.id];
  if (p) return p;
  return { title: group.title || group.id, why: firstSentence(group.consequence) };
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
  return `${esc(file)}${line !== undefined && line !== null && line !== "N/A" ? ":" + esc(line) : ""}`;
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

function renderTop3(groups) {
  const top = groups.slice(0, 3);
  if (!top.length) return "";
  const rows = top.map((g, i) => {
    const p = plainFor(g);
    const loc = g.files[0] || {};
    const more = g.files.length > 1 ? ` and ${g.files.length - 1} more` : "";
    const fix = clip(firstSentence(g.fix), 150);
    return `
      <li class="todo">
        <span class="todo-n">${i + 1}</span>
        <div class="todo-body">
          <div class="todo-title">${esc(p.title)} <span class="chip sev-${esc(g.severity.toLowerCase())}">${esc(SEV_LABEL[g.severity] || g.severity)}</span></div>
          <div class="todo-where"><code>${where(loc.file, loc.line)}</code>${more}</div>
          ${fix ? `<div class="todo-fix"><strong>Next step:</strong> ${esc(fix)}</div>` : ""}
        </div>
      </li>`;
  }).join("");
  return `
    <section class="panel" aria-labelledby="h-first">
      <h2 id="h-first">Start here</h2>
      <p class="sub">The ${top.length === 1 ? "most important item" : `${top.length} most important items`} to look at first.</p>
      <ol class="todos">${rows}</ol>
    </section>`;
}

function renderSeverityBar(groups) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const g of groups) if (counts[g.severity] !== undefined) counts[g.severity] += 1;
  const total = groups.length;
  if (!total) {
    return `<div class="bar empty" role="img" aria-label="No findings"></div>`;
  }
  const segs = Object.keys(counts)
    .filter((k) => counts[k] > 0)
    .map((k) => `<span class="seg sev-${k.toLowerCase()}" style="width:${((counts[k] / total) * 100).toFixed(2)}%"></span>`)
    .join("");
  const legend = Object.keys(counts)
    .map((k) => `<span class="legend-item"><span class="dot sev-${k.toLowerCase()}"></span>${esc(SEV_LABEL[k])} <strong>${counts[k]}</strong></span>`)
    .join("");
  return `<div class="bar" role="img" aria-label="${esc(
    Object.keys(counts).map((k) => `${counts[k]} ${SEV_LABEL[k]}`).join(", ")
  )}">${segs}</div><div class="legend">${legend}</div>`;
}

function renderChecks(groups) {
  const flagged = new Map();
  for (const g of groups) flagged.set(g.id, (flagged.get(g.id) || 0) + 1);
  const known = new Set(CHECKS.map((c) => c.id));
  const extra = [...flagged.keys()].filter((id) => !known.has(id)).map((id) => ({ id, name: id, art: "" }));
  return CHECKS.concat(extra).map((c) => {
    const n = flagged.get(c.id) || 0;
    return `
      <div class="check ${n ? "hit" : "clear"}">
        <span class="check-dot" aria-hidden="true"></span>
        <span class="check-main">
          <span class="check-name">${esc(c.name)}</span>
          <span class="check-meta">${esc(c.art)}${c.art ? " · " : ""}${n ? `${n} flagged` : "nothing flagged"}</span>
        </span>
      </div>`;
  }).join("");
}

function renderCards(groups) {
  if (!groups.length) {
    return `<div class="empty">Nothing was flagged. That only means the checks in this scan found no matching pattern. It is not a clean bill of health.</div>`;
  }
  return groups.map((g) => {
    const p = plainFor(g);
    const tier = tierFor(g);
    const loc = g.files[0] || {};
    const shown = g.files.slice(0, 10);
    const hidden = g.files.length - shown.length;
    const fix = firstSentence(g.fix);
    const exposure = exposureText(g);
    const sure = tier === "direct"
      ? `<span class="sure direct">Pattern match</span>`
      : `<span class="sure review">Needs a human check</span>`;
    const searchText = [p.title, g.id, g.article, ...g.files.map((f) => f.file)].join(" ").toLowerCase();
    return `
      <details class="card sev-${esc(g.severity.toLowerCase())}" data-sev="${esc(g.severity.toLowerCase())}" data-tier="${tier}" data-text="${esc(searchText)}">
        <summary>
          <span class="chip sev-${esc(g.severity.toLowerCase())}">${esc(SEV_LABEL[g.severity] || g.severity)}</span>
          <span class="card-main">
            <span class="card-title">${esc(p.title)}</span>
            <span class="card-why">${esc(p.why)}</span>
          </span>
          <span class="card-side">
            ${sure}
            <span class="card-loc"><code>${where(loc.file, loc.line)}</code>${g.files.length > 1 ? ` +${g.files.length - 1}` : ""}</span>
          </span>
        </summary>
        <div class="card-body">
          ${fix ? `<p class="fix"><strong>What to do:</strong> ${esc(fix)}</p>` : ""}
          ${tier === "review" ? `<p class="hint">This one uses a heuristic and can be wrong. Please confirm in the code before acting. The control may exist somewhere this scan cannot see, such as a gateway, a queue or another service.</p>` : ""}
          <h4>Where it was found</h4>
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

function buildDashboardHTML(findings, score, meta, reportData, helpers) {
  const band = helpers.band;
  const groups = groupFindings(findings);
  const places = findings.length;
  const issues = groups.length;
  const needAttention = groups.filter((g) => g.severity === "CRITICAL" || g.severity === "HIGH").length;
  const reviewCount = groups.filter((g) => tierFor(g) === "review").length;
  const folder = baseName((reportData && reportData.scannedDirectory) || meta.scannedDirectory || "project");
  const when = (reportData && reportData.generatedAt) ? new Date(reportData.generatedAt) : new Date();
  const whenText = isNaN(when.getTime()) ? "" : when.toISOString().slice(0, 16).replace("T", " ") + " UTC";
  const statusPlain = STATUS_PLAIN[band.label] || "";
  const app = (reportData && reportData.applicability) || {};
  const safeJson = JSON.stringify(reportData || { findings, score }).replace(/</g, "\\u003c");
  const astNote = meta.astAvailable === false
    ? `<div class="note warn">Python was not found on this computer, so some checks used a simpler method. Results may be less precise.</div>`
    : "";

  const summaryLine = issues
    ? `${issues} ${issues === 1 ? "issue" : "issues"} flagged${needAttention ? `, ${needAttention} critical or high` : ""}.`
    : "That only means no pattern matched, not that the system is safe.";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Risk Snapshot: ${esc(band.label)} (${esc(folder)})</title>
<style>
  :root {
    --bg: #f4f6f9; --panel: #ffffff; --text: #18202d; --muted: #5d6877; --line: #e4e8ee;
    --crit: #d92d20; --high: #e8590c; --med: #b7791f; --low: #64748b; --ok: #1a8f4c;
    --accent: ${esc(band.color)}; --shadow: 0 1px 2px rgba(16,24,40,.06), 0 4px 14px rgba(16,24,40,.05);
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0f141b; --panel: #171e28; --text: #e8edf4; --muted: #9aa6b6; --line: #263041; --shadow: none; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .86em; word-break: break-all; }
  .top { background: var(--panel); border-bottom: 1px solid var(--line); }
  .top-in { max-width: 1040px; margin: 0 auto; padding: 14px 20px; display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: center; justify-content: space-between; }
  .brand { font-weight: 700; letter-spacing: .01em; }
  .brand small { font-weight: 500; color: var(--muted); margin-left: 8px; }
  .top-meta { color: var(--muted); font-size: .85rem; display: flex; flex-wrap: wrap; gap: 4px 14px; align-items: center; }
  .local { border: 1px solid var(--line); border-radius: 999px; padding: 2px 10px; font-size: .78rem; }
  main { max-width: 1040px; margin: 0 auto; padding: 18px 20px 48px; }
  .banner { background: color-mix(in srgb, var(--med) 12%, var(--panel)); border: 1px solid color-mix(in srgb, var(--med) 35%, var(--line)); border-radius: 12px; padding: 10px 14px; font-size: .88rem; }
  .note.warn { margin-top: 10px; background: color-mix(in srgb, var(--high) 10%, var(--panel)); border: 1px solid color-mix(in srgb, var(--high) 35%, var(--line)); border-radius: 10px; padding: 8px 12px; font-size: .86rem; }
  .tiles { display: grid; gap: 14px; margin-top: 16px; grid-template-columns: 1.5fr 1fr 1fr 1fr; }
  @media (max-width: 860px) { .tiles { grid-template-columns: 1fr 1fr; } }
  @media (max-width: 520px) { .tiles { grid-template-columns: 1fr; } }
  .tile { background: var(--panel); border-radius: 14px; padding: 16px 18px; box-shadow: var(--shadow); border: 1px solid var(--line); }
  .tile .label { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }
  .tile .big { font-size: 2rem; font-weight: 800; line-height: 1.1; margin-top: 4px; }
  .tile .small { color: var(--muted); font-size: .85rem; margin-top: 4px; }
  .tile.status { border-top: 5px solid var(--accent); }
  .tile.status .big { color: var(--accent); font-size: 1.55rem; }
  .tile.status .score { color: var(--muted); font-size: .82rem; margin-top: 8px; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px 20px; box-shadow: var(--shadow); margin-top: 16px; }
  h2 { margin: 0; font-size: 1.1rem; }
  h4 { margin: 14px 0 6px; font-size: .86rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  .sub { color: var(--muted); margin: 2px 0 12px; font-size: .9rem; }
  .two { align-items: start; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 760px) { .two { grid-template-columns: 1fr; } }
  .bar { display: flex; height: 14px; border-radius: 999px; overflow: hidden; background: var(--line); margin-top: 12px; }
  .bar .seg { display: block; height: 100%; }
  .bar.empty { background: color-mix(in srgb, var(--ok) 35%, var(--line)); }
  .legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 10px; font-size: .86rem; color: var(--muted); }
  .legend strong { color: var(--text); }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  .seg.sev-critical, .dot.sev-critical { background: var(--crit); }
  .seg.sev-high, .dot.sev-high { background: var(--high); }
  .seg.sev-medium, .dot.sev-medium { background: var(--med); }
  .seg.sev-low, .dot.sev-low { background: var(--low); }
  .checks { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
  @media (max-width: 520px) { .checks { grid-template-columns: 1fr; } }
  .check { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--line); border-radius: 10px; padding: 8px 10px; }
  .check-dot { flex: 0 0 10px; width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; border: 2px solid var(--muted); }
  .check.hit { border-color: color-mix(in srgb, var(--high) 45%, var(--line)); }
  .check.hit .check-dot { background: var(--high); border-color: var(--high); }
  .check-main { display: grid; line-height: 1.3; }
  .check-name { font-size: .88rem; font-weight: 600; }
  .check-meta { font-size: .76rem; color: var(--muted); }
  .todos { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
  .todo { display: flex; gap: 12px; border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; }
  .todo-n { flex: 0 0 28px; height: 28px; border-radius: 50%; background: var(--accent); color: #fff; font-weight: 700; display: grid; place-items: center; }
  .todo-title { font-weight: 650; }
  .todo-where { color: var(--muted); font-size: .86rem; margin-top: 2px; }
  .todo-fix { margin-top: 6px; font-size: .9rem; }
  .chip { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: .72rem; font-weight: 700; color: #fff; vertical-align: middle; }
  .chip.sev-critical { background: var(--crit); }
  .chip.sev-high { background: var(--high); }
  .chip.sev-medium { background: var(--med); }
  .chip.sev-low { background: var(--low); }
  .tools { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 4px 0 12px; }
  .filter { border: 1px solid var(--line); background: var(--panel); color: var(--text); border-radius: 999px; padding: 5px 13px; font-size: .84rem; cursor: pointer; }
  .filter[aria-pressed="true"] { background: var(--text); color: var(--panel); border-color: var(--text); }
  .filter:focus-visible, .btn:focus-visible, summary:focus-visible, input:focus-visible { outline: 3px solid color-mix(in srgb, var(--accent) 55%, transparent); outline-offset: 2px; }
  .search { flex: 1 1 180px; min-width: 150px; border: 1px solid var(--line); background: var(--panel); color: var(--text); border-radius: 999px; padding: 6px 14px; font-size: .86rem; }
  .count { color: var(--muted); font-size: .84rem; margin-left: auto; }
  .card { border: 1px solid var(--line); border-left-width: 5px; border-radius: 12px; background: var(--panel); margin-bottom: 10px; }
  .card.sev-critical { border-left-color: var(--crit); }
  .card.sev-high { border-left-color: var(--high); }
  .card.sev-medium { border-left-color: var(--med); }
  .card.sev-low { border-left-color: var(--low); }
  .card > summary { list-style: none; cursor: pointer; display: flex; gap: 12px; align-items: flex-start; padding: 12px 14px; }
  .card > summary::-webkit-details-marker { display: none; }
  .card > summary::after { content: "+"; margin-left: 4px; color: var(--muted); font-size: 1.2rem; line-height: 1; }
  .card[open] > summary::after { content: "–"; }
  .card-main { flex: 1 1 auto; min-width: 0; display: grid; gap: 2px; }
  .card-title { font-weight: 650; }
  .card-why { color: var(--muted); font-size: .88rem; }
  .card-side { display: grid; gap: 4px; justify-items: end; text-align: right; font-size: .8rem; color: var(--muted); max-width: 34%; }
  @media (max-width: 700px) { .card > summary { flex-wrap: wrap; } .card-side { justify-items: start; text-align: left; max-width: 100%; } }
  .sure { padding: 1px 9px; border-radius: 999px; font-size: .72rem; font-weight: 600; border: 1px solid var(--line); white-space: nowrap; }
  .sure.direct { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, var(--line)); }
  .sure.review { color: var(--med); border-color: color-mix(in srgb, var(--med) 45%, var(--line)); }
  .card-body { padding: 0 16px 14px 16px; border-top: 1px solid var(--line); }
  .fix { margin: 12px 0 6px; }
  .hint { margin: 6px 0; padding: 8px 10px; border-radius: 8px; font-size: .86rem; background: color-mix(in srgb, var(--med) 10%, var(--panel)); }
  .locs { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
  .locs li { display: flex; flex-wrap: wrap; gap: 4px 12px; border: 1px solid var(--line); border-radius: 8px; padding: 6px 10px; }
  .snip { color: var(--muted); font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .8rem; word-break: break-all; }
  .more { color: var(--muted); font-size: .84rem; margin: 6px 0 0; }
  .tech { margin-top: 12px; }
  .tech > summary { cursor: pointer; color: var(--muted); font-size: .86rem; }
  .tech dl { margin: 8px 0 0; display: grid; grid-template-columns: 200px 1fr; gap: 6px 14px; font-size: .86rem; }
  .tech dt { color: var(--muted); }
  .tech dd { margin: 0; }
  @media (max-width: 600px) { .tech dl { grid-template-columns: 1fr; } }
  .empty { background: var(--panel); border: 1px dashed var(--line); border-radius: 12px; padding: 22px; text-align: center; color: var(--muted); }
  .about summary { cursor: pointer; font-weight: 650; }
  .about ul { margin: 10px 0 0; padding-left: 20px; color: var(--muted); font-size: .9rem; }
  .about li { margin: 5px 0; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .btn { border: 1px solid var(--line); background: var(--panel); color: var(--text); border-radius: 10px; padding: 7px 14px; font-size: .86rem; cursor: pointer; }
  .btn.primary { background: var(--text); color: var(--panel); border-color: var(--text); }
  footer { margin-top: 22px; color: var(--muted); font-size: .8rem; }
  @media print {
    body { background: #fff; color: #000; }
    .tools, .actions, .search { display: none !important; }
    .card { break-inside: avoid; }
    .card:not([open]) > .card-body { display: block; }
  }
</style>
</head>
<body>
  <header class="top">
    <div class="top-in">
      <div class="brand">AI Risk Snapshot<small>v${esc(meta.version || "")}</small></div>
      <div class="top-meta">
        <span>Scanned: <strong>${esc(folder)}</strong></span>
        <span>${esc(meta.filesScanned)} ${meta.filesScanned === 1 ? "file" : "files"}</span>
        ${whenText ? `<span>${esc(whenText)}</span>` : ""}
        <span class="local">Ran on your computer. Nothing was uploaded.</span>
      </div>
    </div>
  </header>

  <main>
    <div class="banner"><strong>EU AI Act review checklist for your AI project.</strong> Code-level indicators for your team to review, not a legal determination. More under “About this scan”.</div>
    ${astNote}

    <div class="tiles">
      <div class="tile status">
        <div class="label">Overall status</div>
        <div class="big">${esc(band.label)}</div>
        <div class="small">${esc(statusPlain)}. ${esc(summaryLine)}</div>
        <div class="score">Readiness score ${esc(score)} / 100</div>
      </div>
      <div class="tile"><div class="label">Issues found</div><div class="big">${issues}</div><div class="small">in ${places} ${places === 1 ? "place" : "places"} in the code</div></div>
      <div class="tile"><div class="label">Critical or high</div><div class="big" style="color:${needAttention ? "var(--crit)" : "var(--ok)"}">${needAttention}</div><div class="small">${needAttention ? "look at these first" : "none found"}</div></div>
      <div class="tile"><div class="label">Need a human check</div><div class="big">${reviewCount}</div><div class="small">issues that use a heuristic</div></div>
    </div>

    ${renderTop3(groups)}

    <div class="two">
      <section class="panel" aria-labelledby="h-sev">
        <h2 id="h-sev">By severity</h2>
        ${renderSeverityBar(groups)}
      </section>
      <section class="panel" aria-labelledby="h-area">
        <h2 id="h-area">What was checked</h2>
        <p class="sub">Each check relates to an EU AI Act review question. “Nothing flagged” means no pattern matched, not that the check passed.</p>
        <div class="checks">${renderChecks(groups)}</div>
      </section>
    </div>

    <section class="panel" aria-labelledby="h-all">
      <h2 id="h-all">All findings</h2>
      <p class="sub">Click an item to see where it was found and what to do.</p>
      <div class="tools" id="tools">
        <button class="filter" data-filter="all" aria-pressed="true">All</button>
        <button class="filter" data-filter="critical" aria-pressed="false">Critical</button>
        <button class="filter" data-filter="high" aria-pressed="false">High</button>
        <button class="filter" data-filter="other" aria-pressed="false">Medium and low</button>
        <button class="filter" data-filter="review" aria-pressed="false">Need a human check</button>
        <input class="search" id="q" type="search" placeholder="Search by file or topic" aria-label="Search findings">
        <span class="count" id="count" aria-live="polite"></span>
      </div>
      <div id="cards">${renderCards(groups)}</div>
    </section>

    <section class="panel about">
      <details>
        <summary>About this scan and what it cannot tell you</summary>
        <ul>
          <li>${esc(app.articleReferencesNote || "Article references are review prompts, not compliance findings.")}</li>
          <li>${esc(app.highRiskOnlyNote || "Some EU AI Act duties apply only to systems classified as high-risk. This scan does not perform that classification.")}</li>
          <li>${esc(app.roleNote || "Provider and deployer duties differ. This scan does not determine which role applies.")}</li>
          <li><strong>Pattern match</strong> means the rule looks for a specific pattern in the text. It can still be a harmless test value, so check the context. <strong>Needs a human check</strong> means the rule uses a heuristic, such as nearby words or file names, and can be wrong in either direction.</li>
          <li>It reads files only. It does not run your code, test live behaviour, or review policies, training data or people and process.</li>
          <li>Not legal advice and not a certified audit.</li>
        </ul>
      </details>
    </section>

    <section class="panel">
      <h2>Want a deeper review?</h2>
      <p class="sub">A full audit tests how these controls behave live and covers what a code scan cannot see. Save report.json and get in touch when you are ready.</p>
      <div class="actions">
        <button class="btn primary" id="copyBtn" onclick="copyReport()">Copy report.json</button>
        <button class="btn" onclick="expandAll(true)">Expand all</button>
        <button class="btn" onclick="expandAll(false)">Collapse all</button>
        <button class="btn" onclick="window.print()">Print or save as PDF</button>
      </div>
    </section>

    <footer>Generated locally by ai-risk-snapshot v${esc(meta.version || "")}. You decide if and when to share this report. It can contain short code excerpts.</footer>
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
      document.querySelectorAll("#cards details.card").forEach((d) => { d.open = open; });
    }
    (function () {
      const cards = Array.from(document.querySelectorAll("#cards details.card"));
      const buttons = Array.from(document.querySelectorAll(".filter"));
      const q = document.getElementById("q");
      const count = document.getElementById("count");
      let mode = "all";
      function matches(c) {
        const sev = c.dataset.sev, tier = c.dataset.tier;
        if (mode === "critical" && sev !== "critical") return false;
        if (mode === "high" && sev !== "high") return false;
        if (mode === "other" && !(sev === "medium" || sev === "low")) return false;
        if (mode === "review" && tier !== "review") return false;
        const term = (q.value || "").trim().toLowerCase();
        return !term || c.dataset.text.indexOf(term) !== -1;
      }
      function apply() {
        let shown = 0;
        cards.forEach((c) => { const ok = matches(c); c.style.display = ok ? "" : "none"; if (ok) shown += 1; });
        count.textContent = cards.length ? "Showing " + shown + " of " + cards.length : "";
      }
      buttons.forEach((b) => b.addEventListener("click", () => {
        mode = b.dataset.filter;
        buttons.forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false"));
        apply();
      }));
      q.addEventListener("input", apply);
      apply();
    })();
  </script>
</body>
</html>`;
}

module.exports = { buildDashboardHTML };
