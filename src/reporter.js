// src/reporter.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { buildDashboardHTML } = require("./dashboard");
const pkg = require("../package.json");

const SEVERITY_PENALTY = { CRITICAL: 25, HIGH: 15, MEDIUM: 5, LOW: 2 };

// A fixed, non-negotiable statement of what this scan can and cannot say.
// It is emitted in report.json and at the top of report.html so the
// applicability boundary travels with the artefact, not only with the paper.
const HIGH_RISK_ARTICLES = ["Article 9", "Article 12", "Article 14", "Article 15"];
const APPLICABILITY = {
  isComplianceDetermination: false,
  highRiskStatusAssessed: false,
  roleDetermined: false,
  roleNote: "Provider and deployer duties differ. This scan does not determine which role the scanned repository has.",
  highRiskArticles: HIGH_RISK_ARTICLES,
  highRiskOnlyNote:
    "Articles 9, 12, 14 and 15 apply only to AI systems classified as high-risk under Article 6 and Annex I or Annex III. This scan does not perform that classification.",
  highRiskObligationsApplyFrom: {
    annexIII: "2027-12-02",
    annexI: "2028-08-02",
    source:
      "Article 113, third paragraph, point (c), Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744"
  },
  articleReferencesNote:
    "Article references are review prompts, not compliance findings. A finding means a pattern was present; it does not establish a breach.",
  detectionMethodNote:
    "Per-finding method is reported. 'ast-same-function' means a structural check of the enclosing function was available; it does not cover the callee or other files."
};

// SARIF 2.1.0 uses error/warning/note. The mapping is intentionally the same
// as the human report: critical and high are errors, medium is a warning, low
// is a note.
const SARIF_LEVEL = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note"
};
const SARIF_SCHEMA_URL =
  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

function sarifLevel(severity) {
  return SARIF_LEVEL[severity] || "warning";
}

// Only use a repository URL that is actually present in package.json. Never
// synthesise a GitHub URL from a package name. Shorthand forms and non-URL
// values are ignored, so informationUri stays absent rather than misleading.
function packageRepositoryUrl() {
  const repository = pkg.repository;
  let url = typeof repository === "string" ? repository : repository && repository.url;
  if (typeof url !== "string") return null;
  url = url.trim();
  if (url.startsWith("git+")) url = url.slice(4);
  return /^https?:\/\//i.test(url) ? url : null;
}

// SARIF artifact URIs must be relative, use forward slashes, and be valid URI
// references. Encode each path segment so spaces and reserved characters do
// not make the document invalid.
function relativeArtifactUri(file, root) {
  let rel = String(file || "").replace(/\\/g, "/");
  if (path.isAbsolute(file)) {
    rel = root ? path.relative(root, file).replace(/\\/g, "/") : path.basename(file);
  }
  const encoded = rel
    .split("/")
    .filter((segment) => segment !== "")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return encoded || "unknown";
}

function startLine(line) {
  const n = Number(line);
  return Number.isInteger(n) && n > 0 ? n : 1;
}

function normalizedSnippet(snippet) {
  return String(snippet || "").trim().replace(/\s+/g, " ");
}

// Fingerprints deliberately exclude the line number so ordinary edits above a
// finding do not create a new identity. The duplicate counter keeps two
// identical snippets in the same file distinct while remaining deterministic.
function findingFingerprint(ruleId, uri, snippet, duplicateIndex) {
  return crypto
    .createHash("sha256")
    .update(`${ruleId}\u0000${uri}\u0000${snippet}\u0000${duplicateIndex}`)
    .digest("hex");
}

// SARIF report-rule names are stable identifiers, not prose. Derive one from
// the rule id so a rule keeps the same name across releases even if its human
// title is reworded: IDENTITY_KEY -> IdentityKey.
function sarifRuleName(id) {
  const name = String(id || "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
  return name || String(id || "Rule");
}

function buildSarifRule(rule) {
  const properties = {
    article: rule.article,
    severity: rule.severity
  };
  if (Object.prototype.hasOwnProperty.call(rule, "providerOrDeployer")) {
    properties.providerOrDeployer = rule.providerOrDeployer;
  }
  if (Object.prototype.hasOwnProperty.call(rule, "highRiskOnly")) {
    properties.highRiskOnly = rule.highRiskOnly;
  }
  const title = rule.title || rule.id;
  return {
    id: rule.id,
    name: sarifRuleName(rule.id),
    shortDescription: { text: title },
    defaultConfiguration: { level: sarifLevel(rule.severity) },
    properties
  };
}

function buildSARIF(findings, meta = {}) {
  // Prefer the full rule pack so ruleIndex is stable even when a rule has no
  // finding. Fall back to the unique rules represented by the findings so the
  // reporter remains usable without the scanner's rule list.
  const ruleDefs = [];
  const seen = new Set();
  for (const rule of Array.isArray(meta.rules) ? meta.rules : []) {
    if (!seen.has(rule.id)) {
      ruleDefs.push(rule);
      seen.add(rule.id);
    }
  }
  for (const finding of findings) {
    if (!seen.has(finding.id)) {
      ruleDefs.push({
        id: finding.id,
        title: finding.title,
        article: finding.article,
        severity: finding.severity
      });
      seen.add(finding.id);
    }
  }

  const rules = ruleDefs.map(buildSarifRule);
  const ruleIndexById = new Map(ruleDefs.map((rule, index) => [rule.id, index]));

  // Assign duplicate-fingerprint counters in a canonical order (file, line,
  // rule id, then snippet as a final tie-break) so the same findings produce
  // the same fingerprints regardless of the order they were discovered in.
  const ordered = findings.map((finding, index) => ({ finding, index }));
  ordered.sort((a, b) => {
    const fa = String(a.finding.file || "");
    const fb = String(b.finding.file || "");
    if (fa !== fb) return fa < fb ? -1 : 1;
    const la = startLine(a.finding.line);
    const lb = startLine(b.finding.line);
    if (la !== lb) return la - lb;
    const ia = String(a.finding.id || "");
    const ib = String(b.finding.id || "");
    if (ia !== ib) return ia < ib ? -1 : 1;
    const sa = normalizedSnippet(a.finding.snippet);
    const sb = normalizedSnippet(b.finding.snippet);
    if (sa !== sb) return sa < sb ? -1 : 1;
    return a.index - b.index;
  });

  const duplicateCounts = new Map();
  const fingerprintsByIndex = new Map();
  for (const { finding, index } of ordered) {
    const uri = relativeArtifactUri(finding.file, meta.scannedDirectory);
    const snippet = normalizedSnippet(finding.snippet);
    const duplicateKey = `${finding.id}\u0000${uri}\u0000${snippet}`;
    const duplicateIndex = duplicateCounts.get(duplicateKey) || 0;
    duplicateCounts.set(duplicateKey, duplicateIndex + 1);
    fingerprintsByIndex.set(
      index,
      findingFingerprint(finding.id, uri, snippet, duplicateIndex)
    );
  }

  const results = findings.map((finding, index) => {
    const uri = relativeArtifactUri(finding.file, meta.scannedDirectory);
    const snippet = normalizedSnippet(finding.snippet);

    const text = snippet
      ? `${finding.title || finding.id}: ${snippet}`
      : String(finding.title || finding.id);

    // method is present only when the scanner actually recorded one. A null
    // value would claim the field was measured, which is not true. confidence
    // is the same label as report.json; confidenceWeight is the number behind
    // it, so consumers never have to guess which type a key holds.
    const weight = findingConfidenceWeight(finding);
    const properties = { confidence: confidenceLabel(weight), confidenceWeight: weight };
    if (finding.method) properties.method = finding.method;

    return {
      ruleId: finding.id,
      ruleIndex: ruleIndexById.get(finding.id),
      level: sarifLevel(finding.severity),
      message: { text },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: startLine(finding.line) }
          }
        }
      ],
      properties,
      partialFingerprints: {
        "aiRiskSnapshot/v1": fingerprintsByIndex.get(index)
      }
    };
  });

  const driver = {
    name: "ai-risk-snapshot",
    version: pkg.version,
    rules
  };
  const informationUri = packageRepositoryUrl();
  if (informationUri) driver.informationUri = informationUri;

  return {
    $schema: SARIF_SCHEMA_URL,
    version: "2.1.0",
    runs: [
      {
        tool: { driver },
        properties: {
          applicability: APPLICABILITY,
          indicatorsNotComplianceDetermination: APPLICABILITY.articleReferencesNote
        },
        results
      }
    ]
  };
}

// Confidence weighting: a finding's severity penalty is scaled by how it was
// produced. ast-same-function always counts fully; pattern-only findings on
// known-noisy rules count half; everything else counts fully. Bands still
// key off worst severity (see getBand), so weighting moves the score only.
const CONFIDENCE_WEIGHT = {
  methodFullWeight: ["ast-same-function"],
  reducedWeightRules: { NO_AI_DISCLOSURE: 0.5, AUTO_DECISION: 0.5 },
};

function confidenceWeight(finding) {
  if (CONFIDENCE_WEIGHT.methodFullWeight.includes(finding.method)) return 1.0;
  if (Object.prototype.hasOwnProperty.call(CONFIDENCE_WEIGHT.reducedWeightRules, finding.id)) {
    return CONFIDENCE_WEIGHT.reducedWeightRules[finding.id];
  }
  return 1.0;
}

// The numeric weight is what moves the score. The label is the same judgement
// in words so report consumers do not have to know the weighting table.
function confidenceLabel(weight) {
  return weight >= 1 ? "high" : "medium";
}

function annotateFindings(findings) {
  return findings.map((finding) => {
    const weight = confidenceWeight(finding);
    return {
      ...finding,
      confidence: confidenceLabel(weight),
      confidenceWeight: weight
    };
  });
}

// Prefer the annotated value so JSON and SARIF cannot drift apart.
function findingConfidenceWeight(finding) {
  return typeof finding.confidenceWeight === "number"
    ? finding.confidenceWeight
    : confidenceWeight(finding);
}

function calculateScore(findings) {
  let score = 100;
  findings.forEach((f) => {
    score -= (SEVERITY_PENALTY[f.severity] || 0) * confidenceWeight(f);
  });
  return Math.max(0, Math.round(score * 10) / 10);
}

function getBand(score, findings = []) {
  // Band labels deliberately avoid the EU AI Act's legal term "high-risk
  // system": they describe the size of the readiness gap found by this scan,
  // not the regulatory classification of the scanned system.
  // A score can look calm while a single serious issue is present (85 with one
  // HIGH finding used to read "Good readiness"). Cap the label at the worst
  // finding severity so the band never understates the findings list.
  if (findings.some((f) => f.severity === "CRITICAL")) return { label: "Severe gap", color: "#ef4444", to: "#b91c1c" };
  if (findings.some((f) => f.severity === "HIGH")) return { label: "Elevated gap", color: "#f97316", to: "#c2410c" };
  if (score >= 80) return { label: "Good readiness", color: "#22c55e", to: "#15803d" };
  if (score >= 50) return { label: "Moderate gap", color: "#eab308", to: "#b45309" };
  if (score >= 25) return { label: "Elevated gap", color: "#f97316", to: "#c2410c" };
  return { label: "Severe gap", color: "#ef4444", to: "#b91c1c" };
}

function buildJSON(findings, score, meta) {
  return {
    tool: "ai-risk-snapshot",
    version: meta.version,
    generatedAt: new Date().toISOString(),
    scannedDirectory: meta.scannedDirectory,
    filesScanned: meta.filesScanned,
    filesSkipped: meta.filesSkipped || 0,
    score,
    riskRating: getBand(score, findings).label,
    riskRatingWhy: ratingExplanation(findings).why,
    astAvailable: meta.astAvailable === undefined ? null : !!meta.astAvailable,
    applicability: APPLICABILITY,
    findings,
    disclaimer:
      "This is a preliminary, automated, local scan. It is not a certified " +
      "compliance audit and does not constitute legal advice. It does not " +
      "determine whether the scanned system is high-risk under the EU AI Act."
  };
}

// Finding cards carry exactly four content blocks: (1) lede sentence (what was
// found + article violation), (2) where (evidence list), (3) fix, plus the
// title/tags chrome. whatItChecks / falsePositiveNote stay in the YAML and in
// report.json for reference but are NOT rendered here; a worth-keeping FP
// caveat folds into the fix line as a parenthetical (FIX_PARENS below).
const LEDE_SPECIFIC = {
  IDENTITY_KEY: (where) => `Secret-shaped credential found at ${where} (value withheld)`,
  IAM_WILDCARD: (where, snippet) => `Wildcard IAM grant ${snippet} found at ${where}`,
  NO_HUMAN_LOOP: (where, snippet) => `Unguarded destructive call ${snippet} at ${where}`,
  NO_LOGGING: (where, snippet) => `Destructive call ${snippet} at ${where} with no logging call nearby`,
  HTTP_NO_AUTH: (where, _snippet, more) => `Route file without endpoint authentication (first seen at ${where}${more})`,
  AUTO_DECISION: (where, snippet) => `Automatic outcome ${snippet} assigned at ${where}`,
  SENSITIVE_DATA: (where) => `Committed sensitive-looking file at ${where}`,
  NO_AI_DISCLOSURE: (where) => `System prompt without AI disclosure at ${where}`,
  CORS_WILDCARD: (where, snippet) => `Permissive CORS setting ${snippet} at ${where}`,
  UNSAFE_DESERIALIZE: (where, snippet) => `Unsafe deserialization call ${snippet} at ${where}`,
  ERROR_LEAKAGE: (where, snippet) => `Exception detail exposed in a client-facing response at ${where} (${snippet})`,
  SAFETY_BYPASS: (where, snippet) => `Disabled safety/validation flag ${snippet} near a high-risk action at ${where}`,
};

const FIX_PARENS = {
  IDENTITY_KEY: "(skip only if this is clearly placeholder or sample text)",
  IAM_WILDCARD: null, // low false-positive risk per the rule itself
  NO_HUMAN_LOOP: "(if the guard lives in a called helper, or outside code such as Slack, middleware, or a queue, verify there instead)",
  NO_LOGGING: "(framework- or gateway-level logging also counts — verify before adding duplicates)",
  HTTP_NO_AUTH: "(gateway-enforced authentication also counts — verify where enforcement runs)",
  AUTO_DECISION: "(a later human review queue before the decision takes effect also counts)",
  SENSITIVE_DATA: "(verify contents first — redacted samples and synthetic fixtures are fine)",
  NO_AI_DISCLOSURE: "(footers, terms links, and platform-level notices count — confirm the user-facing layer)",
  CORS_WILDCARD: "(a wildcard without credentials on a genuinely public API is lower risk)",
  UNSAFE_DESERIALIZE: "(verify the data source — trusted local files only is the exception)",
  ERROR_LEAKAGE: "(verify the response reaches clients — server-side-only logging is fine)",
  SAFETY_BYPASS: "(verify the flag is intentional and time-boxed, not a leftover debug switch)",
};

function firstSentence(text) {
  const t = String(text || "").trim().replace(/\s+/g, " ");
  if (!t) return "";
  return t.endsWith(".") ? t : t + ".";
}

// One specific sentence: concrete evidence + article + violation clause (the
// rule's consequence text, already a single sentence). Code spans escaped.
function buildLede(g) {
  const loc = g.files[0] || { file: "?", line: "N/A", snippet: "" };
  const where = `<code>${escapeHtml(loc.file)}${loc.line !== "N/A" ? `:${loc.line}` : ""}</code>`;
  const more = g.files.length > 1 ? ` (+${g.files.length - 1} more below)` : "";
  const snippet = `<code>${escapeHtml((loc.snippet || "").substring(0, 80))}</code>`;
  const specificFn = LEDE_SPECIFIC[g.id] || ((w) => `${escapeHtml(g.title)} at ${w}`);
  return `${specificFn(where, snippet, more)} — ${escapeHtml(g.article)}: ${escapeHtml(firstSentence(g.consequence))}`;
}

// Groups findings by rule so the same rule firing on many files produces one
// readable block (description/consequence/fix once) with a compact list of
// locations — not N identical verbose rows.
// Groups by rule AND tool exposure: an agent-tool finding and a general-code
// finding for the same rule are different claims and get separate cards.
function buildExposureBadge(exposure) {
  if (exposure === "agent-tool") return `<span class="tag-exposure agent">Agent-exposed tool surface</span>`;
  if (exposure === "general-code") return `<span class="tag-exposure general">General code — no agent-tool registration detected</span>`;
  return "";
}

// Phase 3 honesty label, kept as a tags-row badge (not a content block) so
// cards stay at four content pieces while the method stays visible in HTML.
// The called-helper caveat lives in the NO_HUMAN_LOOP fix parenthetical.
function buildMethodBadge(method) {
  if (method === "ast-same-function") return `<span class="tag-method">AST same-function</span>`;
  if (method === "proximity-heuristic") return `<span class="tag-method">Proximity heuristic</span>`;
  return "";
}

function groupFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = (f.id || f.title) + "|" + (f.toolExposure || "-") + "|" + (f.method || "-");
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
    groups.get(key).files.push({ file: f.file, line: f.line, snippet: f.snippet });
    // Project-level findings (unauthenticated endpoints, committed sensitive
    // documents) carry a list of additional affected files. Render them as
    // extra evidence locations under the same grouped card.
    if (f.extraFiles && f.extraFiles.length) {
      for (const extra of f.extraFiles) {
        groups.get(key).files.push({ file: extra, line: "N/A", snippet: "(additional location)" });
      }
    }
  }
  return [...groups.values()];
}

const RISK_AREAS = [
  { name: "Identity & Access", articles: "Art. 15 · Art. 10", ids: ["IDENTITY_KEY", "IAM_WILDCARD", "HTTP_NO_AUTH", "CORS_WILDCARD", "SENSITIVE_DATA", "UNSAFE_DESERIALIZE", "ERROR_LEAKAGE"] },
  { name: "Human Oversight", articles: "Art. 14", ids: ["NO_HUMAN_LOOP", "AUTO_DECISION", "SAFETY_BYPASS"] },
  { name: "Audit Trail & Logging", articles: "Art. 12", ids: ["NO_LOGGING"] },
  { name: "Transparency", articles: "Art. 50", ids: ["NO_AI_DISCLOSURE"] }
];

function buildSummary(findings, meta) {
  const count = findings.length;
  const files = `${meta.filesScanned} ${meta.filesScanned === 1 ? "file" : "files"}`;
  if (!count) {
    return `We looked through ${files} and found nothing that trips the patterns this scan checks for. A clean result here is a good starting point — but this scan only sees what is written in the code, so it is not the same as a clean bill of health.`;
  }
  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const top = findings.slice().sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9))[0];
  const topText = top.consequence || top.description;
  return `We looked through ${files} and found ${count} ${count === 1 ? "area" : "areas"} worth a closer look. The most serious is "${top.title}"${topText ? ` — ${firstSentence(topText)}` : "."} Each finding below says what it means in plain language, gives one step to fix it, and flags clearly where a pattern needs a human to confirm it before acting.`;
}

function buildBreakdown(findings) {
  return RISK_AREAS.map((area) => {
    const count = findings.filter((f) => area.ids.includes(f.id)).length;
    const status = count === 0
      ? `<span class="cat-dot ok"></span><span class="cat-status">Nothing found</span>`
      : `<span class="cat-dot warn"></span><span class="cat-status">${count} ${count === 1 ? "finding" : "findings"}</span>`;
    return `
      <div class="cat-card">
        <div class="cat-name">${area.name}</div>
        <div class="cat-article">${area.articles}</div>
        ${status}
      </div>`;
  }).join("");
}

function buildFindingCards(groups) {
  if (!groups.length) {
    return `<div class="empty-card">No pattern-based findings in the scanned files. A clean result here only means the checks we run didn't flag anything — it is not a certification.</div>`;
  }
  return groups
    .map(
      (g) => `
      <div class="finding-card sev-${g.severity.toLowerCase()}">
        <h3>${escapeHtml(g.title)}</h3>
        <div class="card-tags">
          <span class="tag-article">${escapeHtml(g.article)}</span>
          <span class="tag-sev ${g.severity.toLowerCase()}">${g.severity}</span>
          <span class="tag-count">${g.files.length} ${g.files.length === 1 ? "location" : "locations"}</span>
          ${buildExposureBadge(g.toolExposure)}
          ${buildMethodBadge(g.method)}
        </div>
        <p class="card-lede">${buildLede(g)}</p>
        ${g.fix ? `<p class="card-fix"><strong>Fix:</strong> ${escapeHtml(g.fix)}${FIX_PARENS[g.id] ? ` ${escapeHtml(FIX_PARENS[g.id])}` : ""}</p>` : ""}
        <details class="card-evidence">
          <summary>Show the exact places this was found (${g.files.length})</summary>
          <ul>
            ${g.files
              .map(
                (f) =>
                  `<li><code>${escapeHtml(f.file)}${f.line !== "N/A" ? `:${f.line}` : ""}</code><span>${escapeHtml(f.snippet)}</span></li>`
              )
              .join("")}
          </ul>
        </details>
      </div>`
    )
    .join("");
}

function svgGauge(score, color) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const off = circ * (1 - Math.max(0, Math.min(100, score)) / 100);
  return `
    <div class="gauge-wrap">
      <svg viewBox="0 0 120 120" class="gauge" role="img" aria-label="${score} out of 100">
        <circle class="gauge-track" cx="60" cy="60" r="${r}"></circle>
        <circle class="gauge-arc" cx="60" cy="60" r="${r}"
          stroke="${color}" stroke-dasharray="${circ.toFixed(2)}" stroke-dashoffset="${off.toFixed(2)}"></circle>
      </svg>
      <div class="gauge-center">
        <div class="gauge-score">${score}</div>
        <div class="gauge-max">out of 100</div>
      </div>
    </div>`;
}

// The rating is set by the most severe finding (ceiling); only when nothing
// CRITICAL/HIGH exists does it fall back to the score bands. Return the "why"
// wording so the report can't be read as score == rating.
function ratingExplanation(findings) {
  if (findings.some((f) => f.severity === "CRITICAL")) return { why: "worst finding: CRITICAL severity" };
  if (findings.some((f) => f.severity === "HIGH")) return { why: "worst finding: HIGH severity" };
  return { why: "no CRITICAL or HIGH finding detected — rating follows the scan score" };
}

function buildLegacyHTML(findings, score, meta, reportData) {
  const band = getBand(score, findings);
  const bandLabel = band.label;
  const ratingWhy = ratingExplanation(findings).why;
  const groups = groupFindings(findings);
  const summary = buildSummary(findings, meta);
  const breakdown = buildBreakdown(findings);
  const cards = buildFindingCards(groups);
  const gauge = svgGauge(score, band.color);
  const safeJson = JSON.stringify(reportData || { findings, score })
    .replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Risk Snapshot — ${score}/100 · ${bandLabel}</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #eef1f4; color: #1c2230; }
  .header { background: linear-gradient(135deg, ${band.color} 0%, ${band.to} 100%); color: #fff; padding: 36px 20px 86px; text-align: center; }
  .header h1 { margin: 0; font-size: 1.5rem; font-weight: 700; letter-spacing: .02em; }
  .local-badge { display: inline-block; margin-top: 12px; padding: 6px 14px; border: 1px solid rgba(255,255,255,.65); border-radius: 999px; font-size: .78rem; letter-spacing: .04em; opacity: .95; }
  .wrap { max-width: 880px; margin: -64px auto 0; padding: 0 20px 48px; }
  .hero { background: #fff; border-radius: 16px; box-shadow: 0 10px 30px rgba(16,24,40,.08); padding: 24px 28px; display: flex; gap: 26px; align-items: center; }
  .gauge-wrap { position: relative; width: 150px; height: 150px; flex: 0 0 150px; }
  .gauge { width: 150px; height: 150px; transform: rotate(-90deg); }
  .gauge-track { fill: none; stroke: #edf0f3; stroke-width: 11; }
  .gauge-arc { fill: none; stroke-width: 11; stroke-linecap: round; }
  .gauge-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .gauge-score { font-size: 2.3rem; font-weight: 800; line-height: 1; }
  .gauge-max { font-size: .75rem; color: #8a94a0; }
  .rating-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .rating-why { color: #5b6572; font-size: .88rem; }
  .band-pill { display: inline-block; padding: 5px 12px; border-radius: 999px; color: #fff; background: ${band.color}; font-weight: 700; font-size: .8rem; letter-spacing: .05em; }
  .score-caption { color: #8a94a0; font-size: .82rem; line-height: 1.55; margin: 10px 0 0; }
  .hero-text .score-context { color: #5b6572; font-size: .92rem; line-height: 1.5; margin: 8px 0 0; }
  .meta { color: #8a94a0; font-size: .8rem; margin: 14px 4px 0; }
  section { margin-top: 22px; }
  .section-title { font-size: 1.02rem; font-weight: 700; margin: 0 0 12px; }
  .section-title .sub { color: #8a94a0; font-weight: 500; font-size: .82rem; }
  .summary-card { background: #fff; border-radius: 14px; padding: 20px 24px; line-height: 1.6; color: #3d4655; box-shadow: 0 4px 16px rgba(16,24,40,.05); border-left: 4px solid ${band.color}; }
  .applicability { background: #fff8e6; border: 1px solid #f0d9a8; border-radius: 14px; padding: 18px 22px; color: #4a3b20; line-height: 1.55; }
  .applicability h2 { margin: 0 0 8px; font-size: .98rem; color: #3a2d16; }
  .applicability ul { margin: 0; padding-left: 20px; }
  .applicability li { margin: 5px 0; font-size: .88rem; }
  .applicability strong { color: #3a2d16; }
  .method-note { margin-top: 9px; padding-top: 8px; border-top: 1px dashed #e2c98f; font-size: .82rem; color: #6b5832; }
  .breakdown { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
  .cat-card { background: #fff; border-radius: 12px; padding: 16px; box-shadow: 0 4px 16px rgba(16,24,40,.05); border: 1px solid #edf0f3; }
  .cat-name { font-weight: 700; font-size: .92rem; }
  .cat-article { color: #8a94a0; font-size: .75rem; margin: 2px 0 10px; }
  .cat-status { display: flex; align-items: center; gap: 7px; font-size: .85rem; color: #3d4655; }
  .cat-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .cat-dot.ok { background: #22c55e; }
  .cat-dot.warn { background: #f59e0b; }
  .finding-card { background: #fff; border-radius: 14px; padding: 20px 24px; box-shadow: 0 4px 16px rgba(16,24,40,.05); border: 1px solid #edf0f3; border-left: 5px solid #94a3b8; margin-bottom: 14px; }
  .finding-card.sev-critical { border-left-color: #ef4444; }
  .finding-card.sev-high { border-left-color: #f97316; }
  .finding-card.sev-medium { border-left-color: #eab308; }
  .finding-card.sev-low { border-left-color: #94a3b8; }
  .finding-card h3 { margin: 0; font-size: 1.02rem; }
  .card-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; align-items: center; }
  .tag-article { font-size: .75rem; color: #5b6572; background: #f1f4f7; border: 1px solid #e3e7ec; padding: 2px 9px; border-radius: 999px; }
  .tag-sev { font-size: .75rem; font-weight: 700; color: #fff; padding: 2px 10px; border-radius: 999px; }
  .tag-sev.critical { background: #ef4444; }
  .tag-sev.high { background: #f97316; }
  .tag-sev.medium { background: #d97706; }
  .tag-sev.low { background: #6b7280; }
  .tag-count { font-size: .75rem; color: #8a94a0; }
  .tag-exposure { font-size: .75rem; font-weight: 600; padding: 2px 10px; border-radius: 999px; }
  .tag-exposure.agent { background: #dbeafe; color: #1d4ed8; border: 1px solid #bfdbfe; }
  .tag-exposure.general { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
  .card-lede { margin: 12px 0 0; color: #3d4655; line-height: 1.55; }
  .card-lede code { color: #1c2230; }
  .card-fix { margin: 10px 0 0; line-height: 1.55; }
  .card-fix strong { color: #1c2230; }
  .tag-method { font-size: .75rem; font-weight: 600; color: #5b6572; background: #f1f4f7; border: 1px solid #e3e7ec; padding: 2px 10px; border-radius: 999px; }
  details { margin-top: 12px; }
  details summary { cursor: pointer; color: #4f8ef7; font-size: .85rem; font-weight: 600; user-select: none; }
  details[open] summary { margin-bottom: 8px; }
  .card-evidence ul { margin: 0; padding-left: 0; list-style: none; }
  .card-evidence li { padding: 6px 0; border-top: 1px dashed #e3e7ec; font-size: .85rem; }
  .card-evidence code { color: #1c2230; font-weight: 600; margin-right: 10px; }
  .card-evidence span { color: #5b6572; }
  .empty-card { background: #fff; border-radius: 14px; padding: 24px; color: #5b6572; line-height: 1.6; border: 1px solid #edf0f3; }
  .cta { background: linear-gradient(135deg, #101c2e, #1c3d5a); color: #fff; border-radius: 16px; padding: 26px 28px; }
  .cta h2 { margin: 0 0 8px; font-size: 1.15rem; }
  .cta p { margin: 0 0 14px; color: #c7d3e0; line-height: 1.55; }
  .actions { display: flex; gap: 10px; flex-wrap: wrap; }
  .btn { border: 0; cursor: pointer; font-family: inherit; font-size: .85rem; font-weight: 700; padding: 10px 18px; border-radius: 10px; background: #fff; color: #1c2230; }
  .btn.ghost { background: transparent; color: #fff; border: 1px solid rgba(255,255,255,.4); }
  footer { margin-top: 26px; font-size: .8rem; color: #8a94a0; line-height: 1.6; border-top: 1px solid #e3e7ec; padding-top: 16px; }
  footer strong { color: #b3503f; }
  @media print {
    body { background: #fff; }
    .header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .local-badge, .btn { display: none; }
    .wrap { margin-top: 0; }
    .hero, .summary-card, .cat-card, .finding-card, .cta { break-inside: avoid; box-shadow: none; }
  }
</style>
</head>
<body>
  <div class="header">
    <h1>AI Risk Snapshot Report</h1>
    <div class="local-badge">Scanned locally &middot; nothing transmitted</div>
  </div>

  <div class="wrap">
    <div class="hero">
      ${gauge}
      <div class="hero-text">
        <div class="rating-row">
          <span class="band-pill">${bandLabel}</span>
          <span class="rating-why">${ratingWhy}</span>
        </div>
        <div class="score-caption">Score is 100 minus severity points per finding &mdash; CRITICAL &minus;25, HIGH &minus;15, MEDIUM &minus;5, LOW &minus;2 &mdash; weighted by detection confidence: structurally confirmed findings count fully, while pattern-only findings on known-noisy checks (AI-disclosure wording, auto-decision status text without structural confirmation) count half. The rating above is set by the most severe finding, not by the score.</div>
        <div class="score-context">This score reflects gaps visible in the scanned code only. It does not rate live behaviour, cloud permissions, or process controls, and it is not a compliance certification.</div>
        <div class="meta">Scanned: ${escapeHtml(meta.scannedDirectory)} &middot; ${meta.filesScanned} files${meta.filesSkipped ? ` &middot; ${meta.filesSkipped} skipped` : ""} &middot; ${new Date().toLocaleString()}</div>
      </div>
    </div>

    <section class="applicability">
      <h2>What this report is &mdash; and is not</h2>
      <ul>
        <li><strong>Not a compliance determination.</strong> This is a static pattern scan. It is not a certified audit, a legal opinion, or evidence of compliance with the EU AI Act or any other law.</li>
        <li><strong>High-risk status not assessed.</strong> Articles 9, 12, 14 and 15 apply only to AI systems classified as high-risk under Article 6 and Annex I or Annex III. This scan does not perform that classification.</li>
        <li><strong>Role not determined.</strong> Provider and deployer duties differ. This scan does not determine which role the scanned repository has.</li>
        <li><strong>Entry into application.</strong> The high-risk obligations above apply from ${APPLICABILITY.highRiskObligationsApplyFrom.annexIII} for Annex III systems and ${APPLICABILITY.highRiskObligationsApplyFrom.annexI} for Annex I systems (${APPLICABILITY.highRiskObligationsApplyFrom.source}).</li>
        <li><strong>Article references are review prompts, not findings of breach.</strong> A finding means a pattern was present; it does not establish that an obligation was breached.</li>
      </ul>
      <div class="method-note">${
        meta.astAvailable === false
          ? "Structural AST checks were unavailable on this machine (Python not found). Findings are pattern/proximity heuristics only."
          : meta.astAvailable === true
            ? "Structural AST checks were available for Python. They cover the enclosing function only, never the callee or other files."
            : "Structural check availability was not recorded."
      }</div>
    </section>

    <section>
      <h2 class="section-title">In plain language</h2>
      <div class="summary-card">${summary}</div>
    </section>

    <section>
      <h2 class="section-title">Where we looked <span class="sub">— the checks in this scan</span></h2>
      <div class="breakdown">${breakdown}</div>
    </section>

    <section>
      <h2 class="section-title">What we found <span class="sub">— click "Show the exact places" for the code evidence</span></h2>
      ${cards}
    </section>

    <section class="cta">
      <h2>Not sure what to do next?</h2>
      <p>This snapshot finds patterns. A full audit goes further: we test the live behaviour of oversight and logging controls, review the parts no static scan can see, and hand you a clear fix list. It's a separate engagement — save the report, reach out when you're ready.</p>
      <div class="actions">
        <button class="btn" id="copyBtn" onclick="copyReport()">Copy report.json</button>
        <button class="btn" onclick="expandAll(true)">Expand all evidence</button>
        <button class="btn" onclick="expandAll(false)">Collapse all</button>
        <button class="btn ghost" onclick="window.print()">Print / save as PDF</button>
      </div>
    </section>

    <footer>
      <p><strong>This is not a certified compliance audit.</strong> It is a preliminary, automated, local scan based on pattern matching and simple heuristics. It can miss real issues and can flag things that turn out to be fine on closer look. It is not legal advice, and no result here should be treated as a compliance certification.</p>
      <p><strong>Privacy:</strong> this report was generated entirely on your machine. Nothing was sent anywhere. You decide if and when to share it.</p>
    </footer>
  </div>

  <script>
    const REPORT_DATA = ${safeJson};
    function copyReport() {
      const done = () => {
        const b = document.getElementById("copyBtn");
        const old = b.textContent;
        b.textContent = "Copied to clipboard";
        setTimeout(() => { b.textContent = old; }, 1600);
      };
      const text = JSON.stringify(REPORT_DATA, null, 2);
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
      } else {
        fallbackCopy(text, done);
      }
    }
    function fallbackCopy(text, done) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } catch (e) {}
      document.body.removeChild(ta);
    }
    function expandAll(open) {
      document.querySelectorAll("details").forEach((d) => { d.open = open; });
    }
  </script>
</body>
</html>`;
}

// The shipped HTML report is the dashboard in src/dashboard.js. The previous
// long-form renderer is kept above as buildLegacyHTML for reference only.
function buildHTML(findings, score, meta, reportData) {
  return buildDashboardHTML(findings, score, meta, reportData, { band: getBand(score, findings) });
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function generateReport(findings, outputDir, meta, options = {}) {
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const formats = new Set(
    Array.isArray(options.formats) ? options.formats : ["json", "html", "sarif"]
  );
  // Annotate once so report.json and report.sarif carry identical confidence
  // values. This is the only finding-level addition in item 2's fix-up.
  const annotatedFindings = annotateFindings(findings);
  const score = calculateScore(annotatedFindings);
  let jsonPath = null;
  let htmlPath = null;
  let sarifPath = null;

  // HTML embeds the JSON report for its copy button, so build the object even
  // when report.json itself was not requested.
  const jsonReport = formats.has("json") || formats.has("html")
    ? buildJSON(annotatedFindings, score, meta)
    : null;

  if (formats.has("json")) {
    jsonPath = path.join(outputDir, "report.json");
    fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));
  }
  if (formats.has("html")) {
    htmlPath = path.join(outputDir, "report.html");
    fs.writeFileSync(htmlPath, buildHTML(annotatedFindings, score, meta, jsonReport));
  }
  if (formats.has("sarif")) {
    sarifPath = path.join(outputDir, "report.sarif");
    fs.writeFileSync(sarifPath, JSON.stringify(buildSARIF(annotatedFindings, meta), null, 2));
  }

  return { score, jsonPath, htmlPath, sarifPath };
}

module.exports = { generateReport, buildSARIF, calculateScore, getBand };
