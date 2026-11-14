// src/rulepack.js
//
// Rule-pack validation. A bad pack must be rejected before any file is
// scanned, with a message that names the pack, the rule (when known), the
// field, the problem, and the fix. Validation runs on the shipped pack at
// startup and on every pack a Scanner is constructed with.
//
// The guards here are deliberately conservative heuristics, not proofs:
//   - the regex shape check catches nested quantifiers, not every ReDoS form
//   - the alias check caps anchor/alias counts and estimates expansion
//   - the file-size cap bounds parsing work before js-yaml sees the document
const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

const MAX_PACK_BYTES = 256 * 1024;
const MAX_ALIAS_TOKENS = 50;
const MAX_EXPANDED_NODES = 100000;

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_SET = new Set(SEVERITIES);
const FILE_TYPES = new Set(["code", "env", "iac"]);
const LOGICS = new Set([
  "high_risk_action_without_approval",
  "high_risk_action_without_logging",
  "bypass_flag_near_action",
  "system_prompt_without_disclosure",
  "endpoint_auth",
  "sensitive_files"
]);

const KNOWN_PACK_KEYS = new Set(["rules"]);
const KNOWN_RULE_KEYS = new Set([
  "id", "title", "article", "severity", "fileTypes", "patterns", "logic",
  "actionsRef", "actions", "approvalMarkers", "loggingMarkers",
  "proximityLines", "description", "whatItChecks", "falsePositiveNote",
  "consequence", "fix", "note", "contextPatterns", "disclosurePatterns",
  "maxFindings", "receiverCheck", "sensitiveNamePatterns",
  "sensitiveExtensions", "bypassPatterns", "providerOrDeployer",
  "highRiskOnly"
]);
const KNOWN_TAXONOMY_KEYS = new Set(["actions"]);
const KNOWN_ACTION_KEYS = new Set(["name", "why"]);

const STRING_FIELDS = [
  "title", "article", "description", "whatItChecks", "falsePositiveNote",
  "consequence", "fix", "note"
];
const REGEX_ARRAY_FIELDS = [
  "patterns", "contextPatterns", "approvalMarkers", "loggingMarkers",
  "disclosurePatterns", "bypassPatterns", "sensitiveNamePatterns"
];
const STRING_ARRAY_FIELDS = [
  "actions", "sensitiveExtensions", ...REGEX_ARRAY_FIELDS
];

class RulePackError extends Error {
  constructor(packPath, issues) {
    const rendered = issues.map((issue) => {
      const where = issue.ruleId
        ? `rule "${issue.ruleId}" field "${issue.field}"`
        : `field "${issue.field}"`;
      return `  - ${where}: ${issue.problem} Fix: ${issue.fix}`;
    });
    super(`Rule pack "${packPath}" is invalid:\n${rendered.join("\n")}`);
    this.name = "RulePackError";
    this.packPath = packPath;
    this.issues = issues;
  }
}

function issue(ruleId, field, problem, fix) {
  return { ruleId: ruleId || null, field, problem, fix };
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function firstLine(text) {
  return String(text || "").split("\n")[0];
}

// Counts anchors/aliases/merge keys and estimates the expansion of the
// anchor graph. This runs on raw text before js-yaml, because a small nested
// anchor bomb can otherwise expand to a huge object during parsing.
function checkYamlComplexity(raw, filePath, issues, ruleId = null) {
  const aliasMatches = raw.match(/(?:^|[\s,[{])\*([A-Za-z_][\w-]*)/g) || [];
  const mergeMatches = raw.match(/(?:^|[\s,{])<<\s*:/g) || [];
  const tokenCount = aliasMatches.length + mergeMatches.length;
  if (tokenCount > MAX_ALIAS_TOKENS) {
    issues.push(issue(
      ruleId,
      "aliases",
      `${filePath} contains ${tokenCount} aliases/merge keys, above the cap of ${MAX_ALIAS_TOKENS}; this can expand into a YAML alias bomb`,
      "remove anchors/aliases or inline the values"
    ));
  }

  const anchorRefs = new Map();
  for (const line of raw.split(/\r?\n/)) {
    const anchor = line.match(/&([A-Za-z_][\w-]*)/);
    if (!anchor) continue;
    const refs = [...line.matchAll(/\*([A-Za-z_][\w-]*)/g)].map((m) => m[1]);
    anchorRefs.set(anchor[1], refs);
  }

  const memo = new Map();
  function estimate(name, stack) {
    if (memo.has(name)) return memo.get(name);
    if (stack.has(name)) return 1;
    let total = 1;
    stack.add(name);
    for (const ref of anchorRefs.get(name) || []) {
      total += estimate(ref, stack);
      if (total > MAX_EXPANDED_NODES) break;
    }
    stack.delete(name);
    memo.set(name, total);
    return total;
  }

  for (const name of anchorRefs.keys()) {
    const size = estimate(name, new Set());
    if (size > MAX_EXPANDED_NODES) {
      issues.push(issue(
        ruleId,
        "aliases",
        `${filePath} has an estimated alias expansion of at least ${MAX_EXPANDED_NODES} nodes from anchor "${name}"; this looks like a YAML alias bomb`,
        "remove nested anchors/aliases or inline the values"
      ));
      break;
    }
  }
}

// Conservative ReDoS shape check: a group that already contains a quantifier
// and is itself quantified, e.g. (a+)+ or (.*)*. Not a proof; a full ReDoS
// analysis is out of scope.
function catastrophicReason(pattern) {
  const nestedQuantifier =
    /\((?:[^()\\]|\\.)*(?:[*+]|\{\d+(?:,\d*)?\})(?:[^()\\]|\\.)*\)\s*(?:[*+]|\{\d+,?\d*\})/;
  if (nestedQuantifier.test(pattern)) {
    return "nested quantifier can backtrack catastrophically";
  }
  return null;
}

function compileRegex(pattern, ruleId, field, issues) {
  try {
    new RegExp(pattern);
  } catch (error) {
    issues.push(issue(
      ruleId,
      field,
      `regex ${JSON.stringify(pattern)} does not compile (${firstLine(error.message)})`,
      "correct the pattern or remove it"
    ));
    return;
  }
  const reason = catastrophicReason(pattern);
  if (reason) {
    issues.push(issue(
      ruleId,
      field,
      `regex ${JSON.stringify(pattern)} is a likely catastrophic shape: ${reason}`,
      "rewrite it without nested quantifiers, or use a cheaper pattern"
    ));
  }
}

function readLimited(filePath, label, issues, ruleId = null) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (error) {
    issues.push(issue(
      ruleId,
      label,
      `could not be read (${error.code || firstLine(error.message)})`,
      "check the path and permissions"
    ));
    return null;
  }
  if (stat.size > MAX_PACK_BYTES) {
    issues.push(issue(
      ruleId,
      label,
      `is ${stat.size} bytes, which exceeds the ${MAX_PACK_BYTES}-byte cap; oversized packs are rejected rather than parsed`,
      "reduce the pack size or split it"
    ));
    return null;
  }
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    issues.push(issue(
      ruleId,
      label,
      `could not be read (${error.code || firstLine(error.message)})`,
      "check the path and permissions"
    ));
    return null;
  }
}

function parseYaml(raw, filePath, issues, ruleId = null) {
  try {
    return yaml.load(raw);
  } catch (error) {
    issues.push(issue(
      ruleId,
      "document",
      `${filePath} is not valid YAML (${firstLine(error.message)})`,
      "fix the YAML syntax"
    ));
    return undefined;
  }
}

function validateStringArray(value, ruleId, field, issues, options = {}) {
  if (!Array.isArray(value)) {
    issues.push(issue(
      ruleId,
      field,
      `expected a list of strings, got ${value === null ? "null" : typeof value}`,
      `provide ${field} as a YAML list`
    ));
    return false;
  }
  if (value.length === 0 && !options.allowEmpty) {
    issues.push(issue(
      ruleId,
      field,
      `${field} is empty; list at least one entry`,
      `add at least one ${options.entry || "string"} to ${field}, or remove the field`
    ));
    return false;
  }
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string" || value[i].length === 0) {
      issues.push(issue(
        ruleId,
        field,
        `${field}[${i}] must be a non-empty string, got ${value[i] === null ? "null" : typeof value[i]}`,
        `make every entry in ${field} a non-empty string`
      ));
    }
  }
  return true;
}

function loadTaxonomy(ref, rulesPath, cache, issues, ruleId) {
  if (cache.has(ref)) return cache.get(ref);
  const filePath = path.join(path.dirname(rulesPath), `${ref}.yaml`);
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (error) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `taxonomy "${ref}" could not be loaded from ${filePath} (${error.code || firstLine(error.message)})`,
      `create ${filePath} or correct actionsRef`
    ));
    return null;
  }
  if (stat.size > MAX_PACK_BYTES) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `taxonomy "${ref}" is ${stat.size} bytes, which exceeds the ${MAX_PACK_BYTES}-byte cap`,
      "reduce the taxonomy size"
    ));
    return null;
  }
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `taxonomy "${ref}" could not be loaded from ${filePath} (${error.code || firstLine(error.message)})`,
      `fix the file permissions or correct actionsRef`
    ));
    return null;
  }

  const complexity = [];
  checkYamlComplexity(raw, filePath, complexity, ruleId);
  if (complexity.length) {
    issues.push(...complexity);
    return null;
  }

  const doc = parseYaml(raw, filePath, issues, ruleId);
  if (doc === undefined) return null;
  if (!isPlainObject(doc)) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `taxonomy ${filePath} must be a YAML mapping with an "actions" list`,
      "rewrite the taxonomy as a mapping"
    ));
    return null;
  }
  for (const key of Object.keys(doc)) {
    if (!KNOWN_TAXONOMY_KEYS.has(key)) {
      issues.push(issue(
        ruleId,
        "actionsRef",
        `taxonomy ${filePath} has unknown top-level key "${key}"; allowed keys: ${[...KNOWN_TAXONOMY_KEYS].join(", ")}`,
        "remove the unknown key or add it to the validator"
      ));
    }
  }
  if (!Array.isArray(doc.actions) || doc.actions.length === 0) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `taxonomy ${filePath} has no usable "actions" list; a rule referencing it would scan with zero actions`,
      "add a non-empty actions list"
    ));
    return null;
  }

  const names = [];
  const seen = new Set();
  for (let i = 0; i < doc.actions.length; i++) {
    const entry = doc.actions[i];
    let name = null;
    if (typeof entry === "string") {
      name = entry;
    } else if (isPlainObject(entry)) {
      for (const key of Object.keys(entry)) {
        if (!KNOWN_ACTION_KEYS.has(key)) {
          issues.push(issue(
            ruleId,
            "actionsRef",
            `taxonomy ${filePath} action[${i}] has unknown key "${key}"; allowed keys: ${[...KNOWN_ACTION_KEYS].join(", ")}`,
            "remove the unknown key or add it to the validator"
          ));
        }
      }
      name = entry.name;
    }
    if (typeof name !== "string" || name.length === 0) {
      issues.push(issue(
        ruleId,
        "actionsRef",
        `taxonomy ${filePath} action[${i}] has no non-empty "name"`,
        "give every action a non-empty name"
      ));
      continue;
    }
    if (seen.has(name)) {
      issues.push(issue(
        ruleId,
        "actionsRef",
        `taxonomy ${filePath} contains duplicate action "${name}"`,
        "remove the duplicate action"
      ));
      continue;
    }
    seen.add(name);
    names.push(name);
  }

  if (names.length === 0) return null;
  try {
    new RegExp(names.join("|"));
  } catch (error) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `taxonomy ${filePath} action names do not form a valid alternation (${firstLine(error.message)})`,
      "use plain call-shaped names without regex metacharacters"
    ));
    return null;
  }

  cache.set(ref, names);
  return names;
}

function validateRule(rule, index, rulesPath, taxonomyCache, issues) {
  const fieldBase = `rules[${index}]`;
  if (!isPlainObject(rule)) {
    issues.push(issue(
      null,
      fieldBase,
      `expected a rule mapping, got ${rule === null ? "null" : typeof rule}`,
      "make every entry in rules a mapping"
    ));
    return;
  }

  const rawId = rule.id;
  const ruleId = typeof rawId === "string" && rawId.length > 0 ? rawId : null;

  for (const key of Object.keys(rule)) {
    if (!KNOWN_RULE_KEYS.has(key)) {
      issues.push(issue(
        ruleId,
        "rules",
        `unknown field "${key}" in ${fieldBase}; allowed fields: ${[...KNOWN_RULE_KEYS].sort().join(", ")}`,
        `remove "${key}" or correct it to a supported field name`
      ));
    }
  }

  if (ruleId === null) {
    issues.push(issue(
      null,
      "id",
      `${fieldBase} has no non-empty string id`,
      "give every rule a unique id"
    ));
  }

  if (!SEVERITY_SET.has(rule.severity)) {
    issues.push(issue(
      ruleId,
      "severity",
      `severity ${JSON.stringify(rule.severity)} is not recognised (allowed: ${SEVERITIES.join(", ")})`,
      `use one of: ${SEVERITIES.join(", ")}`
    ));
  }

  for (const field of STRING_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(rule, field) && typeof rule[field] !== "string") {
      issues.push(issue(
        ruleId,
        field,
        `${field} must be a string, got ${rule[field] === null ? "null" : typeof rule[field]}`,
        `provide ${field} as a string`
      ));
    }
  }

  if (Object.prototype.hasOwnProperty.call(rule, "fileTypes")) {
    if (validateStringArray(rule.fileTypes, ruleId, "fileTypes", issues, { allowEmpty: true })) {
      for (let i = 0; i < rule.fileTypes.length; i++) {
        if (typeof rule.fileTypes[i] === "string" && !FILE_TYPES.has(rule.fileTypes[i])) {
          issues.push(issue(
            ruleId,
            "fileTypes",
            `fileTypes[${i}] is ${JSON.stringify(rule.fileTypes[i])}; allowed values: ${[...FILE_TYPES].join(", ")}`,
            "use a supported file category"
          ));
        }
      }
    }
  }

  if (Object.prototype.hasOwnProperty.call(rule, "logic") && !LOGICS.has(rule.logic)) {
    issues.push(issue(
      ruleId,
      "logic",
      `logic ${JSON.stringify(rule.logic)} is not recognised (allowed: ${[...LOGICS].join(", ")})`,
      "use a supported logic value"
    ));
  }

  for (const field of STRING_ARRAY_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(rule, field)) continue;
    validateStringArray(rule[field], ruleId, field, issues);
  }

  for (const field of REGEX_ARRAY_FIELDS) {
    if (!Array.isArray(rule[field])) continue;
    for (let i = 0; i < rule[field].length; i++) {
      if (typeof rule[field][i] === "string") {
        compileRegex(rule[field][i], ruleId, `${field}[${i}]`, issues);
      }
    }
  }

  for (const field of ["proximityLines", "maxFindings"]) {
    if (!Object.prototype.hasOwnProperty.call(rule, field)) continue;
    if (!Number.isInteger(rule[field]) || rule[field] <= 0) {
      issues.push(issue(
        ruleId,
        field,
        `${field} must be a positive integer, got ${JSON.stringify(rule[field])}`,
        `set ${field} to a positive integer`
      ));
    }
  }

  if (Object.prototype.hasOwnProperty.call(rule, "receiverCheck") && typeof rule.receiverCheck !== "boolean") {
    issues.push(issue(
      ruleId,
      "receiverCheck",
      `receiverCheck must be a boolean, got ${typeof rule.receiverCheck}`,
      "set receiverCheck to true or false"
    ));
  }

  if (Object.prototype.hasOwnProperty.call(rule, "actionsRef") && (typeof rule.actionsRef !== "string" || rule.actionsRef.length === 0)) {
    issues.push(issue(
      ruleId,
      "actionsRef",
      `actionsRef must be a non-empty string, got ${rule.actionsRef === null ? "null" : typeof rule.actionsRef}`,
      "use the name of a taxonomy file in the same directory"
    ));
  }

  const hasPatterns = Array.isArray(rule.patterns) && rule.patterns.length > 0;
  const hasLogic = typeof rule.logic === "string" && rule.logic.length > 0;
  if (!hasPatterns && !hasLogic) {
    issues.push(issue(
      ruleId,
      "patterns/logic",
      "no detection mechanism; provide a non-empty patterns list or a logic value",
      "add patterns (and fileTypes) or a supported logic value"
    ));
  }

  const hasInlineActions = Array.isArray(rule.actions) && rule.actions.length > 0;
  if (hasInlineActions) {
    try {
      new RegExp(rule.actions.join("|"));
    } catch (error) {
      issues.push(issue(
        ruleId,
        "actions",
        `actions do not form a valid alternation (${firstLine(error.message)})`,
        "use plain call-shaped action names without regex metacharacters"
      ));
    }
  } else if (typeof rule.actionsRef === "string" && rule.actionsRef.length > 0) {
    const names = loadTaxonomy(rule.actionsRef, rulesPath, taxonomyCache, issues, ruleId);
    if (names) rule.actions = names;
  }

  const needsActions =
    rule.logic === "high_risk_action_without_approval" ||
    rule.logic === "high_risk_action_without_logging" ||
    rule.logic === "bypass_flag_near_action";
  if (needsActions && !hasInlineActions && !(typeof rule.actionsRef === "string" && rule.actionsRef.length > 0)) {
    issues.push(issue(
      ruleId,
      "actions/actionsRef",
      `logic "${rule.logic}" needs a high-risk action list; provide actions or actionsRef`,
      "add an inline actions list or an actionsRef taxonomy"
    ));
  }

  const requiredMarkers = {
    high_risk_action_without_approval: ["approvalMarkers", "an approval marker list"],
    high_risk_action_without_logging: ["loggingMarkers", "a logging marker list"],
    bypass_flag_near_action: ["bypassPatterns", "a bypass pattern list"],
    system_prompt_without_disclosure: ["disclosurePatterns", "a disclosure pattern list"],
    sensitive_files: ["sensitiveNamePatterns", "a sensitive filename pattern list"]
  };
  const marker = requiredMarkers[rule.logic];
  if (marker) {
    const [field, description] = marker;
    if (!Array.isArray(rule[field]) || rule[field].length === 0) {
      issues.push(issue(
        ruleId,
        field,
        `logic "${rule.logic}" requires ${description}, but ${field} is missing or empty`,
        `add a non-empty ${field} list`
      ));
    }
  }
  if (rule.logic === "sensitive_files" && (!Array.isArray(rule.sensitiveExtensions) || rule.sensitiveExtensions.length === 0)) {
    issues.push(issue(
      ruleId,
      "sensitiveExtensions",
      'logic "sensitive_files" requires a non-empty sensitiveExtensions list',
      "add the file extensions to match"
    ));
  }
}

function firstRuleId(raw) {
  const match = raw.match(/^\s*-\s*id:\s*["']?([A-Za-z0-9_.-]+)["']?\s*$/m);
  return match ? match[1] : null;
}

function validateRulePack(rulesPath) {
  const absolute = path.resolve(rulesPath);
  const issues = [];
  const raw = readLimited(absolute, "pack", issues);
  if (raw === null) throw new RulePackError(absolute, issues);

  // Rule ids are not parsed yet, so use a best-effort raw read for the
  // "rule id (if known)" part of a pre-parse alias-bomb message.
  checkYamlComplexity(raw, absolute, issues, firstRuleId(raw));
  if (issues.length) throw new RulePackError(absolute, issues);

  const doc = parseYaml(raw, absolute, issues);
  if (doc === undefined) throw new RulePackError(absolute, issues);

  if (!isPlainObject(doc)) {
    issues.push(issue(
      null,
      "document",
      `expected a YAML mapping with a "rules" key, got ${doc === null ? "null" : typeof doc}`,
      'wrap the rules as `rules:` in a YAML mapping'
    ));
    throw new RulePackError(absolute, issues);
  }

  for (const key of Object.keys(doc)) {
    if (!KNOWN_PACK_KEYS.has(key)) {
      issues.push(issue(
        null,
        key,
        `unknown top-level key "${key}"; allowed keys: ${[...KNOWN_PACK_KEYS].join(", ")}`,
        `remove "${key}" or add it to the validator`
      ));
    }
  }

  if (!Array.isArray(doc.rules)) {
    issues.push(issue(
      null,
      "rules",
      `expected a list of rule objects, got ${doc.rules === undefined ? "nothing" : typeof doc.rules}`,
      "provide `rules:` as a YAML list"
    ));
    throw new RulePackError(absolute, issues);
  }
  if (doc.rules.length === 0) {
    issues.push(issue(
      null,
      "rules",
      "the rule list is empty; at least one rule is required",
      "add at least one rule"
    ));
    throw new RulePackError(absolute, issues);
  }

  const taxonomyCache = new Map();
  const seenIds = new Set();
  for (let i = 0; i < doc.rules.length; i++) {
    const rule = doc.rules[i];
    const before = issues.length;
    validateRule(rule, i, absolute, taxonomyCache, issues);
    if (isPlainObject(rule) && typeof rule.id === "string" && rule.id.length > 0) {
      if (seenIds.has(rule.id)) {
        issues.push(issue(
          rule.id,
          "id",
          `duplicate rule id "${rule.id}"; rule ids must be unique`,
          "give each rule a distinct id"
        ));
      }
      seenIds.add(rule.id);
    }
    if (issues.length > before + 50) {
      issues.push(issue(null, "rules", "too many validation errors; stopping after the first 50", "fix the reported issues and re-validate"));
      break;
    }
  }

  if (issues.length) throw new RulePackError(absolute, issues);

  return { rules: doc.rules, packPath: absolute };
}

module.exports = {
  validateRulePack,
  RulePackError,
  MAX_PACK_BYTES,
  MAX_ALIAS_TOKENS,
  MAX_EXPANDED_NODES
};
