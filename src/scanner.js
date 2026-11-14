// src/scanner.js
const fs = require("fs").promises;
const path = require("path");
const { spawnSync } = require("child_process");
const yaml = require("js-yaml");
const { redactPII, findFirstNonCommentMatch, getContextWindow } = require("./utils");

const CODE_EXT = [".py", ".js", ".ts", ".jsx", ".tsx"];
const IAC_EXT = [".tf", ".yaml", ".yml"];
const IAC_IGNORE_FILENAMES = ["docker-compose.yml", "docker-compose.yaml"]; // usually not IAM-relevant

const EXCLUDED_DIRS = new Set([
  "node_modules", "dist", "build", ".git", ".next", "coverage",
  "venv", ".venv", "__pycache__", ".mypy_cache", "vendor"
]);

const TEST_DIR_PATTERN = /(^|\/)(tests?|__tests__|spec|fixtures?)(\/|$)/i;
const NON_RELEVANT_JSON = new Set([
  "package.json", "package-lock.json", "tsconfig.json", "composer.json", "composer.lock"
]);

// Receivers that are NOT the destructive operations the high-risk-action rules
// target: in-memory map/collection cleanup, HTTP clients, framework objects,
// and DOM/browser plumbing. `db.delete(` and `report_store.delete_report(` are
// still flagged; `map.delete(` and `axios.delete(` are not. `this.delete(` is
// intentionally NOT benign: calling an action through the current instance is
// still a call, and item 3's positive fixtures require it to fire.
const BENIGN_RECEIVERS = new Set([
  "app", "router", "axios", "http", "request", "res", "response", "req",
  "responseCallbacks", "callbacks", "map", "dict", "records", "state", "list",
  "cache", "session", "window", "document", "localStorage", "sessionStorage",
  "console"
]);

const MINIFIED_LINE_THRESHOLD = 1000;

// A route definition is an @decorator starting at the beginning of a line
// whose first argument is a quoted path beginning with "/". The line-start
// class is horizontal whitespace ONLY ([ \t], never \s): \s matches \n, so
// ^\s* would let a match starting on one line consume blank lines and fire
// on a decorator several lines down — or match route text quoted inside a
// multiline string. Same fix applies to the @tool signal below.
const ROUTE_DEF_RE = /^[ \t]*@(?:app|router|bp|blueprint)\.(?:get|post|put|delete|patch|route)\s*\(\s*["'`]\//m;

// Express-style bare calls (`webapp.post('/callagent', handler)`). The
// lookbehind rejects decorators (`@app.get`), chained access (`foo.app.get`),
// and dict access (`data.get`); the quoted-path-first-arg requirement rejects
// dict lookups (`server.get("name")`) and prose. Receiver names are limited to
// server-app identifiers so HTTP clients (`axios.post('/rel')`, `http.get(`)
// don't register as route definitions.
const ROUTE_CALL_RE = /(?<![\w$.@])(?:app|server|express|webapp|router|route|expressapp|apiserver)\.(?:get|post|put|delete|patch)\s*\(\s*["'`]\//i;

// Endpoint-protection signals. Deliberately excludes generic "Authorization"
// and "api_key" tokens: those appear in OUTBOUND API clients (e.g. a retriever
// calling Google/Bing with a header), which say nothing about whether the
// project's own endpoints require authentication.
const ENDPOINT_AUTH = [
  /\bDepends\s*\(/i,
  /\bOAuth2PasswordBearer\b/i,
  /\bOAuth2AuthorizationCodeBearer\b/i,
  /\bHTTPBearer\b/i,
  /\bHTTPBasic\b/i,
  /\bget_current_user\b/i,
  /\blogin_required\b/i,
  /\bauth_required\b/i,
  /\brequire_auth\b/i,
  /\bIsAuthenticated\b/i,
  /\bpermission_classes\b/i,
  /\bverify_token\b/i,
  /\bverify_jwt\b/i,
  /\brequireAuth\b/i,
  /\bgetServerSession\b/i,
  /\bAUTHENTICATION_BACKENDS\b/i,
  /\bauthentication_classes\b/i,
  /\bjwt\.verify\s*\(/i,
  /\brequire_user\b/i,
  /\bcurrent_user\b/i
];

// A prompt definition is an ASSIGNMENT of a string to a prompt-like name
// (`SYSTEM_PROMPT = '''...`, `system_template = """...`, `"role": "system"`),
// NOT an import line, a call argument (`f(X, SYSTEM_PROMPT, Y)`), or a
// function parameter (`def f(system_prompt, ...)`). Requiring the RHS to be a
// quote also excludes `system_template = SystemMessagePromptTemplate(...)`
// where the actual text lives in a different variable.
const PROMPT_DEF_RE = [
  // prompt-name = <string>  — opener not consumed (lookahead) so extraction
  // can read the literal at fromIndex. Also excludes def params: `f(system_prompt,`
  // has no `=`; excludes call args: `f(X, SYSTEM_PROMPT, Y)` has no `=` after.
  /system[_-]?(?:prompt|message|template)\s*[:=]\s*(?:f|r|b|rf|fr|rb|br|bf)?\s*(?=(?:"""|'''|["'`]))/i,
  /["'`]role["'`]\s*:\s*["'`]system["'`]/i,
  /["'`](?:system|developer)["'`]\s*:\s*["'`]/i
];

const YOU_ARE_RE = /\byou are an?\b/i;

// Agent tool-registration signals (Phase 2). Each entry is one reviewed
// detection regex over raw file content — see phase2_regex_review for the
// match / non-match cases each one was validated against. A file matching
// ANY signal is treated as agent-exposed; proximity findings in files with
// no signal are relabeled as general code risk, not skipped.
const TOOL_REGISTRATION_SIGNALS = [
  { id: "langchain-tool-decorator", pattern: /^[ \t]*@tool(?:\s*\(.*\))?(?:[ \t]*#.*)?[ \t]*$/m },
  { id: "langchain-tool-constructor", pattern: /\b(?:StructuredTool|DynamicTool|Tool)(?:\.\w+)?\s*\(\s*(?=["'`]|\w[\w$]*\s*=)/ },
  { id: "crewai-tools-kwarg", pattern: /\btools\s*=\s*\[(?!\s*\])/ },
  { id: "crewai-tools-colon", pattern: /["']tools["']\s*:\s*\[(?!\s*\])/ },
  { id: "autogen-function-map", pattern: /\bfunction_map\s*=\s*\{(?!\s*\})/ },
  { id: "autogen-register", pattern: /\bregister_(?:function|for_llm|for_execution)\s*\(/ },
  { id: "openai-function-schema", pattern: /(?:["']type["']|(?<![\w$])type)\s*:\s*["']function["']/ },
  { id: "langchainjs-tool-call", pattern: /\btool\s*\((?:(?=[^;]{0,200}=>)|(?=[^(){}]*\bfunction\b)|(?=[^(){}]*\bname\s*=))/ },
];

// Returns the ids of tool-registration signals present in raw content.
// Runs against RAW content like all other detection (see checkRule note).
function detectToolRegistrations(rawContent) {
  return TOOL_REGISTRATION_SIGNALS
    .filter((s) => s.pattern.test(rawContent))
    .map((s) => s.id);
}

// Marks characters that are inside a // line comment, a /* block */ comment,
// a string literal, or the literal text of a template. Template interpolation
// (`${...}`) is code, including nested templates inside an interpolation.
// This is a lexical heuristic, not a parser: it exists so action verbs quoted
// in prose or comments do not look like calls.
function nonCodeMask(content) {
  const mask = new Uint8Array(content.length);
  const stack = [{ type: "code", braceDepth: 0 }];
  let i = 0;
  while (i < content.length) {
    const top = stack[stack.length - 1];
    const ch = content[i];
    const next = content[i + 1];

    if (top.type === "code") {
      if (ch === "/" && next === "/") { mask[i] = mask[i + 1] = 1; i += 2; stack.push({ type: "line" }); continue; }
      if (ch === "/" && next === "*") { mask[i] = mask[i + 1] = 1; i += 2; stack.push({ type: "block" }); continue; }
      if (ch === "'" || ch === '"') { mask[i] = 1; i++; stack.push({ type: ch === "'" ? "single" : "double" }); continue; }
      if (ch === "`") { mask[i] = 1; i++; stack.push({ type: "template" }); continue; }
      if (stack.length > 1) {
        if (ch === "{") top.braceDepth++;
        else if (ch === "}") {
          if (top.braceDepth === 0) {
            // Close `${ ... }` and resume the surrounding template text.
            mask[i] = 1;
            i++;
            stack.pop();
            continue;
          }
          top.braceDepth--;
        }
      }
      i++;
      continue;
    }

    if (top.type === "line") {
      if (ch === "\n") { stack.pop(); i++; continue; }
      mask[i] = 1;
      i++;
      continue;
    }

    if (top.type === "block") {
      mask[i] = 1;
      if (ch === "*" && next === "/") { mask[i + 1] = 1; i += 2; stack.pop(); continue; }
      i++;
      continue;
    }

    if (top.type === "single" || top.type === "double") {
      mask[i] = 1;
      if (ch === "\\") {
        if (i + 1 < content.length) mask[i + 1] = 1;
        i += 2;
        continue;
      }
      if ((top.type === "single" && ch === "'") || (top.type === "double" && ch === '"')) stack.pop();
      i++;
      continue;
    }

    // Template literal text.
    if (ch === "\\") {
      mask[i] = 1;
      if (i + 1 < content.length) mask[i + 1] = 1;
      i += 2;
      continue;
    }
    if (ch === "`") { mask[i] = 1; i++; stack.pop(); continue; }
    if (ch === "$" && next === "{") {
      mask[i] = mask[i + 1] = 1;
      i += 2;
      stack.push({ type: "code", braceDepth: 0 });
      continue;
    }
    mask[i] = 1;
    i++;
  }
  return mask;
}

// Returns the index of the `)` that closes the `(` at openIndex, skipping
// parentheses inside comments and strings. -1 when unbalanced.
function matchingParen(content, mask, openIndex) {
  if (openIndex < 0 || content[openIndex] !== "(") return -1;
  let depth = 0;
  for (let i = openIndex; i < content.length; i++) {
    if (mask[i]) continue;
    const ch = content[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const JS_FUNCTION_PREFIX = /^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?(?:declare\s+)?function\s+$/;
const PY_FUNCTION_PREFIX = /^\s*(?:async\s+)?def\s+$/;

// True when the matched action verb is the *name being declared*, not a call.
// Handles JS/TS function declarations, class/object methods (a `{` body after
// the parameter list), and TS interface/abstract/overload signatures (a return
// type followed by `;`/`,`/`}`). No JS parser is involved.
function isDefinitionMatch(content, mask, match) {
  const lineStart = content.lastIndexOf("\n", match.index - 1) + 1;
  const prefix = content.slice(lineStart, match.index);
  if (JS_FUNCTION_PREFIX.test(prefix) || PY_FUNCTION_PREFIX.test(prefix)) return true;

  const close = matchingParen(content, mask, match.parenIndex);
  if (close === -1) return false;
  let i = close + 1;
  while (i < content.length && (content[i] === " " || content[i] === "\t")) i++;
  if (content[i] === "{") return true;
  if (content[i] !== ":") return false;
  // `cond ? delete(id) : other()` is a call, not a signature.
  if (/\?[^?]*$/.test(prefix)) return false;
  let j = i + 1;
  while (j < content.length && !/[;{},]/.test(content[j]) && content[j] !== "\n") j++;
  if (j >= content.length || content[j] === "\n") return false;
  return content[j] === "{" || content[j] === ";" || content[j] === "," || content[j] === "}";
}

// Collects action-verb candidates from code only, including bracketed string
// keys (`obj["delete"](id)`). Comments and string literals are ignored, except
// for the bracketed-key call shape. Returns the mask so callers can reuse it.
function collectActionMatches(content, actions) {
  const mask = nonCodeMask(content);
  const actionSet = new Set(actions);
  const matches = [];
  const re = new RegExp(`(?<![\\w$.])(?:([A-Za-z_$][\\w$]*)\\.)?\\b(${actions.join("|")})\\s*\\(`, "g");
  let m;
  while ((m = re.exec(content)) !== null) {
    if (mask[m.index]) continue;
    matches.push({
      index: m.index,
      action: m[2],
      receiver: m[1] || null,
      parenIndex: content.indexOf("(", m.index)
    });
  }
  const bracketRe = /\[\s*(["'])([A-Za-z_$][\w$]*)\1\s*\]\s*\(/g;
  while ((m = bracketRe.exec(content)) !== null) {
    if (!actionSet.has(m[2]) || mask[m.index]) continue;
    const nameOffset = m[0].indexOf(m[2], 1);
    const before = content.slice(0, m.index);
    const receiver = /([A-Za-z_$][\w$]*)\.\s*$/.exec(before);
    matches.push({
      index: m.index + nameOffset,
      action: m[2],
      receiver: receiver ? receiver[1] : null,
      parenIndex: m.index + m[0].length - 1
    });
  }
  matches.sort((a, b) => a.index - b.index);
  return { mask, matches };
}

// First REAL action call in `content`: skips decorators, definitions,
// comments/strings, and benign receivers. Returns the match or null.
function firstRealActionCall(content, actions) {
  const { mask, matches } = collectActionMatches(content, actions);
  for (const match of matches) {
    if (content[match.index - 1] === "@") continue;
    if (isDefinitionMatch(content, mask, match)) continue;
    if (match.receiver && BENIGN_RECEIVERS.has(match.receiver)) continue;
    return match;
  }
  return null;
}

function isMinifiedContent(content) {
  // Generated/vendored bundles (minified JS, compiled output, serialized blobs)
  // are typically one or a few very long lines. Proximity heuristics are
  // meaningless there — every call appears adjacent to every other — so such
  // files only get the deterministic pattern checks, never the logic rules.
  return content.split("\n").some((line) => line.length > MINIFIED_LINE_THRESHOLD);
}

class Scanner {
  constructor(rulesPath, rootDir, options = {}) {
    this.rules = yaml.load(require("fs").readFileSync(rulesPath, "utf8")).rules;
    // Phase 4: resolve shared action taxonomies referenced via `actionsRef`.
    // Taxonomy files live next to the rule pack that references them, so a
    // custom pack directory stays self-contained. An inline `actions:` list
    // on a rule takes precedence over its `actionsRef`.
    this.resolveActionRefs(rulesPath);
    this.rootDir = rootDir;
    this.includeTests = !!options.includeTests;
    this.findings = [];
    this.filesScanned = 0;
    this.skippedFiles = 0;
    this.ruleCounts = {};

    this.sensitiveRule = this.rules.find((r) => r.logic === "sensitive_files");
    this.sensitiveNameRe = this.sensitiveRule
      ? new RegExp(this.sensitiveRule.sensitiveNamePatterns.join("|"), "i")
      : null;
    this.sensitiveExts = this.sensitiveRule
      ? new Set(this.sensitiveRule.sensitiveExtensions.map((e) => e.toLowerCase()))
      : null;
    this.sensitiveFiles = [];
    this.routeFileRecords = [];
    // filePath -> array of matched TOOL_REGISTRATION_SIGNALS ids.
    // Populated per file in analyzeFile; consulted by checkProximityLogic.
    this.fileToolSignals = new Map();
    // Probed Python command for the Phase 3 AST helper: null = unprobed,
    // false = unavailable (fall back to proximity), otherwise the command.
    this.pythonCmd = null;
    this.pythonWarned = false;
    // Capability flag reported in JSON: true = an interpreter answered a
    // --version probe, false = no Python, null = not probed yet.
    this.astAvailable = null;
  }

  // Loads `<ref>.yaml` from the rule pack's directory and substitutes its
  // action names into every rule carrying `actionsRef: <ref>`. Throws on a
  // dangling reference: silently scanning with zero actions would suppress
  // every proximity finding, which must never fail quiet.
  resolveActionRefs(rulesPath) {
    const cache = {};
    for (const rule of this.rules) {
      if (Array.isArray(rule.actions) && rule.actions.length > 0) continue;
      if (!rule.actionsRef) continue;
      if (!cache[rule.actionsRef]) {
        const taxPath = path.join(path.dirname(rulesPath), `${rule.actionsRef}.yaml`);
        let taxonomy;
        try {
          taxonomy = yaml.load(require("fs").readFileSync(taxPath, "utf8"));
        } catch (err) {
          throw new Error(
            `Rule "${rule.id}" references actionsRef "${rule.actionsRef}" ` +
            `but ${taxPath} could not be loaded (${err.code || err.message}).`
          );
        }
        const names = (taxonomy && taxonomy.actions || [])
          .map((a) => (typeof a === "string" ? a : a && a.name))
          .filter((n) => typeof n === "string" && n.length > 0);
        if (!names.length) {
          throw new Error(
            `Rule "${rule.id}" references actionsRef "${rule.actionsRef}" ` +
            `but ${taxPath} contains no usable action names.`
          );
        }
        cache[rule.actionsRef] = names;
      }
      rule.actions = cache[rule.actionsRef];
    }
  }

  async scan() {
    console.log("Scanning for identity, oversight, and audit-trail patterns...");
    // Probe once up front so the report can state whether structural checks
    // were available even when the repository contains no Python files.
    this.ensurePython();
    const files = await this.walkDir(this.rootDir);
    for (const file of files) {
      await this.analyzeFile(file);
    }
    this.emitProjectFindings();
    return this.findings;
  }

  categorize(filePath) {
    const base = path.basename(filePath);
    const ext = path.extname(filePath);

    if (base === ".env" || /^\.env\..+/.test(base)) return "env";
    if (IAC_EXT.includes(ext) && !IAC_IGNORE_FILENAMES.includes(base)) return "iac";
    if (ext === ".json" && !NON_RELEVANT_JSON.has(base)) return "iac"; // e.g. IAM policy docs, CDK output
    if (CODE_EXT.includes(ext)) return "code";
    return null;
  }

  async walkDir(dir) {
    let results = [];
    let list;
    try {
      list = await fs.readdir(dir);
    } catch (err) {
      // EACCES/EPERM on a directory is expected and harmless — a locked folder
      // simply isn't part of this scan. Any other failure (a vanished
      // directory, an I/O fault) is worth knowing about, because silently
      // skipping a folder could mean silently skipping the file with the
      // secret in it.
      if (err.code !== "EACCES" && err.code !== "EPERM") {
        console.warn(`  (skipped, unexpected read failure: ${err.code || "unknown"}) ${dir}`);
      }
      return results;
    }

    for (const name of list) {
      if (EXCLUDED_DIRS.has(name)) continue;

      const filePath = path.join(dir, name);
      let stat;
      try {
        stat = await fs.stat(filePath);
      } catch (err) {
        // A stat failure is almost always EACCES (a permission-restricted
        // entry — benign) or ENOENT (the entry disappeared mid-walk, e.g. a
        // file being deleted by another process — worth a mention).
        if (err.code === "ENOENT") {
          console.warn(`  (skipped, disappeared mid-scan) ${filePath}`);
        }
        continue;
      }

      if (stat.isDirectory()) {
        if (!this.includeTests && TEST_DIR_PATTERN.test(filePath.replace(/\\/g, "/"))) continue;
        results = results.concat(await this.walkDir(filePath));
      } else if (this.categorize(filePath)) {
        results.push(filePath);
      } else if (this.sensitiveNameRe && this.sensitiveExts) {
        // Files that aren't code/IaC (PDFs, images, spreadsheets, serialized
        // stores) can still be a problem if they're committed personal
        // documents. Content is never read — only the name is matched.
        const ext = path.extname(filePath).toLowerCase();
        if (this.sensitiveExts.has(ext) && this.sensitiveNameRe.test(path.basename(filePath))) {
          this.sensitiveFiles.push(filePath);
        }
      }
    }
    return results;
  }

  async analyzeFile(filePath) {
    const category = this.categorize(filePath);
    if (!category) return;

    // Live progress on stderr so the scan is visibly transparent step by
    // step — the local-only story is verifiable in real time, not just in
    // the "nothing was sent" line printed at the end.
    process.stderr.write(`  scanning: ${path.relative(this.rootDir, filePath) || filePath}\n`);

    let rawContent;
    try {
      rawContent = await fs.readFile(filePath, "utf8");
    } catch (err) {
      this.skippedFiles++;
      // EACCES/EPERM is expected and harmless — a permission-restricted file
      // is simply skipped. Any OTHER read failure (a file that vanished
      // mid-scan, an encoding error, a broken symlink) is worth knowing
      // about, especially when it's the file holding the credential.
      if (err.code !== "EACCES" && err.code !== "EPERM") {
        console.warn(`  (skipped, unexpected read failure: ${err.code || "unknown"}) ${filePath}`);
      }
      return;
    }

    this.filesScanned++;

    // Tool-surface detection runs once per file on raw content, before any
    // rule checks. Only proximity-style rules (NO_HUMAN_LOOP / NO_LOGGING /
    // SAFETY_BYPASS) consult it; pattern, disclosure and project-level rules
    // are unaffected.
    this.fileToolSignals.set(filePath, detectToolRegistrations(rawContent));

    // Structural record for the project-level no-auth check: whether this file
    // defines HTTP routes and whether it contains any endpoint-protection code.
    if (category === "code") {
      const routeMatch = ROUTE_DEF_RE.exec(rawContent) || ROUTE_CALL_RE.exec(rawContent);
      if (routeMatch) {
        this.routeFileRecords.push({
          filePath,
          relPath: path.relative(this.rootDir, filePath) || filePath,
          hasAuth: ENDPOINT_AUTH.some((re) => re.test(rawContent)),
          snippet: (rawContent.split("\n")[rawContent.slice(0, routeMatch.index).split("\n").length - 1] || "").trim().substring(0, 120),
          lineNumber: rawContent.slice(0, routeMatch.index).split("\n").length
        });
      }
    }

    // IMPORTANT: detection always runs against RAW content, never redacted
    // content. Redaction is applied only when we build the report snippet,
    // right before a finding is recorded — never before matching.
    const minified = isMinifiedContent(rawContent);
    for (const rule of this.rules) {
      const fileTypes = rule.fileTypes || ["code"];
      if (!fileTypes.includes(category)) continue;
      this.checkRule(rule, filePath, rawContent, minified);
    }
  }

  // Project-level findings that only make sense once every file has been seen:
  // route files that never mention endpoint auth, and committed sensitive
  // documents. Each is a single finding listing the affected files, because
  // N files sharing one structural cause is ONE issue, not N.
  emitProjectFindings() {
    const noAuth = this.routeFileRecords.filter((r) => !r.hasAuth);
    if (noAuth.length) {
      const rule = this.rules.find((r) => r.id === "HTTP_NO_AUTH");
      if (rule) {
        const first = noAuth[0];
        this.addFinding(
          rule,
          first.filePath,
          first.snippet,
          first.lineNumber,
          "Unauthenticated endpoints",
          noAuth.slice(1).map((r) => r.relPath)
        );
      }
    }

    if (this.sensitiveFiles.length) {
      const rule = this.rules.find((r) => r.id === "SENSITIVE_DATA");
      if (rule) {
        const first = this.sensitiveFiles[0];
        const rest = this.sensitiveFiles
          .slice(1, 31)
          .map((p) => path.relative(this.rootDir, p) || p);
        this.addFinding(
          rule,
          first,
          path.basename(first),
          null,
          "Committed sensitive documents",
          rest
        );
      }
    }
  }

  checkRule(rule, filePath, rawContent, minified) {
    if (rule.patterns) {
      for (const pattern of rule.patterns) {
        const regex = new RegExp(pattern, "g");
        if (regex.test(rawContent)) {
          // Some patterns are ambiguous outside their real context — e.g. an
          // IAM wildcard pattern matching markdown prose like "**Action:**".
          // If a rule lists context markers, the file must contain at least
          // one before the finding is reported.
          if (rule.contextPatterns && !rule.contextPatterns.some((c) => new RegExp(c).test(rawContent))) {
            break;
          }
          // Comment-aware evidence: a match that lives on a comment-only
          // line is skipped in favour of a live occurrence later in the
          // file. If EVERY occurrence is commented out, try the next
          // pattern rather than recording a wrong-line finding.
          const found = findFirstNonCommentMatch(rawContent, new RegExp(pattern));
          if (!found) continue;
          const { line, lineNumber } = found;
          // Secret values are never partially reproduced in the report.
          // Sequential masking of overlapping patterns is fragile (proven
          // in testing — a second pattern can fail to match text already
          // mutated by a first), so the safer rule is: no attempt to show
          // a redacted version of a secret, just confirm where one exists.
          const safeLine =
            rule.id === "IDENTITY_KEY"
              ? "(value withheld — a secret-shaped pattern was matched on this line)"
              : line;
          // FIX 1: rules opting in via `receiverCheck` (currently AUTO_DECISION)
          // ask whether this status assignment RECORDS an incoming human
          // decision (review handler — suppress) or COMPUTES one (flag).
          // .py + conclusive AST only; anything else keeps today's behavior.
          let method = null;
          if (rule.receiverCheck && filePath.endsWith(".py")) {
            const verdict = this.getDecisionReceiverVerdict(rawContent, lineNumber);
            if (verdict && verdict.received) break; // handler, not an auto-decision
            if (verdict) method = "ast-same-function"; // structurally confirmed in the same function
          }
          this.addFinding(rule, filePath, safeLine, lineNumber, "Pattern Match", [], null, method);
          break; // one finding per rule per file is enough for a snapshot
        }
      }
    }

    // Proximity heuristics are meaningless in minified/generated files, where
    // every call appears adjacent to every other. Pattern checks above still run.
    if (minified) return;

    if (rule.logic === "high_risk_action_without_approval") {
      this.checkProximityLogic(rule, filePath, rawContent, rule.approvalMarkers, "no approval marker nearby", this.fileToolSignals.get(filePath) || []);
    }

    if (rule.logic === "high_risk_action_without_logging") {
      this.checkProximityLogic(rule, filePath, rawContent, rule.loggingMarkers, "no logging marker nearby", this.fileToolSignals.get(filePath) || []);
    }

    if (rule.logic === "bypass_flag_near_action") {
      this.checkBypassLogic(rule, filePath, rawContent, this.fileToolSignals.get(filePath) || []);
    }

    if (rule.logic === "system_prompt_without_disclosure") {
      this.checkDisclosureLogic(rule, filePath, rawContent);
    }
  }

  // Looks for any of `actions` as a function-call-like token, then checks
  // whether any of `markers` appears within `proximityLines` of that call —
  // instead of just "anywhere in the file", which produces both false
  // positives and false negatives.
  checkProximityLogic(rule, filePath, rawContent, markers, reasonSuffix, toolSignals = []) {
    // Agent-exposed vs general code: a destructive action inside a file with
    // tool-registration signals keeps the agent-oversight claim; without any
    // signal the same gap is relabeled (not skipped) as a general code risk.
    // These are different claims and the report must not conflate them.
    const toolExposure = toolSignals.length > 0 ? "agent-tool" : "general-code";
    // Defense in depth: with zero actions the alternation below would match
    // nearly anything. Resolution throws on dangling refs, but a hand-built
    // rule object could still arrive empty — never scan in that state.
    if (!Array.isArray(rule.actions) || rule.actions.length === 0) return;
    // Capture the optional receiver (e.g. `db.delete(` vs `map.delete(`) so
    // the scanner can tell a data-store call from an in-memory/framework call.
    // collectActionMatches also excludes comments, strings, definitions, and
    // understands bracketed string keys (`obj["delete"](id)`).
    const { mask, matches } = collectActionMatches(rawContent, rule.actions);
    const window = rule.proximityLines || 15;
    const candidates = [];

    for (const match of matches) {
      // Python decorators (e.g. `@app.delete(`) register a route — they don't
      // perform a destructive action.
      if (rawContent[match.index - 1] === "@") continue;

      // Function/method DEFINITIONS name an action but don't perform it.
      if (isDefinitionMatch(rawContent, mask, match)) continue;

      // In-memory map/collection cleanup, HTTP clients, framework objects, and
      // similar receivers are not the destructive operations this rule targets.
      const receiver = match.receiver;
      if (receiver && BENIGN_RECEIVERS.has(receiver)) continue;

      const upTo = rawContent.slice(0, match.index);
      const lineNumber = upTo.split("\n").length;
      const context = getContextWindow(rawContent, lineNumber, window);

      const hasMarker = markers.some((m) => new RegExp(m, "i").test(context));
      candidates.push({ lineNumber, action: match.action, hasMarker });
    }
    if (!candidates.length) return;

    // Phase 3 AST gating (NO_HUMAN_LOOP in .py files only): one helper run
    // per file. `astVerdicts` maps line -> {gated, reason} for conclusive
    // verdicts; anything inconclusive falls back to proximity, unchanged.
    let astVerdicts = null;
    if (rule.logic === "high_risk_action_without_approval" && filePath.endsWith(".py")) {
      astVerdicts = this.getAstVerdicts(rawContent, candidates, rule.approvalMarkers);
    }
    const methodFor = (lineNumber) =>
      astVerdicts && astVerdicts.has(lineNumber) ? "ast-same-function" : "proximity-heuristic";

    // First decisive outcome wins (one finding per rule per file). A marker
    // that proximity accepts but AST finds ungated is Phase 3's new case:
    // approval computed but never actually checked before the action.
    for (const c of candidates) {
      const verdict = astVerdicts ? astVerdicts.get(c.lineNumber) : undefined;
      if (!c.hasMarker) {
        if (verdict && verdict.gated) continue; // AST same-function gate beyond the window
        const lines = rawContent.split("\n");
        const line = (lines[c.lineNumber - 1] || "").trim().substring(0, 120);
        this.addFinding(rule, filePath, line, c.lineNumber, `Logic: ${reasonSuffix}`, [], toolExposure, methodFor(c.lineNumber));
        return;
      }
      if (verdict && !verdict.gated) {
        const lines = rawContent.split("\n");
        const line = (lines[c.lineNumber - 1] || "").trim().substring(0, 120);
        this.addFinding(rule, filePath, line, c.lineNumber, `Logic: ${reasonSuffix} (approval present but not gating)`, [], toolExposure, "ast-same-function");
        return;
      }
    }
  }

  // SAFETY_BYPASS logic: a flag assignment matching a bypass shape
  // (require_*/skip_*/bypass_*/validate_* switched off) with a REAL
  // high-risk action call — taxonomy verbs, minus def/decorator/benign
  // matches — inside the function-scoped window. Bypass patterns compile
  // case-insensitively (True/true/False/false). One finding per rule/file.
  checkBypassLogic(rule, filePath, rawContent, toolSignals = []) {
    if (!Array.isArray(rule.actions) || rule.actions.length === 0) return;
    if (!Array.isArray(rule.bypassPatterns) || rule.bypassPatterns.length === 0) return;
    const exposure = toolSignals.length > 0 ? "agent-tool" : "general-code";
    const window = rule.proximityLines || 15;
    for (const bp of rule.bypassPatterns) {
      const flagRe = new RegExp(bp, "gi");
      let m;
      while ((m = flagRe.exec(rawContent)) !== null) {
        const lineNumber = rawContent.slice(0, m.index).split("\n").length;
        const context = getContextWindow(rawContent, lineNumber, window);
        if (firstRealActionCall(context, rule.actions)) {
          const lines = rawContent.split("\n");
          const line = (lines[lineNumber - 1] || "").trim().substring(0, 120);
          this.addFinding(rule, filePath, line, lineNumber, "Logic: bypass flag near high-risk action", [], exposure, "proximity-heuristic");
          return;
        }
      }
    }
  }

  // Runs src/ast_check.py (stdlib only) over one file's proximity candidates.
  // Probed once per process; returns a working python command or false.
  ensurePython() {
    if (this.pythonCmd === null) {
      this.pythonCmd = false;
      for (const cmd of ["python3", "python"]) {
        try {
          const probe = spawnSync(cmd, ["--version"], { encoding: "utf8", timeout: 10000 });
          if (probe.status === 0) { this.pythonCmd = cmd; break; }
        } catch { /* try the next candidate */ }
      }
      this.astAvailable = Boolean(this.pythonCmd);
      if (!this.astAvailable && !this.pythonWarned) {
        // Say it once, on stderr, so a clean JSON result is not mistaken for
        // a structurally checked one. The report carries the same flag.
        console.warn(
          "  (Python not found: structural AST checks are unavailable; " +
          "affected findings fall back to proximity heuristics)"
        );
        this.pythonWarned = true;
      }
    }
    return this.pythonCmd || null;
  }

  // Returns Map(lineNumber -> {gated, reason}) for conclusive verdicts, or
  // null when AST is unavailable (no Python, helper missing, parse failure).
  // Source travels via stdin — never argv — so secret-shaped text cannot leak
  // into process listings; the helper parses with ast and never executes.
  getAstVerdicts(rawContent, candidates, markers) {
    if (!this.ensurePython()) return null;
    try {
      const req = JSON.stringify({
        source: rawContent,
        queries: candidates.map((c) => ({ line: c.lineNumber, action: c.action })),
        markers,
      });
      const res = spawnSync(this.pythonCmd, [path.join(__dirname, "ast_check.py")], {
        input: req, encoding: "utf8", timeout: 15000, maxBuffer: 64 * 1024 * 1024,
      });
      if (res.status !== 0 || !res.stdout) return null;
      const parsed = JSON.parse(res.stdout);
      if (!parsed || !parsed.ok || !Array.isArray(parsed.verdicts)) return null;
      const map = new Map();
      for (const v of parsed.verdicts) {
        if (v.gated !== null && v.gated !== undefined) {
          map.set(v.line, { gated: !!v.gated, reason: v.reason || "" });
        }
      }
      return map;
    } catch {
      return null;
    }
  }

  // FIX 1 receiver check: does the status assignment at `lineNumber` RECORD
  // an incoming human decision (handler) rather than COMPUTE one? Returns
  // {received, reason}, or null when AST is unavailable/inconclusive — in
  // which case the caller keeps today's flagging behavior unchanged.
  // .py only; other languages fall back without calling the helper at all.
  getDecisionReceiverVerdict(rawContent, lineNumber) {
    if (!this.ensurePython()) return null;
    try {
      const req = JSON.stringify({
        source: rawContent,
        queries: [{ line: lineNumber, op: "receiver" }],
        markers: [],
      });
      const res = spawnSync(this.pythonCmd, [path.join(__dirname, "ast_check.py")], {
        input: req, encoding: "utf8", timeout: 15000, maxBuffer: 64 * 1024 * 1024,
      });
      if (res.status !== 0 || !res.stdout) return null;
      const parsed = JSON.parse(res.stdout);
      if (!parsed || !parsed.ok || !Array.isArray(parsed.verdicts) || !parsed.verdicts.length) return null;
      const v = parsed.verdicts[0];
      if (v.received === null || v.received === undefined) return null;
      return { received: !!v.received, reason: v.reason || "" };
    } catch {
      return null;
    }
  }

  checkDisclosureLogic(rule, filePath, rawContent) {
    // Find an actual prompt BODY: a prompt-name assignment to a string, an
    // OpenAI-style "role": "system" entry, or a system message in a dict.
    let prompt = null;
    let idx = 0;

    for (const re of PROMPT_DEF_RE) {
      const m = re.exec(rawContent);
      if (m) {
        let body = null;
        if (idx === 0) {
          // Assignment form: fromIndex sits on the opening quote of the value.
          body = extractStringAt(rawContent, m.index + m[0].length);
        } else {
          // Dict form: find the content/text/prompt value that follows.
          const found = extractSystemContent(rawContent, m.index + m[0].length);
          if (found) body = found.body;
        }
        if (body) {
          prompt = {
            lineNumber: rawContent.slice(0, m.index).split("\n").length,
            body,
            lead: textAtLine(rawContent, m.index)
          };
        }
        break;
      }
      idx++;
    }

    // Fallback: literal "you are a/an" text on a line that also names an
    // assistant/system/bot/agent — i.e. actual prompt text written inline,
    // not prose that merely mentions "system" somewhere.
    if (!prompt) {
      const lines = rawContent.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (YOU_ARE_RE.test(lines[i]) && /\b(assistant|system|bot|agent)\b/i.test(lines[i])) {
          prompt = { lineNumber: i + 1, body: lines.slice(i, i + 8).join("\n"), lead: lines[i].substring(0, 40) };
          break;
        }
      }
    }

    if (!prompt) return;

    if (disclosurePresent(rule, prompt.body)) return;

    const snippet = (prompt.lead || prompt.body.split("\n")[0]).substring(0, 120);
    this.addFinding(rule, filePath, snippet, prompt.lineNumber, "Missing Disclosure");
  }

  addFinding(rule, filePath, rawLine, lineNumber, type, extraFiles = [], toolExposure = null, method = null) {
    // Some rules (e.g. transparency-disclosure) fire on many files at once,
    // which floods a one-page snapshot. `maxFindings` caps a rule's total
    // findings across the whole repo; the report still says "5+ files" not
    // "only these 5" is a known limitation of the cap.
    if (rule.maxFindings) {
      const seen = (this.ruleCounts[rule.id] || 0) + 1;
      this.ruleCounts[rule.id] = seen;
      if (seen > rule.maxFindings) return;
    }

    const relativePath = path.relative(this.rootDir, filePath) || filePath;
    // General-code relabeling: same gap, weaker claim. Severity is unchanged;
    // only the title/description distinguish it from an agent-oversight risk.
    const isGeneralCode = toolExposure === "general-code";
    this.findings.push({
      id: rule.id,
      article: rule.article,
      title: isGeneralCode ? rule.title + " — General Code Risk" : rule.title,
      severity: rule.severity,
      toolExposure,
      // Phase 3: which detection method produced this finding. Only proximity
      // rules set it ("ast-same-function" vs "proximity-heuristic"); pattern,
      // disclosure and project-level findings carry null.
      method,
      file: relativePath,
      line: lineNumber || "N/A",
      // Redaction happens here — at evidence-build time — never earlier.
      snippet: redactPII(rawLine || ""),
      extraFiles: extraFiles.map((p) => redactPII(p)),
      description: isGeneralCode
        ? "NOTE: No agent-tool registration was detected in this file, so this is reported as a general code risk, not an agent oversight risk. " + rule.description
        : rule.description,
      note: rule.note || null,
      consequence: rule.consequence || null,
      fix: rule.fix || null,
      whatItChecks: rule.whatItChecks || null,
      falsePositiveNote: rule.falsePositiveNote || null,
      type
    });
  }
}

// Reads the string literal that starts at `index` (which must sit on the
// opening quote). Handles triple-quoted and single-quoted strings, skips
// backslash-escaped quotes, and calls it at most a few KB long.
function extractStringAt(content, index) {
  if (index < 0 || index >= content.length) return null;
  const tail = content.slice(index, index + 6000);
  let opener;
  if (tail.startsWith('"""') || tail.startsWith("'''")) {
    opener = tail.slice(0, 3);
  } else if (tail[0] === '"' || tail[0] === "'" || tail[0] === "`") {
    opener = tail[0];
  } else {
    return null;
  }

  const body = tail.slice(opener.length);
  if (opener.length === 3) {
    const close = body.indexOf(opener);
    return close === -1 ? body : body.slice(0, close);
  }
  for (let i = 0; i < body.length; i++) {
    if (body[i] === opener && body[i - 1] !== "\\") return body.slice(0, i);
  }
  return body;
}

// After `"role": "system"`, find the content/text/prompt value of the same
// message object and return its string body.
function extractSystemContent(content, fromIndex) {
  const window = content.slice(fromIndex, fromIndex + 2500);
  const m = window.match(/["'`](?:content|text|prompt|message)["'`]\s*:\s*(?:f|r|b|rf|fr|rb|br|bf)?\s*["'`]/);
  if (!m) return null;
  // m[0] ends ON the opening quote of the value; extractStringAt reads there.
  const valueStart = fromIndex + m.index + m[0].length - 1;
  const body = extractStringAt(content, valueStart);
  return body ? { body } : null;
}

function textAtLine(content, index) {
  const lines = content.split("\n");
  const lineNumber = content.slice(0, index).split("\n").length;
  return (lines[lineNumber - 1] || "").trim().substring(0, 120);
}

function disclosurePresent(rule, body) {
  return rule.disclosurePatterns.some((p) => new RegExp(p, "i").test(body));
}

module.exports = Scanner;
