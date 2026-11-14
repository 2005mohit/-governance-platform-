# ai-risk-snapshot
Built as a Node.js CLI tool, with a small hand-rolled argument parser in `src/cli.js` and `js-yaml` for an editable, YAML-based rule pack — with scanning, reporting, and consent logic separated into independent modules for maintainability and extensibility.

A local, read-only scanner that checks an AI agent codebase for structural
identity, human-oversight, and audit-logging gaps, and maps findings to the
relevant EU AI Act articles. It is a **preliminary heuristic scan**, not a
certified audit.

# Tech Stack

| Technology      |             Use Case                                                                 |
| **Node.js**     | Runtime environment for the CLI tool |
| **npm**         | Package manager and distribution (install via `npx`/`npm install -g`)                |
| **Command parsing** | Small hand-rolled parser in `src/cli.js` (no `argparse` dependency)    |
| **js-yaml**     | Parses the YAML rule pack into JS objects for the rule engine                       |
| **cli.js**(entry point) | Bootstraps the tool, reads user input, routes to scanner                     |
| **scanner.js**  | Core engine — scans code/files, detects AI framework usage, checks against loaded rules |
| **reporter.js** | Formats scan results into output reports (console/JSON/HTML)                        |
| **agreement.js** | Handles user consent/terms acknowledgment before running a scan on a system        |
| **utils.js**     | Shared helper functions (file I/O, path handling, common logic)                    |
| **rules/ (YAML files)**| Stores the editable EU AI Act rule pack (an India pack is planned, not shipped) — decoupled from core code |
| **package.json / package-lock.json** | Defines dependencies, scripts, and versioning for reproducible installs |


## What it does

- Reads `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.env*`, and IaC-style
  `.tf`/`.yaml`/`.yml`/non-manifest `.json` files under the target directory.
- Never executes your code, never modifies your files, never makes a
  network call.
- Writes a local report (JSON + HTML, plus SARIF 2.1.0 by default). Nothing is
  sent anywhere unless you choose to send it yourself. `report.json` and
  `report.sarif` include short code excerpts from flagged lines (and mask
  common secret patterns), so review them before sharing them with anyone.

## Usage

```bash
# Scan the current directory, interactive consent prompt
npx ai-risk-snapshot

# Scan a specific path
npx ai-risk-snapshot ./my-agent-project

# Non-interactive (e.g. CI) — --yes is an explicit act of agreement to the terms
npx ai-risk-snapshot --yes

# Custom output location
npx ai-risk-snapshot --output ./scan-results

# Include test/fixture directories (excluded by default)
npx ai-risk-snapshot --include-tests

# Write only one artefact (json, html, or sarif)
npx ai-risk-snapshot --format sarif

# CI: accept the terms and fail the build on HIGH or worse
npx ai-risk-snapshot . --yes --fail-on high
```

Report is written to `./ai-risk-snapshot-report/` (or your `--output` path)
in the current working directory. The default `--format all` writes
`report.json`, `report.html`, and `report.sarif`. Add that folder to your
`.gitignore` — the tool will remind you.

## Rule-pack validation

The shipped pack (`rules/eu_ai_act.yaml` and its `high_risk_actions.yaml`
taxonomy) is validated at startup, before any file is scanned. A custom pack
is validated whenever a `Scanner` is constructed. Invalid packs exit `2` and
write no report files. Each message names the pack path, the rule id (when it
is known), the field, the problem, and the fix, for example:

```
Rule pack ".../rules/eu_ai_act.yaml" is invalid:
  - rule "BAD_REGEX" field "patterns[0]": regex "(" does not compile
    (Invalid regular expression: ...). Fix: correct the pattern or remove it.
```

Validation rejects:

- regexes that do not compile, and obvious catastrophic shapes such as
  `(a+)+` or `(.*)*` (a conservative heuristic, not a ReDoS proof);
- severities outside `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and unknown
  `logic` values or `fileTypes`;
- an empty rule list, empty `patterns`/marker lists, or a rule with neither
  `patterns` nor `logic`;
- missing or wrongly typed required fields (`id`, `severity`, lists where a
  list is expected, positive integers, booleans);
- duplicate rule ids;
- dangling `actionsRef` taxonomies, empty taxonomy action lists, duplicate
  action names, and action names that do not form a valid alternation;
- unknown top-level keys, unknown rule fields, and unknown taxonomy fields;
- packs larger than 256 KiB, and YAML anchor/alias/merge-key bombs (more than
  50 alias tokens, or an estimated expansion above 100,000 nodes).

Validation adds about 1.6 ms to startup on the shipped pack in this
environment (Node 24, 500 warm runs). The caps and the catastrophic-regex
check are intentionally conservative heuristics; they bound the common
failure modes, not every possible malicious document.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed and no finding met the `--fail-on` threshold. With the default `--fail-on none`, this includes scans that found issues. |
| `1` | Scan completed and at least one finding was at or above `--fail-on`. The requested report files are written before the process exits. |
| `2` | Tool or configuration error: bad arguments, invalid `--fail-on` or `--format`, missing or unreadable scan path, rule-pack failure, consent declined, report-write failure, or an unexpected crash. |

`--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none` (the
default). "At or above" follows the severity order CRITICAL > HIGH > MEDIUM >
LOW, so `--fail-on high` also fails on a CRITICAL finding, and `--fail-on
none` never fails on findings.

**CI needs both `--yes` and `--fail-on`.** `--yes` accepts the terms
non-interactively; without it, a non-interactive run exits 2 instead of
scanning. `--fail-on` turns findings into a failing build; without it, the
command exits 0 even when findings exist.

## Output formats

`--format` controls which artefacts are written:

| Value | Files written |
|---|---|
| `all` (default) | `report.json`, `report.html`, and `report.sarif` |
| `json` | `report.json` only |
| `html` | `report.html` only |
| `sarif` | `report.sarif` only |

An explicit format writes **only** that artefact. In particular, `--format
sarif` does not write `report.json` or `report.html`. The HTML report embeds a
copy of the JSON data for its copy button, but that data is not written to
disk unless `json` (or `all`) is selected. An invalid value exits 2 and is
covered by a test. Omitting `--format` keeps the previous behaviour and adds
`report.sarif`.

## SARIF 2.1.0

`report.sarif` is a standard SARIF 2.1.0 log for code-scanning and CI
consumers. It contains only data already present in `report.json` (plus tool
metadata), including the same redacted snippets, so a secret masked in the
JSON report is masked in the SARIF log too.

- `tool.driver` contains the tool name, the version from `package.json`, and
  one rule entry per rule in the pack (including rules with no findings).
  `informationUri` is emitted only when `package.json` contains a real
  repository URL; it is omitted rather than invented.
- Each rule carries `id`, `name`, `shortDescription`,
  `defaultConfiguration.level`, and `properties.article` /
  `properties.severity`. Optional pack fields such as `providerOrDeployer` or
  `highRiskOnly` are copied only if the rule pack defines them.
- Run-level `properties` carry the applicability block and the statement that
  findings are indicators, not a compliance determination.
- Each result maps severity to SARIF level: CRITICAL/HIGH → `error`, MEDIUM →
  `warning`, LOW → `note`. Locations use a relative, forward-slash
  `artifactLocation.uri` and `region.startLine`; absolute paths are never
  written. `properties.method` and `properties.confidence` mirror the JSON
  report.
- `partialFingerprints` use a SHA-256 hash of rule ID, relative path,
  normalised snippet (trimmed, whitespace-collapsed), and a duplicate counter.
  The line number is deliberately excluded, so inserting a blank line above a
  finding does not create a new identity.

### GitHub code scanning (documentation only)

The scanner never uploads anything. If you choose to upload the SARIF file,
do it in a separate step, for example:

```yaml
- run: npx ai-risk-snapshot . --yes --format sarif --output scan-results
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan-results/report.sarif
```

Review the SARIF file (and your organisation's data-handling rules) before
uploading it. The schema used by the tests is vendored under
`test/fixtures/sarif/`; validation runs offline, and `ajv` is a
devDependency that is not part of the published package.

## Scope and limits (read this before trusting the score)

This scan checks what's visible in source/config files:

- Hardcoded secrets (`IDENTITY_KEY`)
- Wildcard IAM permissions in IaC files (`IAM_WILDCARD`) — static file
  scan only, does **not** call any cloud API or check your live console
- Destructive actions with no nearby approval marker (`NO_HUMAN_LOOP`)
- Destructive actions with no nearby logging marker (`NO_LOGGING`)
- System prompts with no obvious AI-disclosure language (`NO_AI_DISCLOSURE`) —
  checks the prompt text, not a user-facing UI notice
- HTTP routes with no auth visible in the same file (`HTTP_NO_AUTH`)
- Auto approve/reject status assignments near decision context (`AUTO_DECISION`)
- Wildcard CORS origins (`CORS_WILDCARD`)
- Committed files whose names look like identity/financial documents
  (`SENSITIVE_DATA`) — filename only, content is not read
- Unsafe deserialization / dynamic execution patterns (`UNSAFE_DESERIALIZE`)
- Error details returned to clients (`ERROR_LEAKAGE`)
- Disabled validation flags near a high-risk action (`SAFETY_BYPASS`)

Article references are **review prompts, not compliance determinations**.
Articles 9, 12, 14 and 15 apply only to systems classified as high-risk under
Article 6 and Annex I or Annex III; this scan does not perform that
classification and does not determine whether the repository is a provider or
a deployer. The high-risk obligations apply from 2 December 2027 (Annex III)
and 2 August 2028 (Annex I) — Article 113, third paragraph, point (c),
Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744.

It does **not** check: whether an approval step is a real human check or a
rubber stamp, whether logs actually capture real runtime events, your live
cloud IAM configuration, or any documented risk-management process. Those
require live testing and a human review — that's a separate, deeper
engagement.

## Known limitations (false positives we know about)

NO_HUMAN_LOOP and NO_LOGGING are not call-graph aware. A destructive action
guarded inside a helper function will still be flagged at every call site
that invokes that helper, even though the guard executes correctly. This is
a known false-positive source, not a regression. Concretely: the proximity
check only looks inside the enclosing function of each call site
(`getContextWindow()` in `src/utils.js` stops at the nearest function
boundary on both sides), so a guard that lives in the called function's own
body is invisible from the caller's side. If the flagged call invokes a
helper that performs the approval/logging itself, verify the helper and
treat the finding as informational. The same blindness applies to the
structural (`ast-same-function`) verdicts for `NO_HUMAN_LOOP`: they cover the
enclosing function only, never the callee.

JS/TS action detection is also heuristic, not a parser. Function declarations,
class/object method definitions, TypeScript signatures, comments, and string
literals are excluded from call matching, and bracketed literal calls such as
`obj["delete"](id)` are recognised. Template literal text is excluded but
`${...}` interpolation is scanned as code, including nested and multi-line
templates, so `` `${db.delete(id)}` `` is detected while `` `delete(id)` `` is
not. Regex literals are *not* lexed as their own state: a pattern such as
`/delete(id)/` is currently treated as code and can fire. It still cannot
resolve aliasing (`const d = db.delete; d(id)`), dynamic dispatch
(`db[name](id)`), or destructured calls
(`const { delete: removeRecord } = db; removeRecord(id)`). Treat a clean JS/TS
result as "no visible literal call", not "no destructive call".

## License

MIT

The vendored SARIF 2.1.0 schema under `test/fixtures/sarif/` is published by
the OASIS SARIF Technical Committee under its own terms (OASIS RF on RAND
Terms Mode), reproduced in `test/fixtures/sarif/SARIF-LICENSE.md`. It is a
test fixture only and is not shipped in the npm package.
