# AI Risk Snapshot

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)
![Local only](https://img.shields.io/badge/runs-offline%20%7C%20local%20only-orange.svg)

**Local static triage of EU AI Act–relevant gaps in agent codebases.**

AI Risk Snapshot is a read-only command-line scanner that looks for structural
evidence of identity, human-oversight, logging, and disclosure controls in an
AI agent codebase, maps each finding to an article of the EU AI Act, and writes
the evidence to a local report. It never executes the scanned code, modifies
your files, or makes a network request.

It is **preliminary triage, not a compliance audit**. A finding is a prompt to
open a file and look; it is not a legal determination. The absence of a finding
is not assurance.

## Why a local scan

Before commissioning a full audit, an engineering team wants to know what its
own code shows. General-purpose security scanners find bugs but do not map
findings to AI Act provisions, and a compliance questionnaire does not read a
repository. This tool occupies the narrow middle ground: a local scan that
produces review prompts backed by a file, a line, and a short excerpt. It does
not issue an opaque readiness grade and does not phone home.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | CLI, scanner, rule-pack validator, JSON/SARIF/HTML reporters, dashboard, exit codes, and a Python `ast` helper for structural approval checks |
| `rules/` | The editable EU AI Act rule pack and the high-risk action taxonomy |
| `LICENSE` | MIT |

## Requirements and install

- Node.js 18 or newer (`engines.node` is `>=18`).
- Python 3 is optional. It is used by the structural approval check; if it is
  absent, those findings fall back to proximity matching and the report says
  so.
- `js-yaml` is the only runtime dependency, pinned to `^4.3.2`.

The tool is distributed from this repository; it is not published to the npm
registry.

```bash
git clone https://github.com/<YOUR-USERNAME>/ai-risk-snapshot.git
cd ai-risk-snapshot
npm install

# Check that it runs
node src/cli.js --help

# Scan a project (interactive consent prompt)
node src/cli.js ./path/to/your-agent-project

# Or install globally for the `ai-risk-snapshot` command
npm install -g .
```

## Usage

```bash
# Show options / version, without scanning or writing anything
ai-risk-snapshot --help
ai-risk-snapshot --version

# Scan the current directory
ai-risk-snapshot

# Non-interactive run (--yes is an explicit act of agreement to the terms)
ai-risk-snapshot . --yes

# Choose the report directory and write only SARIF
ai-risk-snapshot ./my-agent-project --yes --format sarif --output ./scan-results

# Include test and fixture directories (excluded by default)
ai-risk-snapshot --include-tests

# CI gate: accept the terms and fail the build on HIGH or worse
ai-risk-snapshot . --yes --fail-on high
```

| Option | Meaning |
|---|---|
| `[path]` | Directory to scan; defaults to the current directory |
| `-y, --yes` | Accept the terms without the interactive prompt |
| `--include-tests` | Include test and fixture directories |
| `--scan` | Accepted for compatibility; no effect |
| `-o, --output <dir>` | Where to write the report |
| `--format <json\|html\|sarif\|all>` | Artefacts to write; default `all` |
| `--fail-on <critical\|high\|medium\|low\|none>` | Exit 1 when a finding is at or above this level; default `none` |
| `-h, --help` / `-V, --version` | Print and exit without scanning or prompting |

Unknown options and extra positional arguments are rejected with exit code 2.

## Reports

The default `--format all` writes three files to `./ai-risk-snapshot-report/`
(or to `--output`):

| File | Purpose |
|---|---|
| `report.json` | Score, band, file counts, applicability metadata, and annotated findings |
| `report.html` | A self-contained dashboard: no external fonts, scripts, images, or network requests |
| `report.sarif` | SARIF 2.1.0 log for code-scanning and CI consumers |

An explicit `--format json|html|sarif` writes **only** that artefact. The HTML
page embeds a copy of the JSON for its copy button, but that data is not
written to disk unless `json` or `all` is selected.

`report.json` and `report.sarif` contain short excerpts of flagged lines with
common secret shapes masked. Treat reports as sensitive until you have reviewed
them, and add the output directory to your `.gitignore` — the CLI will remind
you.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed and nothing met the `--fail-on` threshold. With the default `none`, this includes scans that found issues. |
| `1` | Scan completed and at least one finding met the threshold. Reports are written before the process exits. |
| `2` | Tool or configuration error: bad arguments, invalid `--format` or `--fail-on`, unreadable path, invalid rule pack, declined consent, report-write failure, or an unexpected crash. |

`--fail-on` follows CRITICAL > HIGH > MEDIUM > LOW, so `--fail-on high` also
fails on a CRITICAL finding. In CI you need **both** flags: `--yes` to accept
the terms non-interactively, and `--fail-on` to turn findings into a failing
build. Without `--yes`, a non-interactive run exits 2 without scanning.

## Rule pack

The shipped pack is `rules/eu_ai_act.yaml` plus its `high_risk_actions.yaml`
taxonomy. Rules are declarative: each names an id, an article, a severity, the
file types it applies to, and either literal patterns or a logic type. You can
edit a pattern or an article mapping without changing the engine.

The CLI loads only the shipped EU pack; there is no `--pack` flag. An India
regulatory pack is planned, not shipped.

The pack is validated before any file is read, and invalid packs exit 2 without
writing a report. Validation rejects:

- regexes that do not compile, and obvious catastrophic shapes such as `(a+)+`
  (a conservative heuristic, not a ReDoS proof);
- unknown severities, logic values, or file types;
- empty rule lists, empty pattern or marker lists, and rules with neither
  `patterns` nor `logic`;
- missing or wrongly typed required fields, duplicate rule ids, and unknown
  top-level or rule fields;
- dangling `actionsRef` taxonomies, empty action lists, duplicate action names,
  and unknown taxonomy fields;
- packs above 256 KiB, and YAML alias/merge-key bombs.

Errors name the pack path, rule id (when known), field, problem, and fix.

## What it checks

The current pack contains twelve rules:

- Hardcoded secrets (`IDENTITY_KEY`)
- Wildcard IAM permissions in IaC files (`IAM_WILDCARD`) — a static file check;
  it does not call a cloud API or inspect a live console
- Destructive actions with no nearby approval marker (`NO_HUMAN_LOOP`)
- Destructive actions with no nearby logging marker (`NO_LOGGING`)
- System prompts with no obvious AI-disclosure language (`NO_AI_DISCLOSURE`) —
  it inspects prompt text, not a user-facing UI notice
- HTTP routes with no authentication visible in the same file (`HTTP_NO_AUTH`)
- Auto approve/reject status assignments near decision context (`AUTO_DECISION`)
- Wildcard CORS origins (`CORS_WILDCARD`)
- Committed files whose names look like identity or financial documents
  (`SENSITIVE_DATA`) — filename only; contents are not read
- Unsafe deserialization and dynamic execution patterns (`UNSAFE_DESERIALIZE`)
- Error details returned to clients (`ERROR_LEAKAGE`)
- Disabled validation flags near a high-risk action (`SAFETY_BYPASS`)

Proximity rules use a nine-verb high-risk taxonomy (`delete`, `drop_table`,
`transfer`, `wire_transfer`, `fire`, `terminate`, `deny_loan`,
`medical_diagnosis`, `send_payment`) and a ±15-line window. Where Python is
available, an `ast-same-function` check distinguishes a call that is actually
guarded from one where approval is merely computed in the same function.

### Agent-tool labelling

Files containing a tool-registration signal are labelled `agent-tool`; the
same gap elsewhere is labelled `general-code`. The label describes the file,
not the repository, and the report says so.

Recognised registration shapes are deliberately narrow: LangChain Python
(`@tool`, `StructuredTool`, `DynamicTool`, `Tool`), CrewAI (`tools=[...]`),
AutoGen (`function_map`, `register_function` / `register_for_llm` /
`register_for_execution`), OpenAI function/tool schemas (`"type": "function"`),
and LangChain.js (`tool(...)`). LangGraph, the OpenAI Agents SDK, Anthropic
tool use, MCP, Semantic Kernel, LlamaIndex, and Pydantic AI are **not
recognised**. In those repositories generic rules still fire, but findings are
labelled `general-code` and no framework name is reported.

## SARIF 2.1.0

`report.sarif` contains the same data as `report.json` plus tool metadata, so a
secret masked in one is masked in the other.

- `tool.driver` carries the tool name, the version from `package.json`, and one
  rule entry per pack rule, including rules with no findings.
- Rules carry `id`, `name`, `shortDescription`, `defaultConfiguration.level`,
  and `properties.article` / `properties.severity`. Optional pack fields such
  as `providerOrDeployer` are copied only when present.
- Run-level properties carry the applicability block and the statement that
  findings are indicators, not a compliance determination.
- Severity maps to SARIF level: CRITICAL and HIGH → `error`, MEDIUM →
  `warning`, LOW → `note`. Locations use relative, forward-slash URIs;
  absolute paths are never written.
- `partialFingerprints` hash the rule id, relative path, normalised snippet,
  and a duplicate counter. Line numbers are excluded, so inserting a blank
  line above a finding does not create a new identity.

The scanner never uploads anything. If you choose to upload the SARIF file to
GitHub code scanning, do it as a separate step and review the file and your
organisation's data-handling rules first:

```yaml
- run: npm install -g .
- run: ai-risk-snapshot . --yes --format sarif --output scan-results
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan-results/report.sarif
```

## Scope and limits — read this before trusting the score

The rules are proxies for controls, not the controls themselves. Articles 9,
12, 14, and 15 apply only to systems classified as high-risk under Article 6
and Annex I or Annex III. This scan does not perform that classification, does
not assign provider or deployer roles, and does not establish legal
compliance. Under Regulation (EU) 2024/1689 as amended by Regulation (EU)
2026/1744, the high-risk obligations apply from **2 December 2027** (Annex
III) and **2 August 2028** (Annex I).

It also does not check whether an approval step is a real human check, whether
logs capture real runtime events, your live cloud IAM configuration, prompt
injection, excessive agency, or any documented risk-management process. Those
need runtime testing and human review.

### Known false positives

- **Proximity and AST checks are not call-graph aware.** A guard inside a
  helper function is invisible from the caller's side, so `getContextWindow()`
  in `src/utils.js` stops at the nearest function boundary. A destructive call
  whose helper performs the approval itself will still be flagged; verify the
  helper and treat the finding as informational. `ast-same-function` verdicts
  cover the enclosing function only — never the callee or another file.
- **JS/TS action detection is heuristic, not a parser.** Comments, string
  literals, function declarations, class and object methods, and TypeScript
  signatures are excluded from call matching; bracketed calls such as
  `obj["delete"](id)` are recognised, and `${...}` interpolation in template
  literals is scanned as code. Regex literals are not lexed as their own state,
  so a pattern such as `/delete(id)/` can fire. Aliasing, dynamic dispatch, and
  destructured calls are not resolved. A clean JS/TS result means "no visible
  literal call", not "no destructive call".
- **Secret shapes are a fixed list.** `IDENTITY_KEY` covers legacy `sk-…`,
  `sk-proj-…`, `sk-ant-…`, AWS `AKIA…`, an RSA private-key header,
  `AWS_SECRET_ACCESS_KEY`, and GitHub `ghp_…`. Google, Azure, Cohere, Mistral,
  and Hugging Face keys, OpenAI `sk-svcacct-…` / `sk-admin-…`, and fine-grained
  GitHub `github_pat_…` tokens are not matched. The `sk-proj-` and `sk-ant-`
  patterns require at least 20 characters after the prefix, so short
  placeholders do not fire but long dummy values do.
- **Repository role matters.** Point the scanner at the application layer. A
  framework's lifecycle teardown calls (`client.delete(sandbox)`,
  `process.terminate()`) are structurally identical to high-risk application
  actions and will be reported.

## License

MIT. See [LICENSE](LICENSE).
