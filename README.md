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
- Writes a local report (JSON + HTML). Nothing is sent anywhere unless you
  choose to send it yourself. `report.json` includes short code excerpts from
  flagged lines (and masks common secret patterns), so review it before
  sharing it with anyone.

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
```

Report is written to `./ai-risk-snapshot-report/` (or your `--output` path)
in the current working directory. Add that folder to your `.gitignore` — the
tool will remind you.

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

## License

MIT
