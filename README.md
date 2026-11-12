# ai-risk-snapshot
Built as a Node.js CLI tool, using `argparse` for command parsing and `js-yaml` for a pluggable, YAML-based rule engine — with scanning, reporting, and consent logic separated into independent modules for maintainability and extensibility.

A local, read-only scanner that checks an AI agent codebase for structural
identity, human-oversight, and audit-logging gaps, and maps findings to the
relevant EU AI Act articles. It is a **preliminary heuristic scan**, not a
certified audit.

# Tech Stack

| Technology      |             Use Case                                                                 |
| **Node.js**     | Runtime environment for the CLI tool |
| **npm**         | Package manager and distribution (install via `npx`/`npm install -g`)                |
| **argparse**    | Parses CLI commands and flags (e.g. `scan --path`, `--output`)                       |
| **js-yaml**     | Parses YAML rule pack files into JS objects for the rule engine                      |
| **cli.js**(entry point) | Bootstraps the tool, reads user input, routes to scanner                     |
| **scanner.js**  | Core engine — scans code/files, detects AI framework usage, checks against loaded rules |
| **reporter.js** | Formats scan results into output reports (console/JSON/HTML)                        |
| **agreement.js** | Handles user consent/terms acknowledgment before running a scan on a system        |
| **utils.js**     | Shared helper functions (file I/O, path handling, common logic)                    |
| **rules/ (YAML files)**| Stores modular, editable compliance rule packs (EU AI Act, India framework) — decoupled from core code |
| **package.json / package-lock.json** | Defines dependencies, scripts, and versioning for reproducible installs |


## What it does

- Reads `.py`, `.js`, `.ts`, `.env*`, and IaC-style `.tf`/`.yaml`/`.json`
  files under the target directory.
- Never executes your code, never modifies your files, never makes a
  network call.
- Writes a local report (JSON + HTML). Nothing is sent anywhere unless you
  choose to send it yourself.

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

Report is written to `./ai-risk-snapshot-report/` (or your `--output` path),
**outside** the scanned directory by default. Add that folder to your
`.gitignore` — the tool will remind you.

## Scope and limits (read this before trusting the score)

This scan checks what's visible in source/config files:

- Hardcoded secrets (`IDENTITY_KEY`)
- Wildcard IAM permissions in IaC files (`IAM_WILDCARD`) — static file
  scan only, does **not** call any cloud API or check your live console
- Destructive actions with no nearby approval marker (`NO_HUMAN_LOOP`)
- Destructive actions with no nearby logging marker (`NO_LOGGING`)
- System prompts with no obvious AI-disclosure language (`NO_AI_DISCLOSURE`)

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
structural (`ast-confirmed`) verdicts for `NO_HUMAN_LOOP`: they cover the
enclosing function only, never the callee.

## License

MIT
