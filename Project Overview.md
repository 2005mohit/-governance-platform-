## Problem Statement

Organizations building and deploying Generative AI applications and AI agents must increasingly comply with emerging AI regulations - most immediately the EU AI Act and, over time, India's evolving AI governance framework (MeitY Guidelines, IT Amendment Rules 2026, DPDP Act 2023). Existing compliance tools are either expensive enterprise GRC suites or free/thin open-source scanners that check for a single framework and only inspect static code. Developers and small AI teams have no affordable, self-run tool that checks both code-level and dataset-level compliance risk against more than one jurisdiction's rules in a single scan.

## Objectives

- Build a CLI tool a developer can run locally on their own AI project to check it against compliance rules — no external server, no account signup required to use the core scan
- Support **static code/dependency scanning** to detect AI framework usage and flag common compliance gaps (e.g. missing documentation, no logging, disallowed high-risk use-case patterns)
- Structure the rule engine so **EU AI Act rules and India-specific rules live as separate, editable YAML rule packs** - start with EU AI Act (binding, highest priority), add India rules second
- Output a clear **JSON report** (machine-readable) and a simple **HTML report** (human-readable) — skip PDF generation for MVP unless time allows
- Ship this as a working, installable open-source CLI (`npm`/`npx`) that a small number of real users can test and give feedback on

## Proposed Solution

A local-first CLI tool that a developer installs and runs against their own AI project folder. It performs a realistic layer of analysis for MVP:

1. **Static code scan** — parses the codebase, detects which AI/ML frameworks are used (OpenAI, LangChain, LangGraph, etc.), and checks for the presence or absence of compliance-relevant patterns (e.g., is there any logging of model decisions, is there a documented risk classification, is user consent captured)

The layer will be evaluated against **YAML rule packs** that map findings to specific EU AI Act articles (Phase 1) and India regulatory references (Phase 2, added once Phase 1 is stable). Output is a pass/fail/warn report per rule, exportable as JSON (for CI pipelines) and a readable HTML summary. All processing happens on the user's machine — no code or data is uploaded anywhere, which is both a genuine privacy benefit and a trust-building differentiator for early adopters.

## Tech Stack (MVP-scoped, solo-buildable)

| Layer         | Technology                                  | Why |
|---            |---                                          |---  |
| Runtime       | Node.js                                     | Matches CLI distribution norms (`npx`), fast to build with |
| CLI parsing   | `argparse` (or `commander`)                 | Handles commands/flags |
| Rule format   | `js-yaml`                                   | Parses YAML rule packs, keeps rules editable without code changes |
| Code scanning | AST-based parsing (`@babel/parser` or `tree-sitter`) | Detects framework imports and basic code patterns |
| Reporting | Custom JSON output + a simple HTML template (no PDF for MVP) | Keeps scope realistic |
| Packaging/distribution | npm, GitHub repo | Free, standard, matches how comparable tools ship |