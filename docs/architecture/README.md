# System Design — AI Risk Snapshot

This folder contains the system-design level architecture diagram for the AI Risk Snapshot project.

## Files

| File | Format | Description |
|---|---|---|
| `system-design-architecture.svg` | SVG (vector) | Editable source. Open in Inkscape, Illustrator, or a browser. |
| `system-design-architecture.png` | PNG (3333 × 2458) | High-resolution raster for reports, slides and README embedding. |

## Layers shown

The diagram is organised into five logical layers plus cross-cutting concerns:

- **L1 — Actors & External Systems**: developer, CI pipeline, target repository, rule-pack author.
- **L2 — Interface Layer**: `cli.js`, `agreement.js`, `rulepack.js`, `exitcodes.js`.
- **L3 — Application / Detection Core**: `scanner.js`, `utils.js`, the scan coordinator, and the three detection layers — literal matching, proximity analysis, and the optional Python AST verification with its fallback path.
- **L4 — Aggregation & Presentation**: `reporter.js`, `dashboard.js`, project-level aggregator.
- **L5 — Data & Output Layer**: consent log, `report.json`, `report.html`, `report.sarif`, and process exit status.

Cross-cutting properties are called out explicitly: read-only scanning, no network interface, no code execution, report-time redaction, editable YAML rules, file-and-line evidence, and the scoring caveat.

## Key design properties

1. Rules live in an editable YAML pack, not in the engine.
2. Detection combines literal patterns, function-scoped proximity, and an optional AST gate.
3. If Python is unavailable, AST verdicts are inconclusive and findings fall back to the proximity heuristic.
4. The tool never executes scanned source and makes no network request.
5. Outputs are written locally in JSON, HTML and SARIF 2.1.0, with deterministic exit codes for CI.
