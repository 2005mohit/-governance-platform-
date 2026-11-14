# Changelog

## [1.2.0] - 2026-11-13

### Added

- `--fail-on <critical|high|medium|low|none>` (default `none`). Exit 1 when
  a finding is at or above the threshold; exit 2 for tool or configuration
  errors. Report files are written before a failing gate exits.
- `--format <json|html|sarif|all>` (default `all`). `all` writes
  `report.json`, `report.html`, and `report.sarif`; an explicit `json`,
  `html`, or `sarif` writes only that artefact. An invalid value exits 2.
- SARIF 2.1.0 output (`report.sarif`) with tool metadata, rule metadata,
  applicability run properties, severity-to-level mapping, relative artifact
  URIs, and stable `partialFingerprints` that ignore line numbers.
- SARIF tests covering the official vendored schema, zero-finding scans,
  result counts, fingerprint stability, blank-line shifts, absent absolute
  paths, secret redaction, format selection, and exit-code compatibility.
- Tests for every threshold, clean and severity-specific fixtures, invalid
  arguments, unreadable paths, declined consent, and rule-pack failure.
- Rule packs are validated before scanning (and at `Scanner` construction).
  Invalid regexes, unknown severities, empty or missing fields, duplicate
  ids, wrong types, dangling `actionsRef` taxonomies, unknown keys, oversized
  packs, YAML alias bombs, and obvious catastrophic-regex shapes exit `2`
  with the pack path, rule id, field, problem, and fix. No report is written.
  Validation adds about 1.6 ms of startup time on the shipped pack. The
  catastrophic-regex and alias-expansion checks are conservative heuristics,
  not proofs.

### Changed

- **Breaking:** the minimum supported Node.js version is now 18
  (`engines.node` is `>=18`). Tested on Node 18.20.8, 20.20.2, 22.23.5 and
  24.19.0.
- `js-yaml` is now `^4.3.2` (was `^4.1.0`), past GHSA-2883-xcg3-v3hh
  (high severity, `maxTotalMergeKeys` did not limit CPU for empty merge
  sources). `npm audit` and `npm audit --omit=dev` report 0 vulnerabilities.
- **Breaking:** the per-finding `method` value `ast-confirmed` is now
  `ast-same-function`. It still means the structural check covered the
  enclosing function only, never the callee or other files. Update any
  downstream consumer that matches on the old string.
- **Breaking:** declining consent — or running non-interactively without
  `--yes` — now exits 2 (previously 1). No scan is run in either case.
- **Breaking:** unknown options and extra positional arguments are rejected
  with exit 2 (previously ignored or overwritten).
- JS/TS action detection now ignores function and method definitions,
  TypeScript signatures, comments, and string literals. It also recognises
  bracketed literal calls (`obj["delete"](id)`) and calls through `this`.
  Template literal text is ignored while `${...}` interpolation is scanned as
  code (nested and multi-line templates included), so calls inside template
  substitutions are detected. Regex literals are not lexed and can still
  produce a false positive; this is documented, not fixed. Detection remains
  heuristic: aliasing, dynamic dispatch, and destructured calls are still not
  resolved.
- With the default `--format all`, scans now also write `report.sarif` beside
  `report.json` and `report.html`. Pass `--format json` or `--format html` to
  keep the old two-file output.
- The applicability source string now cites Article 113, third paragraph,
  point (c), of Regulation (EU) 2024/1689, as amended by Regulation (EU)
  2026/1744.
- README and Project Overview claims now match the shipped tool: no
  `argparse`, no India pack, no dataset or multi-jurisdiction claim, no JS/TS
  AST claim, and the full 12-rule list.
- Added `npm test`, including fixtures that assert the article mapping for
  `SENSITIVE_DATA`, `SAFETY_BYPASS`, `UNSAFE_DESERIALIZE`, `ERROR_LEAKAGE`,
  and `CORS_WILDCARD`.
- Large files no longer scan quadratically. Candidate line numbers come from a
  per-file line index, the file is split once per rule instead of once per
  action, context windows reuse the same line array, and action-call matches
  are cached per file and action list. AST queries were already one helper run
  per file. On the 20,000-call `db.delete()` corpus case the scan dropped from
  ~395 s / 319 MB peak RSS to ~15.6 s / 79 MB, with an identical finding set.
