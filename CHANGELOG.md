# Changelog

## [1.2.0] - 2026-11-13

### Added

- `--fail-on <critical|high|medium|low|none>` (default `none`). Exit 1 when
  a finding is at or above the threshold; exit 2 for tool or configuration
  errors. Report files are written before a failing gate exits.
- Tests for every threshold, clean and severity-specific fixtures, invalid
  arguments, unreadable paths, declined consent, and rule-pack failure.

### Changed

- **Breaking:** the per-finding `method` value `ast-confirmed` is now
  `ast-same-function`. It still means the structural check covered the
  enclosing function only, never the callee or other files. Update any
  downstream consumer that matches on the old string.
- **Breaking:** declining consent — or running non-interactively without
  `--yes` — now exits 2 (previously 1). No scan is run in either case.
- **Breaking:** unknown options and extra positional arguments are rejected
  with exit 2 (previously ignored or overwritten).
- The applicability source string now cites Article 113, third paragraph,
  point (c), of Regulation (EU) 2024/1689, as amended by Regulation (EU)
  2026/1744.
- README and Project Overview claims now match the shipped tool: no
  `argparse`, no India pack, no dataset or multi-jurisdiction claim, no JS/TS
  AST claim, and the full 12-rule list.
- Added `npm test`, including fixtures that assert the article mapping for
  `SENSITIVE_DATA`, `SAFETY_BYPASS`, `UNSAFE_DESERIALIZE`, `ERROR_LEAKAGE`,
  and `CORS_WILDCARD`.
