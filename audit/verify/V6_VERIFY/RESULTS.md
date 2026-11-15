# V6 — citation verification

Every row below was produced by re-running the scanner on the pinned tree, then
reopening each cited file:line with `verify_report.js`. A pass means the citation
resolves; it is **not** a judgment that the finding is correct.

- Tool version: 1.2.0
- Targets: 5
- Findings reopened: 161
- Citations verified: **161/161**

| Target | Source | Findings | Verified | Missing file | Line out of range | Snippet match | Offset | Mismatch | Redacted confirmed | Evaluated redaction | No-line | No-line sentinel | Extra files | Extra missing |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| crewAI | V1 | 18 | 18 | 0 | 0 | 18 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| autogen | V1 | 44 | 44 | 0 | 0 | 43 | 0 | 0 | 1 | 0 | 0 | 0 | 6 | 0 |
| mcp-servers | V1 | 21 | 21 | 0 | 0 | 21 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| mcp-python-sdk | V1 | 14 | 14 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| v3-seeded | V3 | 64 | 64 | 0 | 0 | 60 | 0 | 0 | 3 | 0 | 1 | 1 | 6 | 0 |

## Schema warnings

- v3-seeded: SENSITIVE_DATA `zz_seeded/data/class/credit_report.xlsx` — line is the string "N/A" instead of null

  These are treated as file-level citations (the file is the evidence), not as
  citation failures. The defect is in the report schema, not in the line content.

## Provenance per target

| Target | Tool | Rule pack SHA-256 | Report SHA-256 | Cited file-list SHA-256 | Recomputed inventory SHA-256 |
|---|---|---|---|---|---|
| crewAI | 1.2.0 | `9c0f00b8e0051127…` | `75745fe736f99089…` | `f6a43ea3d375b923…` | `63666d3307f5337a…` |
| autogen | 1.2.0 | `9c0f00b8e0051127…` | `1d7a7ef231ba3ac7…` | `34fa721c358e9674…` | `59df3db25cb0df8d…` |
| mcp-servers | 1.2.0 | `9c0f00b8e0051127…` | `cc77b3cf7675079e…` | `f9a4fbddf8b90c0e…` | `911a7482cf47b236…` |
| mcp-python-sdk | 1.2.0 | `9c0f00b8e0051127…` | `7c69a9288f8b3dac…` | `b6c6b78ee5574beb…` | `b3d334a54917571c…` |
| v3-seeded | 1.2.0 | `9c0f00b8e0051127…` | `8ecfc58b9aa7ca81…` | `818ee22c0c024ed6…` | `da24f1d7fb7ca0cf…` |

Full hashes are in `results.json`.

## What this does and does not establish

- It establishes that the report is internally traceable: every cited path exists, the
  line is in range, and the snippet is on that line (or, for redacted secrets, a
  secret-shaped pattern is on the line).
- It does not establish that the finding is a true positive, that the rule is legally
  correct, or that the scan was complete.
- `recomputedInventorySha256` is recomputed with the scanner's own `walkDir` at
  verification time. The report does not embed a file list, so the original inventory
  cannot be proven from the report alone. That is the gap V7 proposes to close.
- Redacted `IDENTITY_KEY` snippets cannot be matched literally. They are verified by
  applying the rule's own patterns to the cited line; that confirms the shape, not the
  original value.
