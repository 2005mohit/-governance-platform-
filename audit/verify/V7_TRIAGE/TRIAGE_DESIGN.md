# V7 — triage file design

Status: **design + reference implementation**. The implementation is
`build_triage.js` in this folder. It reads a `report.json` and writes a
`triage.json`; it does not change the scanner, the rules, or `report.json`.

## 1. Why a separate file

`report.json` answers "what did the scanner see on this commit". A triage file
answers "what did a human decide about it, and why". Mixing the two makes both
unreliable: a re-scan would overwrite decisions, and a decision would look like
scanner output.

The triage file is therefore an overlay. It is keyed by a stable finding
identity and it preserves human fields across re-scans.

## 2. The key is the SARIF fingerprint

The key is the fingerprint already emitted in SARIF:

```
sha256(ruleId + "\u0000" + uri + "\u0000" + normalizedSnippet + "\u0000" + duplicateIndex)
```

Source: `src/reporter.js:86-94` (`findingFingerprint`) and
`src/reporter.js:157-189` (canonical duplicate-index assignment). The line
number is deliberately excluded, so an edit above a finding does not create a
new identity.

`build_triage.js` does not re-implement this. It calls the project's own
`buildSARIF()` and reads `partialFingerprints["aiRiskSnapshot/v1"]`. If the
SARIF algorithm changes, the triage key changes with it in the same commit.

### What the key is stable against

- Inserting or deleting lines above the finding.
- Reordering findings in the report.
- A different file path separator (SARIF's `uri` is already forward-slashed and
  percent-encoded).
- A re-scan on a different OS, provided the relative path and snippet are the
  same.

### What it is not stable against

- Editing the snippet itself.
- Renaming or moving the file (the relative URI changes).
- Renaming the rule id.
- Two byte-identical snippets in the same file: the duplicate index keeps them
  distinct, but if one is deleted the survivor's index can change. This is a
  known limitation, not a solved problem.

## 3. Fields

| Field | Owner | Type | Meaning |
|---|---|---|---|
| `fingerprint` | tool | string, 64 hex | Primary key. SARIF `aiRiskSnapshot/v1`. |
| `ruleId` | tool | string | Rule id at scan time. |
| `file` | tool | string | Forward-slashed path relative to the scan root. |
| `line` | tool | integer or null | Presentation only. Never a key. |
| `lineRaw` | tool | any | The value the report carried (`53`, `"N/A"`, `null`). |
| `snippet` | tool | string | Normalized snippet, as reported. May be redacted. |
| `severity`, `article`, `title` | tool | string | Report metadata at last sighting. |
| `confidence`, `method`, `toolExposure` | tool | string or null | Detection provenance. `null` means not measured. |
| `status` | human | enum | See §4. Default `unreviewed`. |
| `owner` | human | string or null | One accountable person. Not a team alias if avoidable. |
| `notes` | human | string | Free text. No secrets; cite a file:line instead. |
| `labels` | human | string[] | Free tags (`auth`, `needs-design-review`, ...). |
| `duplicateOf` | human | fingerprint or null | Set only when `status = duplicate`. |
| `acceptedRiskExpiry` | human | ISO date or null | Required for `accepted_risk`. |
| `firstSeen`, `lastSeen` | tool | ISO timestamp | Report `generatedAt` values. |
| `seenCount` | tool | integer | Number of reports in which the row was present. |
| `notSeenInLatest` | tool | boolean | True if absent from the latest report. |
| `verification` | tool | object or null | Citation status from `verify_report.js`, if supplied. |
| `history` | tool | array | One entry per report: hash, timestamp, present flag. |

Human-owned fields are preserved on re-run. Tool-owned fields are refreshed.

## 4. Status lifecycle

```
unreviewed
  ├─ true_positive ──► fixed
  ├─ false_positive
  ├─ context          (real pattern, but the surrounding control exists elsewhere)
  ├─ accepted_risk ──► (requires owner + expiry; re-open at expiry)
  ├─ wont_fix
  └─ duplicate ──► duplicateOf must point at another fingerprint
```

Rules:

- Only a human sets `status`. The tool never infers a label.
- `accepted_risk` without an `owner` and `acceptedRiskExpiry` is invalid.
- `duplicate` without a `duplicateOf` that exists in the file is invalid.
- `fixed` is a human claim. A finding disappearing from a later report is
  `notSeenInLatest`, not `fixed`; the tool cannot tell a fix from a moved file
  or a changed rule.
- `false_positive` and `context` are different. `false_positive` means the
  pattern is not there or is not what the rule says. `context` means the pattern
  is there but an unseeable control makes it acceptable. Collapsing them hides
  real detector weaknesses.

## 5. Merge rules on re-scan

Given an existing `triage.json` and a new `report.json`:

1. Compute the new fingerprints with `buildSARIF()`.
2. For each new finding, if the fingerprint exists, refresh tool fields, keep
   human fields, increment `seenCount`, append a `history` entry with
   `present: true`, clear `notSeenInLatest`.
3. If it is new, create a row with `status: "unreviewed"`.
4. For every existing row not seen in the new report, keep it, set
   `notSeenInLatest: true`, and append `present: false`. Do not delete.
5. Recompute `summary`.

Deletion is a separate, explicit operation. A triage file that silently drops
rows when a report changes is not an audit record.

## 6. Suppression

Suppression is a view over `status`, not a separate ignore file:

- `false_positive`, `context`, `accepted_risk`, `wont_fix` and `duplicate` are
  hidden from the default "open" view.
- They remain in the file with owner and notes.
- There is no line-based ignore syntax. A suppression is always tied to a
  fingerprint.
- An expired `accepted_risk` returns to the open view automatically.

## 7. Reference implementation

```bash
# Build a triage file from a report
node audit/verify/V7_TRIAGE/build_triage.js report.json \
  --verification verification.json \
  --out triage.json \
  --csv triage.csv

# Re-run after a new scan, preserving human decisions
node audit/verify/V7_TRIAGE/build_triage.js new-report.json \
  --existing triage.json \
  --out triage.json
```

The CSV is a convenience export. The JSON is canonical; the CSV loses
`history`, `labels` and `verification`.

## 8. Non-goals

- It is not a ticketing system. It has no comments, assignments by team, or
  SLA clock.
- It does not auto-label anything. No model, heuristic, or rule sets `status`.
- It does not turn a fingerprint into a legal conclusion. `true_positive` means
  "the pattern is real and matters here", not "this is a breach".
- It does not merge AI-assisted labels with human labels. If an AI-assisted
  sheet is used, it is a separate field or a separate file, clearly marked.

## 9. Known failure modes

| Failure | Consequence | Mitigation |
|---|---|---|
| Snippet edited | New fingerprint; old row becomes `notSeenInLatest` | Human marks old row `fixed` or `duplicate`; never auto-merge. |
| File moved/renamed | New fingerprint | Same as above. A path-only heuristic would be unsafe. |
| Rule id renamed | New fingerprint for every finding of that rule | Treat as a migration; document the mapping. |
| Two identical snippets, one removed | Duplicate index can shift | Rare; flag rows where `ruleId + file + snippet` has more than one fingerprint. |
| Snippet normalization changes | All fingerprints for affected snippets change | Version the fingerprint scheme; do not change it silently. |

## 10. Validation

`test/build-triage.test.js` checks three things:

1. The triage fingerprints are byte-identical to `buildSARIF()` output,
   including the duplicate-index case.
2. A re-run preserves `status`, `owner` and `notes`, increments `seenCount`, and
   retains a row that disappeared from the report.
3. A file-level finding (`line: "N/A"`) is stored as `line: null` with
   `lineRaw: "N/A"`.

A JSON Schema for the file is in `triage.schema.json`. It validates shape, not
policy (for example, it cannot express "accepted_risk requires an expiry").
