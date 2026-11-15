# V7 — path normalisation in `report.json` (design only)

Status: **design proposal. No scanner, reporter, rule or test file was changed
for this document.** The current behaviour is described first, then the
change, then the migration. Nothing here has been implemented.

Related evidence: V1–V3 scans were produced with the current behaviour; V6
verified 161/161 citations against reports that carry OS-native separators.

## 1. Current behaviour (verified by reading the code)

### 1.1 `report.json`

| Field | Value | Where |
|---|---|---|
| `findings[].file` | Path relative to the scan root, **OS-native separators** | `src/scanner.js:838` → `relativePath = path.relative(rootDir, filePath)`; stored at `:852` |
| `findings[].extraFiles[]` | Same, already relative, OS-native | `src/scanner.js:461` (`relPath`), `:496`, `:513` |
| `findings[].line` | Integer, or the **string `"N/A"`** when there is no line | `src/scanner.js:853` → `lineNumber \|\| "N/A"` |
| `scannedDirectory` | Absolute path, OS-native | `src/reporter.js:320` |
| `filesScanned` | Count only; no list | `src/reporter.js:321` |

Observed on Windows, from a real report (`mcp-servers`, commit
`e1dc4b18dbb948921da37f3d4224a628730b43b0`):

```
file:       "src\\everything\\resources\\minted.ts"
extraFiles: ["src\\everything\\transports\\streamableHttp.ts"]
line:       "N/A"        (SENSITIVE_DATA only)
```

### 1.2 `report.sarif`

The SARIF output already normalises: `relativeArtifactUri()`
(`src/reporter.js:64-75`) replaces `\` with `/`, drops empty segments, and
percent-encodes each segment. The fingerprint is computed from that
forward-slash, percent-encoded URI (`src/reporter.js:89`, `:180`, `:221`).

So the same finding has two spellings today:

```
report.json : src\everything\resources\minted.ts
report.sarif: src/everything/resources/minted.ts     (uri)
```

And for a path with a space, a third:

```
report.sarif: my%20dir/file.py
```

The fingerprint's identity is the SARIF spelling. `report.json` is the odd
one out.

## 2. Why change it

1. **Two spellings is a bug waiting to be keyed on.** Any consumer that joins
   `report.json` paths to `report.sarif` URIs (or to a git path, or to a
   `file:line` string in a ticket) has to know the difference. V7's triage
   builder already has to call `normSlash()` to compensate.
2. **Windows-only escaping.** A backslash in JSON is `\\`, in a shell it is an
   escape character, and in Markdown it is not a path at all. The triage CSV
   and any copy-paste into an issue are affected.
3. **Portability of reports.** A report produced on Windows and read on Linux
   (or in CI) currently cannot be resolved without rewriting separators.
4. **`line: "N/A"` is a type error in a field named `line`.** Every consumer
   special-cases it; V6 had to add a sentinel check to avoid reporting a
   schema artefact as a citation failure.

## 3. Proposed change

### 3.1 Normalise once, where the finding is created

Change the single choke point rather than each serialiser:

```js
// src/scanner.js, near the other small helpers
function relPosix(rootDir, filePath) {
  const rel = path.relative(rootDir, filePath) || filePath;
  return rel.split(path.sep).join("/");
}
```

- `src/scanner.js:838`: `const relativePath = relPosix(this.rootDir, filePath);`
- `src/scanner.js:461`: `relPath: relPosix(this.rootDir, filePath)`
- `src/scanner.js:513`: the `SENSITIVE_DATA` extra-file list uses the same
  helper instead of bare `path.relative`.

Why here and not in `buildJSON()`: HTML (`src/reporter.js:381`, `:496`) and
SARIF (`src/reporter.js:180`) both read `finding.file` directly. Normalising
at creation makes all three outputs agree by construction, and makes
`relativeArtifactUri()`'s separator replacement a no-op rather than the only
place the rule is enforced.

**Decision inside the change:** `report.json` should carry a **raw**
forward-slash path, not a percent-encoded one (`my dir/file.py`, not
`my%20dir/file.py`). Percent-encoding is a SARIF/URI requirement, not a
filesystem requirement, and a raw path is what `fs` and a human need. The two
fields therefore agree on separators and differ only on encoding, which is
documented.

### 3.2 Replace the `"N/A"` sentinel with `null`

- `src/scanner.js:853`: `line: Number.isInteger(lineNumber) && lineNumber > 0 ? lineNumber : null`
- `src/reporter.js:431`: extra-file evidence rows push `line: null`
- `src/reporter.js:380`: default `line: null`
- `src/reporter.js:381`, `:496`: `loc.line !== "N/A"` becomes `loc.line != null`

The rendered output does not change: the HTML already omits the `:line` when
the sentinel is present, and `null` produces the same omission.

### 3.3 What does **not** change

- `scannedDirectory` stays absolute and OS-native. It is a machine-local
  provenance field; converting it to a POSIX path would make it unusable for
  reopening the tree, and no fingerprint depends on it.
- SARIF URIs stay percent-encoded. That is required by the SARIF schema.
- **Fingerprints do not change.** They are already computed from forward-slash
  URIs. A triage file built before the migration keeps resolving after it.
  This is the property that makes the migration safe, and it must be tested
  explicitly (§5, test 4).

## 4. Migration

### 4.1 Signal

`report.json` has no schema version today. Add `"schemaVersion": 2` at the top
level of `buildJSON()` (`src/reporter.js:315`) in the same commit as the
separator change, and bump `package.json` minor version (`1.2.0` → `1.3.0`).
Consumers that cannot see a `schemaVersion` should assume `1`
(OS-native, `"N/A"` sentinel).

### 4.2 Compatibility

| Consumer | Impact | Action |
|---|---|---|
| SARIF readers | None | URIs unchanged |
| Triage (`build_triage.js`) | None functionally; `normSlash()` becomes a no-op | Keep `normSlash()` for reading v1 reports |
| `verify_report.js` | `path.join(root, file)` already accepts `/` on Windows and POSIX | No change needed |
| CSV export | Paths become copy-pasteable | Cosmetic |
| HTML report | Unchanged rendering | None |
| Any external consumer that `split("\\")` | Breaks on `/` | Migration note in changelog; v1 reports still parse |

No file on disk is renamed by this change. It is a serialisation change only.

### 4.3 Version note for the changelog

> `report.json` now writes `findings[].file` and `findings[].extraFiles[]`
> with forward slashes, and writes `findings[].line` as `null` instead of
> `"N/A"` when a finding is file-level. `schemaVersion: 2` is added. SARIF
> output and finding fingerprints are unchanged. Reports written before this
> version keep their original form; tools should accept both.

## 5. Test plan

The existing test that pins the current behaviour must be inverted, not
deleted:

1. **`test/sarif.test.js` (~line 300).** The block currently asserts:
   ```js
   if (process.platform === "win32") {
     assert.ok(json.findings[0].file.includes("\\"),
       "report.json keeps OS-native separators (documented, not changed here)");
   }
   ```
   Replace with an assertion that `report.json` and `report.sarif` produce the
   **same path modulo percent-encoding** for the same finding, on every
   platform. The comment explaining the old behaviour becomes a comment
   explaining the migration.

2. **New:** a fixture under a directory whose name contains a space and a
   non-ASCII character, asserting `report.json` has the raw path and
   `report.sarif` has the percent-encoded URI, and that the fingerprint
   matches the SARIF spelling.

3. **New:** a `SENSITIVE_DATA` fixture asserting `line === null` and that
   `JSON.parse(JSON.stringify(report))` round-trips it as `null`.

4. **Fingerprint stability:** scan a fixture with the current build and with
   the patched build; assert every `partialFingerprints["aiRiskSnapshot/v1"]`
   is byte-identical. This is the gate for the whole migration.

5. **Regression:** run `node test/build-triage.test.js` against a v1 report
   fixture and assert it still merges; then against a v2 report fixture.

## 6. Open questions (not decided here)

- Should `extraFiles` be capped in count in the JSON, or only in HTML? Today
  `SENSITIVE_DATA` caps at 30 (`src/scanner.js:506`) and the HTML appends all
  of them. Unchanged by this proposal.
- Should `report.json` embed the scanned file list, so V6's inventory hash can
  be proven rather than recomputed? That is a different change (V6 §"what this
  does not establish") and is out of scope here.
- The `line` type change is technically breaking for a typed consumer. If one
  exists outside this repo, the field could be duplicated as `lineNumber`
  (integer/null) with `line` deprecated for one minor version. No such consumer
  is known; this is recorded as an option, not a plan.

## 7. Relationship to V7's triage file

`build_triage.js` already writes a forward-slashed `file` and a `null`
`line` with `lineRaw` preserved (`audit/verify/V7_TRIAGE/TRIAGE_DESIGN.md` §3).
After this migration, `triage.json` and `report.json` would agree on both
fields, and `lineRaw` would only be needed when reading a v1 report. The
schema's `file` pattern `^[^\\]+$` would then be satisfiable directly from
`report.json`, not only via normalisation.
