# Verification evidence — final report

Branch: `verify` (created from `v1.2.0-rc1`, tag at `18c0515`).
Tool version under test: `1.2.0`.
Rule pack SHA-256: `9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`.

**No detection code was changed.** `git diff v1.2.0-rc1 -- src rules package.json`
is empty. Every commit below adds files under `audit/verify/` or `test/` only.

## 1. Deliverables

| Item | Output | Sample size | Headline result |
|---|---|---|---|
| V1 blind labelling | `audit/verify/V1_LABELLING/` — `LABEL_CRITERIA.md`, `findings_pool.json`, `finding_map.json`, blank `labeller_A.csv` / `labeller_B.csv`, `labeller_AI.csv` (marked AI-assisted, unfilled), `kappa.js`, `SAMPLE_SUMMARY.md`, `REPO_PINS.md` | 97 pooled findings from 4 public repos; 32 selected (≤5/rule, 8 rules) | **No labels yet.** Sheets are blank by design; no precision or recall is claimed. |
| V1b third-party fixtures | `audit/verify/V1B_THIRD_PARTY/` — `run.js`, `SUMMARY.md`, `results.json` | Bandit `n=5`; Semgrep CORS `n=2`; Semgrep IAM `n=4`; Gitleaks 0 | Bandit 4/5 instances, CORS 1/2, IAM 2/4. Gitleaks **reference-only**, no number. |
| V2 plain vs evasion | `audit/verify/V2_SPLIT/` — `run.js`, `REPORT.md`, `results.json` | plain 45; evasion 27; framework 12; stress 0 | **No pooled headline.** See §2. |
| V3 seeded recall | `audit/verify/V3_SEEDED/` — `run.js`, `REPORT.md`, `results.json` | 36 seeds (12 rules × 3 placements) on a copy of `mcp-servers@e1dc4b18` | 36/36 detected, 0 misses. Not real-world recall. |
| V4 legal mapping | `audit/verify/V4_LEGAL/` — `EU_AI_ACT_TABLE.md`, `INDIA_TABLE.md`, `LIMITATIONS_PARAGRAPH.md`, `results.json` | 12 EU rows; 10 India rows (proposed, 0 implemented) | Strong 2 / moderate 4 / weak 6 (EU). Status fixed: **AUTHOR-REVIEWED vs PRIMARY TEXT, NOT COUNSEL-REVIEWED**. |
| V5 competitors | `audit/verify/V5_COMPETITORS/` — `MATRIX.md`, `results.json` | 6 tools (5 vendors) | **All capability claims UNVERIFIED.** Only metadata and vendor quotes are verified. |
| V6 citation verification | `audit/verify/V6_VERIFY/` — `verify_report.js`, `run_verification.js`, `RESULTS.md`, `results.json`; `test/verify-report.test.js` | 161 findings across 5 targets | **161/161 citations resolve.** 1 schema warning (`line: "N/A"`). |
| V7 triage design | `audit/verify/V7_TRIAGE/` — `build_triage.js`, `TRIAGE_DESIGN.md`, `triage.schema.json`, `triage.example.json`, `PILOT_PROTOCOL.md`, `PATH_NORMALISATION.md`; `test/build-triage.test.js` | 4 test groups | Fingerprint = SARIF `aiRiskSnapshot/v1`; human fields survive re-scan; absent rows retained. Path normalisation is **design only**. |

Commits: `8feb1f1`, `e16f66b`, `4327553`, `23b5fe6`, `d166d0e`, `21e3880`,
`5b8e8c6`, `5ff37c0`.

## 2. Headline numbers, split

These are kept apart because they measure different claims. Do not add them.

| Group | Cases | Correct | Misses | False positives | Rate |
|---|---:|---:|---:|---:|---|
| Plain corpus | 45 | 38 | 0 | 7 | 38/45 (84.4%) |
| Evasion corpus | 27 | 0 | 22 | 5 | 0/27 (0.0%) |
| Framework exposure | 12 | 5 | — | — | 5/12 expose an agent-tool surface |
| Stress | 0 | — | — | — | no cases exist; no number invented |

Supporting, kept separate from the table above:

- Third-party fixtures: Bandit 4/5 (n=5), Semgrep CORS 1/2 (n=2), Semgrep IAM
  2/4 (n=4), Gitleaks not measured.
- Seeded defects: 36/36 (n=36), 12 rules × 3 placements.
- Real-repository raw counts (no labels): 97 findings, `n=4` repos — crewAI 18,
  autogen 44, mcp-servers 21, mcp-python-sdk 14. These are **not** precision.
- Citations: 161/161 resolve (`n=5` scan targets, 161 findings).

## 3. What each item does and does not support

| Item | Supports | Does not support |
|---|---|---|
| V1 | A reproducible, blind labelling packet exists | Any precision/recall number; no human has labelled |
| V1b | The rules agree with third-party labelled constructs on small fixtures | Our precision or recall; generalisation to real repos |
| V2 | The corpus test passes and the split is reported without pooling | That 84.4% transfers to real code; that evasion 0/27 is fixable |
| V3 | The detector matches its own canonical seeds in three placements | Real-world recall; evasion resistance; that seeds resemble real misuse |
| V4 | Each rule is mapped to a named provision with a short quote | Legal correctness; compliance of any repository |
| V5 | Who the competitors are, what they say, and their licences | That any competitor does what it claims |
| V6 | Report citations are internally traceable | That findings are true positives |
| V7 | A stable-key triage overlay is designed and tested | That anyone has triaged a real report yet |

## 4. Top 10 credibility weaknesses

1. **There are no human labels.** V1's sheets are blank, so every statement
   about real-repository precision is absent, not merely uncertain. The
   `kappa.js` tool has never been run on real data.
2. **Evasion is 0/27.** Any presentation of the 84.4% plain figure without this
   number is misleading. All five negative evasion cases fired the target rule
   (5 FPs), so obfuscation does not merely hide findings; it can also create
   them.
3. **V3 is a self-test, not recall.** The seeds are written by the same author
   against the same regexes, on a copy of one repository, in three syntactic
   placements. 36/36 shows the regexes match their own examples. It also
   produced 43 extra finding rows for 36 seeds (baseline 21 → seeded 64); the 7
   unattributed rows were not individually analysed.
4. **The legal mapping is not counsel-reviewed.** Seven of twelve EU rows are
   `weak`. The EU quotations were read in a third-party reproduction because
   EUR-Lex returned HTTP 202 with an empty body; the Official Journal PDF was
   not read. The DPDP Rules, including rule 7, were not retrieved, so no
   breach-notification timeline is asserted.
5. **Every competitor capability claim is UNVERIFIED.** No competitor was
   installed or run. AIR Blackbox's 144-program benchmark is vendor-run and was
   not reproduced. The matrix compares claims, not measured behaviour.
6. **The V1 sample cannot estimate per-rule precision.** Four of twelve rules
   had zero findings in the 4-repo frame and were not back-filled. A cap of
   5/rule makes per-rule kappa unstable even after labelling.
7. **The scanner reports at most one finding per rule per file.** V1b's
   instance-level coverage numbers therefore come from replaying the rule regex
   against fixture lines, not from scanner output. They measure the pattern, not
   the tool.
8. **V6 proves citations, not correctness.** 161/161 means the cited file exists
   and the snippet is on that line. It says nothing about whether the finding is
   a true positive. The inventory hash is recomputed at verification time, not
   proven from the report, because `report.json` embeds no file list.
9. **`report.json` has schema defects that consumers must work around.**
   `findings[].line` is the string `"N/A"` for file-level findings; `file` and
   `extraFiles` use OS-native separators while SARIF uses forward slashes; there
   is no `schemaVersion` and no scanned-file list. V7 documents a fix; it was
   not applied.
10. **Redaction is partial.** `SENSITIVE_DATA` findings cite the filename, which
    can itself be identifying. Secret masking replaces only the matched
    substring, leaving surrounding line context, and V1 labellers see
    `(value withheld)` rather than the value, which limits what they can judge.

Two further caveats worth stating in any write-up: the Semgrep Rules License
v1.0 restricts redistribution, so V1b publishes counts and line numbers only and
copies nothing; and the seeded-defect work depends on repositories that live in
the OS temp directory, so the trees are reproducible only by re-cloning the
pinned commits.

## 5. Manual follow-ups

**Required before any accuracy claim:**

1. Two independent human labellers fill `labeller_A.csv` and `labeller_B.csv`
   for the 32 selected findings, blind to method, confidence and rule intent;
   a third person adjudicates disagreements. Then run `node
   audit/verify/V1_LABELLING/kappa.js`. Budget roughly 2–4 hours per labeller.
2. Counsel review of `V4_LEGAL/EU_AI_ACT_TABLE.md` and
   `V4_LEGAL/INDIA_TABLE.md`, reading the Official Journal PDF directly.
   Retrieve the DPDP Rules and review rule 7 before any breach-timeline claim.

**Required before any competitive claim:**

3. Install and run at least `air-blackbox comply --scan .` on one shared
   repository, after accepting its licence and confirming its network
   behaviour. Until then every V5 capability row stays UNVERIFIED.

**To turn the design items into evidence:**

4. Run one pilot under `V7_TRIAGE/PILOT_PROTOCOL.md` to get real-repository
   usability and false-positive data with written consent.
5. Have one team triage a real report with `build_triage.js`; that is the first
   time the status lifecycle is exercised by someone other than its author.
6. Implement the `V7_TRIAGE/PATH_NORMALISATION.md` change behind a version bump,
   with the fingerprint-stability test as the gate.

**Housekeeping:**

7. Add `test/build-triage.test.js` and `test/verify-report.test.js` to the
   `npm test` chain. Deliberately not done here, because `package.json` was
   outside the read-only scope of this work.
8. Decide whether `report.json` should embed the scanned file list so V6's
   inventory hash can be proven rather than recomputed.

## 6. Reproducing

```bash
# Corpus split (plain / evasion / framework / stress)
node audit/verify/V2_SPLIT/run.js

# Third-party fixtures (needs Bandit in a scratch venv; see SUMMARY.md)
node audit/verify/V1B_THIRD_PARTY/run.js

# Seeded recall (re-clones the pinned repo into the OS temp dir)
node audit/verify/V3_SEEDED/run.js

# Re-scan the pinned repos and verify every citation
node audit/verify/V6_VERIFY/run_verification.js

# Build a triage file from a report
node audit/verify/V7_TRIAGE/build_triage.js report.json --out triage.json

# Tests for the new tooling
node test/verify-report.test.js
node test/build-triage.test.js
```

`V1_LABELLING/build_sample.js` reproduces the sample deterministically
(hash-sorted pool, cap 5/rule, Mulberry32 shuffle seed `20261114`). It needs the
four pinned checkouts; `REPO_PINS.md` records the commits.

## 7. What was not changed

- No file under `src/` or `rules/` was modified. The rule pack is the same
  SHA-256 that `v1.2.0-rc1` shipped.
- No `package.json` change, so `npm test` does not yet include the new tests.
- No detection issue was fixed. V2's 7 plain false positives, the 22 evasion
  misses, and V1b's coverage gaps are recorded as findings about the tool, not
  repaired.
- No `report.json` schema change. V7's path and sentinel proposals are design
  documents.
- No human label, no AI label, and no merged number. `labeller_AI.csv` remains
  unfilled and is marked AI-assisted if it is ever used.
