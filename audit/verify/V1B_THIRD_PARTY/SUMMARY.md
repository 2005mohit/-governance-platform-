# V1b — third-party labelled suites (run 2026-11-15)

Status: **third-party evidence only**, kept separate from the project corpus. These are
not measurements of this tool's real-world precision or recall.

- Tool version: 1.2.0
- Rule-pack SHA-256: `9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`
- Bandit runtime version: 1.9.4

## Licence check

| Suite | Repository | Commit | Licence | What was copied |
|---|---|---|---|---|
| Bandit | https://github.com/PyCQA/bandit | `2d5467c45c3189f4d7d07e8022276bc73a478abd` | Apache-2.0 (LICENSE read) | Nothing |
| Semgrep rules | https://github.com/semgrep/semgrep-rules | `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` | `LICENSE` is a one-line reference to Semgrep Rules License v1.0; redistribution terms not relied on | Nothing; fixtures read in place, aggregate results only |
| Gitleaks | https://github.com/gitleaks/gitleaks | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | MIT (LICENSE read) | Nothing |

## Bandit examples — UNSAFE_DESERIALIZE

| File | Bandit expected (functional test) | Bandit issues at runtime | Scanner flags file | Rule-pattern lines | Covered B301/B506 matched |
|---|---:|---:|---|---|---|
| pickle_deserialize.py | 4 | 4 | yes | 7, 12 | 2/3 |
| yaml_load.py | 2 | 2 | yes | 9, 22 | 2/2 |
| eval.py | 3 | 3 | no | none | 0/0 |
| exec.py | 1 | 1 | no | none | 0/0 |

Covered-construct coverage: **4/5 (80.0%)** (n=5 B301/B506 instances across 4 files). Out-of-scope Bandit instances (B307/B102, literal eval/exec): 5.

- `pickle_deserialize.py`
  - MISS (covered construct) line 15: B301 — Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
  - out of scope line 2: B403 — Consider possible security implications associated with pickle module.
- `eval.py`
  - out of scope line 3: B307 — Use of possibly insecure function - consider using safer ast.literal_eval.
  - out of scope line 4: B307 — Use of possibly insecure function - consider using safer ast.literal_eval.
  - out of scope line 5: B307 — Use of possibly insecure function - consider using safer ast.literal_eval.
- `exec.py`
  - out of scope line 1: B102 — Use of exec detected.

## Semgrep rule tests

### CORS_WILDCARD — FastAPI wildcard fixture

- Annotated positives: 2 lines (12, 21)
- Annotated negatives: 2 lines (30, 38)
- Rule-pattern matches: 21
- Instance coverage: **1/2 (50.0%)**
- False positives on annotated ok lines: 0/2

### IAM_WILDCARD — Terraform admin-policy fixture

- Annotated positive blocks: 4 (34-57, 61-80, 84-99, 103-118)
- Blocks with at least one rule-pattern match: 2/4 (50.0%)
- Rule-pattern lines: 92, 94, 112, 113, 130, 132
- Unannotated blocks also flagged: 1 (lines 130, 132)

## Gitleaks

**REFERENCE-ONLY — NOT MEASURED.** No per-file expected-findings labels at the pinned
commit; the `testdata/expected` tree holds formatter fixtures, not a labelled corpus.

## Limitations

- Bandit and Semgrep rules are not our rules. The comparison measures coverage of third-party labelled constructs, not our own precision or recall.
- The scanner reports at most one finding per rule per file; instance counts come from applying the rule regex to the fixture lines and are labelled as pattern-level, not scanner output.
- Semgrep fixtures are read in place. Nothing from semgrep-rules is copied into this repository; only aggregate counts and line numbers are published.
- These fixtures are small, hand-written tests. No generalisation to real repositories is claimed.
