# V1 sample summary

- Tool version: 1.2.0
- Rule-pack SHA-256: `9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`
- Pooled findings: 97 across 4 repositories
- Selected for labelling: 32 (up to 5 per rule)
- Shuffle seed: 20261114
- Skipped for no line/file: 0

| Rule | Findings in pool | Selected |
|---|---:|---:|
| CORS_WILDCARD | 6 | 5 |
| ERROR_LEAKAGE | 28 | 5 |
| HTTP_NO_AUTH | 2 | 2 |
| IDENTITY_KEY | 1 | 1 |
| NO_AI_DISCLOSURE | 13 | 5 |
| NO_HUMAN_LOOP | 23 | 5 |
| NO_LOGGING | 20 | 5 |
| UNSAFE_DESERIALIZE | 4 | 4 |

Rules with no real-repository findings in this frame (not back-filled): IAM_WILDCARD, AUTO_DECISION, SENSITIVE_DATA, SAFETY_BYPASS.

`labeller_A.csv` and `labeller_B.csv` contain no labels. `labeller_AI.csv` is
intentionally unfilled and marked AI-assisted if anyone ever fills it.
