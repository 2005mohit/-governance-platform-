# V3 - seeded-defect recall (copy of a real repository)

Source: https://github.com/modelcontextprotocol/servers at `e1dc4b18dbb948921da37f3d4224a628730b43b0` (MIT/Apache-2.0 transition (see LICENSE)).
The copy, the seeds and the scan stayed in the OS temp directory; nothing from the
source repository is committed.

- Tool version: 1.2.0
- Rule-pack SHA-256: `9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`
- Seeds: 36 (3 placement variants per rule)
- Detected: **36/36 (100.0%)**

## Per-rule recall

| Rule | Seeds | Detected | Recall | Misses (file:line) |
|---|---:|---:|---:|---|
| AUTO_DECISION | 3 | 3 | 3/3 | - |
| CORS_WILDCARD | 3 | 3 | 3/3 | - |
| ERROR_LEAKAGE | 3 | 3 | 3/3 | - |
| HTTP_NO_AUTH | 3 | 3 | 3/3 | - |
| IAM_WILDCARD | 3 | 3 | 3/3 | - |
| IDENTITY_KEY | 3 | 3 | 3/3 | - |
| NO_AI_DISCLOSURE | 3 | 3 | 3/3 | - |
| NO_HUMAN_LOOP | 3 | 3 | 3/3 | - |
| NO_LOGGING | 3 | 3 | 3/3 | - |
| SAFETY_BYPASS | 3 | 3 | 3/3 | - |
| SENSITIVE_DATA | 3 | 3 | 3/3 | - |
| UNSAFE_DESERIALIZE | 3 | 3 | 3/3 | - |

## Every seed

| Rule | Variant | File:line | Detected | Reported line |
|---|---|---|---:|---|
| IDENTITY_KEY | direct | `zz_seeded/identity/direct/settings.py:1` | yes | 1 |
| IDENTITY_KEY | function | `zz_seeded/identity/function/client.py:2` | yes | 2 |
| IDENTITY_KEY | class | `zz_seeded/identity/class/vault.py:2` | yes | 2 |
| IAM_WILDCARD | direct | `zz_seeded/iam/direct/policy.tf:9` | yes | 9 |
| IAM_WILDCARD | nested | `zz_seeded/iam/nested/template.yaml:9` | yes | 9 |
| IAM_WILDCARD | hcl | `zz_seeded/iam/hcl/main.tf:7` | yes | 7 |
| NO_HUMAN_LOOP | direct | `zz_seeded/human/direct/ops.py:2` | yes | 2 |
| NO_HUMAN_LOOP | function | `zz_seeded/human/function/purge.py:2` | yes | 2 |
| NO_HUMAN_LOOP | class | `zz_seeded/human/class/actions.py:3` | yes | 3 |
| NO_LOGGING | direct | `zz_seeded/logging/direct/ops.py:2` | yes | 2 |
| NO_LOGGING | function | `zz_seeded/logging/function/move.py:2` | yes | 2 |
| NO_LOGGING | class | `zz_seeded/logging/class/payments.py:3` | yes | 3 |
| NO_AI_DISCLOSURE | direct | `zz_seeded/disclosure/direct/prompt.py:1` | yes | 1 |
| NO_AI_DISCLOSURE | function | `zz_seeded/disclosure/function/chat.py:2` | yes | 2 |
| NO_AI_DISCLOSURE | class | `zz_seeded/disclosure/class/agent.py:2` | yes | 2 |
| AUTO_DECISION | direct | `zz_seeded/decision/direct/decision.py:2` | yes | 2 |
| AUTO_DECISION | function | `zz_seeded/decision/function/review.py:4` | yes | 4 |
| AUTO_DECISION | class | `zz_seeded/decision/class/underwriting.py:5` | yes | 5 |
| CORS_WILDCARD | direct | `zz_seeded/cors/direct/app.py:4` | yes | 4 |
| CORS_WILDCARD | function | `zz_seeded/cors/function/configure.py:2` | yes | 2 |
| CORS_WILDCARD | class | `zz_seeded/cors/class/service.py:3` | yes | 3 |
| SENSITIVE_DATA | direct | `zz_seeded/data/direct/passport_scan.pdf:1` | yes | N/A |
| SENSITIVE_DATA | nested | `zz_seeded/data/nested/finance/bank_statement_2026.csv:1` | yes | N/A |
| SENSITIVE_DATA | class | `zz_seeded/data/class/credit_report.xlsx:1` | yes | N/A |
| HTTP_NO_AUTH | direct | `zz_seeded/http/direct/app.py:4` | yes | 72 |
| HTTP_NO_AUTH | nested | `zz_seeded/http/nested/routes.py:4` | yes | 72 |
| HTTP_NO_AUTH | call | `zz_seeded/http/call/handlers.js:3` | yes | 72 |
| SAFETY_BYPASS | direct | `zz_seeded/bypass/direct/transfer.py:1` | yes | 1 |
| SAFETY_BYPASS | function | `zz_seeded/bypass/function/transfer.py:2` | yes | 2 |
| SAFETY_BYPASS | class | `zz_seeded/bypass/class/payments.py:3` | yes | 3 |
| UNSAFE_DESERIALIZE | direct | `zz_seeded/deserialize/direct/load.py:3` | yes | 3 |
| UNSAFE_DESERIALIZE | function | `zz_seeded/deserialize/function/yaml_load.py:3` | yes | 3 |
| UNSAFE_DESERIALIZE | class | `zz_seeded/deserialize/class/torch_load.py:4` | yes | 4 |
| ERROR_LEAKAGE | direct | `zz_seeded/leakage/direct/api.py:5` | yes | 5 |
| ERROR_LEAKAGE | function | `zz_seeded/leakage/function/handler.py:6` | yes | 6 |
| ERROR_LEAKAGE | class | `zz_seeded/leakage/class/response.py:4` | yes | 4 |

## Baseline scan (unmodified copy)

Findings before seeding: 21.

| Rule | Findings |
|---|---:|
| HTTP_NO_AUTH | 1 |
| NO_AI_DISCLOSURE | 2 |
| NO_HUMAN_LOOP | 9 |
| NO_LOGGING | 9 |

## Counter-evidence (do not generalise)

All 36 seeds are canonical constructs the rules were written to match; none is an evasion
variant. In the same verification run the evasion corpus met stated intent on 0/27 cases
(V2, n=27), and the third-party comparison missed 1 of 5 covered Bandit instances, 1 of 2
Semgrep CORS instances, and 2 of 4 Semgrep IAM blocks (V1b). The 36/36 here must not be
read as a real-world recall estimate.

## Interpretation limits

- These are deliberately planted defects. The seed set is small (n=36) and comes from one repository.
- Detection is credited only when the target rule cites the seeded file (or lists it in `extraFiles` for the project-level rules).
- A missed seed is a real miss for that placement; it is not evidence about any other repository.
- No detector was changed to improve this number.
