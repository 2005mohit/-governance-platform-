# V2 - split corpus report (plain vs evasion/stress)

**No pooled headline.** Plain and evasion cases measure different claims, so they are
reported separately. The corpus test was re-run before this report and exited 0.

- Tool version: 1.2.0
- Rule-pack SHA-256: `9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`
- Corpus manifest SHA-256: `056bb99033b5be10a87b83c84c525308236f62d1bdc36f61cc78bc7698504550`
- Pinned snapshot SHA-256: `d1e0151f1e0e6b12cda590c2ed4f87142d1adfee5b82ac6cd5a8e1f32d46253a`

## Group summary

| Group | Cases (n) | Positive cases | Negative cases | Target-rule correct | Misses | Target false positives |
|---|---:|---:|---:|---:|---:|---:|
| plain | 45 | 17 | 28 | 38/45 (84.4%) | 0 | 7 |
| evasion | 27 | 22 | 5 | 0/27 (0.0%) | 22 | 5 |
| stress | 0 | 0 | 0 | n/a | 0 | 0 |

Framework surface: **5/12 (41.7%)** cases expose an agent-tool surface (n=12).

## Per-rule, split by group

| Rule | Plain correct | Plain misses | Plain FPs | Evasion correct | Evasion misses | Evasion FPs |
|---|---:|---|---:|---:|---|---:|
| AUTO_DECISION | 2/3 (66.7%) | - | ad_fp_js_response | 0/2 (0.0%) | ad_ev_variable, ad_ev_enum | - |
| CORS_WILDCARD | 2/2 (100.0%) | - | - | 0/2 (0.0%) | co_ev_variable, co_ev_express | - |
| ERROR_LEAKAGE | 2/3 (66.7%) | - | el_fp_server_log | 0/2 (0.0%) | el_ev_dot_message, el_ev_traceback | - |
| HTTP_NO_AUTH | 3/3 (100.0%) | - | - | 0/1 (0.0%) | - | ha_ev_middleware |
| IAM_WILDCARD | 3/3 (100.0%) | - | - | 0/2 (0.0%) | iam_ev_list, iam_ev_service | - |
| IDENTITY_KEY | 5/5 (100.0%) | - | - | 0/3 (0.0%) | id_ev_projkey, id_ev_concat, id_ev_github_pat | - |
| NO_AI_DISCLOSURE | 2/2 (100.0%) | - | - | 0/3 (0.0%) | nd_ev_internal_marker, nd_ev_prompt_file | nd_ev_ui_disclosure |
| NO_HUMAN_LOOP | 10/12 (83.3%) | - | nh_neg_or, nh_neg_try | 0/4 (0.0%) | nh_ev_renamed, nh_ev_string_sql, nh_ev_dynamic | nh_ev_helper_guard |
| NO_LOGGING | 3/3 (100.0%) | - | - | 0/2 (0.0%) | - | nl_ev_callee_logging, nl_ev_custom_logger |
| SAFETY_BYPASS | 2/3 (66.7%) | - | sb_fp_validated_var | 0/1 (0.0%) | sb_ev_env_flag | - |
| SENSITIVE_DATA | 1/3 (33.3%) | - | sd_fp_template, sd_fp_1040 | 0/2 (0.0%) | sd_ev_csv, sd_ev_json | - |
| UNSAFE_DESERIALIZE | 3/3 (100.0%) | - | - | 0/3 (0.0%) | ud_ev_dill, ud_ev_eval_req, ud_ev_new_function | - |

## Miss lists (every miss, case level)

### plain

- No positive-case misses.
- FP nh_neg_or (target NO_HUMAN_LOOP); observed rules: NO_HUMAN_LOOP
- FP nh_neg_try (target NO_HUMAN_LOOP); observed rules: NO_HUMAN_LOOP
- FP ad_fp_js_response (target AUTO_DECISION); observed rules: AUTO_DECISION
- FP sd_fp_template (target SENSITIVE_DATA); observed rules: SENSITIVE_DATA
- FP sd_fp_1040 (target SENSITIVE_DATA); observed rules: SENSITIVE_DATA
- FP el_fp_server_log (target ERROR_LEAKAGE); observed rules: ERROR_LEAKAGE
- FP sb_fp_validated_var (target SAFETY_BYPASS); observed rules: SAFETY_BYPASS

### evasion

- MISS id_ev_projkey (target IDENTITY_KEY); observed rules: none
- MISS id_ev_concat (target IDENTITY_KEY); observed rules: none
- MISS id_ev_github_pat (target IDENTITY_KEY); observed rules: none
- MISS iam_ev_list (target IAM_WILDCARD); observed rules: none
- MISS iam_ev_service (target IAM_WILDCARD); observed rules: none
- MISS nh_ev_renamed (target NO_HUMAN_LOOP); observed rules: none
- MISS nh_ev_string_sql (target NO_HUMAN_LOOP); observed rules: none
- MISS nh_ev_dynamic (target NO_HUMAN_LOOP); observed rules: none
- MISS nd_ev_internal_marker (target NO_AI_DISCLOSURE); observed rules: none
- MISS nd_ev_prompt_file (target NO_AI_DISCLOSURE); observed rules: none
- MISS ad_ev_variable (target AUTO_DECISION); observed rules: none
- MISS ad_ev_enum (target AUTO_DECISION); observed rules: none
- MISS co_ev_variable (target CORS_WILDCARD); observed rules: none
- MISS co_ev_express (target CORS_WILDCARD); observed rules: none
- MISS sd_ev_csv (target SENSITIVE_DATA); observed rules: none
- MISS sd_ev_json (target SENSITIVE_DATA); observed rules: none
- MISS ud_ev_dill (target UNSAFE_DESERIALIZE); observed rules: none
- MISS ud_ev_eval_req (target UNSAFE_DESERIALIZE); observed rules: none
- MISS ud_ev_new_function (target UNSAFE_DESERIALIZE); observed rules: none
- MISS el_ev_dot_message (target ERROR_LEAKAGE); observed rules: none
- MISS el_ev_traceback (target ERROR_LEAKAGE); observed rules: none
- MISS sb_ev_env_flag (target SAFETY_BYPASS); observed rules: none
- FP nh_ev_helper_guard (target NO_HUMAN_LOOP); observed rules: NO_HUMAN_LOOP
- FP nl_ev_callee_logging (target NO_LOGGING); observed rules: NO_HUMAN_LOOP, NO_LOGGING
- FP nl_ev_custom_logger (target NO_LOGGING); observed rules: NO_LOGGING
- FP nd_ev_ui_disclosure (target NO_AI_DISCLOSURE); observed rules: NO_AI_DISCLOSURE
- FP ha_ev_middleware (target HTTP_NO_AUTH); observed rules: HTTP_NO_AUTH

## Negative cases where other rules fired

Listed for context only. These are not counted as false positives: the target rule did not fire.

- plain: 0/28 negative cases had another rule fire.
- evasion: 1/5 negative cases had another rule fire.
  - nl_ev_callee_logging: NO_HUMAN_LOOP

## Real-repository counts (V1) — unlabelled, kept separate

Raw findings: 97 across 4 pinned repositories. No human labels exist yet, so these are counts only, not precision or recall.

| Repository | Findings |
|---|---:|
| crewAI | 18 |
| autogen | 44 |
| mcp-servers | 21 |
| mcp-python-sdk | 14 |

| Rule | Findings |
|---|---:|
| CORS_WILDCARD | 6 |
| ERROR_LEAKAGE | 28 |
| HTTP_NO_AUTH | 2 |
| IDENTITY_KEY | 1 |
| NO_AI_DISCLOSURE | 13 |
| NO_HUMAN_LOOP | 23 |
| NO_LOGGING | 20 |
| UNSAFE_DESERIALIZE | 4 |

## How to read this

- A plain miss and an evasion miss are different claims; neither is extrapolated to real repositories.
- The corpus test asserts the pinned per-case rule set, not the stated intent. It passes even where stated intent is not met; those gaps are what this report exposes.
- Nothing here was changed to improve a number.
