# V4 — EU AI Act mapping (author review, not legal advice)

Status of every row: **AUTHOR-REVIEWED vs PRIMARY TEXT, NOT COUNSEL-REVIEWED**

Source of the quoted text: Regulation (EU) 2024/1689 as reproduced by the
AI Act Explorer (`artificialintelligenceact.eu/article/<n>/`), read on
2026-11-15. EUR-Lex returned HTTP 202 with an empty body to automated requests
for both the HTML and PDF endpoints, so the official EUR-Lex rendering could not
be read directly. The reproduction is a third-party copy of the primary text;
quotes were checked against that copy, not against the Official Journal PDF.
This is a provenance limitation, not a claim that the text differs.

## Column meanings

- **Rule** — rule id in `rules/eu_ai_act.yaml` at rule-pack SHA-256
  `9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`.
- **Provision** — article and paragraph relied on. Sub-points are given where
  the rule depends on one.
- **Quote** — fewer than 15 words, copied verbatim from the provision. Word
  counts exclude the quotation marks.
- **Provider / deployer** — who carries the duty in that provision. Where the
  provision splits the duty, both are named.
- **High-risk only?** — whether the provision sits in the Chapter III Section 2
  requirements that apply only to high-risk AI systems.
- **Mapping strength** — how closely the static check corresponds to the legal
  obligation. `strong` = the check tests the thing the provision requires;
  `moderate` = the check is a proxy for it; `weak` = the check is at best
  adjacent, and compliance cannot be inferred from a clean result.
- **Why** — the reason for the strength rating, stated against the rule's
  actual detector behaviour, not its title.

## Table

| Rule | Provision | Quote (<15 words) | Provider / deployer | High-risk only? | Mapping strength | Why |
|---|---|---|---|---|---|---|
| `IDENTITY_KEY` | Art. 15(1) | "achieve an appropriate level of accuracy, robustness, and cybersecurity" (9) | Provider | Yes | weak | A committed credential is a security-hygiene defect. Art. 15(1) requires an appropriate level of cybersecurity overall; it does not name credentials, secret storage, or rotation. A clean scan does not show the required level is met. |
| `IAM_WILDCARD` | Art. 15(7) | "resilient against attempts by unauthorised third parties to alter their use, outputs" (12) | Provider | Yes | weak | Art. 15(7) is about resilience to manipulation of the system's use, outputs or performance. An over-broad cloud IAM policy is an access-control weakness; it is not by itself an AI-specific manipulation path, and the rule sees only IaC text. |
| `NO_HUMAN_LOOP` | Art. 14(1); Art. 14(4)(d) | "effectively overseen by natural persons during the period in which they are in use" (14) | Provider (design); deployer (operation) | Yes | strong | The rule fires when a listed high-risk action has no approval marker within 15 lines. That is close to the Art. 14(1) design duty and the Art. 14(4)(d) ability to refrain. It cannot see oversight that lives in another service or in organisational process, so a finding is a prompt for review, not proof of breach. |
| `NO_LOGGING` | Art. 12(1) | "technically allow for the automatic recording of events (logs) over the lifetime" (12) | Provider | Yes | strong | The rule looks for logging near a high-risk action. Art. 12(1) requires automatic recording of events over the system lifetime. The rule does not test log retention, integrity, or the Art. 12(3) minimum content, so it covers the existence of logging, not its adequacy. |
| `NO_AI_DISCLOSURE` | Art. 50(1) | "natural persons concerned are informed that they are interacting with an AI system" (13) | Provider (Art. 50(1)); deployer (Art. 50(3)–(4)) | No | moderate | The rule infers a missing disclosure from a system prompt that lacks a disclosure phrase. Art. 50(1) is about what the natural person is told, which may be rendered by UI code the rule never sees. It is a proxy, and it can be both over- and under-inclusive. |
| `HTTP_NO_AUTH` | Art. 15(7) | "resilient against attempts by unauthorised third parties to alter their use, outputs" (12) | Provider | Yes | weak | An unauthenticated route is a general application-security defect. Art. 15(7) targets resilience to manipulation of the AI system; the rule does not establish that the route reaches a model, nor that authentication is the required control. |
| `AUTO_DECISION` | Art. 14(4)(d); Art. 14(5) | "to decide, in any particular situation, not to use the high-risk AI system" (13) | Provider (design); deployer (operation) | Yes | moderate | The rule looks for a status assignment such as `approved`/`rejected`. Art. 14 requires effective oversight and, for Annex III point 1(a), separate verification by two natural persons. The rule does not establish that the decision is solely automated or that the system is Annex III 1(a). |
| `CORS_WILDCARD` | Art. 15(7) | "resilient against attempts by unauthorised third parties to alter their use, outputs" (12) | Provider | Yes | weak | A wildcard CORS policy is a web-security weakness. Art. 15(7) is about manipulation of the AI system's use, outputs or performance. The link is indirect and the rule cannot see whether the affected origin exposes model output or control. |
| `SENSITIVE_DATA` | Art. 10(2) | "Training, validation and testing data sets shall be subject to data governance" (12) | Provider | Yes | weak | The rule detects committed documents by filename and extension. Art. 10(2) is about governance of training, validation and testing data sets. A committed payslip or passport scan is not necessarily training data, and the rule cannot assess lawfulness, bias, or representativeness. |
| `UNSAFE_DESERIALIZE` | Art. 15(7) | "alter their use, outputs or performance by exploiting system vulnerabilities" (10) | Provider | Yes | moderate | The rule detects `pickle`/`yaml.load`/`torch.load` style deserialisation. That is a concrete exploitation path of the kind Art. 15(7) addresses, but the rule cannot show the data is untrusted or that the system is high-risk. |
| `ERROR_LEAKAGE` | Art. 15(1) | "achieve an appropriate level of accuracy, robustness, and cybersecurity" (9) | Provider | Yes | weak | Returning exception text to a caller is an information-disclosure weakness. Art. 15(1) sets an overall cybersecurity level; it does not address error handling. The mapping is adjacency, not correspondence. |
| `SAFETY_BYPASS` | Art. 14(4)(d) | "to decide, in any particular situation, not to use the high-risk AI system" (13) | Provider (design); deployer (operation) | Yes | moderate | The rule detects a bypass/disable flag near a high-risk action. Art. 14(4)(d) requires the ability to refrain and override. A bypass flag can remove that ability, but the rule cannot tell whether the flag is reachable in production or is test-only. |

## What this table does not say

- It does not say any scanned repository is compliant or non-compliant.
- It does not treat a clean scan as evidence of conformity assessment, which
  Art. 43 governs separately and which no rule in this pack tests.
- It does not map `NO_HUMAN_LOOP`, `AUTO_DECISION` or `SAFETY_BYPASS` to the
  GDPR Article 22 right not to be subject to solely automated decisions. That
  is a separate instrument and is outside this table.
- It does not cover Art. 9 (risk management), Art. 13 (instructions for use),
  Art. 17 (quality management), Art. 26 (deployer obligations) or Art. 72
  (post-market monitoring), because no rule in the pack claims them.
