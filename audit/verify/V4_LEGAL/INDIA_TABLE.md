# V4 — India mapping (author review, not legal advice)

Status of every row: **AUTHOR-REVIEWED vs PRIMARY TEXT, NOT COUNSEL-REVIEWED**

These are **proposed** India rules. They are design entries in
`audit/INDIA_PACK_DESIGN.md`; no India rule is present in
`rules/eu_ai_act.yaml` at rule-pack SHA-256
`9c0f00b8e00511275d0fef86f3acc70db48dab31037c77b80296e8b761062a34`.
Nothing in this table reports a detector that exists. A row marked as mapped
describes an intended check, not an observed result.

## Sources of the quoted text

| Instrument | Source read | Date | Note |
|---|---|---|---|
| Digital Personal Data Protection Act, 2023 (Act 22 of 2023) | MeitY PDF, `meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf` | 2026-11-15 | Gazette text extracted with `pypdf`; 21 pages. |
| CERT-In Directions under s.70B(6), IT Act (No. 20 of 2000), dated 28 April 2022 | `cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf` | 2026-11-15 | 8 pages; paragraph numbering taken from the PDF body. |
| Digital Personal Data Protection Rules, 2025 | **not retrieved** | — | Rule 7 (breach notification timeline) is **not** quoted or reviewed. No claim is made about it. |

## Column meanings

- **Rule (proposed)** — proposed id only; no detector exists.
- **Provision** — section and sub-section, or CERT-In direction paragraph.
- **Quote** — fewer than 15 words, verbatim from the source above.
- **Fiduciary / processor** — who carries the duty. For CERT-In, the class of
  entity named in the direction.
- **Risk-tiered?** — whether the duty applies only to a notified class
  (for example Significant Data Fiduciaries) rather than to all fiduciaries.
- **Mapping strength** — as in the EU table: `strong` = the intended check
  tests the thing the provision requires; `moderate` = proxy; `weak` = adjacent.
- **What a static check could and could not see** — written against the
  intended detector in `INDIA_PACK_DESIGN.md`.

## Table

| Rule (proposed) | Provision | Quote (<15 words) | Fiduciary / processor | Risk-tiered? | Mapping strength | What a static check could and could not see |
|---|---|---|---|---|---|---|
| `IN_DPDP_NOTICE` | s.5(1) | "accompanied or preceded by a notice given by the Data Fiduciary" (11) | Data Fiduciary | No | moderate | Could see a consent call with no notice text, purpose, or rights link in the same module. Could not see a notice rendered by a shared component or a CMS. The provision requires notice before or with the consent request; absence in one file is not absence in the product. |
| `IN_DPDP_CONSENT_QUALITY` | s.6(1) | "free, specific, informed, unconditional and unambiguous with a clear affirmative action" (11) | Data Fiduciary | No | weak | Could see pre-ticked defaults, "by continuing you agree" copy, or bundled purposes in UI literals. Could not see the rendered flow, the wording actually shown, or whether consent was later withdrawn. Consent quality is a behavioural and UX question. |
| `IN_DPDP_SECURITY` | s.8(5) | "taking reasonable security safeguards to prevent personal data breach" (9) | Data Fiduciary; Data Processor acts on its behalf | No | moderate | Could see plaintext PII columns, public storage configuration, or `http://` endpoints. Could not see key management, access review, encryption at rest, or incident response. "Reasonable" is context-dependent and not testable by pattern. |
| `IN_DPDP_BREACH` | s.8(6) | "intimation of such breach in such form and manner as may be prescribed" (13) | Data Fiduciary | No | weak | Could see whether a breach-notification code path exists. Could not see whether it fires, to whom, or within the period set by the rules. The Act fixes no number of hours; rule 7 was not reviewed. |
| `IN_DPDP_ERASURE` | s.8(7)(a) | "erase personal data, upon the Data Principal withdrawing her consent" (10) | Data Fiduciary; Data Processor on instruction | No | weak | Could see a consent-withdrawal handler with no delete call nearby. Could not see retention schedules, backups, or downstream processors. Erasure is a runtime and organisational property. |
| `IN_DPDP_CHILD_CONSENT` | s.9(1) | "obtain verifiable consent of the parent of such child" (9) | Data Fiduciary | No | moderate | Could see an age gate or child-directed flow without a parental-consent path. Could not verify that consent is verifiable, or that the user is in fact a child. The provision also bans tracking and targeted advertising to children; a static check does not see either. |
| `IN_DPDP_SDF` | s.10(2)(a); s.10(2)(c)(i) | "appoint a Data Protection Officer" (5); "periodic Data Protection Impact Assessment" (5) | Significant Data Fiduciary | Yes (notified SDFs only) | weak | Could see configuration for a DPO contact or a DPIA template. Could not see appointment, independence, board reporting, audit, or whether the entity is a notified SDF. Most of s.10 is organisational. |
| `IN_DPDP_CROSS_BORDER` | s.16(1) | "restrict the transfer of personal data by a Data Fiduciary for processing" (12) | Data Fiduciary | No | weak | Could see a data-residency configuration or an outbound transfer call. Could not see the destination country, whether it is notified, or whether a restriction applies. At the date of review no country had been notified under s.16(1). |
| `IN_CERTIN_INCIDENT_6H` | CERT-In Directions (ii) | "within 6 hours of noticing such incidents or being brought to notice" (12) | Service providers, intermediaries, data centres, body corporates, Government organisations | No (class-based, not risk-tiered) | moderate | Could see whether an incident-reporting call exists. Could not measure six hours, could not see whether the report reaches CERT-In, and could not see "noticing". The check would test the presence of a path, not the duty. |
| `IN_CERTIN_LOGS_180D` | CERT-In Directions (iv) | "maintain them securely for a rolling period of 180 days" (10) | Same class as above | No (class-based, not risk-tiered) | moderate | Could see whether logging is configured and whether a retention setting is present. Could not see actual retention, secure storage, or that logs remain within Indian jurisdiction. A configured number is not evidence of the rolling period. |

## Two points a reader must not skip

1. **The Act does not set the breach clock.** s.8(6) says "such form and manner
   as may be prescribed". The often-quoted 72-hour figure comes from the DPDP
   Rules, which were not retrieved for this review. Do not attribute a number
   of hours to s.8(6).
2. **CERT-In is secondary legislation.** The Directions are issued under
   s.70B(6) of the IT Act, not under the DPDP Act. A repository can be outside
   the named classes and still process personal data. The two instruments are
   mapped on separate rows for that reason.

## What this table does not say

- It does not say any repository complies with the DPDP Act or the CERT-In
  Directions.
- It does not treat the proposed rules as implemented, tested, or approved.
- It does not cover the DPDP Rules, the IT Act apart from s.70B(6), sectoral
  regulators (RBI, SEBI, IRDAI), or state-level rules.
- It does not decide whether an AI agent that processes personal data is a Data
  Fiduciary or a Data Processor; that is a facts-specific question.
