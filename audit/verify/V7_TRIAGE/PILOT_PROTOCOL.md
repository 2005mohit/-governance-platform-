# V7 — pilot protocol for a real-repository trial

Status: **proposed protocol. Not executed.** No pilot has been run. This
document exists so that a pilot cannot be started informally and then
retrofitted with rules. It is written for the case where a small number of
teams agree to run `ai-risk-snapshot` on their own repositories and let the
author see the output.

It does not replace a data-processing agreement, an ethics review, or legal
advice. Those are institution-specific.

## 1. What the pilot is and is not

**Is:** a usability and false-positive study. The question is "when a real
team runs this on a real repo, what does it see, what does it do with it, and
where is the report wrong or unhelpful?"

**Is not:** an accuracy benchmark (V2/V3 cover that), a compliance
assessment, or a security audit. A pilot participant must not be told that a
clean report means anything about compliance.

## 2. Roles

| Role | Who | Responsibility |
|---|---|---|
| Participant | The team whose repository is scanned | Decides scope, gives consent, may withdraw |
| Operator | Person who runs the scan | Runs the CLI under the participant's control; does not copy the tree |
| Analyst | Person who reads the output | Works only from files the participant has released |
| Reviewer | Second person, independent of the Analyst | Checks any published claim against the released files |
| Data owner | Named individual at the participant | Single contact for consent, withdrawal and incidents |

One person may not be both Analyst and Reviewer for anything that is
published.

## 3. Data handling

### 3.1 The scan is local and read-only

The tool reads files and writes a report directory. It does not upload,
phone home, or write into the scanned tree. The operator runs it on the
participant's machine or in a session the participant observes.

### 3.2 What leaves the participant's control

Only these files, and only after the participant has read them:

| File | Contents | Default |
|---|---|---|
| `report.json` | finding metadata, file paths, one-line snippets | Requested |
| `verification.json` | citation status, hashes, no code | Requested |
| `triage.json` | human decisions and notes | Optional |
| `report.html` | rendered report, same content as JSON | Optional |

Source files are **never** sent. If a question cannot be answered from the
report, the participant pastes the relevant lines; the analyst does not ask
for the repository.

### 3.3 Redaction is partial, and the participant must know that

The scanner masks four PII shapes (email, dashed SSN, separated card number,
phone with separators) and masks the matched substring of a detected secret.
It does **not** remove:

- the rest of the line around a redacted secret (variable names, nearby
  literals, comments);
- file and directory names, which can themselves identify a customer, a
  product, or a person;
- `SENSITIVE_DATA` findings, whose evidence **is** the filename
  (`passport_scan.pdf`, `bank_statement_2026.csv`);
- non-secret business logic that happens to match a rule.

So before any file leaves the participant, the participant reads it. If a
filename or snippet is sensitive, the participant removes it or the finding
is excluded. The analyst records the exclusion, and the exclusion is
reported as a number, not silently.

### 3.4 Storage during the pilot

- Raw reports: encrypted at rest, access limited to Analyst and Reviewer.
- Working copies: the participant's own machine, deleted at end of session.
- No reports in a public repository, a shared drive, or a chat tool.
- No reports committed to the `ai-risk-snapshot` repo. `audit/` already holds
  only aggregate counts from V1–V7, not pilot data.

## 4. Consent terms

Consent is written, signed by the Data owner, and states:

1. **Scope** — which repository, which commit, which directories are
   excluded.
2. **Purpose** — usability and false-positive study only; not marketing, not
   a case study, unless a separate publication consent is signed.
3. **What is shared** — the file list in §3.2.
4. **What is published** — either "nothing", "aggregate counts only", or a
   named quotation list the participant approves line by line.
5. **Duration** — the retention period in §5.
6. **Withdrawal** — how, and what happens (§6).
7. **No legal effect** — the report is not an audit, a certification, or
   advice, and the participant will not represent it as one.
8. **No fee and no warranty** — the tool is provided as-is.

A verbal "go ahead" is not consent. Consent must be recorded before the first
scan.

## 5. Retention

| Data | Retention | Then |
|---|---|---|
| Raw report files | 90 days from receipt | Delete; keep only the SHA-256 in the pilot log |
| Snippets in analyst notes | 30 days | Delete; keep the finding fingerprint and the conclusion |
| Consent records | Duration of pilot + 12 months | Delete, or retain if required by the participant's policy |
| Published aggregates | Indefinite | Must not permit re-identification |

The pilot log is a table of `{participant code, commit, report SHA-256,
received date, deleted date}`. It contains no snippets. It is what makes
"we deleted it" checkable.

## 6. Withdrawal

A participant may withdraw at any time, for any reason, with no explanation.

- Withdrawal is effective on written notice to the Data owner.
- Within 10 working days: raw reports, notes, and derived quotations are
  deleted from every location the analyst controls, including backups within
  one backup cycle.
- Aggregate counts already published are **not** retroactively removed, but
  the participant code is retired and no further data is added.
- The pilot log records the withdrawal date and confirms deletion. It keeps
  the SHA-256 so that a later claim "this report was deleted" can be checked
  against a file if one ever surfaces.

Withdrawal is not conditional on the participant giving a reason, and the
analyst does not argue with it.

## 7. Secret handling

If a scan surfaces a live credential, this takes priority over the study:

1. **Stop.** Do not copy the line into notes, chat, a ticket, or this repo.
2. Tell the Data owner which rule fired and on which file:line. Do not send
   the value.
3. The Data owner rotates the credential and removes it from history. The
   analyst does not attempt to verify the credential works.
4. The finding is recorded as `IDENTITY_KEY`, file path, severity, and
   "value withheld". The rotated secret is never written down.
5. If the credential appears to belong to a third party (a vendor key,
   a cloud account not owned by the participant), the Data owner decides
   whether to notify that party. The analyst does not contact them
   independently.

The scanner's own masking is a safety net, not a licence to handle secrets
carelessly. A masked snippet can still show enough of a line to identify a
key's purpose.

## 8. Publication

Default: nothing is published except aggregate counts.

If a participant wants a named case study, all of the following are
required:

- Separate written publication consent, naming the participant and the
  exact text to be published.
- Reviewer sign-off that every number in the text matches the released
  files.
- Every finding mentioned is labelled with its triage status
  (`true_positive`, `false_positive`, `context`, `accepted_risk`).
- No claim about the participant's compliance posture.
- The limitations paragraph from `audit/verify/V4_LEGAL/LIMITATIONS_PARAGRAPH.md`
  is reproduced, not paraphrased.
- A right of review before publication, with a stated response window.

Aggregate publication follows V2's rule: plain and evasion results are
reported separately, every number carries its sample size `(n=...)`, and no
headline single number is used.

## 9. Incident response

An incident is any of: a report reaches someone outside Analyst/Reviewer/
Data owner; a secret is copied into notes or a ticket; a report is committed
to a public repository; a participant's identity is disclosed without
consent.

Response, in order:

1. **Contain** — revoke the share, delete the public copy, rotate the secret.
   Do this before analysis.
2. **Notify** — the Data owner within 24 hours; the participant within 48
   hours if their data or identity is involved.
3. **Record** — date, what leaked, where, how it was contained, who was told.
   No snippets in the record.
4. **Fix** — the process change that prevents recurrence, written down.
5. **Review** — the Reviewer confirms containment. If a secret leaked, the
   Data owner decides on notification to any third party.

The incident record is retained with the pilot log and is available to the
participant on request.

## 10. What a pilot can and cannot produce

A pilot can produce: how long a scan takes on a real tree, which rules fire
most, how often a human disagrees with a finding, which report wording
confuses people, and how many findings a team actually acts on.

A pilot cannot produce: a precision or recall estimate, a compliance
conclusion, or a comparison with a competitor. Those need labelled ground
truth and independent execution, which this protocol does not provide.
