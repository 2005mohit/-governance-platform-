# Labelling criteria (V1)

Status: protocol fixed before any sheet was generated. The author of this file
is the tool author, not an independent labeller. It defines what the two human
labellers are asked to decide; it does not supply any labels.

## What is being measured

Precision of the sampled findings only. Recall is not measurable from this
sheet: it contains no un-flagged code. Do not compute or quote a recall figure
from these CSVs.

## Unit of judgement

One row is one finding at one pinned file:line. Labellers see:

- `finding_id` — random, assigned after a deterministic shuffle;
- `file` — a repository alias plus repo-relative path (`repoA/...`);
- `line` — 1-based line number;
- `snippet` — the scanner's short excerpt, exactly as it will appear in a
  report (secrets are withheld, PII is redacted).

Labellers do **not** see the rule id, the rule's intent, the scanner's method
(`proximity-heuristic` / `ast-same-function`), the confidence label/weight, or
the other labeller's sheet. `finding_map.json` contains those fields and is
for the kappa calculation only.

## Labels

Use exactly one of `TP`, `FP`, `CONTEXT` in the `label` column.

- **TP** — the cited code really does contain the condition the finding claims,
  at or within the cited line, and it is a genuine instance rather than a
  comment, string, test fixture, documentation example, or placeholder. If the
  condition is present but the severity or wording is arguable, still use TP;
  severity is not being labelled.
- **FP** — the cited code does not contain the claimed condition, or the hit is
  a comment/string/definition/placeholder/test-only artefact, or it is a benign
  construct the rule should not treat as the target behaviour.
- **CONTEXT** — the snippet and the surrounding function are not enough to
  decide. Record in `notes` exactly what context is needed (for example:
  "approval may be enforced by a middleware not shown", "this IAM policy is
  attached to a deny-only role", "file is a generated test fixture"). Do not use
  CONTEXT merely because the file is long.

If the line number is off by a few lines but the condition is visible in the
same function, judge the condition, not the line arithmetic, and note the
discrepancy. If the cited line is outside the file at the pinned commit, use
CONTEXT and note "line missing".

## How to inspect

- Open the file at the pinned commit recorded in `REPO_PINS.md`. You may read
  the whole file and the immediately enclosing function/class (±30 lines).
- Do not search the repository for the rule implementation, the scanner's
  documentation, or other findings. Do not compare notes with the other
  labeller until both sheets are complete.
- Do not run the scanner, do not use an LLM, and do not consult
  `labeller_AI.csv`.

## Independence and adjudication

- The two human labellers must work independently. Neither may see the other's
  labels before submission.
- After submission, compute Cohen's kappa. Disagreements are adjudicated by the
  two labellers together (or by a third human); the adjudicated label is stored
  separately and is not retro-fitted into either original sheet.
- No agent, including the one that built the tool, may fill a human sheet or
  act as an adjudicator.

## Metrics

- Cohen's kappa over the three categories `TP`, `FP`, `CONTEXT`, with the
  observed and expected agreement reported alongside it.
- Per-rule agreement (the rule mapping comes from `finding_map.json`).
- A disagreement list with both labels and the needed context.
- `CONTEXT` is reported as its own category. If a binary precision is quoted,
  it must state whether CONTEXT rows were excluded or counted as non-TP, and it
  must carry its own n. No single pooled headline across rules or repositories.

## AI-assisted sheet

`labeller_AI.csv` is optional. If it is ever filled, every row and the file
header must say **"AI-assisted, not independent (agent helped build the tool)"**
and its numbers must never be merged with the human kappa or precision figures.
At the time of this run it is intentionally empty.

## Sampling frame

Up to five findings per rule, pooled across the pinned repositories, selected
deterministically by a hash of repository/path/line/snippet, then shuffled with
a recorded seed. Rules with no findings in the frame are recorded as zero; they
are not back-filled from fixtures or from the project's own corpus.
