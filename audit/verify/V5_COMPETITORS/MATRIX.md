# V5 — competitor matrix (redo, 2026-11-15)

**Every capability claim below is UNVERIFIED.** No competitor tool was installed
or run for this matrix. What is verified is repository metadata (stars, licence,
last push), package metadata (name, version, licence, summary) and the text of
vendor READMEs. Those are marked **VERIFIED (metadata)** or **VERIFIED (vendor
text)**, which means the vendor said it, not that it is true.

The previous matrix in `audit/COMPETITOR_MATRIX.md` (2026-11-12) is superseded
where it conflicts with this file. Two corrections are recorded in §5.

## 1. Matrix

| Tool | Vendor's own description | Category | Static / runtime | EU articles claimed | Languages / scope | Local / offline | Artefacts | Licence | Version, stars, last push | Evidence status |
|---|---|---|---|---|---|---|---|---|---|---|
| **AIR Blackbox** (`air-blackbox` CLI) | "The flight recorder for autonomous AI agents. Record, replay, enforce, audit." | Agent audit + EU AI Act scanner + runtime gate | Both: `comply` is static; gateway/gate is runtime | "Articles 9-15" (README); "51 checks across Articles 9-12, 14-15" (org repo description); "6 EU AI Act articles" (scanner repo) | Python, Jupyter, TypeScript, JavaScript, Java, Kotlin | "runs locally, sends code nowhere" | CLI; JSON? not stated in README; `.air-evidence` for runtime | Apache-2.0 | 1.17.0 (PyPI); 25 stars; pushed 2026-11-13 | **UNVERIFIED** |
| **AIR Blackbox MCP** | "MCP server for AIR Blackbox. Expose audit, replay, scan, and compliance tools to any MCP-compatible agent or IDE." | MCP surface over the same scanner/runtime | Both | Inherits the scanner | Same as CLI, through MCP tools | Local MCP server | MCP tool responses | Apache-2.0 | 3 stars; pushed 2026-10-15 | **UNVERIFIED** |
| **shadowaudit → CapFence** | "ShadowAudit has been renamed to CapFence." CapFence: "authorization gateway for AI agent side effects." | Runtime authorization gateway | Runtime only | None claimed in the README | Agent tool calls: shell, DB, filesystem, payment, API, MCP | Local library / gateway | Allow / deny / approval decision; JSONL audit replay | MIT | shadowaudit 0.6.3 (deprecated); CapFence 0.9.0; 8 stars; pushed 2026-07-29 | **UNVERIFIED** |
| **compliance-agent** | "Check if your AI project follows EU rules." | EU AI Act static scanner | Static | EU AI Act, article list not enumerated in the README head | Python projects; detects OpenAI, Anthropic, LangChain | Local CLI | Terminal report, PDF (PyPI metadata lists WeasyPrint) | MIT | 0.6.1; 4 stars; pushed 2026-10-24 | **UNVERIFIED** |
| **sentinel-kernel** | "Prove your AI decisions to the auditor. In Python. In five minutes." | Runtime evidence / audit trail | Runtime only | "Art. 12/13/14/17 evidence" (PyPI summary); "Art. 12 / Art. 17" (README) | Python decorator | "Runs fully offline"; air-gapped | Signed PDF evidence pack; `audit-gap` score | Apache-2.0 (PyPI); GitHub reports NOASSERTION | 3.4.3; 5 stars; pushed 2026-10-21 | **UNVERIFIED** |
| **vaara** | "A verifiable receipt for every autonomous action, checkable by anyone." | Runtime policy gate + tamper-evident audit | Runtime only | "under the EU AI Act" (PyPI summary); no article-by-article claim in the README head | Python; TypeScript client; MCP proxy | Local; "Your environment, no SaaS, no telemetry" | Hash-chained audit DB; signed receipts; offline verifier page | AGPL-3.0 | 2.17.0; 15 stars; pushed 2026-11-14 | **UNVERIFIED** |

## 2. Vendor quotes and where they came from

Quotations are exact. Square brackets mark an omission.

### AIR Blackbox

Source: `https://github.com/airblackbox/airblackbox` README, read 2026-11-15.

> "The flight recorder for autonomous AI agents. Record, replay, enforce, audit."

> "`air-blackbox comply` reads a codebase and reports gaps against the EU AI Act
> (Articles 9-15), GDPR and US state AI laws."

> "It runs locally, sends code nowhere, and is Apache 2.0."

> "We ran AIR and three other open-source EU AI Act scanners [...] on the same
> 144 hand-labelled programs, in six languages and forms."

The last sentence is the vendor's own benchmark. It is not independent, the
labels are the vendor's, and the programs are not published in a form this
review could re-score. It is recorded as a vendor claim, not as evidence that
AIR Blackbox is more accurate than the others.

**Inconsistency worth noting.** Three AIR Blackbox surfaces state different
coverage:

- `airblackbox/airblackbox` README: "Articles 9-15".
- The GitHub org repo description: "51 checks across Articles 9-12, 14-15".
- `airblackbox/scanner` README: "20+ automated checks to 6 EU AI Act articles".

These can all be true at once only if "checks", "articles" and "coverage" mean
different things on each surface. A buyer should ask which number appears in the
report they will actually receive.

Source for the CLI surface: `https://github.com/airblackbox/scanner` README.

> "The CLI adds a **fine-tuned AI model** that runs locally alongside the
> rule-based engine."

> "pip install air-blackbox"

> "air-blackbox comply --scan . -v --deep"

This is the "main CLI too" item: the CLI is a hybrid of regex checks and a local
model, not only the MCP server. The MCP repo is a separate delivery surface.

### shadowaudit → CapFence

Source: `https://pypi.org/project/shadowaudit/`, read 2026-11-15.

> "**Deprecated:** ShadowAudit has been renamed to **CapFence**."

Source: `https://pypi.org/project/capfence/` and
`https://github.com/capfencelabs/capfence`, read 2026-11-15.

> "Authorization gateway for AI agent side effects."

> "Models may propose actions. CapFence decides whether those actions are
> allowed before execution."

CapFence is a runtime authorization product. It does not claim to scan source
code against the EU AI Act. It is therefore **not a like-for-like competitor** to
a static scanner; it competes with the runtime half of AIR Blackbox and with
`SAFETY_BYPASS` only in spirit.

### compliance-agent

Source: `https://pypi.org/project/compliance-agent/` and the linked README,
read 2026-11-15.

> "Check if your AI project follows EU rules."

> "This tool gives you a fast, automated first pass — one command, about 5
> seconds. It is a heuristic aid, not legal advice, and does not by itself
> establish compliance."

The second sentence is a more careful public claim than this project's own
README makes. It is quoted here because it is the standard a buyer will apply to
both tools.

### sentinel-kernel

Source: `https://github.com/sebastianweiss83/sentinel-kernel` README and
`https://pypi.org/project/sentinel-kernel/`, read 2026-11-15.

> "Prove your AI decisions to the auditor. In Python. In five minutes."

> "One decorator. One command. One signed PDF evidence pack. Runs fully offline."

> "Sentinel is **the cryptographic evidence layer for regulated AI**."

Sentinel is runtime evidence, not static scanning. It does not claim to find
missing human-oversight code before deployment; it claims to prove what happened
after deployment. The GitHub licence API reports `NOASSERTION` while PyPI says
Apache License; that discrepancy is recorded, not resolved.

### vaara

Source: `https://github.com/vaaraio/vaara` README and
`https://pypi.org/project/vaara/`, read 2026-11-15.

> "A verifiable receipt for every autonomous action, checkable by anyone."

> "Every call to a governed function is risk-scored and decided against your
> policy before the body runs."

> "a hash-chained, tamper-evident record anyone can verify offline"

Vaara is runtime policy plus evidence. It does not scan a repository for missing
disclosures or unlogged actions. Its own README states the limits of a passing
receipt check, which is a good sign for honesty but does not verify the product.

## 3. What the matrix actually supports

| Buyer question | Answer supported by this matrix |
|---|---|
| Who else scans code for EU AI Act gaps? | AIR Blackbox (`air-blackbox comply`) and compliance-agent. Both are UNVERIFIED here. |
| Who does runtime authorization? | CapFence (formerly shadowaudit), AIR Blackbox gate/gateway, vaara. |
| Who produces audit evidence at runtime? | sentinel-kernel, vaara, AIR Blackbox. |
| Who does all three? | AIR Blackbox claims all three. That claim is UNVERIFIED. |
| Is there a direct, independent accuracy comparison? | No. AIR Blackbox publishes its own benchmark; this review did not run it or reproduce it. |
| Is any competitor's legal mapping counsel-reviewed? | Not stated by any vendor read here. Do not assume it. |

## 4. Where this project stands against them

This section is about positioning, not detection quality. It does not change any
finding in V2 or V3.

- **Static EU AI Act scanning** is contested. AIR Blackbox has more languages,
  more checks by its own count, and a local model. compliance-agent is a
  one-command Python scanner with a PDF. This project's only clear static
  differentiators are the agent-action rules (`NO_HUMAN_LOOP`, `NO_LOGGING`,
  `SAFETY_BYPASS`) and the plain-language HTML report. Both are unverified as
  differentiators in a buyer's hands.
- **Runtime authorization** is not this project's category. CapFence, vaara and
  AIR Blackbox gate tool calls before execution; this project cannot.
- **Evidence packs** are not this project's category. sentinel-kernel and vaara
  produce signed, offline-verifiable records; this project produces a JSON/HTML
  report with no signature and no hash chain.
- **The honest niche** remains the offline, zero-config first pass for a small
  team that wants prompts for human review, with an explicit "not a compliance
  assessment" label. That niche is narrower than the README implies.

## 5. Corrections to the 2026-11-12 matrix

1. **shadowaudit is a real product, under a new name.** The earlier note said no
   verifiable AI-agent compliance product by that name existed. That was wrong
   as of 2026-11-15: `shadowaudit` 0.6.3 is on PyPI and is deprecated in favour
   of `capfence` 0.9.0. It is a runtime authorization gateway, not a static
   scanner, so it should not be placed in the static-scanner column.
2. **AIR Blackbox is not only an MCP server.** The main deliverable is the
   `air-blackbox` CLI (PyPI 1.17.0), with `air-blackbox comply` as the static
   scan command. The MCP repo is one surface. The earlier matrix listed only the
   MCP repo.

Two things in the earlier matrix still hold: the competitor claims were vendor
statements, and no independent precision benchmark had been run. Neither has
changed.

## 6. What was not done

- No competitor was installed, invoked, or scored. Every capability row is
  UNVERIFIED.
- No vendor benchmark was reproduced. AIR Blackbox's 144-program benchmark is
  cited as a vendor claim only.
- No pricing was compared. Four of the five are open source; hosted tiers, if
  any, were not priced.
- No security review of any competitor was performed.
