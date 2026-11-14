# Corpus regression tests

Fixtures copied from the local audit corpus (`audit/corpus/`, which is not
tracked in git). `manifest.json` records, per case, the rule under test, the
stated-intent expectation (`target` + `expect`), the case kind, and a note.

`test/corpus.test.js` scans every case directory in isolation and compares the
observed rule-id set with `expected.json`. The snapshot is deliberately the
*observed* set, not the stated intent: the audit corpus contains known misses
and false positives, and pinning them makes any drift visible. Regenerate only
after an intentional detection change:

```
node test/corpus.test.js --update
```

Groups are kept separate and are never averaged into one number:

- `plain` — positive, negative, false-positive and AST cases;
- `evasion` — deliberate evasion attempts, reported on their own line;
- `framework` — tool-registration/framework detection, reported on its own
  line (the metric is "cases exposing an agent-tool finding").

The test also prints, per group, how many cases match the manifest's stated
intent. Those counts are informational and describe the known gaps; pass/fail
is the exact pinned set.

`ast-dependent.json` lists the four cases whose outcome changes when Python is
unavailable. On a machine without Python those cases are skipped and the skip
is printed; CI installs Python 3.12 so the full set runs there.
