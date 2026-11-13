// Rule/article fixture test.
//
// Each fixture under test-rules/ is intentionally small and synthetic. The
// test asserts that the rule fires at least once AND that every emitted
// finding carries the expected legal mapping. This catches a rule whose
// detector still works while its article string has drifted.
const assert = require("assert");
const path = require("path");
const Scanner = require("../src/scanner");

const RULES_PATH = path.join(__dirname, "..", "rules", "eu_ai_act.yaml");
const FIXTURE_ROOT = path.join(__dirname, "..", "test-rules");

const EXPECTED_ARTICLES = {
  SENSITIVE_DATA: "Article 10 (Data and Data Governance); GDPR",
  SAFETY_BYPASS: "Article 14 (Human Oversight)",
  UNSAFE_DESERIALIZE: "Article 15 (Cybersecurity)",
  ERROR_LEAKAGE: "Article 15 (Cybersecurity)",
  CORS_WILDCARD: "Article 15 (Cybersecurity)"
};

async function main() {
  const scanner = new Scanner(RULES_PATH, FIXTURE_ROOT);

  // The scanner narrates progress to stderr and stdout. Keep the test output
  // readable, but restore both streams before an assertion can fail.
  const originalLog = console.log;
  const originalStderrWrite = process.stderr.write;
  console.log = () => {};
  process.stderr.write = () => true;
  let findings;
  try {
    findings = await scanner.scan();
  } finally {
    console.log = originalLog;
    process.stderr.write = originalStderrWrite;
  }

  for (const [ruleId, expectedArticle] of Object.entries(EXPECTED_ARTICLES)) {
    const hits = findings.filter((finding) => finding.id === ruleId);
    assert.ok(hits.length > 0, `${ruleId} did not fire on the fixture set`);
    for (const hit of hits) {
      assert.strictEqual(
        hit.article,
        expectedArticle,
        `${ruleId} in ${hit.file} has article ${JSON.stringify(hit.article)}, expected ${JSON.stringify(expectedArticle)}`
      );
    }
  }

  console.log(
    `ok - ${Object.keys(EXPECTED_ARTICLES).length} rules fired with the expected article mapping`
  );
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
