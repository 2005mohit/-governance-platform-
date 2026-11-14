// Equivalence tests for the per-file line index and context window.
//
// Scanning used to compute a candidate's line number with
// `content.slice(0, index).split("\n").length` and to split the whole file
// again for every context window. That is O(file size) per candidate and made
// large files quadratic. The index must be a drop-in replacement: for every
// byte offset it has to agree with the old expression exactly, including CRLF
// line endings, blank lines, and offsets that land on a `\n`.
const assert = require("assert");
const { buildLineIndex, getContextWindow } = require("../src/utils");

let checks = 0;

function assertSameAcrossEveryOffset(label, content) {
  const index = buildLineIndex(content);
  assert.deepStrictEqual(index.lines, content.split("\n"), `${label}: lines must match split("\\n")`);
  for (let offset = 0; offset <= content.length; offset++) {
    const expected = content.slice(0, offset).split("\n").length;
    const actual = index.lineNumberAt(offset);
    assert.strictEqual(actual, expected, `${label}: offset ${offset} expected line ${expected}, got ${actual}`);
  }
  checks++;
}

function main() {
  assertSameAcrossEveryOffset("lf", "alpha\nbeta\n\ngamma\ndelta\n");
  assertSameAcrossEveryOffset("crlf", "alpha\r\nbeta\r\n\r\ngamma\r\ndelta\r\n");
  assertSameAcrossEveryOffset("single-line", "one line with no terminator");
  assertSameAcrossEveryOffset("empty", "");
  assertSameAcrossEveryOffset(
    "function boundaries",
    "def a():\n    db.delete(1)\n\n\ndef b():\n    log.info('x')\n\nconst f = () => {\n  db.delete(2)\n};\n"
  );

  const sample = "def a():\n    db.delete(1)\n\n\ndef b():\n    log.info('x')\n";
  const index = buildLineIndex(sample);
  for (let line = 1; line <= index.lines.length; line++) {
    assert.strictEqual(
      getContextWindow(sample, line, 15, index.lines),
      getContextWindow(sample, line, 15),
      `line ${line}: pre-split context must equal the splitting version`
    );
    checks++;
  }

  console.log(`ok - ${checks} line-index assertions passed`);
}

main();
