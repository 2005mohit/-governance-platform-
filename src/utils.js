// src/utils.js

/**
 * Redacts common PII patterns from a string.
 * IMPORTANT: only ever call this on text you're about to WRITE to the report.
 * Never run this on the content used for secret/rule DETECTION — redaction
 * can mutate or strip the very substrings a detection regex needs to match,
 * turning a real finding into a silent false negative.
 */
function redactPII(text) {
  if (!text) return text;
  return text
    // emails
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]")
    // US SSN-style — only a strictly dashed 3-2-4 digit shape
    .replace(/(?<![A-Za-z0-9])\d{3}-\d{2}-\d{4}(?![A-Za-z0-9])/g, "[REDACTED_ID]")
    // credit card-style — only when separated by spaces/dashes into groups
    // (a bare, unseparated 13-19 digit run is far more likely to be a
    // token, key fragment, or ID than a card number, so it's excluded here
    // deliberately to avoid mangling unrelated evidence)
    .replace(/(?<![A-Za-z0-9])\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}(?![A-Za-z0-9])/g, "[REDACTED_CARD]")
    // phone numbers — require phone-like separators or a leading +, and
    // never match inside a longer alphanumeric token (secrets, IDs, hex)
    .replace(/(?<![A-Za-z0-9])(\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]?\d{3,4}(?![A-Za-z0-9])/g, "[REDACTED_PHONE]");
}

/**
 * Masks any substring of `text` that matches one of the given regex source
 * strings. Used specifically for secret-detection findings, so the report
 * never has to rely on generic PII patterns to hide a credential value —
 * the thing that matched IS the thing that gets masked, deliberately.
 */
function maskSecretMatches(text, patterns) {
  if (!text) return text;
  let out = text;
  for (const p of patterns) {
    out = out.replace(new RegExp(p, "g"), "[SECRET REDACTED]");
  }
  return out;
}

/**
 * First NON-COMMENTED match of a pattern: walks every occurrence and skips
 * ones where the line holds nothing but whitespace + a line-comment marker
 * (# for Python/Terraform/YAML/env, // for JS/TS) before the match. A live
 * unsafe call elsewhere in the file is still found; a file whose ONLY
 * occurrences are commented out yields null (no finding, not a wrong line).
 * Block comments (/* ... *\/) are intentionally not covered — documented
 * residual. Returns {line, lineNumber} like findLineForMatch, or null.
 */
function findFirstNonCommentMatch(content, regex) {
  const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g");
  let match;
  while ((match = re.exec(content)) !== null) {
    if (match[0] === "") { re.lastIndex++; continue; } // never hang on empty
    const lineStart = content.lastIndexOf("\n", match.index - 1) + 1;
    if (/^\s*(?:#|\/\/)/.test(content.slice(lineStart, match.index))) continue;
    const upToMatch = content.slice(0, match.index);
    const lineNumber = upToMatch.split("\n").length;
    const lines = content.split("\n");
    const rawLine = lines[lineNumber - 1] || "";
    return { line: rawLine.trim().substring(0, 120), lineNumber };
  }
  return null;
}

/**
 * Given raw file content and a RegExp, returns the 1-indexed line number
 * and the actual matching line (trimmed, capped in length) — not just
 * whatever happens to be on line 1 of the file.
 */
function findLineForMatch(content, regex) {
  const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g");
  const match = re.exec(content);
  if (!match) return { line: null, lineNumber: null };

  const upToMatch = content.slice(0, match.index);
  const lineNumber = upToMatch.split("\n").length;
  const lines = content.split("\n");
  const rawLine = lines[lineNumber - 1] || "";

  return {
    line: rawLine.trim().substring(0, 120),
    lineNumber
  };
}

const FUNCTION_BOUNDARY = /^\s*(def\s|function\s|async\s+function\s|class\s|const\s+\w+\s*=\s*(async\s*)?\(|export\s+(default\s+)?function)/;

/**
 * Scopes the proximity search to the enclosing function/block where
 * possible, rather than a pure line-count window. A pure line-count window
 * on a short file can pick up an approval/logging marker that actually
 * belongs to a completely different, nearby function — this narrows the
 * search to "between the nearest function boundaries" first, and only
 * falls back to the raw line window if no boundaries are found (e.g. a
 * top-level script with no function structure).
 */
function getContextWindow(content, lineNumber, maxWindow) {
  const lines = content.split("\n");
  let start = Math.max(0, lineNumber - 1 - maxWindow);
  let end = Math.min(lines.length, lineNumber - 1 + maxWindow);

  for (let i = lineNumber - 1; i >= start; i--) {
    if (i !== lineNumber - 1 && FUNCTION_BOUNDARY.test(lines[i])) {
      start = i;
      break;
    }
  }
  for (let i = lineNumber; i < end; i++) {
    if (FUNCTION_BOUNDARY.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

module.exports = { redactPII, maskSecretMatches, findLineForMatch, findFirstNonCommentMatch, getContextWindow };
