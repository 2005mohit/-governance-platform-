#!/usr/bin/env python3
"""AST-based approval-gating check for ai-risk-snapshot (Phase 3).

Reads a JSON request on stdin:
  {"source": "<python source>", "queries": [{"line": int, "action": str}],
   "markers": ["human_approval", ...]}

Writes JSON on stdout:
  {"ok": bool, "verdicts": [{"line": int, "gated": true|false|null,
                             "reason": str}]}

"gated": true  -> the call is structurally gated by an approval check
                 (inside an approval conditional, or dominated by an
                 approval guard-clause / assert).
"gated": false -> parsed fine, no gating structure found (intra-function
                 only: a guard living in a *called helper* is invisible
                 here by design — see KNOWN LIMITATIONS in README.md).
"gated": null  -> inconclusive (call not found at that line); the caller
                 must fall back to the proximity heuristic.

"ok": false means the file did not parse; every verdict falls back.

Stdlib only (ast, json, sys, re). Never executes the analysed code.
Scope notes (v1, documented limits):
  - Same-block + enclosing-block dominance only, not a full CFG.
  - Approval references: marker-name Call/Name/Attribute, or a variable
    assigned from such a call (one common pattern: approval = review(...)).
  - Polarity: `not X`, `X == False`, `X is False` count as negative;
    `and` needs any positive operand; `or` is negative when at least one
    operand is a negative approval test and none is a positive one (the OR
    being false then proves the negated approval operand held).
  - A `try` block whose body contains an exiting approval guard counts as a
    guard for the statements after it only when every handler re-raises/exits.
"""

import ast
import json
import re
import sys


EXIT_CALLS = {"exit", "quit", "sys.exit", "os._exit"}

# Generic decision vocabulary for the receiver check (FIX 1). Deliberately
# domain-free: decision-workflow words only, no app-specific terms. Used to
# recognise function PARAMETERS that carry an incoming human decision — never
# the function NAME alone (a name like validate_order proves nothing; only
# evidence that a decision flows in does).
DECISION_VOCAB = ["decision", "result", "outcome", "verdict",
                  "validation", "approval", "review", "confirm"]


def dotted_name(node):
    """Best-effort dotted name for func expressions: a.b.c / name / None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def block_exits(stmts):
    """True if a statement list unconditionally exits (raise/return/exit)."""
    if not stmts:
        return False
    for s in stmts:
        if isinstance(s, (ast.Raise, ast.Return)):
            continue
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
            if dotted_name(s.value.func) in EXIT_CALLS:
                continue
        if isinstance(s, ast.If):
            if block_exits(s.body) and block_exits(s.orelse):
                continue
        return False
    return True


class GateChecker:
    def __init__(self, source, markers):
        self.tree = ast.parse(source)
        self.marker_res = [re.compile(m, re.I) for m in markers]
        self.parent = {}
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node

    def is_marker_ref(self, dotted):
        return bool(dotted) and any(r.search(dotted) for r in self.marker_res)

    def collect_approval_vars(self, func_node):
        """Variables assigned from approval-marker calls (fixed-point, 3 rounds)."""
        approved = set()
        for _ in range(3):
            grew = False
            for node in ast.walk(func_node):
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                tgt = node.targets[0]
                if not isinstance(tgt, ast.Name) or tgt.id in approved:
                    continue
                val = node.value
                if isinstance(val, ast.Call) and self.is_marker_ref(dotted_name(val.func)):
                    approved.add(tgt.id)
                    grew = True
                elif isinstance(val, ast.Name) and val.id in approved:
                    approved.add(tgt.id)
                    grew = True
            if not grew:
                break
        return approved

    def test_refers_approval(self, test, approval_vars):
        """Plain (non-polarity) reference check used for BoolOp recursion."""
        for node in ast.walk(test):
            if isinstance(node, ast.Name):
                if node.id in approval_vars or self.is_marker_ref(node.id):
                    return True
            elif isinstance(node, ast.Call):
                if self.is_marker_ref(dotted_name(node.func)):
                    return True
            elif isinstance(node, ast.Attribute):
                if self.is_marker_ref(node.attr):
                    return True
        return False

    def polarity(self, test, approval_vars):
        """'pos' / 'neg' / None: does this test passing imply approval?"""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return "neg" if self.test_refers_approval(test.operand, approval_vars) else None
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            if isinstance(op, (ast.Eq, ast.Is)):
                comp = test.comparators[0]
                is_falsey = (isinstance(comp, ast.Constant) and comp.value in (False, None, 0, "", []))
                if is_falsey and self.test_refers_approval(test.left, approval_vars):
                    return "neg"
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And):
                return "pos" if any(
                    self.polarity(v, approval_vars) == "pos" for v in test.values
                ) else None
            # `if not A or not B: raise` is a real gate: the OR being false
            # proves every negated operand held. Keep `or` ungated when any
            # operand is a POSITIVE approval test (its failure could be
            # masked), or when no operand is a negative approval test.
            has_neg = any(self.polarity(v, approval_vars) == "neg" for v in test.values)
            has_pos = any(self.polarity(v, approval_vars) == "pos" for v in test.values)
            return "neg" if has_neg and not has_pos else None
        return "pos" if self.test_refers_approval(test, approval_vars) else None

    def enclosing_scope(self, line):
        """Innermost FunctionDef/AsyncFunctionDef/Module spanning `line`."""
        best = None
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                start = getattr(node, "lineno", 1)
                end = getattr(node, "end_lineno", 10 ** 9)
                if start <= line <= end:
                    if best is None or getattr(node, "lineno", 1) >= getattr(best, "lineno", 1):
                        best = node
        return best

    def find_call(self, scope, line, action):
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != line:
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if name == action:
                return node
        return None

    def body_has_exit_guard(self, stmts, approval_vars):
        """True if `stmts` contains an approval guard that exits the block."""
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                if self.polarity(stmt.test, approval_vars) == "neg" and block_exits(stmt.body):
                    return True
            if isinstance(stmt, ast.Assert):
                if self.polarity(stmt.test, approval_vars) == "pos":
                    return True
        return False

    def dominated_by_guard(self, call_node, scope, approval_vars):
        """Approval guard-clause / assert dominating the call (walk-up).

        At each enclosing statement list on the call's path, inspects the
        statements textually *before* the child: a negated-approval `if`
        whose body unconditionally exits (raise/return/exit), or a positive
        approval `assert`, means the call below it cannot execute without
        approval. Same-block + enclosing-block dominance only, not a full
        CFG — documented limit.
        """
        child = call_node
        node = self.parent.get(child)
        while node is not None:
            body = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                body = node.body
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                for field in ("body", "orelse", "finalbody"):
                    seq = getattr(node, field, None)
                    if isinstance(seq, list) and child in seq:
                        body = seq
                        break
                if body is None:
                    child, node = node, self.parent.get(node)
                    continue
            else:
                child, node = node, self.parent.get(node)
                continue
            idx = body.index(child)
            for stmt in body[:idx]:
                if isinstance(stmt, ast.If):
                    pol = self.polarity(stmt.test, approval_vars)
                    if pol == "neg" and block_exits(stmt.body):
                        return True, "guard-clause"
                if isinstance(stmt, ast.Assert):
                    if self.polarity(stmt.test, approval_vars) == "pos":
                        return True, "assert-gate"
                if isinstance(stmt, ast.Try):
                    # `try: if not approval: raise ... except: raise` still
                    # gates the statements after it when every handler
                    # re-raises/exits; a swallowing handler does not.
                    if (stmt.handlers
                            and all(block_exits(h.body) for h in stmt.handlers)
                            and self.body_has_exit_guard(stmt.body, approval_vars)):
                        return True, "guard-clause-in-try"
            if node is scope:
                break
            child, node = node, self.parent.get(node)
        return False, ""

    def verdict(self, line, action, markers):
        scope = self.enclosing_scope(line)
        if scope is None:
            return None, "no-enclosing-scope"
        call = self.find_call(scope, line, action)
        if call is None:
            return None, "call-not-found-at-line"
        approval_vars = self.collect_approval_vars(scope)
        # (a) inside an approval conditional?
        node = call
        while node is not scope:
            parent = self.parent.get(node)
            if parent is None:
                break
            if isinstance(parent, ast.If):
                branch = "body" if node in parent.body else "orelse"
                pol = self.polarity(parent.test, approval_vars)
                if (branch == "body" and pol == "pos") or (branch == "orelse" and pol == "neg"):
                    return True, "inside-approval-conditional"
            node = parent
        # (b) dominated by a guard-clause / assert?
        gated, reason = self.dominated_by_guard(call, scope, approval_vars)
        if gated:
            return True, reason
        return False, "no-gating-conditional"


def receiver_verdict(checker, line):
    """Does the status assignment at `line` RECORD an incoming human decision
    rather than COMPUTE one? Returns (received, reason) with received None on
    inconclusive input. Suppress-worthy only on True.

    received=True iff the enclosing function takes a decision-vocabulary
    parameter (not shadowed by a local assignment) AND either:
      (a) the assigned status value IS such a parameter, or
      (b) the assignment sits in a branch conditioned on such a parameter.
    A merely suggestive function NAME never suppresses on its own: e.g.
    `def validate_order(order)` hardcoding approved still flags, correctly.
    Module-level assignments have no receiving handler -> computing (False).
    """
    func = None
    for node in ast.walk(checker.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", 10 ** 9)
            if node.lineno <= line <= end:
                if func is None or node.lineno >= func.lineno:
                    func = node
    if func is None:
        return False, "module-level-no-handler"
    params = ([a.arg for a in func.args.posonlyargs] + [a.arg for a in func.args.args]
              + [a.arg for a in func.args.kwonlyargs])
    assigned = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assigned.add(t.id)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.target, ast.Name):
                assigned.add(node.target.id)
        elif isinstance(node, ast.NamedExpr):
            assigned.add(node.target.id)
    cand_params = [p for p in params
                   if any(v in p.lower() for v in DECISION_VOCAB) and p not in assigned]
    if not cand_params:
        return False, "no-decision-param"
    # (a) status value IS an incoming parameter (Assign or dict value)?
    for node in ast.walk(func):
        if getattr(node, "lineno", None) != line:
            continue
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.value, ast.Name) and node.value.id in cand_params:
                return True, "value-is-param"
        if isinstance(node, ast.Dict):
            for v in node.values:
                if isinstance(v, ast.Name) and v.id in cand_params:
                    return True, "value-is-param"
    # (b) assignment control-dependent on a decision-parameter test?
    for node in ast.walk(checker.tree):
        if not isinstance(node, ast.If):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", -1)
        if not (start <= line <= end):
            continue
        refs_param = False
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Name) and sub.id in cand_params:
                refs_param = True
            elif isinstance(sub, ast.Call):
                if any(v in (dotted_name(sub.func) or "").lower() for v in DECISION_VOCAB):
                    refs_param = True
        if refs_param:
            return True, "branch-conditioned-on-decision-param"
    return False, "computing-no-received-decision"


def main():
    try:
        req = json.load(sys.stdin)
    except Exception as e:
        sys.stdout.write(json.dumps({"ok": False, "error": "bad-request: %s" % e}))
        return
    source = req.get("source", "")
    queries = req.get("queries", [])
    markers = req.get("markers", [])
    try:
        checker = GateChecker(source, markers)
    except (SyntaxError, ValueError) as e:
        sys.stdout.write(json.dumps({"ok": False, "error": "parse-failed"}))
        return
    verdicts = []
    for q in queries:
        try:
            if q.get("op") == "receiver":
                received, reason = receiver_verdict(checker, int(q["line"]))
                verdicts.append({"line": q.get("line"), "received": received,
                                 "reason": reason})
            else:
                gated, reason = checker.verdict(int(q["line"]), str(q["action"]), markers)
                verdicts.append({"line": q.get("line"), "gated": gated, "reason": reason})
        except Exception:
            if q.get("op") == "receiver":
                verdicts.append({"line": q.get("line"), "received": None,
                                 "reason": "checker-error"})
            else:
                verdicts.append({"line": q.get("line"), "gated": None, "reason": "checker-error"})
    sys.stdout.write(json.dumps({"ok": True, "verdicts": verdicts}))


if __name__ == "__main__":
    main()
