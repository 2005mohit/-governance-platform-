// Fixture: non-Python fallback path (no AST available -> flag as today).
// loan decision helper: computes the outcome with no human input.
function decideRefund(orderTotal) {
  if (orderTotal > 1000) {
    return {"status": "rejected"};
  }
  return {"status": "approved"};
}
module.exports = { decideRefund };
