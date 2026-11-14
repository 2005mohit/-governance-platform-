// `send` is NOT in the shipped high_risk_actions taxonomy (the pack has
// send_payment, but not send). This is a real call, not a definition; it is
// kept here to document the taxonomy gap rather than adding a new verb and
// widening detection beyond item 3's scope.
async function notify(mailer, x) {
  await mailer.send(x);
}
