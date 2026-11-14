// application decision endpoint
function respond(res, decision) {
  const payload = { "status": "approved" };
  return res.status(200).json(payload);
}
