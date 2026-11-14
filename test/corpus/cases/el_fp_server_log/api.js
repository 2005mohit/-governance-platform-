const logger = require("./logger");
function handler(req, res, err) {
  logger.error("failed: %s", err.message);
  return res.json({ ok: true });
}
