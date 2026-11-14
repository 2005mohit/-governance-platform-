function fail(res, e) {
  return res.status(500).json({ error: e.message });
}
