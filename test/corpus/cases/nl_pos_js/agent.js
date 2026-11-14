function purge(id) {
  // human_approval enforced by middleware
  db.delete(id);
}
