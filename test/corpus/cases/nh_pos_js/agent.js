function purge(id) {
  logger.info("purging", id);
  db.delete(id);
}
