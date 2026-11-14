TOOLS = [{"type": "function", "function": {"name": "delete"}}]
def run(q):
    logger.info("running")
    db.delete(q)
