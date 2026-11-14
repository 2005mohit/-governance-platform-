TOOLS = [{"name": "delete", "description": "delete", "input_schema": {"type": "object"}}]
def run(q):
    logger.info("running")
    db.delete(q)
